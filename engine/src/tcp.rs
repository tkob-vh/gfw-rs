//! TCP Stream Management Module
//!
//! This module provides functionality for handling TCP streams, including
//! creating new TCP streams, processing TCP packets, and updating stream properties.

use std::{
    error::Error,
    net::IpAddr,
    num::NonZero,
    ops::Deref,
    sync::Arc,
    time::{Duration, SystemTime},
};

use lru::LruCache;
use pnet::packet::{tcp::MutableTcpPacket, Packet};
use snowflake::SnowflakeIdGenerator;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::utils::process_prop_update;

/// TCPVerdict is a subset of io.Verdict for TCP streams.
/// We don't allow modifying or dropping a single packet
/// for TCP streams for now, as it doesn't make much sense.
#[derive(Clone, Debug)]
pub enum TCPVerdict {
    Accept,
    AcceptStream,
    DropStream,
}

impl From<TCPVerdict> for nt_io::Verdict {
    fn from(value: TCPVerdict) -> Self {
        match value {
            TCPVerdict::Accept => nt_io::Verdict::Accept,
            TCPVerdict::AcceptStream => nt_io::Verdict::AcceptStream,
            TCPVerdict::DropStream => nt_io::Verdict::DropStream,
        }
    }
}

/// TCPContext holds the current verdict and capture information for a TCP stream.
pub struct TCPContext {
    pub verdict: TCPVerdict,
    pub packet: Vec<u8>,
}

/// TCPStreamFactory is responsible for creating new TCP streams and updating the ruleset.
#[derive(Debug)]
pub struct TCPStreamFactory {
    worker_id: u32,

    /// https://en.wikipedia.org/wiki/Snowflake_ID
    pub node: SnowflakeIdGenerator,

    /// The ruleset for the tcp stream entries.
    ruleset: RwLock<Arc<dyn nt_ruleset::Ruleset>>,
}

impl TCPStreamFactory {
    /// Create a new TCPStreamFactory.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - The ID of the worker.
    /// * `node` - The Snowflake ID generator.
    /// * `ruleset` - The ruleset for the TCP stream entries.
    pub fn new(
        worker_id: u32,
        node: SnowflakeIdGenerator,
        ruleset: RwLock<Arc<dyn nt_ruleset::Ruleset>>,
    ) -> Self {
        Self {
            worker_id,
            node,
            ruleset,
        }
    }

    /// Create a new TCPStream according to the src and dst info (addr and port).
    ///
    /// Inlcuding generating a stream id using snowflake algorithm, generating the stream info for
    /// the ruleset, getting the ruleset, generating stream entries for each analyzer.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `tcp_packet` - The TCP packet.
    ///
    /// # Returns
    ///
    /// An optional TCPStream.
    async fn new_stream<'a>(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_packet: &'a MutableTcpPacket<'a>,
    ) -> Option<TCPStream> {
        // Generate a unique snowflake.
        let id = self.node.generate();

        // Get the port info from the tcp packet.
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();

        // Construct the stream info for the ruleset.
        let info = nt_ruleset::StreamInfo {
            id,
            protocol: nt_ruleset::Protocol::TCP,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            props: nt_analyzer::CombinedPropMap::new(),
        };

        debug!(
            "[New TCP stream]: worker_id = {:?}, id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}",
            self.worker_id, id, src_ip, src_port, dst_ip, dst_port
        );

        // Get the ruleset from the tcp stream factory.
        let rs = self.ruleset.read().await;

        // Get the analyzers and convert them to tcp analyzers.
        let analyzers = rs.analyzers();
        let tcp_analyzers = analyzer_to_tcp_analyzers(&analyzers);

        // Create tcp stream entries for each tcp analyzer
        let entries: Vec<TCPStreamEntry> = tcp_analyzers
            .iter()
            .map(|a| TCPStreamEntry {
                name: a.name().to_string(),
                stream: a.new_tcp(nt_analyzer::TCPInfo {
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                }),
                has_limit: a.limit() > 0,
                quota: a.limit(),
            })
            .collect();

        Some(TCPStream {
            info,
            virgin: true,
            ruleset: rs.deref().clone(),
            active_entries: entries,
            done_entries: Vec::new(),
            last_verdict: TCPVerdict::Accept,
        })
    }

    /// Update the ruleset.
    ///
    /// # Arguments
    ///
    /// * `new_ruleset` - The new ruleset.
    ///
    /// # Returns
    ///
    /// A result indicating success or failure.
    pub async fn update_ruleset(
        &self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut ruleset = self.ruleset.write().await;
        *ruleset = new_ruleset;
        Ok(())
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct TCPStreamManager {
    factory: TCPStreamFactory,
    streams: LruCache<u32, TCPStreamValue>,
    /// The following two variables is not used for now.
    max_buffered_pages_total: u32,
    max_buffered_pages_per_conn: u32,
}

impl TCPStreamManager {
    /// Create a new TCPStreamManager.
    ///
    /// # Arguments
    ///
    /// * `factory` - The TCp stream factory.
    /// * `max_buffered_pages_total` -
    /// * `max_buffered_pages_per_conn` -
    pub fn new(
        factory: TCPStreamFactory,
        max_buffered_pages_total: u32,
        max_buffered_pages_per_conn: u32,
    ) -> Self {
        Self {
            factory,
            streams: LruCache::new(NonZero::new(max_buffered_pages_total as usize).unwrap()),
            max_buffered_pages_total,
            max_buffered_pages_per_conn,
        }
    }

    /// Matches the tcp packet with a stream and then handle the packet.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream ID of the stream to be matched.
    /// * `src_ip` - The source IP address of the packet.
    /// * `dst_ip` - The destination IP address of the packet.
    /// * `udp_packet` - The UDP packet to be matched.
    /// * `udp_context` - The UDP context.
    pub async fn match_with_context<'a>(
        &mut self,
        stream_id: u32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_packet: &'a mut MutableTcpPacket<'a>,
        tcp_context: &mut TCPContext,
    ) {
        let mut reverse = false;
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();

        debug!("Get the stream according to the stream_id.");
        if let Some(value) = self.streams.get_mut(&stream_id) {
            let (matches, is_reverse) = value.matches(src_ip, dst_ip, src_port, dst_port);

            if !matches {
                debug!("Stream ID exists but different flow - create a new stream.");
                value.stream.close_active_entries();
                let new_stream = self.factory.new_stream(src_ip, dst_ip, tcp_packet).await;
                if let Some(stream) = new_stream {
                    let value = TCPStreamValue {
                        stream,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        last_seen: SystemTime::now(),
                    };
                    self.streams.put(stream_id, value);
                }
            } else {
                reverse = is_reverse;
            }
        } else {
            debug!("Stream ID not exists, create a new stream.");
            if let Some(stream) = self.factory.new_stream(src_ip, dst_ip, tcp_packet).await {
                let value = TCPStreamValue {
                    stream,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    last_seen: SystemTime::now(),
                };
                self.streams.put(stream_id, value);
            }
        }

        // Handle the packet in the matched stream.
        if let Some(value) = self.streams.get_mut(&stream_id) {
            if value.stream.accept(tcp_packet, tcp_context) {
                value
                    .stream
                    .feed(tcp_packet.payload(), reverse, tcp_context);
            }
        }
    }

    /// Find any streams waiting for packets older than
    /// the given time `timeout`, and pushes through the data they have (ie. tells
    /// them to stop waiting and skip the data they're waiting for).
    ///
    /// It also closes streams older than `timeout`
    ///
    /// Each Stream maintains a list of zero or more sets of bytes it has received
    /// out-of-order.  For example, if it has processed up through sequence number
    /// 10, it might have bytes [15-20), [20-25), [30,50) in its list.  Each set of
    /// bytes also has the timestamp it was originally viewed.  A flush call will
    /// look at the smallest subsequent set of bytes, in this case [15-20), and if
    /// its timestamp is older than the passed-in time, it will push it and all
    /// contiguous byte-sets out to the Stream's Reassembled function.  In this case,
    /// it will push [15-20), but also [20-25), since that's contiguous.  It will
    /// only push [30-50) if its timestamp is also older than the passed-in time,
    /// otherwise it will wait until the next FlushCloseOlderThan to see if bytes
    /// [25-30) come in.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The given timeout.
    ///
    /// # Returns
    ///
    /// Returns the number of connections flushed, and of those, the number closed
    /// because of the flush.
    pub fn flush_close_older_than(&mut self, timeout: Duration) -> (usize, usize) {
        let time = SystemTime::now().checked_sub(timeout).unwrap();
        let mut closes: usize = 0;
        let mut flushes: usize = 0;

        // Create a list of stream IDs to remove
        let mut streams_to_remove = Vec::new();

        // Check each stream in the LRU cache
        for (&stream_id, stream_value) in self.streams.iter_mut() {
            let mut should_remove = false;

            // If the stream has been inactive for longer than the timeout
            if stream_value.last_seen <= time {
                // Close any active entries
                stream_value.stream.close_active_entries();
                closes += 1;
                should_remove = true;
            }

            // If any data was processed
            if should_remove {
                flushes += 1;
                streams_to_remove.push(stream_id);
            }
        }

        // Remove closed streams from the LRU cache
        for stream_id in streams_to_remove {
            self.streams.pop(&stream_id);
        }

        (flushes, closes)
    }
}

/// Only used in the LruCache. 1-1 relationship with TCPStream.
struct TCPStreamValue {
    stream: TCPStream,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,

    /// Updated on Constructing the struct, used when flushing the stream.
    last_seen: SystemTime,
}

impl TCPStreamValue {
    fn matches(
        &self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> (bool, bool) {
        let forward = self.src_ip == src_ip
            && self.dst_ip == dst_ip
            && self.src_port == src_port
            && self.dst_port == dst_port;

        let reverse = self.src_ip == dst_ip
            && self.dst_ip == src_ip
            && self.src_port == dst_port
            && self.dst_port == src_port;

        (forward || reverse, reverse)
    }
}

/// TCPStream contains many entries.
struct TCPStream {
    /// The stream info for the ruleset.
    info: nt_ruleset::StreamInfo,

    /// True if no packets have been processed.
    virgin: bool,

    /// The ruleset for the tcp stream.
    ruleset: Arc<dyn nt_ruleset::Ruleset>,

    /// The unprocessed stream entries.
    active_entries: Vec<TCPStreamEntry>,

    /// The processed stream entries.
    done_entries: Vec<TCPStreamEntry>,

    /// The verdict for the last processed packet.
    /// Because tcp is stream based. If we known the verdict for the first packet, the remaining
    /// packets should also use the same verdcit.
    last_verdict: TCPVerdict,
}

impl TCPStream {
    /// Determine whether accept a TCP packet and updates the context verdict.
    ///
    /// # Arguments
    ///
    /// * `tcp` - The TCP packet.
    /// * `context` - A mutable reference to the TCPContext.
    ///
    /// # Returns
    ///
    /// A boolean indicating whether the packet is accepted.
    #[allow(unused_variables)]
    fn accept(&self, tcp: &MutableTcpPacket, context: &mut TCPContext) -> bool {
        // Make sure every stream matches against the ruleset at least once,
        // even if there are no active entries, as the ruleset may have built-in
        // properties that need to be matched.
        if !self.active_entries.is_empty() || self.virgin {
            // If there are active entries or this is the first packet, accept the packet.
            true
        } else {
            // If there are no active entries and this is not the first packet,
            // set the context verdict to the last verdict of the stream.
            context.verdict = self.last_verdict.clone();
            false
        }
    }

    /// Feed the TCP stream by processing the provided data.
    ///
    /// This function processes the provided data for each active TCP stream entry,
    /// updates the stream properties, and determines the final verdict for the stream.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the data to be processed.
    /// * `reverse` - A boolean indicating whether the data is in reverse order.
    /// * `context` - A mutable reference to the TCPContext, which holds the current verdict and capture information.
    fn feed(&mut self, data: &[u8], reverse: bool, context: &mut TCPContext) {
        let start: bool = false;
        let end: bool = false;
        let skip: usize = 0;
        let mut updated = false;
        let mut indices_to_remove = Vec::new();

        // First pass: process entries and collect indices to remove
        for (i, entry) in self.active_entries.iter_mut().enumerate() {
            // Feed the data to the stream entry and get the final property map.
            let (update, close_update, done) =
                TCPStream::feed_entry(entry, reverse, start, end, skip, data);

            // process the property maps for the analyzer using the got update/close_update.
            let up1 = process_prop_update(&mut self.info.props, &entry.name, update);
            // Always false for now (because close_update is always None).
            let up2 = process_prop_update(&mut self.info.props, &entry.name, close_update);

            updated = updated || up1 || up2;

            if done {
                indices_to_remove.push(i);
            }
        }

        // Second pass: remove entries in reverse order
        for &i in indices_to_remove.iter().rev() {
            let entry = self.active_entries.remove(i);
            self.done_entries.push(entry);
        }

        // If any properties were updated or this is the first packet, update the verdict
        if updated || self.virgin {
            self.virgin = false;

            debug!(
                "[TCP stream property update]: id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}, props = {:?}, close = {}",
                self.info.id,
                self.info.src_ip,
                self.info.src_port,
                self.info.dst_ip,
                self.info.dst_port,
                self.info.props, 
                false,
            );

            // Match the ruleset with the got properties.
            let result = self.ruleset.matches(&self.info);

            match result.action {
                nt_ruleset::Action::Maybe | nt_ruleset::Action::Modify => {}
                action => {
                    let verdict = action_to_tcp_verdict(&action);
                    self.last_verdict = verdict.clone();
                    context.verdict = verdict;
                    info!(
                        "[TCP stream action]: id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}, action = {:?}",
                        self.info.id,
                        self.info.src_ip,
                        self.info.src_port,
                        self.info.dst_ip,
                        self.info.dst_port,
                        &action,
                    );
                    self.close_active_entries();
                }
            }
        }

        // If there are no active entries and the current verdict is Accept, update the verdict to AcceptStream
        if self.active_entries.is_empty() && matches!(context.verdict, TCPVerdict::Accept) {
            self.last_verdict = TCPVerdict::AcceptStream;
            context.verdict = TCPVerdict::AcceptStream;
            
            debug!("[TCP stream no match]: id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}, action = {:?}",
                self.info.id,
                self.info.src_ip,
                self.info.src_port,
                self.info.dst_ip,
                self.info.dst_port,
                nt_ruleset::Action::Allow,
                );

        }
    }

    /// Feeds data to a TCP stream entry and updates its properties.
    ///
    /// # Arguments
    ///
    /// * `entry` - A mutable reference to the TCPStreamEntry.
    /// * `reverse` - A boolean indicating whether the data is in reverse order.
    /// * `start` - A boolean indicating whether this is the start of the stream.
    /// * `end` - A boolean indicating whether this is the end of the stream.
    /// * `skip` - The number of bytes to skip.
    /// * `data` - A slice of bytes representing the data to be processed.
    ///
    /// # Returns
    ///
    /// A tuple containing the property update, close update, and a boolean indicating whether the entry is done.
    fn feed_entry(
        entry: &mut TCPStreamEntry,
        reverse: bool,
        start: bool,
        end: bool,
        skip: usize,
        data: &[u8],
    ) -> (
        Option<nt_analyzer::PropUpdate>,
        Option<nt_analyzer::PropUpdate>,
        bool,
    ) {
        if !entry.has_limit {
            // If the stream dose not have limit, just feed the data to it.
            let (update, done) = entry.stream.feed(reverse, start, end, skip, data);
            (update, None, done)
        } else {
            // Else feed the data within the quota and update the quota.
            let data = if data.len() > entry.quota as usize {
                &data[..entry.quota as usize]
            } else {
                data
            };
            let (update, done) = entry.stream.feed(reverse, start, end, skip, data);
            entry.quota -= data.len() as i32;

            if entry.quota <= 0 {
                // If there is no quota left, close the stream entry (Moved to the done_entries list
                // later).
                let close_update = entry.stream.close(true);
                (update, close_update, true)
            } else {
                (update, None, done)
            }
        }
    }

    /// Signal close to all active entries & move them to doneEntries
    ///
    /// This function signals the close of all active TCP stream entries and moves them to the done entries list.
    fn close_active_entries(&mut self) {
        let mut updated = false;

        for entry in &mut self.active_entries {
            if let Some(update) = entry.stream.close(false) {
                updated |= process_prop_update(&mut self.info.props, &entry.name, Some(update));
            }
        }

        if updated {
            debug!(
                "[TCP stream property update]: id = {:?}, src = {:?}:{:?}, dst = {:?}:{:?}, props = {:?}, close = {}",
                self.info.id,
                self.info.src_ip,
                self.info.src_port,
                self.info.dst_ip,
                self.info.dst_port,
                self.info.props, 
                true,
            );

        }

        self.done_entries.append(&mut self.active_entries);
    }
}

/// TCPStreamEntry represents a single TCP stream entry.
struct TCPStreamEntry {
    /// The name of the analyzer.
    name: String,

    /// The tcp stream created by the analyzers (new_tcp(..)).
    stream: Box<dyn nt_analyzer::TCPStream>,

    /// If the stream has any byte limit.
    has_limit: bool,

    /// The byte limit for the stream.
    quota: i32,
}

/// Downcast trait `Analyzer` to trait `TCPAnalyzer`.
///
/// # Arguments
///
/// * `analyzers` - A slice of Arc-wrapped Analyzer trait objects.
///
/// # Returns
///
/// A vector of Arc-wrapped TCPAnalyzer trait objects.
fn analyzer_to_tcp_analyzers(
    analyzers: &[Arc<dyn nt_analyzer::Analyzer>],
) -> Vec<Arc<dyn nt_analyzer::TCPAnalyzer>> {
    analyzers
        .iter()
        .filter_map(|a| {
            a.as_any()
                .downcast_ref::<Arc<dyn nt_analyzer::TCPAnalyzer>>()
                .cloned()
        })
        .collect()
}

/// Convert ruleset action to tcp verdict.
///
/// # Arguments
///
/// * `action` - The ruleset action.
///
/// # Returns
///
/// The corresponding TCPVerdict.
fn action_to_tcp_verdict(action: &nt_ruleset::Action) -> TCPVerdict {
    match action {
        nt_ruleset::Action::Maybe | nt_ruleset::Action::Allow | nt_ruleset::Action::Modify => {
            TCPVerdict::AcceptStream
        }
        nt_ruleset::Action::Block | nt_ruleset::Action::Drop => TCPVerdict::DropStream,
    }
}
