//! This module provides functionality for handling TCP streams, including
//! creating new TCP streams, processing TCP packets, and updating stream properties.

use crate::utils::process_prop_update;

use pnet::packet::tcp::TcpPacket;
use snafu::Whatever;
use snowflake::SnowflakeIdGenerator;
use tokio::sync::RwLock;
use tracing::info;

use std::{net::IpAddr, ops::Deref, sync::Arc};

/// TCPVerdict is a subset of io.Verdict for TCP streams.
/// We don't allow modifying or dropping a single packet
/// for TCP streams for now, as it doesn't make much sense.
#[derive(Clone, Debug)]
enum TCPVerdict {
    Accept,
    AcceptStream,
    DropStream,
}

/// TCPContext holds the current verdict and capture information for a TCP stream.
pub struct TCPContext {
    verdict: TCPVerdict,
    capture_info: CaptureInfo,
}

/// CaptureInfo holds the timestamp and length of a captured packet.
#[derive(Clone)]
pub struct CaptureInfo {
    timestamp: std::time::SystemTime,
    length: u32,
}

/// TCPStreamFactory is responsible for creating new TCP streams and updating the ruleset.
pub struct TCPStreamFactory {
    worker_id: i32,

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
        worker_id: i32,
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
    /// # Arguments
    ///
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `tcp_packet` - The TCP packet.
    ///
    /// # Returns
    ///
    /// An optional TCPStreamEngine.
    async fn new_stream<'a>(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_packet: &'a TcpPacket<'a>,
    ) -> Option<TCPStreamEngine> {
        // Generate a unique snowflake.
        let id = self.node.generate();

        // Get the port info from the tcp packet.
        let src_port = tcp_packet.get_source();
        let dst_port = tcp_packet.get_destination();

        // Construct the stream info for the ruleset.
        let info = nt_ruleset::StreamInfo {
            id: id as i64,
            protocol: nt_ruleset::Protocol::TCP,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            props: nt_analyzer::CombinedPropMap::new(),
        };

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

        Some(TCPStreamEngine {
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
    async fn update_ruleset(
        &self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Whatever> {
        let mut ruleset = self.ruleset.write().await;
        *ruleset = new_ruleset;
        Ok(())
    }
}

/// TCPStreamEngine processes TCP packets and updates stream properties.
struct TCPStreamEngine {
    /// The stream info for the ruleset.
    info: nt_ruleset::StreamInfo,

    /// True if no packets have been processed
    virgin: bool,

    /// The ruleset for the tcp stream.
    ruleset: Arc<dyn nt_ruleset::Ruleset>,

    /// The unprocessed stream entries.
    active_entries: Vec<TCPStreamEntry>,

    /// The processed stream entries.
    done_entries: Vec<TCPStreamEntry>,

    last_verdict: TCPVerdict,
}

impl TCPStreamEngine {
    /// Accepts a TCP packet and updates the context verdict.
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
    fn accept(&self, tcp: &TcpPacket, context: &mut TCPContext) -> bool {
        // Make sure every stream matches against the ruleset at least once,
        // even if there are no active entries, as the ruleset may have built-in
        // properties that need to be matched.
        if !self.active_entries.is_empty() || self.virgin {
            true
        } else {
            context.verdict = self.last_verdict.clone();
            false
        }
    }

    /// Reassembles the TCP stream by processing the provided data.
    ///
    /// This function processes the provided data for each active TCP stream entry,
    /// updates the stream properties, and determines the final verdict for the stream.
    ///
    /// # Arguments
    ///
    /// * `data` - A slice of bytes representing the data to be processed.
    /// * `reverse` - A boolean indicating whether the data is in reverse order.
    /// * `context` - A mutable reference to the TCPContext, which holds the current verdict and capture information.
    #[allow(unused)]
    fn reassemble(&mut self, data: &[u8], reverse: bool, context: &mut TCPContext) {
        let start: bool = false;
        let end: bool = false;
        let skip: usize = 0;
        let mut updated = false;
        let mut indices_to_remove = Vec::new();

        // First pass: process entries and collect indices to remove
        for (i, entry) in self.active_entries.iter_mut().enumerate() {
            let (update, close_update, done) =
                TCPStreamEngine::feed_entry(entry, reverse, start, end, skip, data);

            let up1 = process_prop_update(&mut self.info.props, &entry.name, update);
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

            let result = self.ruleset.matches(&self.info);
            match result.action {
                nt_ruleset::Action::Maybe | nt_ruleset::Action::Modify => {}
                action => {
                    let verdict = action_to_tcp_verdict(action);
                    self.last_verdict = verdict.clone();
                    context.verdict = verdict;
                    self.close_active_entries();
                }
            }
        }

        // If there are no active entries and the current verdict is Accept, update the verdict to AcceptStream
        if self.active_entries.is_empty() && matches!(context.verdict, TCPVerdict::Accept) {
            self.last_verdict = TCPVerdict::AcceptStream;
            context.verdict = TCPVerdict::AcceptStream;
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
            let (update, done) = entry.stream.feed(reverse, start, end, skip, data);
            (update, None, done)
        } else {
            let data = if data.len() > entry.quota as usize {
                &data[..entry.quota as usize]
            } else {
                data
            };

            let (update, done) = entry.stream.feed(reverse, start, end, skip, data);
            entry.quota -= data.len() as i32;

            if entry.quota <= 0 {
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
            info!("TCP stream prop update");
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
fn action_to_tcp_verdict(action: nt_ruleset::Action) -> TCPVerdict {
    match action {
        nt_ruleset::Action::Maybe | nt_ruleset::Action::Allow | nt_ruleset::Action::Modify => {
            TCPVerdict::AcceptStream
        }
        nt_ruleset::Action::Block | nt_ruleset::Action::Drop => TCPVerdict::DropStream,
    }
}
