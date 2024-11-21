//! UDP Stream Management Module
//!
//! This module provides functionality for managing UDP streams, including creating new streams,
//! feeding packets to streams, and handling stream properties and actions based on rulesets.

use std::{error::Error, net::IpAddr, num::NonZero, ops::Deref, sync::Arc};

use bytes::BytesMut;
use lru::LruCache;
use nt_modifier::UDPModifierInstance;
use pnet::packet::{udp::MutableUdpPacket, MutablePacket, Packet};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::utils::process_prop_update;

/// UDPVerdict is a subset of io.Verdict for UDP streams.
/// For UDP, we support all verdicts.
#[derive(Clone, Debug)]
pub enum UDPVerdict {
    Accept,
    AcceptModify,
    AcceptStream,
    Drop,
    DropStream,
}

impl From<UDPVerdict> for nt_io::Verdict {
    fn from(value: UDPVerdict) -> Self {
        match value {
            UDPVerdict::Accept => nt_io::Verdict::Accept,
            UDPVerdict::AcceptModify => nt_io::Verdict::AcceptModify,
            UDPVerdict::AcceptStream => nt_io::Verdict::AcceptStream,
            UDPVerdict::Drop => nt_io::Verdict::Drop,
            UDPVerdict::DropStream => nt_io::Verdict::DropStream,
        }
    }
}

/// Context for UDP processing, including the verdict and the packet.
pub struct UDPContext {
    pub verdict: UDPVerdict,
    pub packet: BytesMut,
}

/// Factory for creating UDP streams.
pub struct UDPStreamFactory {
    worker_id: i32,

    /// https://en.wikipedia.org/wiki/Snowflake_ID
    node: snowflake::SnowflakeIdGenerator,

    /// The ruleset for the tcp stream entries.
    ruleset: RwLock<Arc<dyn nt_ruleset::Ruleset>>,
}

impl UDPStreamFactory {
    /// Creates a new UDPStreamFactory.
    ///
    /// # Arguments
    ///
    /// * `worker_id` - The worker ID.
    /// * `node` - The Snowflake ID generator.
    /// * `ruleset` - The ruleset for the UDP stream entries.
    pub fn new(
        worker_id: i32,
        node: snowflake::SnowflakeIdGenerator,
        ruleset: RwLock<Arc<dyn nt_ruleset::Ruleset>>,
    ) -> Self {
        Self {
            worker_id,
            node,
            ruleset,
        }
    }

    /// Creates a new UDP stream.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `udp_packet` - The UDP packet.
    ///
    /// # Returns
    ///
    /// An option containing the new UDPStreamEngine if successful.
    pub async fn new_stream<'a>(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_packet: &'a MutableUdpPacket<'a>,
    ) -> Option<UDPStream> {
        // Generate a unique snowflake.
        let id = self.node.generate();

        // Get the port info from the tcp packet.
        let src_port = udp_packet.get_source();
        let dst_port = udp_packet.get_destination();

        // Construct the stream info for the ruleset.
        let info = nt_ruleset::StreamInfo {
            id,
            protocol: nt_ruleset::Protocol::UDP,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            props: nt_analyzer::CombinedPropMap::new(),
        };

        info!(
            "New UDP stream: worker_id = {:?}, id = {:?}, src = {:?}, dst = {:?}",
            self.worker_id, id, src_ip, dst_ip
        );

        // Get the ruleset from the tcp stream factory.
        let rs = self.ruleset.read().await;

        // Get the analyzers and convert them to tcp analyzers.
        let analyzers = rs.analyzers();
        let udp_analyzers = analyzers_to_udp_analyzers(&analyzers);

        // Create entries for each analyzer
        let entries = udp_analyzers
            .iter()
            .map(|a| UDPStreamEntry {
                name: a.name().to_string(),
                stream: a.new_udp(nt_analyzer::UDPInfo {
                    src_ip,
                    src_port,
                    dst_ip,
                    dst_port,
                }),
                has_limit: a.limit() > 0,
                quota: a.limit(),
            })
            .collect();

        Some(UDPStream {
            info,
            virgin: true,
            ruleset: rs.deref().clone(),
            active_entries: entries,
            done_entries: Vec::new(),
            last_verdict: UDPVerdict::Accept,
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
        &mut self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut ruleset = self.ruleset.write().await;
        *ruleset = new_ruleset;
        Ok(())
    }
}

/// Manager for UDP streams.
pub struct UDPStreamManager {
    factory: UDPStreamFactory,
    streams: LruCache<i32, UDPStreamValue>,
}

impl UDPStreamManager {
    /// Creates a new UDPStreamManager.
    ///
    /// # Arguments
    ///
    /// * `factory` - The UDP stream factory.
    /// * `max_streams` - The maximum number of streams.
    ///
    /// # Returns
    ///
    /// An option containing the new UDPStreamManager if successful.
    pub fn new(factory: UDPStreamFactory, max_streams: u32) -> Option<Self> {
        Some(UDPStreamManager {
            factory,
            streams: LruCache::new(
                NonZero::new(max_streams as usize).expect("max_streams should be non zero."),
            ),
        })
    }

    /// Matches the udp packet with a stream with the given context.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The stream ID.
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `udp_packet` - The UDP packet.
    /// * `udp_context` - The UDP context.
    pub async fn match_with_context<'a>(
        &mut self,
        stream_id: i32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_packet: &'a mut MutableUdpPacket<'a>,
        udp_context: &mut UDPContext,
    ) -> (nt_io::Verdict, Option<Vec<u8>>) {
        let mut reverse = false;
        let src_port = udp_packet.get_source();
        let dst_port = udp_packet.get_destination();

        // Get the stream according to the stream_id.
        if let Some(value) = self.streams.get_mut(&stream_id) {
            // Stream ID exists, but is it really the same stream?
            let (matches, is_reverse) = value.matches(src_ip, dst_ip, src_port, dst_port);

            if !matches {
                // Stream ID exists but different flow - create a new stream.
                value.stream.close();
                let new_stream = self.factory.new_stream(src_ip, dst_ip, udp_packet).await;
                if let Some(stream) = new_stream {
                    let value = UDPStreamValue {
                        stream,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                    };
                    self.streams.put(stream_id, value);
                }
            } else {
                reverse = is_reverse;
            }
        } else {
            // Stream ID not exists, create a new stream.
            if let Some(stream) = self.factory.new_stream(src_ip, dst_ip, udp_packet).await {
                let value = UDPStreamValue {
                    stream,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                };
                self.streams.put(stream_id, value);
            }
        }

        // Handle the packet in the stream.
        if let Some(value) = self.streams.get_mut(&stream_id) {
            if value.stream.accept(udp_packet, reverse, udp_context) {
                value.stream.feed(udp_packet, reverse, udp_context);
            }
        }

        // Modify the payload of the packet and its checksum.
        let verdict: nt_io::Verdict = udp_context.verdict.clone().into();
        if matches!(verdict, nt_io::Verdict::AcceptModify) && !udp_context.packet.is_empty() {
            udp_packet.set_payload(&udp_context.packet);

            match src_ip {
                IpAddr::V4(src_ipv4) => match dst_ip {
                    IpAddr::V4(dst_ipv4) => {
                        udp_packet.set_checksum(pnet::packet::udp::ipv4_checksum(
                            &udp_packet.to_immutable(),
                            &src_ipv4,
                            &dst_ipv4,
                        ));

                        (verdict, Some(udp_packet.packet().to_vec()))
                    }
                    IpAddr::V6(_dst_ipv6) => {
                        error!("The version of src_ip and dst_ip does not match");
                        (verdict, None)
                    }
                },
                IpAddr::V6(src_ipv6) => match dst_ip {
                    IpAddr::V4(_dst_ipv4) => (verdict, None),
                    IpAddr::V6(dst_ipv6) => {
                        udp_packet.set_checksum(pnet::packet::udp::ipv6_checksum(
                            &udp_packet.to_immutable(),
                            &src_ipv6,
                            &dst_ipv6,
                        ));

                        (verdict, Some(udp_packet.packet().to_vec()))
                    }
                },
            }
        } else {
            (verdict, None)
        }
    }
}

/// The value corresponding to the key in the LruCache.
struct UDPStreamValue {
    stream: UDPStream,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16,
}

impl UDPStreamValue {
    /// Checks if the stream matches the given parameters.
    ///
    /// # Arguments
    ///
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `src_port` - The source port.
    /// * `dst_port` - The destination port.
    ///
    /// # Returns
    ///
    /// A tuple containing a boolean indicating if the stream matches and a boolean indicating if the stream is in reverse.
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

/// Engine for processing UDP streams.
pub struct UDPStream {
    /// The stream info for the ruleset.
    /// Such as id, protocal, address, port, and PropUpdate.
    info: nt_ruleset::StreamInfo,

    /// True if no packets have been processed
    virgin: bool,

    /// The ruleset for the udp stream.
    ruleset: Arc<dyn nt_ruleset::Ruleset>,

    /// The unprocessed stream entries.
    active_entries: Vec<UDPStreamEntry>,

    /// The processed stream entries.
    done_entries: Vec<UDPStreamEntry>,

    last_verdict: UDPVerdict,
}

impl UDPStream {
    /// Checks if the stream accepts the given packet.
    ///
    /// # Arguments
    ///
    /// * `udp_packet` - The UDP packet.
    /// * `reverse` - A boolean indicating if the stream is in reverse.
    /// * `udp_context` - The UDP context.
    ///
    /// # Returns
    ///
    /// A boolean indicating if the stream accepts the packet.
    #[allow(unused_variables)]
    fn accept(
        &self,
        udp_packet: &MutableUdpPacket,
        reverse: bool,
        udp_context: &mut UDPContext,
    ) -> bool {
        if !self.active_entries.is_empty() || self.virgin {
            true
        } else {
            udp_context.verdict = self.last_verdict.clone();
            false
        }
    }

    /// Feeds a packet to the stream.
    ///
    /// # Arguments
    ///
    /// * `udp_packet` - The UDP packet.
    /// * `reverse` - A boolean indicating if the stream is in reverse.
    /// * `udp_context` - The UDP context.
    fn feed(
        &mut self,
        udp_packet: &mut MutableUdpPacket,
        reverse: bool,
        udp_context: &mut UDPContext,
    ) {
        let mut updated = false;
        let mut indices_to_remove = Vec::new();

        // First pass: process entries and collect indices to remove
        for (i, entry) in self.active_entries.iter_mut().enumerate() {
            let (update, close_update, done) =
                UDPStream::feed_entry(entry, reverse, udp_packet.payload());

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
                nt_ruleset::Action::Modify => {
                    // Handle modification
                    if let Some(modifier) = result.modifier {
                        match modifier
                            .as_any()
                            .downcast_ref::<Arc<dyn UDPModifierInstance>>()
                            .unwrap()
                            .process(udp_packet.payload_mut())
                        {
                            Some(modified) => {
                                udp_context.packet = BytesMut::from(&modified[..]);
                                udp_context.verdict = UDPVerdict::AcceptModify;
                            }
                            None => {
                                error!("Modifer error, fallback to Accept");
                                udp_context.verdict = UDPVerdict::Accept;
                            }
                        }
                    }
                }
                nt_ruleset::Action::Maybe => {}
                action => {
                    let (verdict, final_verdict) = action_to_udp_verdict(action);
                    self.last_verdict = verdict.clone();
                    udp_context.verdict = verdict;

                    if final_verdict {
                        self.close_active_entries();
                    }
                }
            }
        }

        if self.active_entries.is_empty() && matches!(udp_context.verdict, UDPVerdict::Accept) {
            self.last_verdict = UDPVerdict::AcceptStream;
            udp_context.verdict = UDPVerdict::AcceptStream;
        }
    }

    /// Feeds a packet to a specific entry.
    ///
    /// # Arguments
    ///
    /// * `entry` - The UDP stream entry.
    /// * `reverse` - A boolean indicating if the stream is in reverse.
    /// * `data` - The packet data.
    ///
    /// # Returns
    ///
    /// A tuple containing the property update, close update, and a boolean indicating if the entry is done.
    fn feed_entry(
        entry: &mut UDPStreamEntry,
        reverse: bool,
        data: &[u8],
    ) -> (
        Option<nt_analyzer::PropUpdate>,
        Option<nt_analyzer::PropUpdate>,
        bool,
    ) {
        if !entry.has_limit {
            let (update, done) = entry.stream.feed(reverse, data);
            (update, None, done)
        } else {
            let data = if data.len() > entry.quota as usize {
                &data[..entry.quota as usize]
            } else {
                data
            };

            let (update, done) = entry.stream.feed(reverse, data);
            entry.quota -= data.len() as i32;

            if entry.quota <= 0 {
                let close_update = entry.stream.close(true);
                (update, close_update, true)
            } else {
                (update, None, done)
            }
        }
    }

    /// Closes all active entries.
    fn close_active_entries(&mut self) {
        let mut updated = false;

        for entry in &mut self.active_entries {
            if let Some(update) = entry.stream.close(false) {
                updated |= process_prop_update(&mut self.info.props, &entry.name, Some(update));
            }
        }

        if updated {
            info!("UDPStreamPropUpdate");
        }

        self.done_entries.append(&mut self.active_entries);
    }

    /// Closes the stream.
    fn close(&mut self) {
        self.close_active_entries();
    }
}

/// Entry for a UDP stream.
struct UDPStreamEntry {
    name: String,

    /// The stream in crate analyzer.
    stream: Box<dyn nt_analyzer::UDPStream>,
    has_limit: bool,
    quota: i32,
}

/// Converts actions to UDP verdicts.
///
/// # Arguments
///
/// * `action` - The action to convert.
///
/// # Returns
///
/// A tuple containing the UDP verdict and a boolean indicating if the verdict is final.
fn action_to_udp_verdict(action: nt_ruleset::Action) -> (UDPVerdict, bool) {
    match action {
        nt_ruleset::Action::Maybe => (UDPVerdict::Accept, false),
        nt_ruleset::Action::Allow => (UDPVerdict::AcceptStream, true),
        nt_ruleset::Action::Block => (UDPVerdict::DropStream, true),
        nt_ruleset::Action::Drop => (UDPVerdict::Drop, false),
        nt_ruleset::Action::Modify => (UDPVerdict::AcceptModify, false),
    }
}

/// Converts analyzers to UDP analyzers.
///
/// # Arguments
///
/// * `analyzers` - The analyzers to convert.
///
/// # Returns
///
/// A vector of UDP analyzers.
fn analyzers_to_udp_analyzers(
    analyzers: &[Arc<dyn nt_analyzer::Analyzer>],
) -> Vec<Arc<dyn nt_analyzer::UDPAnalyzer>> {
    analyzers
        .iter()
        .filter_map(|a| {
            a.as_any()
                .downcast_ref::<Arc<dyn nt_analyzer::UDPAnalyzer>>()
                .cloned()
        })
        .collect()
}
