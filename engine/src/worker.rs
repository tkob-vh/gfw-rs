//! This module defines the `Worker` struct and its associated functionality for handling TCP and UDP packets.
//! It includes the creation of workers, packet handling, and ruleset updates.

use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet,
    tcp::MutableTcpPacket, udp::MutableUdpPacket, MutablePacket, Packet,
};
use snowflake::SnowflakeIdGenerator;
use tokio::{
    sync::{mpsc, RwLock},
    time,
};
use tracing::{debug, error, trace, warn};

use crate::{
    tcp::{TCPContext, TCPStreamFactory, TCPStreamManager, TCPVerdict},
    udp::{UDPContext, UDPStreamFactory, UDPStreamManager, UDPVerdict},
};

const DEFAULT_CHAN_SIZE: u32 = 64;
const DEFAULT_TCP_MAX_BUFFERED_PAGES_TOTAL: u32 = 65536;
const DEFAULT_TCP_MAX_BUFFERED_PAGES_PER_CONNECTION: u32 = 16;
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_UDP_MAX_STREAMS: u32 = 4096;
const TCP_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

type SetVerdict = Box<
    dyn FnOnce(nt_io::Verdict, Option<Vec<u8>>) -> Result<(), Box<dyn Error + Send + Sync>>
        + Send
        + Sync,
>;

pub struct WorkerPacket {
    pub stream_id: u32,

    pub packet: Vec<u8>,

    pub set_verdict: SetVerdict,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Worker {
    id: u32,

    packet_rx: mpsc::Receiver<WorkerPacket>,

    tcp_stream_factory: TCPStreamFactory,
    tcp_stream_manager: TCPStreamManager,
    tcp_timeout: Duration,

    udp_stream_factory: UDPStreamFactory,
    udp_stream_manager: UDPStreamManager,

    mod_serialize_buffer: BytesMut,
}

impl Worker {
    /// Creates a new `Worker` instance with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - A `WorkerConfig` instance containing the configuration for the worker.
    ///
    /// # Returns
    ///
    /// A tuple containing the `Worker` instance and an `mpsc::Sender` for sending `WorkerPacket`s.
    pub fn new(
        config: WorkerConfig,
    ) -> Result<(Self, mpsc::Sender<WorkerPacket>), Box<dyn Error + Send + Sync>> {
        // Refer to (https://medium.com/@jitenderkmr/demystifying-snowflake-ids-a-unique-identifier-in-distributed-computing-72796a827c9d)
        // Snowflakes are 64 bits in binary. (Only 63 are used to fit in a signed integer.)
        // The first 41 bits are a timestamp, representing milliseconds since the chosen epoch.
        // The next 10 bits represent a machine ID (aka node ID), preventing clashes.
        // Twelve more bits represent a per-machine sequence number (aka step), to allow creation of multiple
        // snowflakes in the same millisecond. The final number is generally serialized in decimal.
        let discord_epoch = std::time::UNIX_EPOCH + Duration::from_millis(1420070400000);
        let node =
            SnowflakeIdGenerator::with_epoch(config.id as i32, config.id as i32, discord_epoch);

        let tcp_stream_factory =
            TCPStreamFactory::new(config.id, node, RwLock::new(config.ruleset.clone()));

        let tcp_stream_manager = TCPStreamManager::new(
            tcp_stream_factory,
            config.tcp_max_buffered_pages_total,
            config.tcp_max_buffered_pages_per_conn,
        );

        let udp_stream_factory =
            UDPStreamFactory::new(config.id, node, RwLock::new(config.ruleset.clone()));

        let udp_stream_manager =
            UDPStreamManager::new(udp_stream_factory, config.udp_max_streams).unwrap();

        let (tx, rx) = mpsc::channel(config.chan_size as usize);

        Ok((
            Worker {
                id: config.id,
                packet_rx: rx,

                tcp_stream_factory: TCPStreamFactory::new(
                    config.id,
                    node,
                    RwLock::new(config.ruleset.clone()),
                ),
                tcp_stream_manager,
                tcp_timeout: config.tcp_timeout,

                udp_stream_manager,
                udp_stream_factory: UDPStreamFactory::new(
                    config.id,
                    node,
                    RwLock::new(config.ruleset.clone()),
                ),
                mod_serialize_buffer: BytesMut::new(),
            },
            tx,
        ))
    }

    /// Runs the worker, processing incoming packets and flushing TCP streams at regular intervals.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error + Send + Sync>> {
        debug!("Worker started: id = {}", self.id);
        let mut tcp_flush_interval = time::interval(TCP_FLUSH_INTERVAL);

        loop {
            tokio::select! {
                Some(packet) = self.packet_rx.recv() => {
                    let (verdict, modified) = self.handle_packet(packet.stream_id, packet.packet).await;
                    if (packet.set_verdict)(verdict, modified).is_err() {
                        error!("Failed to set the verdict");
                    }
                }
                _ = tcp_flush_interval.tick() => {
                    self.flush_tcp(self.tcp_timeout).await;
                }
                else => break,

            }
        }

        Ok(())
    }

    /// Updates the ruleset used by the worker.
    ///
    /// # Arguments
    ///
    /// * `new_ruleset` - A new ruleset to be used by the worker.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure.
    pub async fn update_ruleset(
        &mut self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        self.tcp_stream_factory
            .update_ruleset(new_ruleset.clone())
            .await?;

        self.udp_stream_factory
            .update_ruleset(new_ruleset.clone())
            .await
    }

    /// Handles an incoming packet, determining its type (TCP/UDP) and processing it accordingly.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream the packet belongs to.
    /// * `packet_data` - The raw packet data.
    ///
    /// # Returns
    ///
    /// A tuple containing the verdict and an optional modified packet.
    async fn handle_packet(
        &mut self,
        stream_id: u32,
        mut packet_data: Vec<u8>,
    ) -> (nt_io::Verdict, Option<Vec<u8>>) {
        if let Some(mut ipv4) = MutableIpv4Packet::new(&mut packet_data) {
            debug!("Handling ipv4 packet");
            let src_ip = ipv4.get_source();
            debug!("src_ip: {}", &src_ip);
            let dst_ip = ipv4.get_destination();
            debug!("dst_ip: {}", &dst_ip);
            trace!("ipv4 packet data: {:02x?}", ipv4.packet());

            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    debug!("Transport layer: TCP");
                    if let Some(mut tcp_packet) = MutableTcpPacket::new(ipv4.payload_mut()) {
                        debug!("Successfully setting up tcp packet");
                        return (
                            self.handle_tcp(
                                stream_id,
                                IpAddr::V4(src_ip),
                                IpAddr::V4(dst_ip),
                                &mut tcp_packet,
                            )
                            .await,
                            None,
                        );
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    debug!("Transport layer: UDP");
                    if let Some(mut udp_packet) = MutableUdpPacket::new(ipv4.payload_mut()) {
                        debug!("Successfully setting up udp packet");
                        let (verdict, udp_data) = self
                            .handle_udp(
                                stream_id,
                                IpAddr::V4(src_ip),
                                IpAddr::V4(dst_ip),
                                &mut udp_packet,
                            )
                            .await;
                        if let Some(ip_payload) = udp_data {
                            let mut ip_packet = ipv4.packet().to_owned();
                            let mut modified = MutableIpv4Packet::new(&mut ip_packet).unwrap();
                            modified.set_payload(&ip_payload);
                            return (verdict, Some(modified.packet().to_owned()));
                        } else {
                            return (verdict, None);
                        }
                    }
                }
                other => {
                    warn!("Transport layer is neither TCP nor UDP: {}", other);
                }
            }
        } else if let Some(mut ipv6) = MutableIpv6Packet::new(&mut packet_data) {
            debug!("Handling ipv6 packet");
            let src_ip = ipv6.get_source();
            let dst_ip = ipv6.get_destination();
            match ipv6.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(mut tcp_packet) = MutableTcpPacket::new(ipv6.payload_mut()) {
                        return (
                            self.handle_tcp(
                                stream_id,
                                IpAddr::V6(src_ip),
                                IpAddr::V6(dst_ip),
                                &mut tcp_packet,
                            )
                            .await,
                            None,
                        );
                    }
                }
                IpNextHeaderProtocols::Udp => {
                    if let Some(mut udp_packet) = MutableUdpPacket::new(ipv6.payload_mut()) {
                        let (verdict, udp_data) = self
                            .handle_udp(
                                stream_id,
                                IpAddr::V6(src_ip),
                                IpAddr::V6(dst_ip),
                                &mut udp_packet,
                            )
                            .await;

                        if let Some(ip_payload) = udp_data {
                            let mut ip_packet = ipv6.packet().to_owned();
                            let mut modified = MutableIpv6Packet::new(&mut ip_packet).unwrap();
                            modified.set_payload(&ip_payload);
                            return (verdict, Some(modified.packet().to_owned()));
                        } else {
                            return (verdict, None);
                        }
                    }
                }
                _ => {}
            }
        }

        debug!("Returning default verdict Accept");
        (nt_io::Verdict::Accept, None)
    }

    /// Handles a TCP packet.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream the packet belongs to.
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `tcp_packet` - The TCP packet to be processed.
    ///
    /// # Returns
    ///
    /// The verdict for the packet.
    async fn handle_tcp<'a>(
        &mut self,
        stream_id: u32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_packet: &'a mut MutableTcpPacket<'a>,
    ) -> nt_io::Verdict {
        debug!("Handling tcp packet");

        let mut tcp_context = TCPContext {
            packet: tcp_packet.packet().to_owned(),
            verdict: TCPVerdict::Accept,
        };

        self.tcp_stream_manager
            .match_with_context(stream_id, src_ip, dst_ip, tcp_packet, &mut tcp_context)
            .await;

        tcp_context.verdict.into()
    }

    /// Flushes TCP streams that are older than the specified timeout.
    ///
    /// # Arguments
    ///
    /// * `timeout` - The duration after which TCP streams should be flushed.
    async fn flush_tcp(&mut self, timeout: Duration) {
        let (_flushed, _closed) = self.tcp_stream_manager.flush_close_older_than(timeout);

        // debug!(
        //     "[TCP flush]: worker_id: {:?}, flushed: {:?}, closed: {:?}",
        //     self.id, _flushed, _closed
        // );
    }

    /// Handles a UDP packet.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream the packet belongs to.
    /// * `src_ip` - The source IP address.
    /// * `dst_ip` - The destination IP address.
    /// * `udp_packet` - The UDP packet to be processed.
    ///
    /// # Returns
    ///
    /// A tuple containing the verdict and an optional modified packet.
    async fn handle_udp<'a>(
        &mut self,
        stream_id: u32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_packet: &'a mut MutableUdpPacket<'a>,
    ) -> (nt_io::Verdict, Option<Vec<u8>>) {
        debug!("Handling udp packet");

        let mut udp_context = UDPContext {
            verdict: UDPVerdict::Accept,
            packet: BytesMut::new(),
        };

        self.udp_stream_manager
            .match_with_context(stream_id, src_ip, dst_ip, udp_packet, &mut udp_context)
            .await
    }
}

/// Configuration for creating a `Worker` instance.
pub struct WorkerConfig {
    pub id: u32,
    pub chan_size: u32,

    pub ruleset: Arc<dyn nt_ruleset::Ruleset>,

    pub tcp_max_buffered_pages_total: u32,
    pub tcp_max_buffered_pages_per_conn: u32,
    pub tcp_timeout: Duration,

    pub udp_max_streams: u32,
}

impl Default for WorkerConfig {
    /// Provides a default configuration for `WorkerConfig`.
    fn default() -> Self {
        Self {
            id: 0,
            chan_size: DEFAULT_CHAN_SIZE,
            ruleset: Arc::new(nt_ruleset::expr_rule::ExprRuleset {
                engine: Arc::new(rhai::Engine::new()),
                rules: Vec::new(),
                analyzers: Vec::new(),
            }),
            tcp_max_buffered_pages_total: DEFAULT_TCP_MAX_BUFFERED_PAGES_TOTAL,
            tcp_max_buffered_pages_per_conn: DEFAULT_TCP_MAX_BUFFERED_PAGES_PER_CONNECTION,
            tcp_timeout: DEFAULT_TCP_TIMEOUT,
            udp_max_streams: DEFAULT_UDP_MAX_STREAMS,
        }
    }
}
