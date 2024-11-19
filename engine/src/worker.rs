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
use tracing::error;

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
    dyn FnMut(nt_io::Verdict, Option<Vec<u8>>) -> Result<(), Box<dyn Error + Send + Sync>>
        + Send
        + Sync,
>;

pub struct WorkerPacket {
    pub stream_id: i32,

    pub packet: Vec<u8>,

    pub set_verdict: SetVerdict,
}

#[allow(dead_code)]
pub struct Worker {
    id: i32,

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
        let node = SnowflakeIdGenerator::with_epoch(config.id, config.id, discord_epoch);

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
        let mut tcp_flush_interval = time::interval(TCP_FLUSH_INTERVAL);

        loop {
            tokio::select! {
                Some(mut packet) = self.packet_rx.recv() => {
                    let (verdict, modified) = self.handle_packet(packet.stream_id, packet.packet.as_mut()).await;
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
        stream_id: i32,
        packet_data: &mut [u8],
    ) -> (nt_io::Verdict, Option<Vec<u8>>) {
        // Try IPv4 first
        if let Some(mut ipv4) = MutableIpv4Packet::new(packet_data) {
            let src_ip = ipv4.get_source();
            let dst_ip = ipv4.get_destination();
            match ipv4.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(mut tcp_packet) = MutableTcpPacket::new(ipv4.payload_mut()) {
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
                    if let Some(mut udp_packet) = MutableUdpPacket::new(ipv4.payload_mut()) {
                        let (verdict, modified) = self
                            .handle_udp(
                                stream_id,
                                IpAddr::V4(src_ip),
                                IpAddr::V4(dst_ip),
                                &mut udp_packet,
                            )
                            .await;

                        match verdict {
                            nt_io::Verdict::AcceptModify if modified.is_some() => {
                                // Serialize modified packet.
                                todo!("Implement packet serialization.");
                                return (verdict, modified);
                            }
                            _ => return (verdict, None),
                        }
                    }
                }
                _ => {}
            }
        } else if let Some(mut ipv6) = MutableIpv6Packet::new(packet_data) {
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
                        let (verdict, modified) = self
                            .handle_udp(
                                stream_id,
                                IpAddr::V6(src_ip),
                                IpAddr::V6(dst_ip),
                                &mut udp_packet,
                            )
                            .await;

                        match verdict {
                            nt_io::Verdict::AcceptModify if modified.is_some() => {
                                // Serialize modified packet.
                                todo!("Implement packet serialization.");
                                return (verdict, modified);
                            }
                            _ => return (verdict, None),
                        }
                    }
                }
                _ => {}
            }
        }

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
        stream_id: i32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        tcp_packet: &'a mut MutableTcpPacket<'a>,
    ) -> nt_io::Verdict {
        let mut tcp_context = TCPContext {
            packet: tcp_packet.payload().to_owned(),
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
        let (_flushed, _closed) = self.tcp_stream_manager.flush_older_than(timeout);
        todo!("To be implemented.");
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
        stream_id: i32,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        udp_packet: &'a mut MutableUdpPacket<'a>,
    ) -> (nt_io::Verdict, Option<Vec<u8>>) {
        let mut udp_context = UDPContext {
            verdict: UDPVerdict::Accept,
            packet: BytesMut::new(),
        };

        self.udp_stream_manager
            .match_with_context(stream_id, src_ip, dst_ip, udp_packet, &mut udp_context)
            .await;

        (
            udp_context.verdict.into(),
            if udp_context.packet.is_empty() {
                None
            } else {
                Some(udp_context.packet.to_vec())
            },
        )
    }
}

/// Configuration for creating a `Worker` instance.
pub struct WorkerConfig {
    pub id: i32,
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
