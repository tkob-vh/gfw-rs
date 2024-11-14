//!

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use pnet::packet::{
    ip::IpNextHeaderProtocols, ipv4::MutableIpv4Packet, ipv6::MutableIpv6Packet,
    tcp::MutableTcpPacket, udp::MutableUdpPacket, MutablePacket, Packet,
};
use snafu::Whatever;
use snowflake::SnowflakeIdGenerator;
use tokio::{
    sync::{mpsc, RwLock},
    time,
};
use tracing::{error, info};

use crate::{
    tcp::{TCPContext, TCPStreamFactory, TCPStreamManager, TCPVerdict},
    udp::{UDPContext, UDPStreamFactory, UDPStreamManager, UDPVerdict},
};

const DEFAULT_CHAN_SIZE: usize = 64;
const DEFAULT_TCP_MAX_BUFFERED_PAGES_TOTAL: usize = 65536;
const DEFAULT_TCP_MAX_BUFFERED_PAGES_PER_CONNECTION: usize = 16;
const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(600);
const DEFAULT_UDP_MAX_STREAMS: usize = 4096;
const TCP_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

pub struct WorkerPacket {
    stream_id: i32,

    packet: Vec<u8>,

    set_verdict: Box<dyn Fn(nt_io::Verdict, Option<Vec<u8>>) -> Result<(), Whatever>>,
}

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
    pub fn new(config: WorkerConfig) -> Result<(Self, mpsc::Sender<WorkerPacket>), Whatever> {
        // TODO: Modify the logic of this generation.
        let node = SnowflakeIdGenerator::new(config.id, config.id);

        let tcp_stream_factory =
            TCPStreamFactory::new(config.id, node.clone(), RwLock::new(config.ruleset.clone()));

        let tcp_stream_manager = TCPStreamManager::new(
            tcp_stream_factory,
            config.tcp_max_buffered_pages_total,
            config.tcp_max_buffered_pages_per_conn,
        );

        let udp_stream_factory =
            UDPStreamFactory::new(config.id, node.clone(), RwLock::new(config.ruleset.clone()));

        let udp_stream_manager =
            UDPStreamManager::new(udp_stream_factory, config.udp_max_streams).unwrap();

        let (tx, rx) = mpsc::channel(config.chan_size);

        Ok((
            Worker {
                id: config.id,
                packet_rx: rx,

                tcp_stream_factory: TCPStreamFactory::new(
                    config.id,
                    node.clone(),
                    RwLock::new(config.ruleset.clone()),
                ),
                tcp_stream_manager,
                tcp_timeout: config.tcp_timeout,

                udp_stream_manager,
                udp_stream_factory: UDPStreamFactory::new(
                    config.id,
                    node.clone(),
                    RwLock::new(config.ruleset.clone()),
                ),
                mod_serialize_buffer: BytesMut::new(),
            },
            tx,
        ))
    }

    pub async fn run(&mut self) {
        let mut tcp_flush_interval = time::interval(TCP_FLUSH_INTERVAL);

        loop {
            tokio::select! {
                Some(mut packet) = self.packet_rx.recv() => {
                    let (verdict, modified) = self.handle_packet(packet.stream_id, packet.packet.as_mut()).await;
                    if let Err(_) = (packet.set_verdict)(verdict, modified) {
                        error!("Failed to set the verdict");
                    }
                }
                _ = tcp_flush_interval.tick() => {
                    self.flush_tcp(self.tcp_timeout).await;
                }
                else => break,

            }
        }
    }

    pub async fn update_ruleset(
        &mut self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Whatever> {
        if let Err(e) = self
            .tcp_stream_factory
            .update_ruleset(new_ruleset.clone())
            .await
        {
            return Err(e);
        }
        self.udp_stream_factory
            .update_ruleset(new_ruleset.clone())
            .await
    }

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
                                //TODO: Implement packet serialization.
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
                                //TODO: Implement packet serialization.
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

    async fn flush_tcp(&mut self, timeout: Duration) {
        let (flushed, closed) = self.tcp_stream_manager.flush_older_than(timeout);

        info!("TCP flush completed");
    }

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

pub struct WorkerConfig {
    id: i32,
    chan_size: usize,

    ruleset: Arc<dyn nt_ruleset::Ruleset>,

    tcp_max_buffered_pages_total: usize,
    tcp_max_buffered_pages_per_conn: usize,
    tcp_timeout: Duration,

    udp_max_streams: usize,
}

impl Default for WorkerConfig {
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
