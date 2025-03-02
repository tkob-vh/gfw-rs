//! This module defines the `Engine` struct and its associated methods for managing packet processing
//! and worker tasks. The `Engine` is responsible for initializing workers, handling packets, and
//! updating rulesets.

use std::error::Error;
use std::sync::Arc;

use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{
    worker::{Worker, WorkerConfig, WorkerPacket},
    Config,
};
use gfw_ruleset::engine::Engine as RulesetEngine;

/// The gfw engine
pub struct Engine {
    io: Arc<dyn gfw_io::PacketIO>,

    /// The workers.
    workers: Vec<Worker>,

    /// The senders which send tasks to the workers.
    worker_senders: Vec<mpsc::Sender<WorkerPacket>>,

    /// engine for ruleset
    ruleset_engine: RulesetEngine,
}

impl Engine {
    /// Create a new engine using the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - A `Config` struct containing the configuration for the engine.
    /// * `ruleset_engine` - A `RulesetEngine` instance for managing rulesets.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Box<dyn Error + Send + Sync>>` - Returns an `Engine` instance on success, or an error on failure.
    pub fn new(
        config: Config,
        ruleset_engine: RulesetEngine,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Decide the number of workers.
        let worker_count = if config.workers > 0 {
            config.workers
        } else {
            num_cpus::get()
        };
        debug!("Setting the number of workers to {}", worker_count);

        // Construct the workers according to the config.
        let mut workers: Vec<Worker> = Vec::with_capacity(worker_count);
        let mut worker_senders = Vec::with_capacity(worker_count);
        for i in 0..worker_count {
            let (worker, sender) = Worker::new(WorkerConfig {
                id: i as u32,
                chan_size: config.worker_queue_size,
                ruleset: config.ruleset.clone(),
                tcp_max_buffered_pages_total: config.worker_tcp_max_buffered_pages_total,
                tcp_max_buffered_pages_per_conn: config.worker_tcp_max_buffered_pages_per_conn,
                tcp_timeout: config.worker_tcp_timeout,
                udp_max_streams: config.worker_udp_max_streams,
            })?;

            workers.push(worker);
            worker_senders.push(sender);
        }

        Ok(Engine {
            io: config.io,
            workers,
            worker_senders,
            ruleset_engine,
        })
    }
}

#[async_trait::async_trait]
impl crate::Engine for Engine {
    /// Run the engine, starting all workers and handling packets.
    ///
    /// # Returns
    ///
    /// * `Result<(), Box<dyn Error + Send + Sync>>` - Returns `Ok(())` on success, or an error on failure.
    async fn run(
        &mut self,
        program_cancellation_token: tokio_util::sync::CancellationToken,
        service_tx: tokio::sync::watch::Sender<bool>,
        config_tx: tokio::sync::watch::Sender<()>,
        ruleset_file: String,
        analyzers: Vec<Arc<dyn gfw_analyzer::Analyzer>>,
        modifiers: Vec<Arc<dyn gfw_modifier::Modifier>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let (err_tx, mut err_rx) = mpsc::channel::<Box<dyn Error + Send + Sync>>(1);
        let (rs_tx, mut _rs_rx) = tokio::sync::broadcast::channel(self.workers.len());

        debug!("Start workers.");
        for mut worker in std::mem::take(&mut self.workers) {
            let err_tx = err_tx.clone();
            let program_cancellation_token = program_cancellation_token.clone();
            tokio::spawn({
                let rs_rx = rs_tx.subscribe();
                async move {
                    if let Err(e) = worker.run(rs_rx, program_cancellation_token).await {
                        let _ = err_tx.send(e).await;
                    }
                }
            });
        }

        let worker_senders = self.worker_senders.clone();
        let io = self.io.clone();

        debug!("Create packet handler");

        let packet_handler: gfw_io::PacketCallback = Box::new(
            move |packet: Box<dyn gfw_io::Packet>, err: Option<Box<dyn Error + Send + Sync>>| {
                let worker_senders = worker_senders.clone();
                let err_tx = err_tx.clone();
                let io = io.clone();

                Box::pin(async move {
                    if let Some(e) = err {
                        error!("Encountered error");
                        let _ = err_tx.send(e).await;
                        return false;
                    }
                    Self::dispatch(packet, &worker_senders, io).await
                })
            },
        );

        // Register packet handler
        let service_rx = service_tx.subscribe();
        self.io.register(packet_handler, service_rx).await?;

        let io = self.io.clone();
        let mut config_rx = config_tx.subscribe();
        // Wait for either error or shutdown signal or ruleset reload.
        loop {
            tokio::select! {
                Some(err) = err_rx.recv() => {
                    info!("Encountered error: {}", &err);
                    return Err(err);
                }
                _ = program_cancellation_token.cancelled() => {
                    info!("Shutdown the gfw engine...");

                    // Delete the nftables.
                    io.close().await;
                    return Ok(());
                }
                Ok(_) = config_rx.changed() => {
                    info!("Configuration changed, updating the ruleset...");
                    match gfw_ruleset::expr_rule::read_expr_rules_from_file(&ruleset_file).await {
                        Ok(raw_rs) => {

                            debug!("rules: {:?}", raw_rs);
                            let rs = gfw_ruleset::expr_rule::compile_expr_rules(
                                raw_rs,
                                &analyzers,
                                &modifiers,
                                self.ruleset_engine.clone(),
                            ).await;

                            _ = rs_tx.send(rs).unwrap();

                        }
                        Err(e) => error!("Failed to load rules: {}", e),
                    }
                }

            }
        }
    }
}

impl Engine {
    /// Dispatch a packet to a worker.
    ///
    /// # Arguments
    ///
    /// * `packet` - A boxed packet to be dispatched.
    /// * `worker_senders` - A slice of worker senders to send the packet to.
    /// * `io` - An `Arc` containing the packet IO interface.
    ///
    /// # Returns
    ///
    /// * `bool` - Returns `true` if the packet was successfully dispatched, or `false` on failure.
    async fn dispatch(
        packet: Box<dyn gfw_io::Packet>,
        worker_senders: &[mpsc::Sender<WorkerPacket>],
        io: Arc<dyn gfw_io::PacketIO>,
    ) -> bool {
        let data = packet.data();
        if data.is_empty() {
            return true;
        }

        let version = (data[0] >> 4) & 0xF;
        let packet_data = match version {
            4 => {
                debug!("Dispatching Ipv4 packet");
                if let Some(ip_packet) = Ipv4Packet::new(data) {
                    ip_packet.packet().to_vec()
                } else {
                    return true;
                }
            }
            6 => {
                debug!("Dispatching Ipv6 packet");
                if let Some(ip_packet) = Ipv6Packet::new(data) {
                    ip_packet.packet().to_vec()
                } else {
                    return true;
                }
            }
            _ => {
                debug!("Unsupported network layer - accept stream");
                // TODO: Check the Vec::new().
                if let Err(e) = io
                    .set_verdict(packet, gfw_io::Verdict::AcceptStream, Vec::new())
                    .await
                {
                    error!("Failed to set verdict: {}", e);
                }
                return true;
            }
        };

        // Load balance by stream ID (same as Go version)
        let stream_id = packet.stream_id();
        let index = (stream_id % worker_senders.len() as u32) as usize;

        let worker_packet = WorkerPacket {
            stream_id,
            packet: packet_data,
            set_verdict: Box::new(
                move |verdict: gfw_io::Verdict, modified_data: Option<Vec<u8>>| {
                    let io = io.clone();
                    let fut = async move {
                        io.set_verdict(packet, verdict, modified_data.unwrap_or_default())
                            .await
                    };
                    tokio::spawn(fut);
                    Ok(())
                },
            ),
        };

        // Send to worker using try_send to avoid blocking
        if let Err(e) = worker_senders[index].try_send(worker_packet) {
            error!("Failed to send packet to worker: {}", e);
            return false;
        }
        true
    }
}
