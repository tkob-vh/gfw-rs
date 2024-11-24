//! This module defines the `Engine` struct and its associated methods for managing packet processing
//! and worker tasks. The `Engine` is responsible for initializing workers, handling packets, and
//! updating rulesets.

use std::error::Error;
use std::sync::Arc;

use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet};
use tokio::{
    runtime::Handle,
    sync::mpsc::{self, Receiver},
};
use tracing::error;

use crate::{
    worker::{Worker, WorkerConfig, WorkerPacket},
    Config,
};

/// The gfw engine
pub struct Engine {
    io: Arc<dyn nt_io::PacketIO>,

    /// The workers.
    workers: Vec<Worker>,

    /// The senders which send tasks to the workers.
    worker_senders: Vec<mpsc::Sender<WorkerPacket>>,

    runtime: Handle,
}

impl Engine {
    /// Create a new engine using the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - A `Config` struct containing the configuration for the engine.
    ///
    /// # Returns
    ///
    /// * `Result<Self, Box<dyn Error + Send + Sync>>` - Returns an `Engine` instance on success, or an error on failure.
    pub fn new(config: Config) -> Result<Self, Box<dyn Error + Send + Sync>> {
        // Decide the number of workers.
        let worker_count = if config.workers > 0 {
            config.workers
        } else {
            num_cpus::get()
        };

        // Construct the workers according to the config.
        let mut workers: Vec<Worker> = Vec::with_capacity(worker_count);
        let mut worker_senders = Vec::with_capacity(worker_count);
        for i in 0..worker_count {
            let (worker, sender) = Worker::new(WorkerConfig {
                id: i as i32,
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
            runtime: Handle::current(),
        })
    }
}

#[async_trait::async_trait]
impl crate::Engine for Engine {
    /// Update the ruleset for all the workers.
    ///
    /// # Arguments
    ///
    /// * `new_ruleset` - A new ruleset to be applied to the workers.
    ///
    /// # Returns
    ///
    /// * `Result<(), Box<dyn Error + Send + Sync>>` - Returns `Ok(())` on success, or an error on failure.
    async fn update_ruleset(
        &mut self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        for worker in &mut self.workers {
            worker.update_ruleset(new_ruleset.clone()).await?
        }

        Ok(())
    }

    /// Run the engine, starting all workers and handling packets.
    ///
    /// # Returns
    ///
    /// * `Result<(), Box<dyn Error + Send + Sync>>` - Returns `Ok(())` on success, or an error on failure.
    async fn run(
        &mut self,
        mut shutdown_rx: Receiver<()>,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        // Create contexts similar to Go's context cancellation
        // shutdown logic is implemented in cmd/main.rs using ctrl_c.
        let (err_tx, mut err_rx) = mpsc::channel::<Box<dyn Error + Send + Sync>>(1);

        // Start workers.
        for mut worker in std::mem::take(&mut self.workers) {
            let err_tx = err_tx.clone();
            self.runtime.spawn(async move {
                if let Err(e) = worker.run().await {
                    let _ = err_tx.send(e).await;
                }
            });
        }

        let worker_senders = self.worker_senders.clone();
        let io = self.io.clone();
        let runtime_handle = self.runtime.clone();

        // Create packet handler closure
        let packet_handler = {
            move |packet: Box<dyn nt_io::Packet>, err: Option<Box<dyn Error + Send + Sync>>| {
                let worker_senders = worker_senders.clone();
                let err_tx = err_tx.clone();
                let io = io.clone();

                runtime_handle.block_on(async move {
                    if let Some(e) = err {
                        let _ = err_tx.send(e).await;
                        return false;
                    }
                    Self::dispatch(packet, &worker_senders, io).await
                })
            }
        };

        // Register packet handler
        self.io.register(Box::new(packet_handler)).await?;

        // Wait for either error or shutdown signal (similar to Go's select)
        tokio::select! {
            Some(err) = err_rx.recv() => Err(err),
            _ = shutdown_rx.recv() => Ok(()),
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
        mut packet: Box<dyn nt_io::Packet>,
        worker_senders: &[mpsc::Sender<WorkerPacket>],
        io: Arc<dyn nt_io::PacketIO>,
    ) -> bool {
        let data = packet.data();
        if data.is_empty() {
            return true;
        }

        // Check IP version (same logic as Go version)
        let version = (data[0] >> 4) & 0xF;
        let packet_data = match version {
            4 => {
                if let Some(ip_packet) = Ipv4Packet::new(data) {
                    ip_packet.payload().to_vec()
                } else {
                    return true;
                }
            }
            6 => {
                if let Some(ip_packet) = Ipv6Packet::new(data) {
                    ip_packet.payload().to_vec()
                } else {
                    return true;
                }
            }
            _ => {
                // Unsupported network layer - accept stream
                // TODO: Check the Vec::new().
                if let Err(e) =
                    io.set_verdict(&mut packet, nt_io::Verdict::AcceptStream, Vec::new())
                {
                    error!("Failed to set verdict: {}", e);
                }
                return true;
            }
        };

        // Load balance by stream ID (same as Go version)
        let stream_id = packet.stream_id();
        let index = (stream_id % worker_senders.len() as i32) as usize;

        let worker_packet = WorkerPacket {
            stream_id,
            packet: packet_data,
            set_verdict: Box::new(
                move |verdict: nt_io::Verdict, modified_data: Option<Vec<u8>>| {
                    let io = io.clone();
                    io.set_verdict(&mut packet, verdict, modified_data.unwrap_or_default())
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
