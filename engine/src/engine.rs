//!
//!

use std::sync::Arc;

use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet};
use snafu::{ResultExt, Whatever};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tracing::error;

use crate::{
    worker::{Worker, WorkerConfig, WorkerPacket},
    Config,
};

struct Engine {
    io: Arc<dyn nt_io::PacketIO>,
    workers: Vec<Worker>,
    worker_senders: Vec<mpsc::Sender<WorkerPacket>>,
    runtime: Runtime,
}

impl Engine {
    pub fn new(config: Config) -> Result<Self, Whatever> {
        let worker_count = if config.workers > 0 {
            config.workers
        } else {
            num_cpus::get()
        };

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .whatever_context("Failed to create tokio runtime")?;

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
            runtime,
        })
    }
}

impl crate::Engine for Engine {
    async fn update_ruleset(
        &mut self,
        new_ruleset: Arc<dyn nt_ruleset::Ruleset>,
    ) -> Result<(), Whatever> {
        for worker in &mut self.workers {
            if let Err(e) = worker.update_ruleset(new_ruleset.clone()).await {
                return Err(e);
            }
        }

        Ok(())
    }

    async fn run(&mut self) -> Result<(), Whatever> {
        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        for mut worker in self.workers {
            self.runtime.spawn(async move {
                worker.run().await;
            });
        }

        let worker_senders = self.worker_senders.clone();
        let (err_tx, mut err_rx) = mpsc::channel::<Whatever>(1);
        let err_tx_clone = err_tx.clone();

        self.runtime.block_on(async {
            self.io
                .register(Box::new(
                    move |packet: Box<dyn nt_io::Packet>, err: Option<Whatever>| {
                        if let Some(e) = err {
                            if err_tx.blocking_send(e).is_err() {
                                error!("Failed to send error");
                            }
                            return false;
                        }
                        self.dispatch(packet, &worker_senders).await
                    },
                ))
                .whatever_context("Failed to register IO callback")?;
        });

        tokio::select! {
            Some(err) = err_rx.recv() => {
                Err(err)
            }
            _ = stop_rx.recv() => {
                Ok(())
            }
        }
    }
}

impl Engine {
    async fn dispatch(
        &self,
        packet: Box<dyn nt_io::Packet>,
        worker_senders: &[mpsc::Sender<WorkerPacket>],
    ) -> bool {
        let data = packet.data();
        if data.is_empty() {
            return true;
        }

        // Check IP version.
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
                // Upsupported network layer
                if let Err(e) = self
                    .io
                    .set_verdict(&mut packet, nt_io::Verdict::AcceptStream, Vec::new())
                    .await
                {
                    error!("Failed to set verdict: {}", e);
                }
                return true;
            }
        };

        // Load balance by stream ID.
        let stream_id = packet.stream_id();
        let index = (stream_id % worker_senders.len() as i32) as usize;

        let worker_packet = WorkerPacket {
            stream_id,
            packet: packet_data,
            set_verdict: Box::new(move |verdict, modified_data| {
                self.io
                    .set_verdict(&mut packet, verdict, modified_data.unwrap())
                    .await
            }),
        };

        // Send to worker
        if let Err(e) = worker_senders[index].try_send(worker_packet) {
            error!("Failed to send packet to worker: {}", e);
            return false;
        }
        true
    }
}
