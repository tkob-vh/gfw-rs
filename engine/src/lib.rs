//! This crate provides the main engine for gfw-rs, including modules for TCP, UDP, utilities, and workers.

pub mod engine;
pub mod tcp;
pub mod udp;
pub mod utils;
pub mod worker;

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use nt_io::PacketIO;
use nt_ruleset::Ruleset;

/// Engine is the main engine for gfw-rs.
#[async_trait::async_trait]
pub trait Engine {
    /// Run runs the engine, until an error occurs or the context is cancelled.
    async fn run(
        &mut self,
        program_cancellation_token: tokio_util::sync::CancellationToken,
        service_tx: tokio::sync::watch::Sender<bool>,
        config_tx: tokio::sync::watch::Sender<()>,
        ruleset_file: String,
        analyzers: Vec<Arc<dyn nt_analyzer::Analyzer>>,
        modifier: Vec<Arc<dyn nt_modifier::Modifier>>,
    ) -> Result<(), Box<dyn Error + Send + Sync>>;
}

/// Config is the configuration for the engine.
pub struct Config {
    pub io: Arc<dyn PacketIO>,

    pub ruleset: Arc<dyn Ruleset>,

    /// Number of workers. Zero or negative means auto (number of CPU cores).
    pub workers: usize,

    pub worker_queue_size: u32,

    pub worker_tcp_max_buffered_pages_total: u32,

    pub worker_tcp_max_buffered_pages_per_conn: u32,

    pub worker_tcp_timeout: Duration,

    pub worker_udp_max_streams: u32,
}

// Logger is the combined logging interface for the engine, workers and analyzers.
