//!
//!
//!

pub mod engine;
pub mod tcp;
pub mod udp;
pub mod utils;
pub mod worker;

use std::sync::Arc;
use std::time::Duration;

use nt_io::PacketIO;
use nt_ruleset::Ruleset;
use snafu::Whatever;

/// Engine is the main engine for OpenGFW.
pub trait Engine {
    /// UpdateRuleset updates the ruleset.
    async fn update_ruleset(&mut self, new_ruleset: Arc<dyn Ruleset>) -> Result<(), Whatever>;

    /// Run runs the engine, until an error occurs or the context is cancelled.
    async fn run(&mut self) -> Result<(), Whatever>;
}

/// Config is the configuration for the engine.
struct Config {
    io: Arc<dyn PacketIO>,

    ruleset: Arc<dyn Ruleset>,

    /// Number of workers. Zero or negative means auto (number of CPU cores).
    workers: usize,

    worker_queue_size: u32,

    worker_tcp_max_buffered_pages_total: u32,

    worker_tcp_max_buffered_pages_per_conn: u32,

    worker_tcp_timeout: Duration,

    worker_udp_max_streams: u32,
}

// Logger is the combined logging interface for the engine, workers and analyzers.
