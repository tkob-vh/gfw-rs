//!
//!
//!

pub mod engine;
pub mod tcp;
pub mod udp;
pub mod utils;
pub mod worker;

use std::time::Duration;

use nt_io::PacketIO;
use nt_ruleset::Ruleset;

/// Engine is the main engine for OpenGFW.
pub trait Engine {
    /// UpdateRuleset updates the ruleset.
    fn update_ruleset(ruleset: Box<dyn Ruleset>);

    /// Run runs the engine, until an error occurs or the context is cancelled.
    fn run();
}

/// Config is the configuration for the engine.
struct Config {
    io: Box<dyn PacketIO>,

    ruleset: Box<dyn Ruleset>,

    /// Number of workers. Zero or negative means auto (number of CPU cores).
    workers: i32,

    worker_queue_size: u32,

    worker_tcp_max_buffered_pages_total: u32,

    worker_tcp_max_buffered_pages_per_conn: u32,

    worker_tcp_timeout: Duration,

    worker_udp_max_streams: u32,
}

// Logger is the combined logging interface for the engine, workers and analyzers.
