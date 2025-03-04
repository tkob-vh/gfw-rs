use logger::LogWriter;
use gfw_analyzer::Analyzer;
use gfw_io::PacketIO;
use gfw_modifier::Modifier;
use gfw_ruleset::expr_rule::ExprRuleset;
use gfw_config::config;
use gfw_ruleset::engine::Engine as RulesetEngine;
use std::sync::Arc;
use tokio::sync::watch::Sender;
use tokio::sync::RwLock;

pub mod error;
pub mod file;
pub mod logger;
pub mod save;
pub mod service;

type SharedServerConfig = Arc<RwLock<ServerConfig>>;

/// The server configuration.
pub struct ServerConfig {
    /// The log writer, used to write logs.
    pub log_writer: LogWriter,
    pub analyzers: Vec<Arc<dyn Analyzer>>,
    pub modifiers: Vec<Arc<dyn Modifier>>,
    pub config: Arc<config::CliConfig>,
    pub rule_set: Option<Arc<ExprRuleset>>,
    pub ruleset_engine: RulesetEngine,
    pub ruleset_file: String,
    pub io_impl: Option<Arc<dyn PacketIO>>,

    /// The channel to notify the engine to reload the configuration.
    pub config_tx: tokio::sync::watch::Sender<()>,

    /// The channel to notify the engine to stop.
    pub engine_starter: Option<Sender<bool>>,

    /// The program cancellation token. used for deal with ctrl c
    pub program_cancellation_token: tokio_util::sync::CancellationToken,

    /// The tracker to track the running tasks. used for spawn engine
    pub tracker: tokio_util::task::TaskTracker,
}
