use logger::LogWriter;
use nt_analyzer::Analyzer;
use nt_cmd::config;
use nt_io::PacketIO;
use nt_modifier::Modifier;
use nt_ruleset::expr_rule::ExprRuleset;
use std::error::Error;
use std::sync::Arc;
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
    /// _
    pub rule_set: Option<Arc<ExprRuleset>>,
    pub ruleset_file: String,
    pub io_impl: Option<Arc<dyn PacketIO>>,

    /// The channel to notify the engine to reload the configuration.
    pub config_tx: tokio::sync::watch::Sender<()>,

    /// shutdown also stand for the engine is running.
    //pub shutdown: Option<Sender<()>>,
    pub engine_cancellation_token: tokio_util::sync::CancellationToken,
    pub program_cancellation_token: tokio_util::sync::CancellationToken,
    pub engine_handler: Option<tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>>>,
}
