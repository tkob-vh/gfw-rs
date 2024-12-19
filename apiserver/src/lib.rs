use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use nt_analyzer::Analyzer;
use nt_cmd::config;
use nt_io::PacketIO;
use nt_modifier::Modifier;
use nt_ruleset::expr_rule::ExprRuleset;
use snafu::Snafu;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};
use tracing_subscriber::fmt::MakeWriter;

pub mod file;
pub mod save;
pub mod service;

type SharedServerConfig = Arc<RwLock<ServerConfig>>;

#[derive(Clone)]
pub struct LogWriter {
    pub tx: broadcast::Sender<String>,
}

impl LogWriter {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity);
        Self { tx }
    }

    pub async fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }
}

impl<'a> MakeWriter<'a> for LogWriter {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl std::io::Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let log = String::from_utf8_lossy(buf).to_string();
        let _ = self.tx.send(log);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

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

#[derive(Debug, Snafu)]
pub enum ServiceError {
    #[snafu(display("Failed to setup engine: {}", source))]
    SetupEngine {
        source: Box<dyn Error + Send + Sync>,
    },

    #[snafu(display("Failed to send shutdown signal"))]
    ShutdownSignal,

    #[snafu(display("{}", message))]
    Common { message: String },

    #[snafu(display("IO error {}", source))]
    IoError { source: std::io::Error },

    #[snafu(display("Serde error {}", source))]
    SerdeError { source: serde_yaml::Error },
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ServiceError::SetupEngine { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            ServiceError::ShutdownSignal => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::Common { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::IoError { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::SerdeError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, error_message).into_response()
    }
}
