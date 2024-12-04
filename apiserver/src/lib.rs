use nt_analyzer::Analyzer;
use nt_cmd::config;
use nt_io::PacketIO;
use nt_modifier::Modifier;
use nt_ruleset::expr_rule::ExprRuleset;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::Sender, Mutex, RwLock};
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
    pub io_impl: Option<Arc<dyn PacketIO>>,
    pub engine: Option<Arc<Mutex<nt_engine::engine::Engine>>>,
    pub shutdown: Option<Sender<()>>,

    /// stop_engine_tx also stand for the engine is running.
    pub stop_engine_tx: Option<tokio::sync::oneshot::Sender<()>>,
}
