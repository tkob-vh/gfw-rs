use tokio::sync::broadcast;
use tracing_subscriber::fmt::MakeWriter;

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
