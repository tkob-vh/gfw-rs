use apiserver::LogWriter;
use apiserver::ServerConfig;
use axum::Extension;
use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

async fn create_router() -> Router {
    apiserver::file::create_router()
        .await
        .merge(apiserver::save::create_router().await)
        .merge(apiserver::service::create_router().await)
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let app = create_router().await;

    let log_writer = LogWriter::new(100);
    let app = app.layer(Extension(Arc::new(RwLock::new(ServerConfig {
        log_writer: log_writer.clone(),
        analyzers: vec![
            Arc::new(nt_analyzer::tcp::http::HTTPAnalyzer::new()),
            Arc::new(nt_analyzer::udp::dns::DNSAnalyzer::new()),
            Arc::new(nt_analyzer::udp::openvpn::OpenVPNAnalyzer::new()),
            Arc::new(nt_analyzer::udp::wireguard::WireGuardAnalyzer::new()),
        ],
        modifiers: vec![Arc::new(nt_modifier::udp::dns::DNSModifier::new())],
        config: Arc::new(nt_cmd::config::CliConfig::default()),
        io_impl: None,
        rule_set: None,
        shutdown: None,
        engine_handler: None,
    }))));

    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_writer(log_writer)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .init();

    // Start the server
    println!("Listening on {}", addr);
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap();
}
