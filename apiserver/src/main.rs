use apiserver::LogWriter;
use apiserver::ServerConfig;
use axum::Extension;
use axum::Router;
use std::net::SocketAddr;
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
    let app = app.layer(Extension(ServerConfig {
        log_writer: log_writer.clone(),
    }));

    let _subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .with_writer(log_writer)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .init();

    // Start the server
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    tokio::spawn(async {
        // 模拟一些日志事件
        loop {
            info!("This is a log message");
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
    });

    axum::serve(listener, app).await.unwrap();
}
