use crate::SharedServerConfig;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Router,
};
use nt_engine::Engine;
use std::error::Error;
use std::{sync::Arc, time::Duration};
use tracing::info;

use snafu::{ResultExt, Snafu};

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
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ServiceError::SetupEngine { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            ServiceError::ShutdownSignal => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::Common { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (status, error_message).into_response()
    }
}

pub async fn create_router() -> Router {
    Router::new()
        .route("/service/start", post(start_service))
        .route("/service/stop", post(stop_service))
        .route("/ws", get(ws_handler))
}

async fn start_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let mut server_config = server.write().await;
    if server_config.shutdown.is_some() {
        return Ok("Engine already started".to_string());
    }

    if server_config.io_impl.is_none() {
        info!("Setup IO for nfqueue...");
        server_config.io_impl = Some(Arc::new(
            nt_io::nfqueue::NFQueuePacketIO::new(nt_io::nfqueue::NFQueuePacketIOConfig {
                queue_size: server_config.config.io.queue_size,
                local: server_config.config.io.local,
                rst: server_config.config.io.rst,
            })
            .ok_or(ServiceError::Common {
                message: "Failed to setup IO".to_string(),
            })?,
        ));
    }

    let engine_config = nt_engine::Config {
        workers: server_config.config.workers.count,
        worker_queue_size: server_config.config.workers.queue_size,
        worker_tcp_max_buffered_pages_total: server_config
            .config
            .workers
            .tcp_max_buffered_pages_total,
        worker_tcp_max_buffered_pages_per_conn: server_config
            .config
            .workers
            .tcp_max_buffered_pages_per_conn,
        worker_tcp_timeout: Duration::from_secs(server_config.config.workers.tcp_timeout),
        worker_udp_max_streams: server_config.config.workers.udp_max_streams,
        io: server_config.io_impl.clone().unwrap(), // here should not panic
        ruleset: server_config.rule_set.clone().ok_or(ServiceError::Common {
            message: "Ruleset not found".to_string(),
        })?,
    };
    let mut engine = nt_engine::engine::Engine::new(engine_config).context(SetupEngineSnafu)?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Shutting down gracefully...");
        shutdown_tx_clone.send(()).await.unwrap();
    });

    let (_config_tx, config_rx) = tokio::sync::watch::channel(());

    info!("Engine started");

    server_config.shutdown = Some(shutdown_tx);

    // Run the engine until shutdown signal
    let engine_handle = tokio::spawn(async move {
        engine
            .run(
                shutdown_rx,
                config_rx,
                "None".to_owned(),
                Vec::new(),
                Vec::new(),
            )
            .await
    });
    drop(engine_handle);
    Ok("Engine started".to_string())
}

async fn stop_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let mut server_config = server.write().await;
    if server_config.shutdown.is_none() {
        return Ok("Engine Has Not Started Yet".to_string());
    }
    let shutdown = server_config.shutdown.take().unwrap();
    shutdown
        .send(())
        .await
        .map_err(|_| ServiceError::ShutdownSignal)?;
    let engine_handler = server_config.engine_handler.take().unwrap();
    let _ = engine_handler.await.unwrap();
    Ok("Engine stopped".to_string())
}

async fn ws_handler(
    server: Extension<SharedServerConfig>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, server))
}

async fn handle_websocket(mut ws: WebSocket, server: Extension<SharedServerConfig>) {
    let config = server.read().await;

    let mut rx = config.log_writer.subscribe().await;

    tokio::spawn(async move {
        while let Ok(log) = rx.recv().await {
            if ws.send(Message::Text(log)).await.is_err() {
                break;
            }
        }
        let _ = ws.close().await;
    });
}
