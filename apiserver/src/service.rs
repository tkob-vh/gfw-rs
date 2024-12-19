use crate::SharedServerConfig;
use crate::{ServiceError, SetupEngineSnafu};
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use nt_engine::Engine;
use snafu::ResultExt;
use std::{sync::Arc, time::Duration};
use tracing::info;

pub async fn create_router() -> Router {
    Router::new()
        .route("/service/start", post(start_service))
        .route("/service/stop", post(stop_service))
        .route("/ws", get(ws_handler))
}

async fn start_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let mut server_config = server.write().await;
    if !server_config.engine_cancellation_token.is_cancelled() {
        return Ok("Engine already started".to_string());
    }
    server_config.engine_cancellation_token = tokio_util::sync::CancellationToken::new();

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

    tokio::spawn({
        let program_cancellation_token = server_config.program_cancellation_token.clone();
        async move {
            tokio::signal::ctrl_c().await.unwrap();
            info!("Received ctrlc, shutdown the program...");
            program_cancellation_token.cancel();
        }
    });

    let (config_tx, _config_rx) = tokio::sync::watch::channel(());
    let (service_tx, _service_rx) = tokio::sync::watch::channel(true);

    info!("Engine started");

    // Run the engine until shutdown signal
    let engine_handle = tokio::spawn({
        let program_cancellation_token = server_config.program_cancellation_token.clone();
        let analyzers = server_config.analyzers.clone();
        let modifiers = server_config.modifiers.clone();
        async move {
            engine
                .run(
                    program_cancellation_token,
                    service_tx,
                    config_tx,
                    "None".to_owned(),
                    analyzers,
                    modifiers,
                )
                .await
        }
    });
    drop(engine_handle);
    Ok("Engine started".to_string())
}

async fn stop_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let server_config = server.write().await;
    if server_config.engine_cancellation_token.is_cancelled() {
        return Ok("Engine Has Not Started Yet".to_string());
    }
    server_config.engine_cancellation_token.cancel();
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
