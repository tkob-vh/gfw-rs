use crate::error::{SendSnafu, ServiceError, SetupEngineSnafu};
use crate::SharedServerConfig;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use gfw_engine::Engine;
use snafu::ResultExt;
use std::{sync::Arc, time::Duration};
use tracing::debug;
use tracing::info;

pub async fn create_router() -> Router {
    Router::new()
        .route("/service/start", post(start_service))
        .route("/service/stop", post(stop_service))
        .route("/ws", get(ws_handler))
}

async fn start_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let mut server_config = server.write().await;

    if server_config.engine_starter.is_some() {
        server_config
            .engine_starter
            .as_ref()
            .unwrap()
            .send(true)
            .context(SendSnafu)?;
        return Ok("Engine Has Already Started".to_string());
    } else {
        // `true` represents the active state, while `false` represents the inactive state.
        let (service_tx, _service_rx) = tokio::sync::watch::channel(true);
        server_config.engine_starter = Some(service_tx);
    }

    if server_config.io_impl.is_none() {
        info!("Setup IO for nfqueue...");
        server_config.io_impl = Some(Arc::new(
            gfw_io::nfqueue::NFQueuePacketIO::new(gfw_io::nfqueue::NFQueuePacketIOConfig {
                queue_size: server_config.config.io.queue_size,
                local: server_config.config.io.local,
                rst: server_config.config.io.rst,
            })
            .ok_or(ServiceError::Common {
                message: "Failed to setup IO".to_string(),
            })?,
        ));
    }

    let engine_config = gfw_engine::Config {
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

    let mut engine =
        gfw_engine::engine::Engine::new(engine_config, server_config.ruleset_engine.clone())
            .context(SetupEngineSnafu)?;

    info!("Engine started");

    // Run the engine until shutdown signal
    server_config.tracker.spawn({
        let program_cancellation_token = server_config.program_cancellation_token.clone();
        let analyzers = server_config.analyzers.clone();
        let modifiers = server_config.modifiers.clone();
        let config_tx = server_config.config_tx.clone();
        let service_tx = server_config.engine_starter.clone().unwrap();
        let ruleset_file = server_config.ruleset_file.clone();
        async move {
            let _ = engine
                .run(
                    program_cancellation_token,
                    service_tx,
                    config_tx,
                    ruleset_file,
                    analyzers,
                    modifiers,
                )
                .await;
            debug!("Engine stopped");
        }
    });
    Ok("Engine started".to_string())
}

async fn stop_service(server: Extension<SharedServerConfig>) -> Result<String, ServiceError> {
    let server_config = server.write().await;
    if server_config.engine_starter.is_none() {
        return Ok("Engine Has Not Started Yet".to_string());
    }
    server_config
        .engine_starter
        .as_ref()
        .unwrap()
        .send(false)
        .context(SendSnafu)?;
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
