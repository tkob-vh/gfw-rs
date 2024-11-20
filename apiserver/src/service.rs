use crate::SharedServerConfig;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
    routing::{get, post},
    Extension, Router,
};
use serde_json::json;

pub async fn create_router() -> Router {
    Router::new()
        .route("/service/start", post(start_service))
        .route("/service/stop", post(stop_service))
        .route("/ws", get(ws_handler))
}

async fn start_service() -> String {
    json!({
        "message": "start service"
    })
    .to_string()
}

async fn stop_service() -> String {
    json!({
        "message": "stop service"
    })
    .to_string()
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
    });
}
