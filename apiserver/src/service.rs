use axum::{routing::post, Router};
use serde_json::json;

pub async fn create_router() -> Router {
    Router::new()
        .route("/service/start", post(start_service))
        .route("/service/stop", post(stop_service))
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
