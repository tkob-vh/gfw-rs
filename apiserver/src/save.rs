use axum::{routing::post, Router};

pub async fn create_router() -> Router {
    Router::new()
        .route("/save/config", post(save_config))
        .route("/save/rules", post(save_rules))
}

async fn save_config() -> String {
    "save config".to_string()
}

async fn save_rules() -> String {
    "save rules".to_string()
}
