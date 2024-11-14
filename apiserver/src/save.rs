use axum::{routing::post, Json, Router};
use nt_cmd::config::CliConfig;

pub async fn create_router() -> Router {
    Router::new()
        .route("/save/config", post(save_config))
        .route("/save/rules", post(save_rules))
}

async fn save_config(Json(config): Json<CliConfig>) -> String {
    println!("{:?}", config);
    "save config".to_string()
}

async fn save_rules() -> String {
    "save rules".to_string()
}
