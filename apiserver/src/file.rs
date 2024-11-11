use axum::{routing::get, Router};
use lazy_static::lazy_static;
use std::env;
use tokio::fs;

lazy_static! {
    static ref STATIC_FILES_PATH: String =
        env::var("STATIC_FILES_PATH").unwrap_or_else(|_| "./front".to_string());
}

pub async fn create_router() -> Router {
    Router::new()
        .route("/", get(serve_index))
        .route("/index.html", get(serve_index))
        .route("/styles.css", get(serve_styles))
        .route("/script.js", get(serve_script))
}

async fn serve_index() -> axum::response::Html<String> {
    let index_path = format!("{}/index.html", *STATIC_FILES_PATH);
    let index_content = fs::read_to_string(index_path)
        .await
        .unwrap_or_else(|_| "Error loading index.html".to_string());
    axum::response::Html(index_content)
}

async fn serve_styles() -> axum::response::Response<String> {
    let css_content = fs::read_to_string(format!("{}/styles.css", STATIC_FILES_PATH.to_owned()))
        .await
        .unwrap();
    axum::response::Response::builder()
        .header("Content-Type", "text/css")
        .body(css_content)
        .unwrap()
}

async fn serve_script() -> axum::response::Response<String> {
    let script_content = fs::read_to_string(format!("{}/script.js", STATIC_FILES_PATH.to_owned()))
        .await
        .unwrap();
    axum::response::Response::builder()
        .header("Content-Type", "application/javascript")
        .body(script_content)
        .unwrap()
}
