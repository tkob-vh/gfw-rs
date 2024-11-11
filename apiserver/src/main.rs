use axum::Router;
use std::net::SocketAddr;

async fn create_router() -> Router {
    let root = apiserver::file::create_router()
        .await
        .merge(apiserver::save::create_router().await)
        .merge(apiserver::service::create_router().await);
    root
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let app = create_router().await;

    // Start the server
    tracing::info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app).await.unwrap()
}
