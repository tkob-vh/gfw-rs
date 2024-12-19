use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use snafu::Snafu;
use std::error::Error;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ServiceError {
    #[snafu(display("Failed to setup engine: {}", source))]
    SetupEngine {
        source: Box<dyn Error + Send + Sync>,
    },

    #[snafu(display("Failed to send shutdown signal"))]
    ShutdownSignal,

    #[snafu(display("{}", message))]
    Common { message: String },

    #[snafu(display("IO error {}", source))]
    IoError { source: std::io::Error },

    #[snafu(display("Serde error {}", source))]
    SerdeError { source: serde_yaml::Error },
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            ServiceError::SetupEngine { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            ServiceError::ShutdownSignal => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::Common { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::IoError { .. } => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            ServiceError::SerdeError { .. } => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
        };
        (status, error_message).into_response()
    }
}
