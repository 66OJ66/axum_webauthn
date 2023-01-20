use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use thiserror::Error;
use tracing::*;

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("unknown webauthn error")]
    Unknown,
    #[error("Error communicating with Postgres database: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Error during serialisation/deserialisation: {0}")]
    SerialisationError(serde_json::Error),
    #[error("Error updating the session: {0}")]
    SessionError(serde_json::Error),
    #[error("Corrupt Session")]
    CorruptSession,
    #[error("User Not Found")]
    UserNotFound,
    #[error("User Has No Credentials")]
    UserHasNoCredentials,
}
impl IntoResponse for WebauthnError {
    fn into_response(self) -> Response {
        let body = match self {
            WebauthnError::CorruptSession => "Corrupt Session",
            WebauthnError::DatabaseError(_) => "Internal Server Error",
            WebauthnError::UserNotFound => "User Not Found",
            WebauthnError::Unknown => "Unknown Error",
            WebauthnError::UserHasNoCredentials => "User Has No Credentials",
            WebauthnError::SerialisationError(_) => "Internal Server Error",
            WebauthnError::SessionError(_) => "Internal Server Error",
        };

        error!("{}", self);

        // its often easiest to implement `IntoResponse` by calling other implementations
        (StatusCode::INTERNAL_SERVER_ERROR, body).into_response()
    }
}

pub async fn handle_404(_: std::io::Error) -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}
