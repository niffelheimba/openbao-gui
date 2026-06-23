use serde::Serialize;
use thiserror::Error;

pub type AppResult<T> = Result<T, AppError>;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("OpenBao request failed: {0}")]
    Api(String),
    #[error("Authentication was cancelled")]
    Cancelled,
    #[error("Authentication timed out")]
    Timeout,
    #[error("You must sign in first")]
    NotAuthenticated,
    #[error("Certificate operation failed: {0}")]
    Certificate(String),
    #[error("Internal error")]
    Internal,
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(error: reqwest::Error) -> Self {
        let message = if error.is_timeout() {
            "request timed out"
        } else if error.is_connect() {
            "connection failed"
        } else {
            "unexpected HTTP error"
        };
        tracing::warn!(error = %crate::redaction::redact(&error.to_string()), "OpenBao transport error");
        Self::Api(message.into())
    }
}
