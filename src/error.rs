use axum::{http::StatusCode, Json};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Database(String),
    Rusqlite(rusqlite::Error),
    Serialization(serde_json::Error),
    BadRequest(String),
    Internal(String),
    #[allow(dead_code)]
    FilterParse(String),
    Configuration(String),
    #[allow(dead_code)]
    PreconditionFailed,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Database(e) => write!(f, "Database error: {}", e),
            AppError::Rusqlite(e) => write!(f, "SQLite error: {}", e),
            AppError::Serialization(e) => write!(f, "Serialization error: {}", e),
            AppError::BadRequest(e) => write!(f, "Bad request: {}", e),
            AppError::Internal(e) => write!(f, "Internal error: {}", e),
            AppError::FilterParse(e) => write!(f, "Filter parse error: {}", e),
            AppError::Configuration(e) => write!(f, "Configuration error: {}", e),
            AppError::PreconditionFailed => {
                write!(f, "Precondition failed: Resource version mismatch")
            }
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Rusqlite(e) => Some(e),
            AppError::Serialization(e) => Some(e),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        AppError::Rusqlite(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Serialization(err)
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>> for AppError {
    fn from(err: std::sync::PoisonError<std::sync::MutexGuard<'_, rusqlite::Connection>>) -> Self {
        AppError::Internal(err.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;

// SCIM 2.0 standard error response helper
pub fn scim_error_response(
    status_code: StatusCode,
    scim_type: &str,
    detail: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let status_str = status_code.as_u16().to_string();
    (
        status_code,
        Json(json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
            "detail": detail,
            "status": status_str,
            "scimType": scim_type
        })),
    )
}

// HTTPレスポンスへの変換
impl AppError {
    pub fn to_response(&self) -> (StatusCode, Json<serde_json::Value>) {
        let (status, message) = match self {
            AppError::Database(e) => {
                eprintln!("Database error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            }
            AppError::Rusqlite(e) => {
                eprintln!("SQLite error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            AppError::Serialization(e) => {
                eprintln!("Serialization error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
            }
            AppError::BadRequest(e) => (StatusCode::BAD_REQUEST, e.clone()),
            AppError::Internal(e) => {
                eprintln!("Internal error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            }
            AppError::FilterParse(e) => (StatusCode::BAD_REQUEST, e.clone()),
            AppError::Configuration(e) => {
                eprintln!("Configuration error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.clone())
            }
            AppError::PreconditionFailed => {
                return scim_error_response(
                    StatusCode::PRECONDITION_FAILED,
                    "preconditionFailed",
                    "Resource version mismatch",
                );
            }
        };

        (status, Json(json!({ "error": message })))
    }
}
