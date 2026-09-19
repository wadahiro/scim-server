use axum::{http::StatusCode, Json};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    Database(String),
    Rusqlite(rusqlite::Error),
    Serialization(serde_json::Error),
    BadRequest(String),
    Conflict(String),
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
            AppError::Conflict(e) => write!(f, "Conflict: {}", e),
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

// SCIM 2.0 standard error response helper (RFC 7644 §3.12).
//
// `scim_type` is the optional `scimType` detail keyword. RFC 7644 only
// defines `scimType` values for 400-class errors (e.g. `invalidFilter`,
// `invalidValue`, `invalidSyntax`, `invalidPath`) plus `uniqueness` (409) and
// `preconditionFailed` (412); 404 and 5xx responses carry no `scimType` at
// all, so callers pass `None` for those.
pub fn scim_error_response(
    status_code: StatusCode,
    scim_type: Option<&str>,
    detail: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let status_str = status_code.as_u16().to_string();
    let mut body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "detail": detail,
        "status": status_str,
    });
    if let Some(scim_type) = scim_type {
        body["scimType"] = json!(scim_type);
    }
    (status_code, Json(body))
}

// HTTPレスポンスへの変換
impl AppError {
    pub fn to_response(&self) -> (StatusCode, Json<serde_json::Value>) {
        match self {
            AppError::Database(e) => {
                eprintln!("Database error: {}", e);
                scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, None, e)
            }
            AppError::Rusqlite(e) => {
                eprintln!("SQLite error: {}", e);
                scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, None, &e.to_string())
            }
            AppError::Serialization(e) => {
                eprintln!("Serialization error: {}", e);
                scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, None, &e.to_string())
            }
            AppError::BadRequest(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("invalidValue"), e)
            }
            AppError::Conflict(e) => {
                scim_error_response(StatusCode::CONFLICT, Some("uniqueness"), e)
            }
            AppError::Internal(e) => {
                eprintln!("Internal error: {}", e);
                scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, None, e)
            }
            AppError::FilterParse(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("invalidFilter"), e)
            }
            AppError::Configuration(e) => {
                eprintln!("Configuration error: {}", e);
                scim_error_response(StatusCode::INTERNAL_SERVER_ERROR, None, e)
            }
            AppError::PreconditionFailed => scim_error_response(
                StatusCode::PRECONDITION_FAILED,
                Some("preconditionFailed"),
                "Resource version mismatch",
            ),
        }
    }
}
