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
    /// A PATCH (or other) operation attempted to remove or otherwise violate
    /// the mutability of an attribute the schema marks `required` or
    /// `readOnly`. Maps to HTTP 400 with `scimType: "mutability"`
    /// (RFC 7644 §3.5.2).
    Mutability(String),
    /// A PATCH `path` selected a value via a filter that matched nothing.
    /// Maps to HTTP 400 with `scimType: "noTarget"` (RFC 7644 §3.5.2).
    NoTarget(String),
    /// A PATCH `path` named no attribute this server can actually persist
    /// (e.g. a sub-attribute of a known complex attribute, or an attribute
    /// inside a schema-extension container, that the schema doesn't
    /// define) -- so applying the operation would silently have no effect.
    /// Maps to HTTP 400 with `scimType: "invalidPath"` (RFC 7644 §3.12:
    /// "The 'path' attribute was invalid or malformed").
    InvalidPath(String),
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
            AppError::Mutability(e) => write!(f, "Mutability violation: {}", e),
            AppError::NoTarget(e) => write!(f, "No target: {}", e),
            AppError::InvalidPath(e) => write!(f, "Invalid path: {}", e),
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
// `scim_type` is the optional `scimType` detail keyword. RFC 7644 §3.12
// Table 9 (rfc7644.txt:3818-3910) defines exactly ten values, all for
// HTTP 400 responses: `invalidFilter`, `tooMany`, `uniqueness`,
// `mutability`, `invalidSyntax`, `invalidPath`, `noTarget`, `invalidValue`,
// `invalidVers`, `sensitive`. (`uniqueness` is also reused for 409, per
// Table 8.) Table 9 defines no keyword for 412 (Precondition Failed) --
// the string "preconditionFailed" does not occur anywhere in RFC 7644 --
// so 412 responses carry no `scimType`. 404 and 5xx responses likewise
// carry no `scimType`; callers pass `None` for all of these.
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
        // RFC 7644 §3.12 error responses are meant for API clients, not for
        // server-internal diagnostics. For 5xx-class errors we log the real
        // cause (which may include driver/serialization internals such as
        // SQL error text or serde messages) but always return a generic,
        // sanitized `detail` to the client instead of that raw message.
        const INTERNAL_ERROR_DETAIL: &str = "An internal error occurred";

        match self {
            AppError::Database(e) => {
                eprintln!("Database error: {}", e);
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    INTERNAL_ERROR_DETAIL,
                )
            }
            AppError::Rusqlite(e) => {
                eprintln!("SQLite error: {}", e);
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    INTERNAL_ERROR_DETAIL,
                )
            }
            AppError::Serialization(e) => {
                eprintln!("Serialization error: {}", e);
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    INTERNAL_ERROR_DETAIL,
                )
            }
            AppError::BadRequest(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("invalidValue"), e)
            }
            AppError::Conflict(e) => {
                scim_error_response(StatusCode::CONFLICT, Some("uniqueness"), e)
            }
            AppError::Internal(e) => {
                eprintln!("Internal error: {}", e);
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    INTERNAL_ERROR_DETAIL,
                )
            }
            AppError::FilterParse(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("invalidFilter"), e)
            }
            AppError::Configuration(e) => {
                eprintln!("Configuration error: {}", e);
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    INTERNAL_ERROR_DETAIL,
                )
            }
            AppError::PreconditionFailed => scim_error_response(
                StatusCode::PRECONDITION_FAILED,
                // RFC 7644 Table 9 defines no scimType for 412; see the
                // comment on `scim_error_response` above.
                None,
                "Resource version mismatch",
            ),
            AppError::Mutability(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("mutability"), e)
            }
            AppError::NoTarget(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("noTarget"), e)
            }
            AppError::InvalidPath(e) => {
                scim_error_response(StatusCode::BAD_REQUEST, Some("invalidPath"), e)
            }
        }
    }
}
