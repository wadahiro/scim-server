use axum::{
    extract::{rejection::JsonRejection, FromRequest, Request},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::de::DeserializeOwned;
use serde_json::json;

/// Custom JSON extractor that accepts both application/json and application/scim+json
/// as required by SCIM 2.0 specification (RFC 7644)
pub struct ScimJson<T>(pub T);

impl<T, S> FromRequest<S> for ScimJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ScimJsonRejection;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let headers = req.headers();

        // Check Content-Type header
        if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
            let content_type_str = content_type
                .to_str()
                .map_err(|_| ScimJsonRejection::InvalidContentType)?;

            // Extract the media type without parameters (e.g., charset)
            let media_type = content_type_str
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase();

            // Accept both application/json and application/scim+json
            if media_type != "application/json" && media_type != "application/scim+json" {
                return Err(ScimJsonRejection::InvalidContentType);
            }
        }

        // Use Axum's Json extractor for the actual parsing
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ScimJson(value)),
            Err(rejection) => Err(ScimJsonRejection::JsonRejection(rejection)),
        }
    }
}

pub enum ScimJsonRejection {
    InvalidContentType,
    JsonRejection(JsonRejection),
}

impl IntoResponse for ScimJsonRejection {
    fn into_response(self) -> Response {
        match self {
            ScimJsonRejection::InvalidContentType => {
                let body = Json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "400",
                    "scimType": "invalidValue",
                    "detail": "Content-Type must be application/json or application/scim+json"
                }));
                (StatusCode::BAD_REQUEST, body).into_response()
            }
            ScimJsonRejection::JsonRejection(rejection) => {
                // Convert Axum's JSON rejection to SCIM error format
                let body = Json(json!({
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                    "status": "400",
                    "scimType": "invalidValue",
                    "detail": format!("Invalid JSON: {}", rejection)
                }));
                (StatusCode::BAD_REQUEST, body).into_response()
            }
        }
    }
}

// Helper function to set SCIM content type in responses
#[allow(dead_code)]
pub fn scim_content_type() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/scim+json; charset=utf-8"),
    );
    headers
}
