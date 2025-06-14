use axum::{
    extract::{Request, State},
    http::{StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::Arc;

use crate::{auth::TenantInfo, backend::ScimBackend, config::AppConfig};

/// Handle custom endpoint requests
pub async fn handle_custom_endpoint(
    State((_, app_config)): State<(Arc<dyn ScimBackend>, Arc<AppConfig>)>,
    request: Request,
) -> impl IntoResponse {
    let path = request.uri().path();
    
    // Get tenant info from auth middleware
    let tenant_info = request
        .extensions()
        .get::<TenantInfo>()
        .cloned();
    
    // Find matching custom endpoint
    if let Some((tenant, endpoint)) = app_config.find_custom_endpoint(path) {
        // Verify tenant matches (this should always be true if auth middleware worked correctly)
        if let Some(info) = tenant_info {
            if info.tenant_id != tenant.id {
                return (StatusCode::FORBIDDEN, "Tenant mismatch").into_response();
            }
        } else {
            // This shouldn't happen if auth middleware is properly configured
            return (StatusCode::INTERNAL_SERVER_ERROR, "No tenant info found").into_response();
        }

        // Return custom response
        let response = Response::builder()
            .status(endpoint.status_code)
            .header("content-type", &endpoint.content_type);

        if let Ok(response) = response.body(endpoint.response.clone()) {
            response.into_response()
        } else {
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create response").into_response()
        }
    } else {
        (StatusCode::NOT_FOUND, "Custom endpoint not found").into_response()
    }
}