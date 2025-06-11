use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;
use std::sync::Arc;

use crate::config::{AppConfig, RequestInfo, TenantConfig};

/// Tenant information extracted from request
#[derive(Debug, Clone)]
pub struct TenantInfo {
    pub tenant_id: u32,
    pub tenant_config: TenantConfig,
}

/// Authentication middleware for SCIM endpoints
pub async fn auth_middleware(
    State(app_config): State<Arc<AppConfig>>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    // Extract URI and headers from request
    let uri = request.uri().clone();
    let headers = request.headers().clone();
    
    // Skip authentication for non-SCIM endpoints (e.g., health checks)
    let path = uri.path();
    if path == "/" || path == "/health" {
        return Ok(next.run(request).await);
    }
    
    // Resolve tenant and validate authentication
    let tenant_info = match resolve_tenant_and_authenticate(&app_config, &uri, &headers) {
        Ok(info) => info,
        Err(StatusCode::UNAUTHORIZED) => {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(json!({"message": "Authentication required"})),
            ));
        }
        Err(status) => {
            return Err((
                status,
                Json(json!({"message": format!("Tenant not found for path '{}'", path)})),
            ));
        }
    };
    
    // Store tenant info in request extensions for handlers to use
    request.extensions_mut().insert(tenant_info);
    
    Ok(next.run(request).await)
}

/// Helper function to resolve tenant and validate authentication
fn resolve_tenant_and_authenticate(
    app_config: &AppConfig,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<TenantInfo, StatusCode> {
    let tenant_id = resolve_tenant_id_from_request(app_config, uri, headers)?;
    
    // Find the tenant configuration
    let tenant = app_config
        .tenants
        .iter()
        .find(|t| t.id == tenant_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();
    
    // Extract Authorization header
    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());
    
    // Validate authentication for this tenant
    validate_tenant_authentication(&tenant, auth_header)?;
    
    Ok(TenantInfo {
        tenant_id,
        tenant_config: tenant,
    })
}

/// Helper function to resolve tenant ID from URL path and headers using config
fn resolve_tenant_id_from_request(
    app_config: &AppConfig,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<u32, StatusCode> {
    let path = uri.path();
    
    // Create RequestInfo from headers for host resolution
    let request_info = RequestInfo {
        path,
        host_header: headers.get("host").and_then(|h| h.to_str().ok()),
        forwarded_header: headers.get("forwarded").and_then(|h| h.to_str().ok()),
        x_forwarded_proto: headers
            .get("x-forwarded-proto")
            .and_then(|h| h.to_str().ok()),
        x_forwarded_host: headers
            .get("x-forwarded-host")
            .and_then(|h| h.to_str().ok()),
        x_forwarded_port: headers
            .get("x-forwarded-port")
            .and_then(|h| h.to_str().ok()),
        client_ip: None, // For now, we don't need the client IP for tenant resolution
    };
    
    // First try to use host resolution for tenants that support it
    if let Some((tenant, _resolved_url)) = app_config.find_tenant_by_request(&request_info) {
        return Ok(tenant.id);
    }
    
    // Fallback to simple path matching for tenants without host resolution
    for tenant in &app_config.tenants {
        // Skip tenants with host resolution - they were handled above
        if tenant.host_resolution.is_some() {
            continue;
        }
        
        // Extract expected base path from tenant URL
        let base_path = if tenant.url.starts_with("http://") || tenant.url.starts_with("https://") {
            // Extract path from full URL
            if let Ok(url) = url::Url::parse(&tenant.url) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            // Already a path
            tenant.url.trim_end_matches('/').to_string()
        };
        
        // Check if the request path starts with this tenant's base path
        if path.starts_with(&base_path) {
            return Ok(tenant.id);
        }
    }
    
    Err(StatusCode::NOT_FOUND)
}

/// Helper function to validate authentication for a tenant
fn validate_tenant_authentication(
    tenant: &TenantConfig,
    auth_header: Option<&str>,
) -> Result<(), StatusCode> {
    match tenant.auth.auth_type.as_str() {
        "unauthenticated" => {
            // No authentication required - always allow
            Ok(())
        }
        "bearer" => {
            // Validate Bearer token
            let auth_header = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;
            
            if !auth_header.starts_with("Bearer ") {
                return Err(StatusCode::UNAUTHORIZED);
            }
            
            let provided_token = &auth_header[7..]; // Remove "Bearer " prefix
            
            match &tenant.auth.token {
                Some(expected_token) => {
                    if provided_token == expected_token {
                        Ok(())
                    } else {
                        Err(StatusCode::UNAUTHORIZED)
                    }
                }
                None => Err(StatusCode::UNAUTHORIZED), // No token configured
            }
        }
        "basic" => {
            // Validate HTTP Basic authentication
            let auth_header = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;
            
            if !auth_header.starts_with("Basic ") {
                return Err(StatusCode::UNAUTHORIZED);
            }
            
            let encoded_credentials = &auth_header[6..]; // Remove "Basic " prefix
            
            // Decode base64 credentials
            use base64::{Engine as _, engine::general_purpose};
            let decoded = general_purpose::STANDARD
                .decode(encoded_credentials)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            
            let credentials_str =
                String::from_utf8(decoded).map_err(|_| StatusCode::UNAUTHORIZED)?;
            
            let parts: Vec<&str> = credentials_str.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(StatusCode::UNAUTHORIZED);
            }
            
            let (provided_username, provided_password) = (parts[0], parts[1]);
            
            match &tenant.auth.basic {
                Some(basic_config) => {
                    if provided_username == basic_config.username
                        && provided_password == basic_config.password
                    {
                        Ok(())
                    } else {
                        Err(StatusCode::UNAUTHORIZED)
                    }
                }
                None => Err(StatusCode::UNAUTHORIZED), // No basic auth configured
            }
        }
        _ => {
            // Unknown authentication type
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}