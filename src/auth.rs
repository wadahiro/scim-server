use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode, Uri},
    middleware::Next,
    response::Response,
    Json,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{AppConfig, AuthConfig, RequestInfo, TenantConfig};

/// Tenant information extracted from request
#[derive(Debug, Clone)]
pub struct TenantInfo {
    pub tenant_id: u32,
    pub tenant_config: TenantConfig,
    pub base_path: String, // Resolved absolute base URL for this tenant
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

    // Extract client IP from connection info if available
    let client_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());

    // Skip authentication for non-SCIM endpoints (e.g., health checks)
    let path = uri.path();
    if path == "/" || path == "/health" {
        return Ok(next.run(request).await);
    }

    // Resolve tenant and validate authentication
    let tenant_info = match resolve_tenant_and_authenticate(&app_config, &uri, &headers, client_ip)
    {
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
    client_ip: Option<std::net::IpAddr>,
) -> Result<TenantInfo, StatusCode> {
    let path = uri.path();
    let tenant_id = resolve_tenant_id_from_request(app_config, uri, headers, client_ip)?;

    // Find the tenant configuration
    let tenant = app_config
        .tenants
        .iter()
        .find(|t| t.id == tenant_id)
        .ok_or(StatusCode::NOT_FOUND)?
        .clone();

    // Extract Authorization header
    let auth_header = headers.get("authorization").and_then(|h| h.to_str().ok());

    // Check if this is a custom endpoint with specific auth config
    let auth_config =
        if let Some(custom_endpoint) = tenant.custom_endpoints.iter().find(|ep| ep.path == path) {
            // Use custom endpoint's auth config if available, otherwise tenant's auth config
            custom_endpoint.effective_auth_config(&tenant.auth)
        } else {
            // Regular SCIM endpoint - use tenant's auth config
            &tenant.auth
        };

    // Validate authentication using the effective auth config
    validate_authentication(auth_config, auth_header)?;

    // Resolve the absolute base URL for this tenant
    let base_url = resolve_tenant_base_url(app_config, &tenant, uri, headers);

    Ok(TenantInfo {
        tenant_id,
        tenant_config: tenant,
        base_path: base_url,
    })
}

/// Helper function to resolve tenant ID from URL path and headers using config
fn resolve_tenant_id_from_request(
    app_config: &AppConfig,
    uri: &Uri,
    headers: &HeaderMap,
    client_ip: Option<std::net::IpAddr>,
) -> Result<u32, StatusCode> {
    let path = uri.path();

    // Create RequestInfo from headers
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
        client_ip,
    };

    // Use the unified find_tenant_by_request method that handles both SCIM and custom endpoints
    if let Some((tenant, _resolved_url)) = app_config.find_tenant_by_request(&request_info) {
        return Ok(tenant.id);
    }

    Err(StatusCode::NOT_FOUND)
}

/// Helper function to validate authentication using auth config
fn validate_authentication(
    auth_config: &AuthConfig,
    auth_header: Option<&str>,
) -> Result<(), StatusCode> {
    match auth_config.auth_type.as_str() {
        "unauthenticated" => {
            // No authentication required - always allow
            Ok(())
        }
        "bearer" => {
            // Validate Bearer token (case-insensitive per RFC 7235)
            let auth_header = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;

            // Check for "Bearer " prefix case-insensitively
            if auth_header.len() < 7
                || !auth_header[..7].to_ascii_lowercase().starts_with("bearer ")
            {
                return Err(StatusCode::UNAUTHORIZED);
            }

            let provided_token = &auth_header[7..]; // Remove "Bearer " prefix

            match &auth_config.token {
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
        "token" => {
            // Validate token authentication (case-insensitive per RFC 7235)
            let auth_header = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;

            // Check for "token " prefix case-insensitively
            if auth_header.len() < 6 || !auth_header[..6].to_ascii_lowercase().starts_with("token ")
            {
                return Err(StatusCode::UNAUTHORIZED);
            }

            let provided_token = &auth_header[6..]; // Remove "token " prefix

            match &auth_config.token {
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
            // Validate HTTP Basic authentication (case-insensitive per RFC 7235)
            let auth_header = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;

            // Check for "Basic " prefix case-insensitively
            if auth_header.len() < 6 || !auth_header[..6].to_ascii_lowercase().starts_with("basic ")
            {
                return Err(StatusCode::UNAUTHORIZED);
            }

            let encoded_credentials = &auth_header[6..]; // Remove "Basic " prefix

            // Decode base64 credentials
            use base64::{engine::general_purpose, Engine as _};
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

            match &auth_config.basic {
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

/// Helper function to resolve the absolute base URL for a tenant
fn resolve_tenant_base_url(
    _app_config: &AppConfig,
    tenant: &TenantConfig,
    uri: &Uri,
    headers: &HeaderMap,
) -> String {
    // Create RequestInfo for URL resolution
    let request_info = RequestInfo {
        path: uri.path(),
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
        client_ip: None,
    };

    // Use the new build_base_url method that handles override_base_url and auto-construction
    tenant.build_base_url(&request_info)
}
