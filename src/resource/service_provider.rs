use axum::{extract::{State, Extension}, http::StatusCode, Json};
use scim_v2::models::{
    scim_schema::Meta,
    service_provider_config::{
        AuthenticationScheme, Bulk, Filter, ServiceProviderConfig, Supported,
    },
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::TenantInfo;
use crate::config::AppConfig;
use crate::backend::ScimBackend;


/// Create authentication schemes for a specific tenant
fn create_authentication_schemes_for_tenant(tenant_info: &TenantInfo) -> Vec<AuthenticationScheme> {
    match tenant_info.tenant_config.auth.auth_type.as_str() {
            "bearer" => {
                vec![AuthenticationScheme {
                    name: "OAuth 2.0 Bearer Token".to_string(),
                    description: "Authentication using OAuth 2.0 Bearer tokens as specified in RFC 6750".to_string(),
                    documentation_uri: Some("https://tools.ietf.org/html/rfc6750".to_string()),
                    primary: Some(true),
                    spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
                    type_: "oauthbearertoken".to_string(),
                }]
            }
            "basic" => {
                vec![AuthenticationScheme {
                    name: "HTTP Basic Authentication".to_string(),
                    description: "Authentication using HTTP Basic Authentication as specified in RFC 7617".to_string(),
                    documentation_uri: Some("https://tools.ietf.org/html/rfc7617".to_string()),
                    primary: Some(true),
                    spec_uri: "https://tools.ietf.org/html/rfc7617".to_string(),
                    type_: "httpbasic".to_string(),
                }]
            }
            "unauthenticated" => {
                // Anonymous access - no authentication required
                vec![AuthenticationScheme {
                    name: "Anonymous Access".to_string(),
                    description: "No authentication required for development/testing purposes".to_string(),
                    documentation_uri: None,
                    primary: Some(true),
                    spec_uri: "".to_string(),
                    type_: "none".to_string(),
                }]
            }
            _ => {
                // Unknown authentication type, return default OAuth Bearer
                vec![AuthenticationScheme {
                    name: "OAuth 2.0 Bearer Token".to_string(),
                    description: "Authentication using OAuth 2.0 Bearer tokens as specified in RFC 6750".to_string(),
                    documentation_uri: Some("https://tools.ietf.org/html/rfc6750".to_string()),
                    primary: Some(true),
                    spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
                    type_: "oauthbearertoken".to_string(),
                }]
            }
        }
}

type AppState = (Arc<dyn ScimBackend>, Arc<String>, Arc<AppConfig>);

pub async fn service_provider_config(
    State((_storage, _base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<ServiceProviderConfig>), (StatusCode, Json<Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Create auth schemes based on the specific tenant
    let auth_schemes = create_authentication_schemes_for_tenant(&tenant_info);

    let config = ServiceProviderConfig {
        authentication_schemes: auth_schemes,
        bulk: Bulk {
            supported: false,
            max_operations: 0,
            max_payload_size: 0,
        },
        change_password: Supported { supported: true },
        documentation_uri: Some("https://github.com/wadahiro/scim-server".to_string()),
        etag: Supported { supported: false },
        filter: Filter {
            supported: true,
            max_results: 1000,
        },
        meta: Some(Meta {
            resource_type: Some("ServiceProviderConfig".to_string()),
            created: None,
            last_modified: None,
            location: Some(format!("{}/ServiceProviderConfig", 
                if tenant_info.tenant_config.url.starts_with("http://") || tenant_info.tenant_config.url.starts_with("https://") {
                    if let Ok(url) = url::Url::parse(&tenant_info.tenant_config.url) {
                        url.path().trim_end_matches('/').to_string()
                    } else {
                        "/scim".to_string()
                    }
                } else {
                    tenant_info.tenant_config.url.trim_end_matches('/').to_string()
                }
            )),
            version: None,
        }),
        patch: Supported { supported: true },
        sort: Supported { supported: true },
    };

    Ok((StatusCode::OK, Json(config)))
}