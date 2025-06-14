use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use scim_v2::models::{
    scim_schema::Meta,
    service_provider_config::{
        AuthenticationScheme, Bulk, Filter, ServiceProviderConfig, Supported,
    },
};
use serde_json::Value;
use std::sync::Arc;

use crate::auth::TenantInfo;
use crate::backend::ScimBackend;
use crate::config::AppConfig;

/// Create authentication schemes for a specific tenant
fn create_authentication_schemes_for_tenant(tenant_info: &TenantInfo) -> Vec<AuthenticationScheme> {
    match tenant_info.tenant_config.auth.auth_type.as_str() {
        "bearer" => {
            vec![AuthenticationScheme {
                name: "OAuth 2.0 Bearer Token".to_string(),
                description:
                    "Authentication using OAuth 2.0 Bearer tokens as specified in RFC 6750"
                        .to_string(),
                documentation_uri: Some("https://tools.ietf.org/html/rfc6750".to_string()),
                primary: Some(true),
                spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
                type_: "oauthbearertoken".to_string(),
            }]
        }
        "basic" => {
            vec![AuthenticationScheme {
                name: "HTTP Basic Authentication".to_string(),
                description:
                    "Authentication using HTTP Basic Authentication as specified in RFC 7617"
                        .to_string(),
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
                description: "No authentication required for development/testing purposes"
                    .to_string(),
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
                description:
                    "Authentication using OAuth 2.0 Bearer tokens as specified in RFC 6750"
                        .to_string(),
                documentation_uri: Some("https://tools.ietf.org/html/rfc6750".to_string()),
                primary: Some(true),
                spec_uri: "https://tools.ietf.org/html/rfc6750".to_string(),
                type_: "oauthbearertoken".to_string(),
            }]
        }
    }
}

type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

pub async fn service_provider_config(
    State((_storage, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<ServiceProviderConfig>), (StatusCode, Json<Value>)> {
    let _tenant_id = tenant_info.tenant_id;

    // Get the correct path from tenant configuration
    let tenant_path = tenant_info
        .tenant_config
        .path
        .trim_end_matches('/')
        .to_string();

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
            location: Some(format!(
                "{}{}/ServiceProviderConfig",
                tenant_info.base_path, tenant_path
            )),
            version: None,
        }),
        patch: Supported { supported: true },
        sort: Supported { supported: true },
    };

    Ok((StatusCode::OK, Json(config)))
}
