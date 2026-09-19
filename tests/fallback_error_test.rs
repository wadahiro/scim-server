//! RFC 7644 §3.12: every error response, including one for a path that
//! doesn't match any resource, must be a SCIM Error resource -- not a bare,
//! bodyless 404.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::Value;

mod common;

#[tokio::test]
async fn test_unmatched_scim_path_returns_scim_error_body() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/NoSuchThing").await;
    response.assert_status(StatusCode::NOT_FOUND);

    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.contains("json"),
        "expected a JSON content type, got '{}'",
        content_type
    );

    let body: Value = response.json();
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(body["status"], "404");
}

#[tokio::test]
async fn test_custom_endpoints_are_unaffected_by_fallback() {
    // The fallback must not intercept custom-endpoint responses or rewrite
    // their configured content type.
    use scim_server::config::{
        AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, CustomEndpoint, DatabaseConfig,
        ServerConfig, TenantConfig,
    };

    let app_config = AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
        },
        backend: BackendConfig {
            backend_type: "database".to_string(),
            database: Some(DatabaseConfig {
                db_type: "sqlite".to_string(),
                url: ":memory:".to_string(),
                max_connections: 10,
            }),
        },
        compatibility: CompatibilityConfig::default(),
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            host: None,
            host_resolution: None,
            auth: AuthConfig {
                auth_type: "unauthenticated".to_string(),
                token: None,
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/health/custom".to_string(),
                response: "plain text ok".to_string(),
                status_code: 200,
                content_type: "text/plain".to_string(),
                auth: None,
            }],
            compatibility: None,
        }],
    };

    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/health/custom").await;
    response.assert_status(StatusCode::OK);
    response.assert_text("plain text ok");
    let content_type = response
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(content_type, "text/plain");
}
