use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

mod common;

use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, CustomEndpoint, DatabaseConfig,
    HostResolutionConfig, HostResolutionType, ServerConfig, TenantConfig,
};

/// Test that custom endpoints work correctly with simple tenant setup
#[tokio::test]
async fn test_custom_endpoint_basic_with_tenant_isolation() {
    // Create config with multiple tenants to test isolation
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
                max_connections: 1,
            }),
        },
        compatibility: CompatibilityConfig::default(),
        tenants: vec![
            TenantConfig {
                id: 1,
                path: "/tenant1/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host: None,
                host_resolution: None,
                override_base_url: None,
                custom_endpoints: vec![CustomEndpoint {
                    path: "/tenant1/custom/status".to_string(),
                    response: r#"{"tenant": "tenant1", "status": "ok"}"#.to_string(),
                    status_code: 200,
                    content_type: "application/json".to_string(),
                    auth: None,
                }],
                compatibility: None,
            },
            TenantConfig {
                id: 2,
                path: "/tenant2/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host: None,
                host_resolution: None,
                override_base_url: None,
                custom_endpoints: vec![CustomEndpoint {
                    path: "/tenant2/custom/status".to_string(),
                    response: r#"{"tenant": "tenant2", "status": "healthy"}"#.to_string(),
                    status_code: 200,
                    content_type: "application/json".to_string(),
                    auth: None,
                }],
                compatibility: None,
            },
        ],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test tenant 1 custom endpoint
    let response = server.get("/tenant1/custom/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"tenant": "tenant1", "status": "ok"})
    );

    // Test tenant 2 custom endpoint
    let response = server.get("/tenant2/custom/status").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"tenant": "tenant2", "status": "healthy"})
    );

    // Test that each tenant's SCIM endpoints work
    let response = server.get("/tenant1/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let response = server.get("/tenant2/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

/// Test host resolution config exists in tenant structure
#[tokio::test]
async fn test_tenant_config_supports_route() {
    // This test ensures that the host resolution configuration structure is available
    let tenant_config = TenantConfig {
        id: 1,
        path: "/scim/v2".to_string(),
        auth: AuthConfig {
            auth_type: "unauthenticated".to_string(),
            token: None,
            basic: None,
        },
        host: Some("api.example.com".to_string()),
        host_resolution: Some(HostResolutionConfig {
            resolution_type: HostResolutionType::Host,
            trusted_proxies: Some(vec!["192.168.1.0/24".to_string()]),
        }),
        override_base_url: Some("https://api.example.com".to_string()),
        custom_endpoints: vec![CustomEndpoint {
            path: "/custom/health".to_string(),
            response: json!({"status": "healthy"}).to_string(),
            status_code: 200,
            content_type: "application/json".to_string(),
            auth: None,
        }],
        compatibility: None,
    };

    // Verify that host resolution configuration is properly structured
    assert!(tenant_config.host_resolution.is_some());

    let host_resolution = tenant_config.host_resolution.unwrap();
    assert_eq!(host_resolution.resolution_type, HostResolutionType::Host);
    assert!(host_resolution.trusted_proxies.is_some());
    assert_eq!(host_resolution.trusted_proxies.unwrap().len(), 1);

    // Verify custom endpoint structure with auth field
    assert_eq!(tenant_config.custom_endpoints.len(), 1);
    assert!(tenant_config.custom_endpoints[0].auth.is_none());
}
