use axum::http::StatusCode;
use axum_test::TestServer;
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, BasicAuthConfig, CompatibilityConfig, CustomEndpoint,
    DatabaseConfig, ServerConfig, TenantConfig,
};
use serde_json::json;

mod common;

#[tokio::test]
async fn test_custom_endpoint_auth_override_from_tenant_to_unauthenticated() {
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
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            auth: AuthConfig {
                auth_type: "bearer".to_string(),
                token: Some("tenant-token-123".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/api/public".to_string(),
                response: json!({"message": "This endpoint overrides tenant auth to be public"})
                    .to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                auth: Some(AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                }),
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test that regular SCIM endpoint still requires authentication
    let response = server.get("/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test that regular SCIM endpoint works with auth
    let response = server
        .get("/scim/v2/ServiceProviderConfig")
        .add_header("Authorization", "Bearer tenant-token-123")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test that custom endpoint with auth override works WITHOUT authentication
    let response = server.get("/api/public").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"message": "This endpoint overrides tenant auth to be public"})
    );

    // Test that custom endpoint with auth override still works WITH authentication (should be ignored)
    let response = server
        .get("/api/public")
        .add_header("Authorization", "Bearer tenant-token-123")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn test_custom_endpoint_auth_override_from_unauthenticated_to_bearer() {
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
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            auth: AuthConfig {
                auth_type: "unauthenticated".to_string(),
                token: None,
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/api/secure".to_string(),
                response: json!({"message": "This endpoint overrides tenant auth to require bearer token"}).to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                auth: Some(AuthConfig {
                    auth_type: "bearer".to_string(),
                    token: Some("custom-endpoint-token".to_string()),
                    basic: None,
                }),
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test that regular SCIM endpoint works without authentication
    let response = server.get("/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test that custom endpoint with auth override requires authentication
    let response = server.get("/api/secure").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test that custom endpoint works with correct token
    let response = server
        .get("/api/secure")
        .add_header("Authorization", "Bearer custom-endpoint-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"message": "This endpoint overrides tenant auth to require bearer token"})
    );

    // Test that custom endpoint fails with wrong token
    let response = server
        .get("/api/secure")
        .add_header("Authorization", "Bearer wrong-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_custom_endpoint_auth_override_from_bearer_to_basic() {
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
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            auth: AuthConfig {
                auth_type: "bearer".to_string(),
                token: Some("tenant-bearer-token".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/api/basic-auth".to_string(),
                response:
                    json!({"message": "This endpoint overrides tenant auth to use basic auth"})
                        .to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                auth: Some(AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "custom-user".to_string(),
                        password: "custom-pass".to_string(),
                    }),
                }),
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test that regular SCIM endpoint requires bearer token
    let response = server
        .get("/scim/v2/ServiceProviderConfig")
        .add_header("Authorization", "Bearer tenant-bearer-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Test that custom endpoint doesn't work with bearer token
    let response = server
        .get("/api/basic-auth")
        .add_header("Authorization", "Bearer tenant-bearer-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test that custom endpoint works with correct basic auth
    use base64::{engine::general_purpose, Engine as _};
    let auth = general_purpose::STANDARD.encode("custom-user:custom-pass");
    let response = server
        .get("/api/basic-auth")
        .add_header("Authorization", format!("Basic {}", auth))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"message": "This endpoint overrides tenant auth to use basic auth"})
    );

    // Test that custom endpoint fails with wrong basic auth
    let wrong_auth = general_purpose::STANDARD.encode("wrong-user:wrong-pass");
    let response = server
        .get("/api/basic-auth")
        .add_header("Authorization", format!("Basic {}", wrong_auth))
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_custom_endpoint_without_auth_override_inherits_tenant_auth() {
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
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            auth: AuthConfig {
                auth_type: "bearer".to_string(),
                token: Some("tenant-token-inherited".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/api/inherit-auth".to_string(),
                response: json!({"message": "This endpoint inherits tenant auth"}).to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                auth: None, // No override - should inherit tenant auth
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test that custom endpoint without auth override fails without authentication
    let response = server.get("/api/inherit-auth").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test that custom endpoint without auth override works with tenant token
    let response = server
        .get("/api/inherit-auth")
        .add_header("Authorization", "Bearer tenant-token-inherited")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"message": "This endpoint inherits tenant auth"})
    );

    // Test that custom endpoint fails with wrong token
    let response = server
        .get("/api/inherit-auth")
        .add_header("Authorization", "Bearer wrong-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}
