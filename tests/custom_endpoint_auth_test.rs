mod common;

use axum::http::StatusCode;
use axum_test::TestServer;
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, CustomEndpoint, DatabaseConfig,
    ServerConfig, TenantConfig,
};
use serde_json::json;

#[tokio::test]
async fn test_custom_endpoint_with_unauthenticated_access() {
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
                path: "/custom/health".to_string(),
                status_code: 200,
                content_type: "application/json".to_string(),
                response: "{\"status\":\"healthy\"}".to_string(),
                auth: None,
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test custom endpoint without authentication
    let response = server.get("/custom/health").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"status": "healthy"})
    );
}

#[tokio::test]
async fn test_custom_endpoint_with_bearer_auth() {
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
                token: Some("test-token-123".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/api/status".to_string(),
                status_code: 200,
                content_type: "text/plain".to_string(),
                response: "Service is running".to_string(),
                auth: None,
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test custom endpoint without authentication - should fail
    let response = server.get("/api/status").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test with correct Bearer token
    let response = server
        .get("/api/status")
        .add_header("Authorization", "Bearer test-token-123")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "Service is running");

    // Test with incorrect Bearer token
    let response = server
        .get("/api/status")
        .add_header("Authorization", "Bearer wrong-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_custom_endpoint_with_basic_auth() {
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
                auth_type: "basic".to_string(),
                token: None,
                basic: Some(scim_server::config::BasicAuthConfig {
                    username: "admin".to_string(),
                    password: "secret123".to_string(),
                }),
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![CustomEndpoint {
                path: "/metrics".to_string(),
                status_code: 200,
                content_type: "text/plain".to_string(),
                response: "requests_total 42".to_string(),
                auth: None,
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test without authentication
    let response = server.get("/metrics").await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);

    // Test with correct Basic auth
    use base64::{engine::general_purpose, Engine as _};
    let auth = general_purpose::STANDARD.encode("admin:secret123");
    let response = server
        .get("/metrics")
        .add_header("Authorization", format!("Basic {}", auth))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(response.text(), "requests_total 42");

    // Test with incorrect credentials
    let wrong_auth = general_purpose::STANDARD.encode("admin:wrongpass");
    let response = server
        .get("/metrics")
        .add_header("Authorization", format!("Basic {}", wrong_auth))
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_multiple_tenants_with_custom_endpoints() {
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
                    auth_type: "bearer".to_string(),
                    token: Some("tenant1-token".to_string()),
                    basic: None,
                },
                host: None,
                host_resolution: None,
                override_base_url: None,
                custom_endpoints: vec![CustomEndpoint {
                    path: "/tenant1/status".to_string(),
                    status_code: 200,
                    content_type: "application/json".to_string(),
                    response: "{\"tenant\":\"1\",\"status\":\"ok\"}".to_string(),
                    auth: None,
                }],
                compatibility: None,
            },
            TenantConfig {
                id: 2,
                path: "/tenant2/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "bearer".to_string(),
                    token: Some("tenant2-token".to_string()),
                    basic: None,
                },
                host: None,
                host_resolution: None,
                override_base_url: None,
                custom_endpoints: vec![CustomEndpoint {
                    path: "/tenant2/status".to_string(),
                    status_code: 200,
                    content_type: "application/json".to_string(),
                    response: "{\"tenant\":\"2\",\"status\":\"ok\"}".to_string(),
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

    // Test tenant1 custom endpoint with tenant1 token
    let response = server
        .get("/tenant1/status")
        .add_header("Authorization", "Bearer tenant1-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"tenant":"1","status":"ok"})
    );

    // Test tenant2 custom endpoint with tenant2 token
    let response = server
        .get("/tenant2/status")
        .add_header("Authorization", "Bearer tenant2-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.json::<serde_json::Value>(),
        json!({"tenant":"2","status":"ok"})
    );

    // Test tenant1 endpoint with tenant2 token - should fail
    let response = server
        .get("/tenant1/status")
        .add_header("Authorization", "Bearer tenant2-token")
        .await;
    assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_custom_endpoint_not_found() {
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
                path: "/custom/test".to_string(),
                status_code: 200,
                content_type: "text/plain".to_string(),
                response: "test".to_string(),
                auth: None,
            }],
            compatibility: None,
        }],
    };

    let (app, _) = common::setup_test_app_with_db(app_config, common::TestDatabaseType::Sqlite)
        .await
        .expect("Failed to create test app");
    let server = TestServer::new(app).unwrap();

    // Test non-existent custom endpoint should still get "Tenant not found" error
    // because it's not a registered custom endpoint
    let response = server.get("/custom/nonexistent").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    let error = response.json::<serde_json::Value>();
    assert!(error["message"]
        .as_str()
        .unwrap()
        .contains("Tenant not found"));
}
