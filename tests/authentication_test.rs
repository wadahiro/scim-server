mod common;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use common::{create_test_user_json, setup_test_app};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, BasicAuthConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};
use tower::ServiceExt;

#[tokio::test]
async fn test_unauthenticated_access() {
    // Test unauthenticated auth type - should allow access without auth header
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
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Create a user without any Authorization header - should succeed
    let user_payload = create_test_user_json("alice", "Alice", "Smith");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_bearer_token_authentication_success() {
    // Test bearer token authentication - correct token should allow access
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
                token: Some("test-secret-token-123".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Create a user with correct Bearer token - should succeed
    let user_payload = create_test_user_json("bob", "Bob", "Johnson");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", "Bearer test-secret-token-123")
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_bearer_token_authentication_failure() {
    // Test bearer token authentication - wrong token should be rejected
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
                token: Some("test-secret-token-123".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Test with wrong token - should fail
    let user_payload = create_test_user_json("charlie", "Charlie", "Brown");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", "Bearer wrong-token")
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_token_missing_header() {
    // Test bearer token authentication - missing header should be rejected
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
                token: Some("test-secret-token-123".to_string()),
                basic: None,
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Test without Authorization header - should fail
    let user_payload = create_test_user_json("dave", "Dave", "Wilson");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_basic_authentication_success() {
    // Test HTTP Basic authentication - correct credentials should allow access
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
                basic: Some(BasicAuthConfig {
                    username: "testuser".to_string(),
                    password: "testpass".to_string(),
                }),
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Create a user with correct Basic auth - should succeed
    let user_payload = create_test_user_json("eve", "Eve", "Davis");

    // Encode "testuser:testpass" in base64
    use base64::{engine::general_purpose, Engine as _};
    let credentials = general_purpose::STANDARD.encode("testuser:testpass");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", format!("Basic {}", credentials))
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_basic_authentication_failure() {
    // Test HTTP Basic authentication - wrong credentials should be rejected
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
                basic: Some(BasicAuthConfig {
                    username: "testuser".to_string(),
                    password: "testpass".to_string(),
                }),
            },
            host: None,
            host_resolution: None,
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Test with wrong credentials - should fail
    let user_payload = create_test_user_json("frank", "Frank", "Miller");

    // Encode "wronguser:wrongpass" in base64
    use base64::{engine::general_purpose, Engine as _};
    let credentials = general_purpose::STANDARD.encode("wronguser:wrongpass");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", format!("Basic {}", credentials))
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_multi_tenant_authentication() {
    // Test that different tenants can have different authentication methods
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
                path: "/tenant-a/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "bearer".to_string(),
                    token: Some("tenant-a-token".to_string()),
                    basic: None,
                },
                host: None,
            host_resolution: None,
            override_base_url: None,
                custom_endpoints: vec![],
            compatibility: None,
            },
            TenantConfig {
                id: 2,
                path: "/tenant-b/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "basic".to_string(),
                    token: None,
                    basic: Some(BasicAuthConfig {
                        username: "tenant-b-user".to_string(),
                        password: "tenant-b-pass".to_string(),
                    }),
                },
                host: None,
            host_resolution: None,
            override_base_url: None,
                custom_endpoints: vec![],
            compatibility: None,
            },
        ],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Test tenant A with Bearer token
    let user_payload_a = create_test_user_json("alice-a", "Alice", "A");

    let request_a = Request::builder()
        .method(Method::POST)
        .uri("/tenant-a/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", "Bearer tenant-a-token")
        .body(Body::from(serde_json::to_string(&user_payload_a).unwrap()))
        .unwrap();

    let response_a = app.clone().oneshot(request_a).await.unwrap();
    assert_eq!(response_a.status(), StatusCode::CREATED);

    // Test tenant B with Basic auth
    let user_payload_b = create_test_user_json("bob-b", "Bob", "B");

    use base64::{engine::general_purpose, Engine as _};
    let credentials_b = general_purpose::STANDARD.encode("tenant-b-user:tenant-b-pass");

    let request_b = Request::builder()
        .method(Method::POST)
        .uri("/tenant-b/scim/v2/Users")
        .header("Content-Type", "application/scim+json")
        .header("Authorization", format!("Basic {}", credentials_b))
        .body(Body::from(serde_json::to_string(&user_payload_b).unwrap()))
        .unwrap();

    let response_b = app.oneshot(request_b).await.unwrap();
    assert_eq!(response_b.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_tenant_not_found() {
    // Test accessing non-existent tenant path
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
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let app = setup_test_app(app_config).await.unwrap();

    // Try to access non-existent tenant path - should fail
    let user_payload = create_test_user_json("ghost", "Ghost", "User");

    let request = Request::builder()
        .method(Method::POST)
        .uri("/nonexistent/v2/Users")
        .header("Content-Type", "application/scim+json")
        .body(Body::from(serde_json::to_string(&user_payload).unwrap()))
        .unwrap();

    let response = app.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
