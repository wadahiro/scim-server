use axum::{middleware, Router};
use scim_server::backend::database::DatabaseBackendConfig;
use scim_server::backend::{BackendFactory, DatabaseType, ScimBackend};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(test)]
use testcontainers::ContainerAsync;
#[cfg(test)]
use testcontainers_modules::postgres::Postgres;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
pub enum TestDatabaseType {
    Sqlite,
    Postgres,
}

#[allow(dead_code)]
pub struct TestDatabase {
    pub database_type: TestDatabaseType,
    #[cfg(test)]
    pub postgres_container: Option<ContainerAsync<Postgres>>,
}

/// Create backend for testing with in-memory SQLite database
pub async fn setup_test_database() -> Result<Arc<dyn ScimBackend>, Box<dyn std::error::Error>> {
    let backend_config = DatabaseBackendConfig {
        database_type: DatabaseType::SQLite,
        connection_path: ":memory:".to_string(),
        max_connections: 1,
        connection_timeout: 30,
        options: std::collections::HashMap::new(),
    };

    let backend = BackendFactory::create(&backend_config).await?;

    // Create tables for all tenants that tests use
    // Use standard tenant IDs that match the URL routing
    let tenant_ids = vec![1, 2, 3];
    for tenant_id in tenant_ids {
        backend.init_tenant(tenant_id).await?;
    }

    Ok(backend)
}

/// A real (not in-memory-transport) SCIM server bound to `127.0.0.1:0`, for
/// tests that need to speak actual HTTP -- currently only
/// `scim-diagnose`'s integration tests, which drive a real
/// `reqwest`-backed `scim_diagnose::ScimClient` rather than
/// `axum_test::TestServer`'s in-process transport.
///
/// Ported from `feat/rfc-extract`'s `tests/common/mod.rs`.
#[allow(dead_code)]
pub struct TestServerHandle {
    pub base_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

#[allow(dead_code)]
impl TestServerHandle {
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let _ = self.join.await;
    }
}

/// Spawns `app_config` behind a real listener on an OS-assigned port
/// (port 0, so parallel tests never collide).
///
/// Must use `into_make_service_with_connect_info::<SocketAddr>()`: the auth
/// middleware reads `ConnectInfo<SocketAddr>` (`src/auth.rs`), and without
/// it every request served through a real listener 500s.
#[allow(dead_code)]
pub async fn spawn_real_server(cfg: AppConfig) -> TestServerHandle {
    let backend = setup_test_database().await.unwrap();
    let app_config_arc = Arc::new(cfg);
    let router = scim_server::app::build_router(&app_config_arc)
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            rx.await.ok();
        })
        .await
        .unwrap();
    });
    TestServerHandle {
        base_url: format!("http://{addr}/scim/v2"),
        shutdown: Some(tx),
        join,
    }
}

/// Create backend for testing with PostgreSQL using TestContainers
#[cfg(test)]
#[allow(dead_code)]
pub async fn setup_postgres_test_database(
) -> Result<(Arc<dyn ScimBackend>, ContainerAsync<Postgres>), Box<dyn std::error::Error>> {
    use testcontainers::runners::AsyncRunner;

    let postgres_container = Postgres::default()
        .start()
        .await
        .expect("Failed to start postgres container");

    let connection_string = format!(
        "postgresql://postgres:postgres@127.0.0.1:{}/postgres",
        postgres_container.get_host_port_ipv4(5432).await?
    );

    let backend_config = DatabaseBackendConfig {
        database_type: DatabaseType::PostgreSQL,
        connection_path: connection_string,
        max_connections: 5,
        connection_timeout: 30,
        options: std::collections::HashMap::new(),
    };

    let backend = BackendFactory::create(&backend_config).await?;

    // Create tables for all tenants that tests use
    // Use standard tenant IDs that match the URL routing
    let tenant_ids = vec![1, 2, 3];
    for tenant_id in tenant_ids {
        backend.init_tenant(tenant_id).await?;
    }

    Ok((backend, postgres_container))
}

/// Create a test app with in-memory database and given tenant configuration
///
/// Route construction is shared with the production binary via
/// `scim_server::app::build_router`, so the two can never drift apart (see
/// that module for the route table, the custom-endpoint router, and the
/// RFC 7644 §3.12 fallback for unmatched paths).
pub async fn setup_test_app(app_config: AppConfig) -> Result<Router, Box<dyn std::error::Error>> {
    let backend = setup_test_database().await?;

    let app_config_arc = Arc::new(app_config.clone());

    let app = scim_server::app::build_router(&app_config)
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc));

    Ok(app)
}

/// Create a test app with PostgreSQL using TestContainers
#[cfg(test)]
#[allow(dead_code)]
pub async fn setup_postgres_test_app(
    app_config: AppConfig,
) -> Result<(Router, ContainerAsync<Postgres>), Box<dyn std::error::Error>> {
    let (backend, postgres_container) = setup_postgres_test_database().await?;

    let app_config_arc = Arc::new(app_config.clone());

    let app = scim_server::app::build_router(&app_config)
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc));

    Ok((app, postgres_container))
}

/// Unified setup function for any database type
#[allow(dead_code)]
pub async fn setup_test_app_with_db(
    app_config: AppConfig,
    db_type: TestDatabaseType,
) -> Result<(Router, TestDatabase), Box<dyn std::error::Error>> {
    match db_type {
        TestDatabaseType::Sqlite => {
            let app = setup_test_app(app_config).await?;
            Ok((
                app,
                TestDatabase {
                    database_type: TestDatabaseType::Sqlite,
                    #[cfg(test)]
                    postgres_container: None,
                },
            ))
        }
        TestDatabaseType::Postgres => {
            #[cfg(test)]
            {
                let (app, postgres_container) = setup_postgres_test_app(app_config).await?;
                Ok((
                    app,
                    TestDatabase {
                        database_type: TestDatabaseType::Postgres,
                        postgres_container: Some(postgres_container),
                    },
                ))
            }
            #[cfg(not(test))]
            {
                panic!("PostgreSQL test database setup requires test configuration")
            }
        }
    }
}

/// Helper function to create a test app configuration
#[allow(dead_code)]
pub fn create_test_app_config() -> AppConfig {
    AppConfig {
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
        tenants: vec![
            TenantConfig {
                id: 1,
                path: "/tenant-a/scim/v2".to_string(),
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
            },
            TenantConfig {
                id: 2,
                path: "/tenant-b/scim/v2".to_string(),
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
            },
            TenantConfig {
                id: 3,
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
            },
        ],
    }
}

/// Helper function to create a test user JSON payload
#[allow(dead_code)]
pub fn create_token_auth_config() -> AppConfig {
    AppConfig {
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
                auth_type: "token".to_string(),
                token: Some("test-token-123".to_string()),
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    }
}

#[allow(dead_code)]
pub fn create_bearer_auth_config() -> AppConfig {
    AppConfig {
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
                auth_type: "bearer".to_string(),
                token: Some("test-token-123".to_string()),
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    }
}

#[allow(dead_code)]
pub fn create_test_user_json(
    username: &str,
    given_name: &str,
    family_name: &str,
) -> serde_json::Value {
    json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username,
        "name": {
            "givenName": given_name,
            "familyName": family_name
        },
        "emails": [{
            "value": format!("{}@example.com", username),
            "primary": true
        }],
        "active": true
    })
}
