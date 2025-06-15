use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use scim_server::backend::database::DatabaseBackendConfig;
use scim_server::backend::{BackendFactory, DatabaseType, ScimBackend};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};
use serde_json::json;
use std::sync::Arc;
#[cfg(test)]
use testcontainers::ContainerAsync;
#[cfg(test)]
use testcontainers_modules::postgres::Postgres;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestDatabaseType {
    Sqlite,
    Postgres,
}

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

/// Create backend for testing with PostgreSQL using TestContainers
#[cfg(test)]
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
pub async fn setup_test_app(app_config: AppConfig) -> Result<Router, Box<dyn std::error::Error>> {
    let backend = setup_test_database().await?;

    let app_config_arc = Arc::new(app_config.clone());

    // Build our application with multi-tenant routes based on tenant configuration
    let mut app = Router::new();

    // Add custom endpoints first (before SCIM routes)
    for tenant in &app_config.tenants {
        for endpoint in &tenant.custom_endpoints {
            app = app.route(
                &endpoint.path,
                get(scim_server::resource::custom::handle_custom_endpoint),
            );
        }
    }

    // Add routes for each tenant based on their configured URL path
    for tenant in &app_config.tenants {
        // Extract path from tenant path (remove protocol and host if present)
        let base_path = if tenant.path.starts_with("http://") || tenant.path.starts_with("https://")
        {
            // Extract path from full URL
            if let Ok(url) = Url::parse(&tenant.path) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            // Already a path
            tenant.path.trim_end_matches('/').to_string()
        };

        // ServiceProviderConfig routes
        app = app.route(
            &format!("{}/ServiceProviderConfig", base_path),
            get(scim_server::resource::service_provider::service_provider_config),
        );

        // Schema and ResourceType routes
        app = app.route(
            &format!("{}/Schemas", base_path),
            get(scim_server::resource::schema::schemas),
        );
        app = app.route(
            &format!("{}/ResourceTypes", base_path),
            get(scim_server::resource::resource_type::resource_types),
        );

        // User routes
        app = app.route(
            &format!("{}/Users", base_path),
            post(scim_server::resource::user::create_user),
        );
        app = app.route(
            &format!("{}/Users", base_path),
            get(scim_server::resource::user::search_users),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            get(scim_server::resource::user::get_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            put(scim_server::resource::user::update_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            patch(scim_server::resource::user::patch_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            delete(scim_server::resource::user::delete_user),
        );

        // Group routes
        app = app.route(
            &format!("{}/Groups", base_path),
            post(scim_server::resource::group::create_group),
        );
        app = app.route(
            &format!("{}/Groups", base_path),
            get(scim_server::resource::group::search_groups),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            get(scim_server::resource::group::get_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            put(scim_server::resource::group::update_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            patch(scim_server::resource::group::patch_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            delete(scim_server::resource::group::delete_group),
        );
    }

    let app = app
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc));

    Ok(app)
}

/// Create a test app with PostgreSQL using TestContainers
#[cfg(test)]
pub async fn setup_postgres_test_app(
    app_config: AppConfig,
) -> Result<(Router, ContainerAsync<Postgres>), Box<dyn std::error::Error>> {
    let (backend, postgres_container) = setup_postgres_test_database().await?;

    let app_config_arc = Arc::new(app_config.clone());

    // Build our application with multi-tenant routes based on tenant configuration
    let mut app = Router::new();

    // Add custom endpoints first (before SCIM routes)
    for tenant in &app_config.tenants {
        for endpoint in &tenant.custom_endpoints {
            app = app.route(
                &endpoint.path,
                get(scim_server::resource::custom::handle_custom_endpoint),
            );
        }
    }

    // Add routes for each tenant based on their configured URL path
    for tenant in &app_config.tenants {
        // Extract path from tenant path (remove protocol and host if present)
        let base_path = if tenant.path.starts_with("http://") || tenant.path.starts_with("https://")
        {
            // Extract path from full URL
            if let Ok(url) = Url::parse(&tenant.path) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            // Already a path
            tenant.path.trim_end_matches('/').to_string()
        };

        // ServiceProviderConfig routes
        app = app.route(
            &format!("{}/ServiceProviderConfig", base_path),
            get(scim_server::resource::service_provider::service_provider_config),
        );

        // Schema and ResourceType routes
        app = app.route(
            &format!("{}/Schemas", base_path),
            get(scim_server::resource::schema::schemas),
        );
        app = app.route(
            &format!("{}/ResourceTypes", base_path),
            get(scim_server::resource::resource_type::resource_types),
        );

        // User routes
        app = app.route(
            &format!("{}/Users", base_path),
            post(scim_server::resource::user::create_user),
        );
        app = app.route(
            &format!("{}/Users", base_path),
            get(scim_server::resource::user::search_users),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            get(scim_server::resource::user::get_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            put(scim_server::resource::user::update_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            patch(scim_server::resource::user::patch_user),
        );
        app = app.route(
            &format!("{}/Users/{{id}}", base_path),
            delete(scim_server::resource::user::delete_user),
        );

        // Group routes
        app = app.route(
            &format!("{}/Groups", base_path),
            post(scim_server::resource::group::create_group),
        );
        app = app.route(
            &format!("{}/Groups", base_path),
            get(scim_server::resource::group::search_groups),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            get(scim_server::resource::group::get_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            put(scim_server::resource::group::update_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            patch(scim_server::resource::group::patch_group),
        );
        app = app.route(
            &format!("{}/Groups/{{id}}", base_path),
            delete(scim_server::resource::group::delete_group),
        );
    }

    let app = app
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc));

    Ok((app, postgres_container))
}

/// Unified setup function for any database type
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
