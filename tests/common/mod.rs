use axum::{
    middleware,
    routing::{delete, get, patch, post, put},
    Router,
};
use scim_server::backend::{ScimBackend, BackendFactory, DatabaseType};
use scim_server::backend::database::DatabaseBackendConfig;
use scim_server::config::{AppConfig, TenantConfig, AuthConfig, ServerConfig, BackendConfig, DatabaseConfig};
use serde_json::json;
use std::sync::Arc;
#[cfg(test)]
use testcontainers::Container;
#[cfg(test)]
use testcontainers_modules::postgres::Postgres;


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TestDatabaseType {
    Sqlite,
    Postgres,
}

pub struct TestDatabase {
    pub database_type: TestDatabaseType,
    #[cfg(test)]
    pub postgres_container: Option<Container<'static, Postgres>>,
}

/// Create backend for testing with in-memory SQLite database
pub async fn setup_test_database() -> Result<Arc<dyn ScimBackend>, Box<dyn std::error::Error>> {
    let backend_config = DatabaseBackendConfig {
        database_type: DatabaseType::SQLite,
        connection_url: ":memory:".to_string(),
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
pub async fn setup_postgres_test_database() -> Result<(Arc<dyn ScimBackend>, Container<'static, Postgres>), Box<dyn std::error::Error>> {
    use testcontainers::clients::Cli;
    
    let docker = Box::leak(Box::new(Cli::default()));
    let postgres_container = docker.run(Postgres::default());
    
    let connection_string = format!(
        "postgresql://postgres:postgres@127.0.0.1:{}/postgres",
        postgres_container.get_host_port_ipv4(5432)
    );
    
    let backend_config = DatabaseBackendConfig {
        database_type: DatabaseType::PostgreSQL,
        connection_url: connection_string,
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
pub async fn setup_test_app(
    app_config: AppConfig,
) -> Result<Router, Box<dyn std::error::Error>> {
    let backend = setup_test_database().await?;
    
    let app_config_arc = Arc::new(app_config.clone());

    // Build our application with multi-tenant routes based on tenant configuration
    let mut app = Router::new();
    
    // Add routes for each tenant based on their configured URL path
    for tenant in &app_config.tenants {
        // Extract path from tenant URL (remove protocol and host if present)
        let base_path = if tenant.url.starts_with("http://") || tenant.url.starts_with("https://") {
            // Extract path from full URL
            if let Ok(url) = url::Url::parse(&tenant.url) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            // Already a path
            tenant.url.trim_end_matches('/').to_string()
        };
        
        // ServiceProviderConfig routes
        app = app.route(
            &format!("{}/ServiceProviderConfig", base_path),
            get(scim_server::resource::service_provider::service_provider_config),
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
            &format!("{}/Users/:id", base_path),
            get(scim_server::resource::user::get_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
            put(scim_server::resource::user::update_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
            patch(scim_server::resource::user::patch_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
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
            &format!("{}/Groups/:id", base_path),
            get(scim_server::resource::group::get_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            put(scim_server::resource::group::update_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            patch(scim_server::resource::group::patch_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            delete(scim_server::resource::group::delete_group),
        );
    }
    
    let app = app
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, Arc::new("http://localhost:3000".to_string()), app_config_arc));

    Ok(app)
}

/// Create a test app with PostgreSQL using TestContainers
#[cfg(test)]
pub async fn setup_postgres_test_app(
    app_config: AppConfig,
) -> Result<(Router, Container<'static, Postgres>), Box<dyn std::error::Error>> {
    let (backend, postgres_container) = setup_postgres_test_database().await?;
    
    let app_config_arc = Arc::new(app_config.clone());

    // Build our application with multi-tenant routes based on tenant configuration
    let mut app = Router::new();
    
    // Add routes for each tenant based on their configured URL path
    for tenant in &app_config.tenants {
        // Extract path from tenant URL (remove protocol and host if present)
        let base_path = if tenant.url.starts_with("http://") || tenant.url.starts_with("https://") {
            // Extract path from full URL
            if let Ok(url) = url::Url::parse(&tenant.url) {
                url.path().trim_end_matches('/').to_string()
            } else {
                "/scim".to_string() // fallback
            }
        } else {
            // Already a path
            tenant.url.trim_end_matches('/').to_string()
        };
        
        // ServiceProviderConfig routes
        app = app.route(
            &format!("{}/ServiceProviderConfig", base_path),
            get(scim_server::resource::service_provider::service_provider_config),
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
            &format!("{}/Users/:id", base_path),
            get(scim_server::resource::user::get_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
            put(scim_server::resource::user::update_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
            patch(scim_server::resource::user::patch_user),
        );
        app = app.route(
            &format!("{}/Users/:id", base_path),
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
            &format!("{}/Groups/:id", base_path),
            get(scim_server::resource::group::get_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            put(scim_server::resource::group::update_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            patch(scim_server::resource::group::patch_group),
        );
        app = app.route(
            &format!("{}/Groups/:id", base_path),
            delete(scim_server::resource::group::delete_group),
        );
    }
    
    let app = app
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            scim_server::auth::auth_middleware,
        ))
        .with_state((backend, Arc::new("http://localhost:3000".to_string()), app_config_arc));

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
            Ok((app, TestDatabase {
                database_type: TestDatabaseType::Sqlite,
                #[cfg(test)]
                postgres_container: None,
            }))
        }
        TestDatabaseType::Postgres => {
            #[cfg(test)]
            {
                let (app, postgres_container) = setup_postgres_test_app(app_config).await?;
                Ok((app, TestDatabase {
                    database_type: TestDatabaseType::Postgres,
                    postgres_container: Some(postgres_container),
                }))
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
        tenants: vec![
            TenantConfig {
                id: 1,
                url: "/tenant-a/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host_resolution: None,
            },
            TenantConfig {
                id: 2,
                url: "/tenant-b/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host_resolution: None,
            },
            TenantConfig {
                id: 3,
                url: "/scim/v2".to_string(),
                auth: AuthConfig {
                    auth_type: "unauthenticated".to_string(),
                    token: None,
                    basic: None,
                },
                host_resolution: None,
            },
        ],
    }
}

/// Helper function to create a test user JSON payload
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
