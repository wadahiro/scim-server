use axum::middleware;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::backend::database::DatabaseBackendConfig;
use crate::backend::{BackendFactory, ScimBackend};
use crate::config::AppConfig;
use crate::{app, auth, logging};

/// Builds the backend from the app configuration and initializes every
/// tenant's schema. Combines the former `main.rs::setup_backend` and
/// `startup.rs::initialize_tenant_schemas`.
pub async fn build_backend(
    app_config: &AppConfig,
) -> Result<Arc<dyn ScimBackend>, Box<dyn std::error::Error>> {
    // Create backend configuration from app config
    if app_config.backend.backend_type != "database" {
        return Err(format!(
            "Unsupported backend type: {}",
            app_config.backend.backend_type
        )
        .into());
    }

    let database_config = app_config
        .backend
        .database
        .as_ref()
        .ok_or("Database configuration is required when backend type is 'database'")?;

    let backend_config = DatabaseBackendConfig {
        database_type: match database_config.db_type.as_str() {
            "postgresql" => crate::backend::DatabaseType::PostgreSQL,
            "sqlite" => crate::backend::DatabaseType::SQLite,
            _ => {
                return Err(
                    format!("Unsupported database type: {}", database_config.db_type).into(),
                )
            }
        },
        connection_path: database_config.url.clone(),
        max_connections: database_config.max_connections,
        connection_timeout: 30,
        options: std::collections::HashMap::new(),
    };

    println!("Setting up {} backend...", database_config.db_type);

    // Create backend instance
    let backend = BackendFactory::create(&backend_config).await?;

    // Initialize tenant schemas using the same backend instance
    for tenant in &app_config.tenants {
        backend.init_tenant(tenant.id).await?;
        println!("✅ Initialized backend for tenant: {}", tenant.id);
    }

    Ok(backend)
}

/// Sets up the backend, builds the router, binds the listener, and runs the server
/// until a shutdown signal is received (graceful shutdown).
pub async fn serve(app_config: AppConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Setup backend
    let backend = build_backend(&app_config).await?;

    // Use AppConfig directly
    let app_config_arc = Arc::new(app_config.clone());

    // Build our application with multi-tenant routes. Route construction
    // (including the custom-endpoint router, the SCIM content-type layer,
    // and the RFC 7644 §3.12 fallback) lives in `app::build_router` so the
    // production binary and the integration tests can never drift apart.
    for tenant in &app_config.tenants {
        if tenant.host.is_some() {
            println!(
                "🔧 Setting up host-based routing for tenant {} (host: {})",
                tenant.id,
                tenant.host.as_ref().unwrap_or(&"unspecified".to_string())
            );
        } else {
            println!(
                "🔗 Setting up path-only routes for tenant {} at {}",
                tenant.id, tenant.path
            );
        }
        for endpoint in &tenant.custom_endpoints {
            println!(
                "🔗 Setting up custom endpoint for tenant {} at {}",
                tenant.id, endpoint.path
            );
        }
    }

    let app = app::build_router(&app_config)
        .layer(middleware::from_fn(logging::logging_middleware))
        .layer(middleware::from_fn_with_state(
            app_config_arc.clone(),
            auth::auth_middleware,
        ))
        .with_state((backend, app_config_arc.clone()));

    // Start the server
    let host: std::net::IpAddr = app_config.server.host.parse().unwrap_or_else(|_| {
        eprintln!(
            "Invalid host address: {}, using 127.0.0.1",
            app_config.server.host
        );
        [127, 0, 0, 1].into()
    });
    let addr = SocketAddr::from((host, app_config.server.port));

    // Display version and server info
    println!("🚀 SCIM Server v{}", env!("CARGO_PKG_VERSION"));
    println!("📍 Listening on {}", addr);
    println!("🏢 Configured tenants:");
    for (index, tenant) in app_config.get_all_tenants().iter().enumerate() {
        println!("  - Tenant {} (Path: {}):", index + 1, tenant.path);

        // Display authentication info based on type
        match tenant.auth.auth_type.as_str() {
            "bearer" => {
                if let Some(token) = &tenant.auth.token {
                    println!(
                        "    🔒 Authentication: Bearer Token (***{})",
                        &token[token.len().saturating_sub(3)..]
                    );
                }
            }
            "token" => {
                if let Some(token) = &tenant.auth.token {
                    println!(
                        "    🔒 Authentication: Token (***{})",
                        &token[token.len().saturating_sub(3)..]
                    );
                }
            }
            "basic" => {
                if let Some(basic) = &tenant.auth.basic {
                    println!(
                        "    🔒 Authentication: HTTP Basic (user: {})",
                        basic.username
                    );
                }
            }
            "unauthenticated" => {
                println!("    🔓 Authentication: Anonymous access (no authentication required)");
            }
            _ => {
                println!(
                    "    🔒 Authentication: Unknown type ({})",
                    tenant.auth.auth_type
                );
            }
        }

        println!(
            "    📖 ServiceProviderConfig: {}/ServiceProviderConfig",
            tenant.path
        );
        println!("    📋 Schemas: {}/Schemas", tenant.path);
        println!("    🏷️ ResourceTypes: {}/ResourceTypes", tenant.path);
        println!("    👥 Users: {}/Users", tenant.path);
        println!("    👥 Groups: {}/Groups", tenant.path);

        // Display custom endpoints if any
        if !tenant.custom_endpoints.is_empty() {
            println!("    🎯 Custom endpoints:");
            for endpoint in &tenant.custom_endpoints {
                println!("      - {} ({})", endpoint.path, endpoint.content_type);
            }
        }
    }

    let listener = TcpListener::bind(&addr).await?;

    // Enable graceful shutdown with proper cleanup
    let shutdown_future = shutdown_signal();
    let server_future = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_future);

    // Run server and handle shutdown
    let result = server_future.await;

    // Perform cleanup
    println!("🧹 Performing cleanup...");

    // Note: Backend cleanup would be implemented here if needed
    // Currently SQLite/PostgreSQL connections are automatically cleaned up
    // when the connection pools are dropped

    println!("✅ Cleanup completed, server stopped");

    result?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            println!("\n📛 Received Ctrl+C, initiating graceful shutdown...");
        },
        _ = terminate => {
            println!("\n📛 Received SIGTERM, initiating graceful shutdown...");
        },
    }
}
