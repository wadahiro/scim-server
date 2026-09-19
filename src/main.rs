use axum::middleware;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

mod app;
mod auth;
mod backend;
mod config;
mod error;
mod extractors;
mod logging;
mod models;
mod parser;
mod password;
mod resource;
mod schema;
mod startup;
mod utils;

use backend::database::DatabaseBackendConfig;
use backend::{BackendFactory, ScimBackend};
use config::AppConfig;

#[derive(Parser, Debug)]
#[command(name = "scim-server")]
#[command(about = "A SCIM 2.0 server implementation")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Args {
    /// Configuration file path
    #[arg(short, long)]
    config: Option<String>,

    /// Port to listen on (overrides config file)
    #[arg(short, long)]
    port: Option<u16>,

    /// Host to bind to (overrides config file)
    #[arg(long)]
    host: Option<String>,
}

async fn setup_backend(
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
            "postgresql" => backend::DatabaseType::PostgreSQL,
            "sqlite" => backend::DatabaseType::SQLite,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing for better debugging
    tracing_subscriber::fmt::init();

    // Load configuration from specified file or use defaults
    let (mut app_config, using_defaults) = if let Some(config_path) = &args.config {
        let config = AppConfig::load_from_file(config_path)
            .map_err(|e| format!("Failed to load configuration: {}", e))?;
        (config, false)
    } else {
        println!("⚠️  No configuration file specified, using default configuration:");
        println!("   - In-memory SQLite database");
        println!("   - Anonymous access (no authentication)");
        println!("   - Single tenant at /scim/v2");
        println!("   🚀 Perfect for development and testing!\n");
        (AppConfig::default_config(), true)
    };

    // Override with command line arguments if provided
    if let Some(port) = args.port {
        app_config.server.port = port;
    }
    if let Some(host) = args.host {
        app_config.server.host = host;
    }

    if !using_defaults {
        println!("🔧 Configuration loaded:");
        println!(
            "   Server: {}:{}",
            app_config.server.host, app_config.server.port
        );
        if let Some(db_config) = &app_config.backend.database {
            println!(
                "   Backend: database/{} ({})",
                db_config.db_type, db_config.url
            );
        } else {
            println!("   Backend: {}", app_config.backend.backend_type);
        }
        println!("   Tenants: {} configured", app_config.tenants.len());
    }

    // Setup backend
    let backend = setup_backend(&app_config).await?;

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
