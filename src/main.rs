use clap::Parser;
use scim_server::config::AppConfig;
use scim_server::serve;

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

    serve::serve(app_config).await
}
