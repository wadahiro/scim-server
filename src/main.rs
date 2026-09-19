use clap::Parser;

use scim_server::cli::Cli;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Initialize tracing for better debugging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    scim_server::cli::run(cli).await
}
