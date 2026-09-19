//! Top-level CLI: bare-flag `serve` (the container's default entrypoint
//! behaviour) plus the `diagnose` subcommand.
//!
//! This lives in the lib crate — not `src/main.rs` — specifically so
//! integration tests (which link the lib, not the bin) can construct a
//! [`Cli`] and assert on its parsing (see `tests/diagnose_self_test.rs`'s
//! `cli_backward_compat`, the regression guard for the container contract
//! in `Dockerfile`/`docker-compose.yml`). `main.rs` just parses and
//! dispatches.

use std::process::ExitCode;

use crate::config::AppConfig;
use crate::diag;
use crate::diag::cli::DiagnoseArgs;

#[derive(clap::Parser, Debug)]
#[command(
    name = "scim-server",
    version = env!("CARGO_PKG_VERSION"),
    about = "A SCIM 2.0 server implementation",
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
    #[command(flatten)]
    pub serve: ServeArgs,
}

#[derive(clap::Args, Debug, Default, Clone)]
pub struct ServeArgs {
    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<String>,
    /// Port to listen on (overrides config file)
    #[arg(short, long)]
    pub port: Option<u16>,
    /// Host to bind to (overrides config file)
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    /// Start the SCIM server (explicit form of the default behaviour)
    Serve(ServeArgs),
    /// Probe an external SCIM 2.0 server for conformance and known quirks
    // Boxed (clippy::large_enum_variant): DiagnoseArgs is much larger than
    // ServeArgs, so this keeps every Command match/move from paying for the
    // bigger variant's size. A `//` comment, not `///`: clap-derive turns
    // doc comments into the subcommand's `--help` text, and this note isn't
    // user-facing.
    Diagnose(Box<DiagnoseArgs>),
}

/// Parses `Cli` and dispatches to the right entry point. `main.rs` calls
/// this directly.
pub async fn run(cli: Cli) -> ExitCode {
    match cli.command {
        Some(Command::Diagnose(args)) => diag_main(*args).await,
        Some(Command::Serve(a)) => serve_main(a).await,
        None => serve_main(cli.serve).await,
    }
}

pub async fn diag_main(args: DiagnoseArgs) -> ExitCode {
    let opts = match diag::cli::into_options(args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    match diag::run(&opts).await {
        Ok(report) => {
            let text = diag::render::render(&report, opts.format, opts.emit_config_snippet);
            match &opts.output {
                Some(p) => {
                    if let Err(e) = std::fs::write(p, &text) {
                        eprintln!("error: {}: {e}", p.display());
                        return ExitCode::from(2);
                    }
                }
                None => {
                    // Colorizing only makes sense for the `[ OK  ]`-style
                    // tags `render::text` emits — `render::markdown` uses
                    // bare words in table cells, so `style::apply` would be
                    // a harmless no-op there anyway, but skip it explicitly
                    // rather than rely on that.
                    if opts.format == diag::cli::Format::Text
                        && diag::render::style::enabled(opts.quiet, opts.output.is_some())
                    {
                        println!("{}", diag::render::style::apply(&text));
                    } else {
                        println!("{text}");
                    }
                }
            }
            // Cleanup can leave leftovers on the ordinary completion path
            // too (not just the interrupted/panicked one below) — a
            // `Report` still gets built, `exit_code()` already returns 3
            // for it, but nothing else prints the operator-facing
            // "here's what's left, here's how to retry" block unless we
            // do it here.
            if let Some(cleanup) = &report.cleanup {
                if !cleanup.failures.is_empty() {
                    eprintln!(
                        "{}",
                        diag::fixtures::cleanup_incomplete_block(
                            cleanup,
                            &opts.base_url,
                            &opts.prefix
                        )
                    );
                }
            }
            ExitCode::from(report.exit_code())
        }
        Err(e @ diag::DiagError::CleanupIncomplete { .. }) => {
            eprintln!("{e}");
            ExitCode::from(3)
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

pub async fn serve_main(args: ServeArgs) -> ExitCode {
    // Load configuration from specified file or use defaults
    let (mut app_config, using_defaults) = if let Some(config_path) = &args.config {
        match AppConfig::load_from_file(config_path) {
            Ok(config) => (config, false),
            Err(e) => {
                eprintln!("Failed to load configuration: {e}");
                return ExitCode::from(1);
            }
        }
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

    match crate::serve::serve(app_config).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::from(1)
        }
    }
}
