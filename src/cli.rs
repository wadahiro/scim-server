//! CLI argument shape for the `scim-server` binary, kept in the library
//! crate (rather than `src/main.rs`, which is a separate binary crate
//! target with its own private module tree) so integration tests can
//! parse it in-process with `Args::try_parse_from` -- no subprocess, no
//! I/O -- to guard against the CLI accidentally breaking its existing
//! no-subcommand serve behavior (`tests/conformance_cli_backward_compat.rs`).
//!
//! `main.rs` does the actual work (`run_diagnose`): building a client,
//! sending requests, writing files, calling `std::process::exit`. None of
//! that belongs in a library crate a test links against, so only the pure,
//! side-effect-free pieces -- the argument shapes and
//! [`DiagnoseArgs::to_diag_options`]'s validation -- live here.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scim-server")]
#[command(about = "A SCIM 2.0 server implementation")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// Run RFC 7643/7644 conformance checks against a live SCIM server
    /// instead of serving. Omitting this keeps today's exact serve
    /// behavior (see `tests/conformance_cli_backward_compat.rs`).
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Configuration file path
    #[arg(short, long)]
    pub config: Option<String>,

    /// Port to listen on (overrides config file)
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Host to bind to (overrides config file)
    #[arg(long)]
    pub host: Option<String>,

    /// Validate the configuration and exit without starting the server (no
    /// database file or tables are created, no port is bound). With no -c,
    /// validates the built-in zero-config defaults.
    #[arg(long)]
    pub validate: bool,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run the RFC 7643/7644 conformance checks in `scim-conformance`
    /// against a live SCIM server and print a report citing the RFC
    /// section and raw-file line range behind every finding.
    Diagnose(DiagnoseArgs),
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    None,
    Bearer,
    Token,
    Basic,
}

#[derive(clap::Args, Debug)]
pub struct DiagnoseArgs {
    /// Base URL of the tenant to diagnose, e.g.
    /// http://127.0.0.1:3000/scim/v2
    pub base_url: String,

    /// How to authenticate against the target tenant.
    #[arg(long, value_enum, default_value_t = AuthKind::None)]
    pub auth: AuthKind,

    /// Bearer/Token credential (required by --auth bearer / --auth token).
    #[arg(long)]
    pub token: Option<String>,

    /// Basic auth username (required by --auth basic).
    #[arg(long)]
    pub username: Option<String>,

    /// Basic auth password (required by --auth basic).
    #[arg(long)]
    pub password: Option<String>,

    /// Extra header to send on every request, "Name: Value". Repeatable.
    #[arg(long = "header", value_name = "Name: Value")]
    pub headers: Vec<String>,

    /// Skip TLS certificate verification entirely.
    #[arg(long)]
    pub insecure: bool,

    /// Additional PEM CA certificate to trust. Repeatable.
    #[arg(long = "ca-cert", value_name = "PATH")]
    pub ca_certs: Vec<PathBuf>,

    /// Also trust the OS's native certificate store (off by default).
    #[arg(long)]
    pub native_roots: bool,

    /// Only run checks reachable via GET -- skip every check family that
    /// creates, mutates, or deletes fixtures (see `DiagOptions::read_only`
    /// in `scim-conformance` for exactly what that excludes).
    #[arg(long)]
    pub read_only: bool,

    /// Per-request timeout, in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Write the report to this file instead of stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// Show full detail for every finding, not just FAIL/ERROR.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// With --output, suppress the "report written to <path>" line printed
    /// after the report is saved (the report itself is always written;
    /// this only silences that one confirmation line, not the report body
    /// -- there is no report body on stdout to suppress when --output is
    /// used at all).
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

impl DiagnoseArgs {
    /// Validates the `--auth`/`--token`/`--username`/`--password` pairing
    /// and the "Name: Value" shape of every `--header`, then builds the
    /// `scim-conformance` options this reduces to. Returns a one-line,
    /// user-facing message on failure (the binary prints it and exits with
    /// status 2 -- a CLI usage error, distinct from a failed diagnose
    /// run's exit 1).
    pub fn to_diag_options(&self) -> Result<scim_conformance::DiagOptions, String> {
        let auth = match self.auth {
            AuthKind::None => scim_conformance::Auth::None,
            AuthKind::Bearer => scim_conformance::Auth::Bearer(
                self.token.clone().ok_or("--auth bearer requires --token")?,
            ),
            AuthKind::Token => scim_conformance::Auth::Token(
                self.token.clone().ok_or("--auth token requires --token")?,
            ),
            AuthKind::Basic => scim_conformance::Auth::Basic {
                username: self
                    .username
                    .clone()
                    .ok_or("--auth basic requires --username")?,
                password: self
                    .password
                    .clone()
                    .ok_or("--auth basic requires --password")?,
            },
        };

        let mut headers = Vec::with_capacity(self.headers.len());
        for h in &self.headers {
            let (name, value) = h
                .split_once(':')
                .ok_or_else(|| format!("--header {h:?} must be \"Name: Value\""))?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }

        Ok(scim_conformance::DiagOptions {
            base_url: self.base_url.clone(),
            auth,
            headers,
            insecure: self.insecure,
            ca_certs: self.ca_certs.clone(),
            native_roots: self.native_roots,
            timeout_secs: self.timeout,
            read_only: self.read_only,
        })
    }
}
