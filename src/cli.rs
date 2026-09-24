//! CLI argument shape for the `scim-server` binary, kept in the library
//! crate (rather than `src/main.rs`, which is a separate binary crate
//! target with its own private module tree) so integration tests can
//! parse it in-process with `Args::try_parse_from` -- no subprocess, no
//! I/O -- to guard against the CLI accidentally breaking its existing
//! no-subcommand serve behavior.
//!
//! `main.rs` does the actual work (`run_diagnose`): building a client,
//! sending requests, writing files, calling `std::process::exit`. None of
//! that belongs in a library crate a test links against, so only the pure,
//! side-effect-free pieces -- the argument shapes and
//! [`DiagnoseArgs::to_diag_options`]'s validation -- live here.
//!
//! Ported and adapted from `feat/rfc-extract`'s `src/cli.rs`: the
//! auth/TLS argument set is taken essentially as-is. `--format` and
//! `--allow-writes` land here, alongside `scim_diagnose::runner`'s
//! cost/capability-gated axis runner; `--emit-config` lands in the next
//! commit alongside the seven axes it has something to emit for.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "scim-server")]
#[command(about = "A SCIM 2.0 server implementation")]
#[command(version = env!("CARGO_PKG_VERSION"))]
pub struct Args {
    /// Run the scim-diagnose tool against a live SCIM server instead of
    /// serving. Omitting this keeps today's exact serve behavior (see
    /// `tests/conformance_cli_backward_compat.rs`).
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
    /// Runs `scim-diagnose` against a live SCIM server and prints its
    /// behavioural profile. Until the next commit lands the seven axes,
    /// every axis reports itself as not yet implemented -- see
    /// `scim_diagnose::axes`'s module docs.
    Diagnose(DiagnoseArgs),
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthKind {
    None,
    Bearer,
    Token,
    Basic,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
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

    /// Output shape: human-readable text, or the stable/diffable JSON
    /// profile (`scim_diagnose::profile_json`).
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Opt into the axes that need write access (`Cost::NeedsUser` /
    /// `Cost::NeedsUserAndGroup`): creating a User, a Group, or both.
    /// Without this flag, only discovery-only axes are observed and the
    /// rest report `Unobservable::NeedsWrite` -- never silently omitted.
    /// Creating a User against a production tenant may send real email to
    /// a real person, so this is opt-in.
    #[arg(long)]
    pub allow_writes: bool,

    /// Per-request timeout, in seconds.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,

    /// Write the report to this file instead of stdout.
    #[arg(short = 'o', long)]
    pub output: Option<PathBuf>,

    /// With --output, suppress the "report written to <path>" line printed
    /// after the report is saved.
    #[arg(short = 'q', long)]
    pub quiet: bool,
}

impl DiagnoseArgs {
    /// Validates the `--auth`/`--token`/`--username`/`--password` pairing
    /// and the "Name: Value" shape of every `--header`, then builds the
    /// `scim_diagnose` options this reduces to. Returns a one-line,
    /// user-facing message on failure (the binary prints it and exits with
    /// status 2 -- a CLI usage error).
    pub fn to_diag_options(&self) -> Result<scim_diagnose::DiagOptions, String> {
        let auth = match self.auth {
            AuthKind::None => scim_diagnose::Auth::None,
            AuthKind::Bearer => scim_diagnose::Auth::Bearer(
                self.token.clone().ok_or("--auth bearer requires --token")?,
            ),
            AuthKind::Token => scim_diagnose::Auth::Token(
                self.token.clone().ok_or("--auth token requires --token")?,
            ),
            AuthKind::Basic => scim_diagnose::Auth::Basic {
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

        Ok(scim_diagnose::DiagOptions {
            base_url: self.base_url.clone(),
            auth,
            headers,
            insecure: self.insecure,
            ca_certs: self.ca_certs.clone(),
            native_roots: self.native_roots,
            timeout_secs: self.timeout,
            allow_writes: self.allow_writes,
        })
    }
}
