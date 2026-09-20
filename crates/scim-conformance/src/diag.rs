//! T11: the CLI-facing entry point. Builds a [`crate::ScimClient`] from a
//! [`DiagOptions`], preflights it with a single `GET
//! /ServiceProviderConfig` (refusing to run any check at all against a
//! target that doesn't even answer that, or that rejects it with 401/403),
//! and then runs the full generated-check suite (or, for `--read-only`, a
//! GET-only subset -- see [`DiagOptions::read_only`]).

use std::path::PathBuf;
use std::time::Duration;

use crate::client::{self, ClientConfig, ClientExtra, ScimClient};
use crate::report::{Counts, DiagnosticReport, Finding};

/// Everything `scim-server diagnose` needs to run a check against one live
/// target. Deliberately its own type rather than an extended
/// [`ClientConfig`]: every existing `ScimClient::new(ClientConfig { .. })`
/// call site in this repository's test suite constructs `ClientConfig`
/// with an exhaustive struct literal of exactly its 3 fields, so adding
/// CLI-only concerns (headers, TLS trust, read-only) to `ClientConfig`
/// itself would force an unrelated edit onto every one of those tests for
/// no benefit to them.
#[derive(Debug, Clone)]
pub struct DiagOptions {
    pub base_url: String,
    pub auth: client::Auth,
    pub headers: Vec<(String, String)>,
    pub insecure: bool,
    pub ca_certs: Vec<PathBuf>,
    pub native_roots: bool,
    pub timeout_secs: u64,
    /// See the module doc on [`crate::diagnose`] vs. this module: when set,
    /// `run` skips the schema-driven matrix, the protocol probes, and the
    /// ledger-generated checks entirely (every one of those creates and
    /// mutates its own fixtures) and runs only
    /// [`crate::checks_from_attrdefs`], the one family that is GET-only
    /// end to end. This is a coarse, family-level gate, not per-check: see
    /// the T11 task report for why that's the honest tradeoff here.
    pub read_only: bool,
}

/// What can go wrong before a single check runs.
#[derive(Debug)]
pub enum DiagError {
    /// The base URL itself doesn't parse, or a request built from it
    /// couldn't be constructed.
    BadUrl(String),
    /// The options given are individually well-formed but incompatible or
    /// incomplete (e.g. an unreadable `--ca-cert` file, a malformed
    /// `--header`).
    BadArgs(String),
    /// The preflight request could not be sent or its response could not
    /// be read at all (DNS, connection refused, TLS handshake, timeout).
    Transport(String),
    /// The preflight `GET /ServiceProviderConfig` came back 401 or 403:
    /// the auth this `DiagOptions` was given isn't accepted by the target,
    /// so no check would get further than the first request either.
    AuthRejected { status: u16 },
}

impl std::fmt::Display for DiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagError::BadUrl(s) => write!(f, "bad URL: {s}"),
            DiagError::BadArgs(s) => write!(f, "bad arguments: {s}"),
            DiagError::Transport(s) => write!(f, "transport error: {s}"),
            DiagError::AuthRejected { status } => {
                write!(
                    f,
                    "preflight GET /ServiceProviderConfig was rejected with {status}"
                )
            }
        }
    }
}

impl std::error::Error for DiagError {}

impl From<client::Error> for DiagError {
    fn from(e: client::Error) -> Self {
        match e {
            client::Error::BadUrl(s) => DiagError::BadUrl(s),
            client::Error::Tls(s) => DiagError::BadArgs(s),
            client::Error::Transport(s) => DiagError::Transport(s),
        }
    }
}

/// Builds a client from `opts`, preflights it, and runs the generated
/// checks this crate has (the full suite, or the read-only subset -- see
/// [`DiagOptions::read_only`]).
pub async fn run(opts: &DiagOptions) -> Result<DiagnosticReport, DiagError> {
    if opts.base_url.trim().is_empty() {
        return Err(DiagError::BadArgs("base_url must not be empty".to_string()));
    }

    let cfg = ClientConfig {
        base_url: opts.base_url.clone(),
        auth: opts.auth.clone(),
        timeout: Duration::from_secs(opts.timeout_secs),
    };
    let extra = ClientExtra {
        insecure: opts.insecure,
        ca_certs: opts.ca_certs.clone(),
        native_roots: opts.native_roots,
        headers: opts.headers.clone(),
    };
    let mut client = ScimClient::with_extra(cfg, extra)?;

    let preflight = client.get("/ServiceProviderConfig").await?;
    if preflight.status == 401 || preflight.status == 403 {
        return Err(DiagError::AuthRejected {
            status: preflight.status,
        });
    }
    if !preflight.is_success() {
        return Err(DiagError::Transport(format!(
            "GET /ServiceProviderConfig returned {}: {}",
            preflight.status,
            preflight.detail()
        )));
    }

    let findings: Vec<Finding> = if opts.read_only {
        crate::checks_from_attrdefs(&mut client)
            .await
            .into_iter()
            .map(Finding::from)
            .collect()
    } else {
        crate::diagnose(&mut client).await.findings
    };

    let counts = Counts::tally(&findings);
    Ok(DiagnosticReport {
        target: opts.base_url.clone(),
        findings,
        counts,
    })
}
