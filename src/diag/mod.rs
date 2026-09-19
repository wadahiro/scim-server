//! `scim-server diagnose` — probes a SCIM 2.0 service provider over real
//! HTTP and reports RFC 7644 conformance plus the quirks this server's
//! `CompatibilityConfig` knows how to emulate.

pub mod checks;
pub mod cli;
pub mod client;
pub mod ctx;
pub mod email;
pub mod fixtures;
pub mod model;
pub mod render;
pub mod runner;

use std::sync::Arc;
use std::time::Duration;

use crate::diag::checks::catalog;
use crate::diag::cli::DiagOptions;
use crate::diag::client::ScimClient;
use crate::diag::ctx::DiagContext;
use crate::diag::email::EmailTemplate;
use crate::diag::fixtures::FixtureSet;
use crate::diag::model::{CheckOutcome, CleanupReport, Report, Tier};
use crate::diag::runner::{run_all, select};

/// Errors that prevent a [`Report`] from being produced at all — as opposed
/// to an individual check's failure, which is represented as
/// [`model::Verdict::Error`] and still lands in the report.
///
/// `AppError` (`crate::error::AppError`) is deliberately not reused here: it
/// carries an `axum::http::StatusCode` and a `to_response()` method — i.e.
/// it is about what *this server* returns to callers, the opposite
/// direction from a client reporting what some *other* server did.
#[derive(Debug)]
pub enum DiagError {
    BadUrl(String),
    BadArgs(String),
    Tls(String),
    Transport {
        url: String,
        source: reqwest::Error,
    },
    /// The very first request came back 401/403. Exit code 2.
    AuthRejected {
        status: u16,
        body: String,
    },
    /// Preflight `GET /ServiceProviderConfig` came back neither 2xx nor
    /// 401/403 (e.g. 404, 500). Not enumerated by name in the original
    /// design note — added because `Transport` requires a real
    /// `reqwest::Error`, which a non-2xx HTTP response does not produce.
    Preflight {
        status: u16,
        body: String,
    },
    Io(std::io::Error),
    Interrupted,
    DeadlineExceeded,
    /// Cleanup ran (after Ctrl-C, a deadline, or a panicked check task —
    /// the only paths that reach cleanup without a `Report` ever being
    /// built) but left resources behind on the target. `cli.rs`'s
    /// `diag_main` special-cases this variant to exit 3, matching what
    /// `Report::exit_code()` already does for the same situation reached
    /// via the ordinary completion path.
    CleanupIncomplete {
        report: CleanupReport,
        base_url: String,
        prefix: String,
    },
}

impl std::fmt::Display for DiagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagError::BadUrl(s) => write!(f, "invalid URL: {s}"),
            DiagError::BadArgs(s) => write!(f, "invalid arguments: {s}"),
            DiagError::Tls(s) => write!(f, "TLS setup failed: {s}"),
            DiagError::Transport { url, source } => write!(f, "request to {url} failed: {source}"),
            DiagError::AuthRejected { status, body } => {
                write!(f, "authentication rejected ({status}): {body}")
            }
            DiagError::Preflight { status, body } => {
                write!(f, "GET /ServiceProviderConfig failed ({status}): {body}")
            }
            DiagError::Io(e) => write!(f, "I/O error: {e}"),
            DiagError::Interrupted => write!(f, "interrupted (Ctrl-C)"),
            DiagError::DeadlineExceeded => write!(f, "deadline exceeded"),
            DiagError::CleanupIncomplete {
                report,
                base_url,
                prefix,
            } => write!(
                f,
                "{}",
                fixtures::cleanup_incomplete_block(report, base_url, prefix)
            ),
        }
    }
}

impl std::error::Error for DiagError {}

/// Runs a `GET /ServiceProviderConfig` before anything else in the catalog.
/// This is done directly (not as a `CheckDef`) because `CheckDef::run`
/// returns a plain `CheckResult` with no error channel — it cannot express
/// "abort the whole run", which is exactly what a failed connect/auth
/// preflight needs to do.
///
/// Synthesizes the `rfc.connect` and `rfc.auth` outcomes that the report
/// always leads with. Under `--dry-run` the GET is still issued (so it
/// shows up in the printed transcript, matching every other request) but
/// its synthetic `status: 0` response is not treated as a connect failure —
/// both outcomes just report `Skip("dry-run")`, same as every check in the
/// catalog ends up doing.
async fn preflight(
    client: &mut ScimClient,
    dry_run: bool,
) -> Result<(CheckOutcome, CheckOutcome, Option<serde_json::Value>), DiagError> {
    let resp = client.get("/ServiceProviderConfig").await?;
    let transcript = client.take_log();

    if dry_run {
        let connect_outcome = CheckOutcome {
            id: "rfc.connect",
            title: "ServiceProviderConfig reachable",
            tier: Tier::Rfc7644,
            severity: model::Severity::Error,
            knob: None,
            verdict: model::Verdict::Skip {
                reason: "dry-run".to_string(),
            },
            note: None,
            transcript,
        };
        let auth_outcome = CheckOutcome {
            id: "rfc.auth",
            title: "Authentication accepted",
            tier: Tier::Rfc7644,
            severity: model::Severity::Error,
            knob: None,
            verdict: model::Verdict::Skip {
                reason: "dry-run".to_string(),
            },
            note: None,
            transcript: vec![],
        };
        return Ok((connect_outcome, auth_outcome, None));
    }

    if resp.status == 401 || resp.status == 403 {
        return Err(DiagError::AuthRejected {
            status: resp.status,
            body: resp.detail(),
        });
    }
    if !resp.is_success() {
        return Err(DiagError::Preflight {
            status: resp.status,
            body: resp.detail(),
        });
    }

    let spc = resp.body.clone();

    let connect_outcome = CheckOutcome {
        id: "rfc.connect",
        title: "ServiceProviderConfig reachable",
        tier: Tier::Rfc7644,
        severity: model::Severity::Error,
        knob: None,
        verdict: model::Verdict::Pass { detected: None },
        note: None,
        transcript,
    };
    let auth_outcome = CheckOutcome {
        id: "rfc.auth",
        title: "Authentication accepted",
        tier: Tier::Rfc7644,
        severity: model::Severity::Error,
        knob: None,
        verdict: model::Verdict::Pass { detected: None },
        note: None,
        transcript: vec![],
    };

    Ok((connect_outcome, auth_outcome, spc))
}

/// Runs the full diagnostic: preflight, the selected catalog, and cleanup —
/// in that order, with cleanup always running regardless of how the middle
/// step ends (success, Ctrl-C, deadline, or a panicked check task).
///
/// `--cleanup-only` bypasses all of this (no preflight, no catalog) and
/// goes straight to `fixtures::run_cleanup_only`.
pub async fn run(opts: &DiagOptions) -> Result<Report, DiagError> {
    let started = std::time::Instant::now();
    let started_at = chrono::Utc::now();

    // Repeat calls (tests invoke `diag::run` many times in one process) are
    // expected to fail after the first; that's fine, the provider is
    // already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if opts.cleanup_only {
        return fixtures::run_cleanup_only(opts).await;
    }

    let mut client = ScimClient::new(opts)?;
    let (connect_outcome, auth_outcome, spc) = preflight(&mut client, opts.dry_run).await?;

    let fixtures = Arc::new(std::sync::Mutex::new(FixtureSet::new(&opts.prefix)));
    let ctx = DiagContext {
        client,
        opts: opts.clone(),
        spc,
        fixtures: fixtures.clone(),
        writes_disabled: if opts.read_only {
            Some("--read-only was specified".to_string())
        } else {
            None
        },
        content_type: "application/scim+json",
        state: ctx::ProbeState::default(),
    };

    let defs = select(catalog(), &opts.only, &opts.skip);

    let mut handle = tokio::spawn(run_all(ctx, defs));
    let result: Result<Vec<CheckOutcome>, DiagError> = tokio::select! {
        r = &mut handle => r.map_err(|_| DiagError::Interrupted),
        _ = tokio::signal::ctrl_c() => {
            handle.abort();
            Err(DiagError::Interrupted)
        }
        _ = tokio::time::sleep(Duration::from_secs(opts.deadline)) => {
            handle.abort();
            Err(DiagError::DeadlineExceeded)
        }
    };

    // Whatever branch we fell through from, fixtures (created via the Arc
    // the runner mutated) are still visible here — clean them up before
    // deciding whether the whole run failed.
    let cleanup = fixtures::cleanup(&fixtures, opts).await;

    let outcomes = match result {
        Ok(outcomes) => outcomes,
        Err(e) => {
            // The ordinary completion path folds cleanup failures into
            // `Report::exit_code()` (-> 3). This path never builds a
            // `Report` at all (the run was interrupted/timed out/panicked),
            // so a cleanup failure has to be surfaced as its own error
            // variant instead, or it would silently vanish behind the
            // original `Interrupted`/`DeadlineExceeded` (-> exit 2).
            if !cleanup.failures.is_empty() {
                return Err(DiagError::CleanupIncomplete {
                    report: cleanup,
                    base_url: opts.base_url.clone(),
                    prefix: opts.prefix.clone(),
                });
            }
            return Err(e);
        }
    };

    let mut warnings = Vec::new();
    if opts.insecure {
        warnings.push("TLS verification DISABLED (--insecure)".to_string());
    }
    if let Some(reason) = fixtures.lock().unwrap().degraded.clone() {
        warnings.push(format!("WRITE TIER DEGRADED: {reason}"));
    }
    if let Some(t) = &opts.probe_email {
        if let Ok(template) = EmailTemplate::parse(t) {
            if let Ok(Some(w)) = template.check_domain(opts.allow_consumer_email) {
                warnings.push(w);
            }
        }
    }

    let header = model::ReportHeader {
        target: opts.base_url.clone(),
        auth: describe_auth(opts),
        tls: describe_tls(opts),
        mode: if opts.dry_run {
            "dry-run".to_string()
        } else if opts.read_only {
            "read-only".to_string()
        } else {
            "read-write".to_string()
        },
        prefix: opts.prefix.clone(),
        probe_email: opts.probe_email.clone(),
        probe_attribute: opts.probe_attribute.attr_name().to_string(),
        started: started_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        duration_ms: started.elapsed().as_millis(),
        tool_version: env!("CARGO_PKG_VERSION"),
        verbose: opts.verbose,
        warnings,
    };

    let mut all_outcomes = vec![connect_outcome, auth_outcome];
    all_outcomes.extend(outcomes);

    Ok(Report {
        header,
        outcomes: all_outcomes,
        cleanup: Some(cleanup),
    })
}

pub(crate) fn describe_auth(opts: &DiagOptions) -> String {
    use crate::diag::cli::AuthKind;
    match opts.auth {
        AuthKind::Bearer => "bearer".to_string(),
        AuthKind::Token => "token".to_string(),
        AuthKind::Basic => format!("basic (user: {})", opts.username.as_deref().unwrap_or("?")),
        AuthKind::None => "none".to_string(),
    }
}

pub(crate) fn describe_tls(opts: &DiagOptions) -> String {
    if opts.insecure {
        "DISABLED (--insecure)".to_string()
    } else if opts.native_roots {
        "verified (built-in Mozilla roots + OS store)".to_string()
    } else {
        "verified (built-in Mozilla roots)".to_string()
    }
}
