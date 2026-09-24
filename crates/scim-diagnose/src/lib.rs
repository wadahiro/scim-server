//! `scim-diagnose`: points at an arbitrary third-party SCIM SCIM 2.0
//! endpoint and reports a machine-readable behavioural profile --
//! particularly the dimensions RFC 7643/7644 leave unregulated -- so that
//! providers' real-world behaviour can be turned into `scim-server`
//! `CompatibilityConfig` options (see `CLAUDE.md`). It is not a
//! conformance/pass-fail checker: see `crate::axis`'s module docs and the
//! brief this crate was built from for why that distinction drives every
//! design choice here.
//!
//! Ported, with adaptation, from `feat/rfc-extract`'s
//! `crates/scim-conformance` (a different tool, built for pass/fail
//! conformance checking against a fixed matrix derived from `GET
//! /Schemas`). Taken essentially as-is: `client` (HTTP client),
//! `capability` (`/ServiceProviderConfig` parsing, trimmed of the
//! `Cell`-based gating that tool needed and this one doesn't),
//! `schema::decl` (schema-driven `AttrDecl`, included now — per the brief
//! — for a future schema-driven matrix this crate doesn't yet have). New
//! for this crate's purpose: `axis`, `rfc`, `axes`, `runner`, `render`.
//!
//! ```text
//! ScimClient ---> runner::run ---> Profile ---> render::{render_profile, profile_json, compatibility_config}
//!                     ^
//!                     | (gated by Cost / --allow-writes, and by
//!                     |  capability::Capabilities for the two filter axes)
//!                 axes::AXES (32 static axes: 7 CompatibilityConfig
//!                 dimensions + 9 ported from feat/rfc-extract's
//!                 uniqueness/sequence/atomicity/conditional templates +
//!                 16 ported from feat/rfc-extract's etag.rs, RFC 7644
//!                 §3.14 ETag/conditional-request family)
//! ```

pub mod axes;
pub mod axis;
pub mod capability;
pub mod client;
pub mod fixtures;
pub mod matrix;
pub mod render;
pub mod rfc;
pub mod runner;
pub mod schema;

use std::path::PathBuf;

pub use axis::{Axis, Cost, Observation, Profile, Unobservable, Value};
pub use client::{Auth, ClientConfig, ClientExtra, ScimClient};
pub use render::{compatibility_config, profile_json, render_profile};

/// Everything `diagnose` needs to build a [`ScimClient`] and run
/// [`runner::run`] -- the CLI-facing bundle, mirroring
/// `feat/rfc-extract`'s `scim_conformance::DiagOptions` shape (adapted:
/// `read_only` there becomes `allow_writes`, inverted, since this crate's
/// default posture is "discovery only" rather than "run everything unless
/// told not to" -- see the brief's write-budget requirement).
#[derive(Debug, Clone)]
pub struct DiagOptions {
    pub base_url: String,
    pub auth: Auth,
    pub headers: Vec<(String, String)>,
    pub insecure: bool,
    pub ca_certs: Vec<PathBuf>,
    pub native_roots: bool,
    pub timeout_secs: u64,
    /// Opts into `Cost::NeedsUser`/`Cost::NeedsUserAndGroup` axes. Default
    /// posture (`false`) is discovery-only: no fixture is ever created
    /// against a target unless the caller explicitly allows it (see
    /// `crate::runner::run` and `Unobservable::NeedsWrite`).
    pub allow_writes: bool,
}

#[derive(Debug)]
pub enum Error {
    Client(client::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Client(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<client::Error> for Error {
    fn from(e: client::Error) -> Self {
        Error::Client(e)
    }
}

/// Builds a [`ScimClient`] from `opts` and runs every axis, returning the
/// resulting [`Profile`]. The one entry point `diagnose`'s CLI (and tests)
/// use.
pub async fn run(opts: &DiagOptions) -> Result<Profile, Error> {
    let extra = ClientExtra {
        insecure: opts.insecure,
        ca_certs: opts.ca_certs.clone(),
        native_roots: opts.native_roots,
        headers: opts.headers.clone(),
    };
    let cfg = ClientConfig {
        base_url: opts.base_url.clone(),
        auth: opts.auth.clone(),
        timeout: std::time::Duration::from_secs(opts.timeout_secs),
    };
    let mut client = ScimClient::with_extra(cfg, extra)?;
    Ok(runner::run(&mut client, &opts.base_url, opts.allow_writes).await)
}
