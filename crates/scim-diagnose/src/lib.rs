//! `scim-diagnose`: points at an arbitrary third-party SCIM 2.0 endpoint
//! in order to discover what it actually does -- especially the
//! behaviours RFC 7643/7644 do not regulate -- so that those behaviours
//! can be implemented as `scim-server` `CompatibilityConfig` options (see
//! `CLAUDE.md`). It is not a conformance/pass-fail checker.
//!
//! This first commit ports the reusable plumbing from `feat/rfc-extract`'s
//! `crates/scim-conformance` (a different tool, built for pass/fail
//! conformance checking against a fixed matrix derived from `GET
//! /Schemas`) essentially as-is: `client` (the HTTP client),
//! `capability` (`/ServiceProviderConfig` parsing, trimmed of the
//! `Cell`-based gating that tool needed and this one doesn't),
//! `schema::decl` (schema-driven `AttrDecl`, included now -- per the brief
//! this crate was built from -- for a schema-driven matrix a later commit
//! may add), and `fixtures` (fixture creation/cleanup helpers the seven
//! axis probes, landing in a later commit, will use).
//!
//! No axes yet: [`run`] only fetches the three discovery endpoints
//! (`/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`) and returns
//! them verbatim, so the `diagnose` CLI has something real to print while
//! the behavioural-axis machinery (`axis`, `rfc`, `axes`, `runner`,
//! `render`) is built out in the commits that follow.

pub mod capability;
pub mod client;
pub mod fixtures;
pub mod schema;

use std::path::PathBuf;

pub use client::{Auth, ClientConfig, ClientExtra, ScimClient};
use serde_json::Value;

/// Everything `diagnose` needs to build a [`ScimClient`], mirroring
/// `feat/rfc-extract`'s `scim_conformance::DiagOptions` shape.
#[derive(Debug, Clone)]
pub struct DiagOptions {
    pub base_url: String,
    pub auth: Auth,
    pub headers: Vec<(String, String)>,
    pub insecure: bool,
    pub ca_certs: Vec<PathBuf>,
    pub native_roots: bool,
    pub timeout_secs: u64,
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

/// The three discovery endpoints every SCIM provider is expected to
/// expose, fetched verbatim -- no axes derived from them yet (see module
/// docs).
#[derive(Debug, Clone)]
pub struct Discovery {
    pub service_provider_config: Option<Value>,
    pub schemas: Option<Value>,
    pub resource_types: Option<Value>,
}

fn build_client(opts: &DiagOptions) -> Result<ScimClient, Error> {
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
    Ok(ScimClient::with_extra(cfg, extra)?)
}

/// Builds a [`ScimClient`] from `opts` and fetches the three discovery
/// endpoints. A non-2xx or unreachable endpoint degrades to `None` for
/// that field rather than failing the whole run.
pub async fn run(opts: &DiagOptions) -> Result<Discovery, Error> {
    let client = build_client(opts)?;

    async fn fetch(client: &ScimClient, path: &str) -> Option<Value> {
        let r = client.get(path).await.ok()?;
        if r.is_success() {
            r.body
        } else {
            None
        }
    }

    Ok(Discovery {
        service_provider_config: fetch(&client, "/ServiceProviderConfig").await,
        schemas: fetch(&client, "/Schemas").await,
        resource_types: fetch(&client, "/ResourceTypes").await,
    })
}
