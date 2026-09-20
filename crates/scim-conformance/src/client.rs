//! The HTTP client the generated checks issue probes through.
//!
//! Ported from `feat/scim-diagnose`'s `src/diag/client.rs`, decoupled from
//! that branch's CLI option struct: this crate only needs a base URL and an
//! auth mode, not dry-run/verbosity/logging.

use std::time::{Duration, Instant};

use reqwest::Method;
use serde_json::Value;

/// How the client authenticates against the target tenant.
#[derive(Debug, Clone)]
pub enum Auth {
    None,
    Bearer(String),
    Token(String),
    Basic { username: String, password: String },
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub base_url: String,
    pub auth: Auth,
    pub timeout: Duration,
}

#[derive(Debug)]
pub enum Error {
    Tls(String),
    BadUrl(String),
    Transport(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Tls(s) => write!(f, "TLS error: {s}"),
            Error::BadUrl(s) => write!(f, "bad URL: {s}"),
            Error::Transport(s) => write!(f, "transport error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// One HTTP request/response pair, kept for diagnostics.
#[derive(Debug, Clone)]
pub struct Exchange {
    pub method: String,
    pub url: String,
    pub status: Option<u16>,
    pub elapsed_ms: u128,
    pub request_body: Option<String>,
    pub response_body: Option<String>,
}

pub struct ScimResponse {
    pub status: u16,
    pub headers: reqwest::header::HeaderMap,
    /// Only `Some` when the body parsed as JSON; parse failures leave the
    /// raw text in `raw` instead.
    pub body: Option<Value>,
    pub raw: String,
    pub exchange: Exchange,
}

impl ScimResponse {
    pub fn ptr(&self, pointer: &str) -> Option<&Value> {
        self.body.as_ref()?.pointer(pointer)
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Error-body summary: `/detail` -> `/scimType` -> raw, truncated.
    pub fn detail(&self) -> String {
        if let Some(d) = self.ptr("/detail").and_then(|v| v.as_str()) {
            return truncate(d, 200);
        }
        if let Some(t) = self.ptr("/scimType").and_then(|v| v.as_str()) {
            return truncate(t, 200);
        }
        truncate(&self.raw, 200)
    }

    pub fn scim_type(&self) -> Option<String> {
        self.ptr("/scimType")
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    pub fn id(&self) -> Option<String> {
        self.ptr("/id").and_then(|v| v.as_str()).map(String::from)
    }
}

pub(crate) fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push('…');
        out
    }
}

pub struct ScimClient {
    inner: reqwest::Client,
    /// No trailing slash — paths are joined with `format!("{base}{path}")`,
    /// never `Url::join` (which drops the base path when `path` starts with
    /// `/`).
    base: String,
    auth: Auth,
}

impl ScimClient {
    pub fn new(cfg: ClientConfig) -> Result<Self, Error> {
        // Installs the `ring` crypto provider so rustls has exactly one
        // registered (the `-no-provider` reqwest features leave this to the
        // caller); avoids pulling in `aws-lc-rs` as a second provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let inner = reqwest::Client::builder()
            .timeout(cfg.timeout)
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("scim-conformance/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            .tls_built_in_webpki_certs(true)
            .tls_built_in_native_certs(true)
            .build()
            .map_err(|e| Error::Tls(e.to_string()))?;

        Ok(Self {
            inner,
            base: cfg.base_url.trim_end_matches('/').to_string(),
            auth: cfg.auth,
        })
    }

    pub async fn get(&self, path: &str) -> Result<ScimResponse, Error> {
        self.request(Method::GET, path, &[], None).await
    }

    pub async fn get_query(&self, path: &str, q: &[(&str, &str)]) -> Result<ScimResponse, Error> {
        self.request(Method::GET, path, q, None).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<ScimResponse, Error> {
        self.request(Method::POST, path, &[], Some(body)).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<ScimResponse, Error> {
        self.request(Method::PUT, path, &[], Some(body)).await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<ScimResponse, Error> {
        self.request(Method::PATCH, path, &[], Some(body)).await
    }

    pub async fn delete(&self, path: &str) -> Result<ScimResponse, Error> {
        self.request(Method::DELETE, path, &[], None).await
    }

    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<ScimResponse, Error> {
        let url_str = format!("{}{}", self.base, path);
        let parsed: reqwest::Url =
            reqwest::Url::parse(&url_str).map_err(|e| Error::BadUrl(format!("{url_str}: {e}")))?;

        let mut req = self
            .inner
            .request(method.clone(), parsed)
            .query(query) // query params always go through RequestBuilder::query(), never hand-built
            .header(
                reqwest::header::ACCEPT,
                "application/scim+json, application/json",
            );

        if body.is_some() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/scim+json");
        }

        req = match &self.auth {
            Auth::Bearer(token) => {
                req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
            }
            Auth::Token(token) => {
                req.header(reqwest::header::AUTHORIZATION, format!("token {token}"))
            }
            Auth::Basic { username, password } => req.basic_auth(username, Some(password.clone())),
            Auth::None => req,
        };

        if let Some(b) = body {
            req = req.json(b);
        }

        let request_body = body.map(|b| serde_json::to_string(b).unwrap_or_default());

        let start = Instant::now();
        let method_str = method.to_string();
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Transport(format!("{url_str}: {e}")))?;
        let elapsed_ms = start.elapsed().as_millis();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let raw = resp
            .text()
            .await
            .map_err(|e| Error::Transport(format!("{url_str}: {e}")))?;
        let value: Option<Value> = serde_json::from_str(&raw).ok();

        let exchange = Exchange {
            method: method_str,
            url: url_str,
            status: Some(status),
            elapsed_ms,
            request_body,
            response_body: Some(raw.clone()),
        };

        Ok(ScimResponse {
            status,
            headers,
            body: value,
            raw,
            exchange,
        })
    }
}
