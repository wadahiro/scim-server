//! The HTTP client `diag::*` checks issue probes through.
//!
//! Every request goes through [`ScimClient::request`] (or the `get`/
//! `get_query` shorthands), which is the single place that owns URL
//! joining, auth header selection, and Exchange logging — checks never
//! touch `reqwest` directly.

use std::time::{Duration, Instant};

use reqwest::{Method, Url};
use serde_json::Value;

use crate::diag::cli::{AuthKind, DiagOptions};
use crate::diag::model::Exchange;
use crate::diag::DiagError;

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

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name)?.to_str().ok()
    }

    /// Error-body summary: `/detail` -> `/scimType` -> raw, truncated to
    /// 200 chars, in that order.
    pub fn detail(&self) -> String {
        if let Some(d) = self.ptr("/detail").and_then(|v| v.as_str()) {
            return truncate(d, 200);
        }
        if let Some(t) = self.ptr("/scimType").and_then(|v| v.as_str()) {
            return truncate(t, 200);
        }
        truncate(&self.raw, 200)
    }

    /// Whether the body looks like a SCIM Error resource.
    pub fn is_scim_error(&self) -> bool {
        self.ptr("/schemas")
            .and_then(|v| v.as_array())
            .map(|schemas| {
                schemas
                    .iter()
                    .any(|s| s.as_str() == Some("urn:ietf:params:scim:api:messages:2.0:Error"))
            })
            .unwrap_or(false)
    }
}

fn truncate(s: &str, max_chars: usize) -> String {
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
    /// `/`, e.g. `https://x/scim/v2` + `/Users` -> `https://x/Users`).
    base: String,
    auth: AuthKind,
    token: Option<String>,
    username: Option<String>,
    password: Option<String>,
    extra_headers: Vec<(String, String)>,
    dry_run: bool,
    /// Content-Type used for request bodies. `rfc.content_type` (PR3) can
    /// flip this after negotiating with the target.
    pub content_type: &'static str,
    log: Vec<Exchange>,
}

impl ScimClient {
    pub fn new(opts: &DiagOptions) -> Result<Self, DiagError> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(opts.timeout))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("scim-server-diagnose/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::limited(5))
            .tls_built_in_webpki_certs(true)
            .tls_built_in_native_certs(opts.native_roots);

        for path in &opts.ca_certs {
            let pem = std::fs::read(path).map_err(DiagError::Io)?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| DiagError::Tls(format!("{}: {e}", path.display())))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        if opts.insecure {
            builder = builder
                .danger_accept_invalid_certs(true)
                .danger_accept_invalid_hostnames(true);
        }

        let inner = builder.build().map_err(|e| DiagError::Tls(e.to_string()))?;

        Ok(Self {
            inner,
            base: opts.base_url.trim_end_matches('/').to_string(),
            auth: opts.auth,
            token: opts.token.clone(),
            username: opts.username.clone(),
            password: opts.password.clone(),
            extra_headers: opts.headers.clone(),
            dry_run: opts.dry_run,
            content_type: "application/scim+json",
            log: Vec::new(),
        })
    }

    pub async fn get(&mut self, path: &str) -> Result<ScimResponse, DiagError> {
        self.request(Method::GET, path, &[], None, &[]).await
    }

    pub async fn get_query(
        &mut self,
        path: &str,
        q: &[(&str, &str)],
    ) -> Result<ScimResponse, DiagError> {
        self.request(Method::GET, path, q, None, &[]).await
    }

    pub async fn request(
        &mut self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<ScimResponse, DiagError> {
        let url_str = format!("{}{}", self.base, path);
        let parsed: Url =
            Url::parse(&url_str).map_err(|e| DiagError::BadUrl(format!("{url_str}: {e}")))?;
        self.send(method, parsed, query, body, extra_headers).await
    }

    /// Like [`Self::request`], but `url` is used as-is (not joined with
    /// `base`). For following a server-returned absolute URL verbatim —
    /// e.g. `rfc.location_roundtrip`'s `Location` header — where
    /// `base + path` joining would double up the tenant path prefix if the
    /// server's `Location` already includes it (which it does).
    pub async fn get_absolute(&mut self, url: &str) -> Result<ScimResponse, DiagError> {
        let parsed: Url = Url::parse(url).map_err(|e| DiagError::BadUrl(format!("{url}: {e}")))?;
        self.send(Method::GET, parsed, &[], None, &[]).await
    }

    async fn send(
        &mut self,
        method: Method,
        parsed: Url,
        query: &[(&str, &str)],
        body: Option<&Value>,
        extra_headers: &[(&str, &str)],
    ) -> Result<ScimResponse, DiagError> {
        let url_str = parsed.to_string();
        let mut req = self
            .inner
            .request(method.clone(), parsed)
            .query(query) // query params always go through RequestBuilder::query(), never hand-built
            .header(
                reqwest::header::ACCEPT,
                "application/scim+json, application/json",
            );

        if body.is_some() {
            req = req.header(reqwest::header::CONTENT_TYPE, self.content_type);
        }

        req = match self.auth {
            AuthKind::Bearer => req.header(
                reqwest::header::AUTHORIZATION,
                format!("Bearer {}", self.token.clone().unwrap_or_default()),
            ),
            AuthKind::Token => req.header(
                reqwest::header::AUTHORIZATION,
                format!("token {}", self.token.clone().unwrap_or_default()),
            ),
            AuthKind::Basic => req.basic_auth(
                self.username.clone().unwrap_or_default(),
                self.password.clone(),
            ),
            AuthKind::None => req,
        };

        for (k, v) in &self.extra_headers {
            req = req.header(k, v);
        }
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }

        if let Some(b) = body {
            req = req.json(b);
        }

        // Always captured, regardless of verbosity: the client keeps
        // everything, and the renderer decides what to print based on
        // `-v`/`-vv` (see render rules — Fail/Error checks always show the
        // one-line Exchange summary, but the body text itself only shows at
        // verbose >= 2).
        let request_body = body.map(|b| serde_json::to_string(b).unwrap_or_default());

        if self.dry_run {
            let built = req.build().map_err(|e| DiagError::Transport {
                url: url_str.clone(),
                source: e,
            })?;
            let exchange = Exchange {
                method: built.method().to_string(),
                url: built.url().to_string(),
                status: None,
                elapsed_ms: 0,
                request_body,
                response_body: None,
            };
            self.log.push(exchange.clone());
            return Ok(ScimResponse {
                status: 0,
                headers: reqwest::header::HeaderMap::new(),
                body: None,
                raw: String::new(),
                exchange,
            });
        }

        let start = Instant::now();
        let method_str = method.to_string();
        let resp = req.send().await.map_err(|e| DiagError::Transport {
            url: url_str.clone(),
            source: e,
        })?;
        let elapsed_ms = start.elapsed().as_millis();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let raw = resp.text().await.map_err(|e| DiagError::Transport {
            url: url_str.clone(),
            source: e,
        })?;
        let value: Option<Value> = serde_json::from_str(&raw).ok();

        let exchange = Exchange {
            method: method_str,
            url: url_str,
            status: Some(status),
            elapsed_ms,
            request_body,
            response_body: Some(raw.clone()),
        };
        self.log.push(exchange.clone());

        Ok(ScimResponse {
            status,
            headers,
            body: value,
            raw,
            exchange,
        })
    }

    /// Drains the Exchanges recorded since the last call. The runner calls
    /// this once per check so each `CheckOutcome::transcript` only contains
    /// that check's own requests.
    pub fn take_log(&mut self) -> Vec<Exchange> {
        std::mem::take(&mut self.log)
    }
}
