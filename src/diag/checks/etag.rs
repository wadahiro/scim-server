//! Tier 4 — ETag / RFC 7232 conditional requests.
//!
//! `etag.response_header` gates everything else in this module: if the
//! target sends no `ETag` header at all, every other check here Skips
//! (`require_etag_support`, below) rather than trying to build a
//! conditional request around a value that doesn't exist.
//!
//! The trio `etag.response_header` / `etag.matches_meta_version` /
//! `etag.weak_form` runs early in the catalog (§5.9 position 4, right after
//! U1 is created) so that Tier 3's `spc.etag_supported` has
//! `ctx.state.etag_observed` available. Every *other* check in this module
//! runs much later (position 13) — by then U1 has been mutated repeatedly
//! by Tier 1/2 write probes, so the ETag captured at position 4 is stale.
//! Every check below therefore fetches its own fresh `ETag` immediately
//! before using it, the same "re-issue the idempotent GET" pattern
//! `rfc7644::error_status_is_string` uses.

use reqwest::Method;
use serde_json::Value;

use crate::diag::ctx::DiagContext;
use crate::diag::model::{CheckResult, Verdict};

fn err(e: crate::diag::DiagError) -> CheckResult {
    (
        Verdict::Error {
            detail: e.to_string(),
        },
        None,
    )
}

fn skip(reason: impl Into<String>) -> CheckResult {
    (
        Verdict::Skip {
            reason: reason.into(),
        },
        None,
    )
}

/// `Some(outcome)` if a prior check hasn't established that the target
/// sends `ETag` headers at all — every check but `etag.response_header`
/// itself calls this first.
fn require_etag_support(ctx: &DiagContext) -> Option<CheckResult> {
    match ctx.state.etag_observed {
        Some(true) => None,
        Some(false) => Some(skip(
            "target sends no ETag header (see etag.response_header)",
        )),
        None => Some(skip("requires etag.response_header to have run")),
    }
}

/// A fresh `GET /Users/{id}`, returning the `ETag` header value (if any).
async fn current_etag(
    ctx: &mut DiagContext,
    id: &str,
) -> Result<Option<String>, crate::diag::DiagError> {
    let resp = ctx.client.get(&format!("/Users/{id}")).await?;
    Ok(resp.header("etag").map(str::to_string))
}

/// A fresh `GET /Users/{id}`, returning its body with `groups` stripped
/// (server-managed, not expected to round-trip through PUT — same
/// treatment as `rfc7644::put_replace`) so it can be used as a PUT body.
async fn current_put_body(
    ctx: &mut DiagContext,
    id: &str,
) -> Result<Option<Value>, crate::diag::DiagError> {
    let resp = ctx.client.get(&format!("/Users/{id}")).await?;
    let mut body = match resp.body {
        Some(b) => b,
        None => return Ok(None),
    };
    if let Value::Object(ref mut obj) = body {
        obj.remove("groups");
    }
    Ok(Some(body))
}

pub async fn response_header(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.header("etag").map(str::to_string) {
        Some(etag) => {
            ctx.state.etag_seen = Some(etag);
            ctx.state.etag_observed = Some(true);
            (Verdict::Pass { detected: None }, None)
        }
        None => {
            ctx.state.etag_observed = Some(false);
            (
                Verdict::Fail {
                    detail: "GET /Users/{id} response has no ETag header".to_string(),
                },
                None,
            )
        }
    }
}

pub async fn matches_meta_version(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let etag = resp.header("etag").map(str::to_string);
    let meta_version = resp
        .ptr("/meta/version")
        .and_then(Value::as_str)
        .map(str::to_string);
    match (etag, meta_version) {
        (Some(e), Some(v)) if e == v => (Verdict::Pass { detected: None }, None),
        (Some(e), Some(v)) => (
            Verdict::Fail {
                detail: format!("ETag header ({e:?}) does not match meta.version ({v:?})"),
            },
            None,
        ),
        (Some(_), None) => (
            Verdict::Fail {
                detail: "ETag header is present but meta.version is missing".to_string(),
            },
            None,
        ),
        (None, _) => (
            Verdict::Fail {
                detail: "GET /Users/{id} response has no ETag header".to_string(),
            },
            None,
        ),
    }
}

pub async fn weak_form(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let Some(etag) = (match current_etag(ctx, &u1.id).await {
        Ok(e) => e,
        Err(e) => return err(e),
    }) else {
        return (
            Verdict::Fail {
                detail: "GET /Users/{id} response has no ETag header".to_string(),
            },
            None,
        );
    };
    if let Some(inner) = etag.strip_prefix("W/") {
        if inner.starts_with('"') && inner.ends_with('"') && inner.len() >= 2 {
            return (Verdict::Pass { detected: None }, Some("weak".to_string()));
        }
    } else if etag.starts_with('"') && etag.ends_with('"') && etag.len() >= 2 {
        return (Verdict::Pass { detected: None }, Some("strong".to_string()));
    }
    (
        Verdict::Fail {
            detail: format!("{etag:?} is not a valid entity-tag (RFC 7232 §2.3)"),
        },
        None,
    )
}

pub async fn if_none_match_304(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let etag = match current_etag(ctx, &u1.id).await {
        Ok(e) => e,
        Err(e) => return err(e),
    };
    let Some(etag) = etag else {
        return (
            Verdict::Fail {
                detail: "GET /Users/{id} response has no ETag header".to_string(),
            },
            None,
        );
    };
    let resp = match ctx
        .client
        .request(
            Method::GET,
            &format!("/Users/{}", u1.id),
            &[],
            None,
            &[("If-None-Match", etag.as_str())],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        304 if resp.raw.trim().is_empty() => (Verdict::Pass { detected: None }, None),
        304 => (
            Verdict::Fail {
                detail: "304 Not Modified response had a non-empty body".to_string(),
            },
            None,
        ),
        200 => (
            Verdict::Fail {
                detail: "conditional GET not honoured: If-None-Match with the current ETag returned 200, expected 304".to_string(),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("GET with If-None-Match -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

/// `Severity::Info` and always `Pass` (§5.10) — this only records whether
/// the target does RFC 7232 weak comparison (matches the strong form of its
/// own weak ETag) or byte-exact comparison. Both are defensible; only the
/// note differs.
pub async fn if_none_match_weak_compare(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let etag = match current_etag(ctx, &u1.id).await {
        Ok(e) => e,
        Err(e) => return err(e),
    };
    let Some(etag) = etag else {
        return (
            Verdict::Fail {
                detail: "GET /Users/{id} response has no ETag header".to_string(),
            },
            None,
        );
    };
    let strong_form = etag.strip_prefix("W/").unwrap_or(&etag).to_string();
    let resp = match ctx
        .client
        .request(
            Method::GET,
            &format!("/Users/{}", u1.id),
            &[],
            None,
            &[("If-None-Match", strong_form.as_str())],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        304 => (
            Verdict::Pass { detected: None },
            Some("performs RFC 7232 weak comparison".to_string()),
        ),
        200 => (
            Verdict::Pass { detected: None },
            Some("byte-exact comparison only".to_string()),
        ),
        other => (
            Verdict::Error {
                detail: format!(
                    "GET with the strong form of the ETag in If-None-Match -> {other} (unexpected)"
                ),
            },
            None,
        ),
    }
}

pub async fn if_none_match_star(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let resp = match ctx
        .client
        .request(
            Method::GET,
            &format!("/Users/{}", u1.id),
            &[],
            None,
            &[("If-None-Match", "*")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        304 => (Verdict::Pass { detected: None }, None),
        other => (
            Verdict::Fail {
                detail: format!(
                    "If-None-Match: * -> {other}, expected 304 (RFC 7232 §3.2: * always matches an existing resource)"
                ),
            },
            None,
        ),
    }
}

pub async fn if_none_match_stale(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let resp = match ctx
        .client
        .request(
            Method::GET,
            &format!("/Users/{}", u1.id),
            &[],
            None,
            &[("If-None-Match", "W/\"scimdiag-bogus\"")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        200 => (Verdict::Pass { detected: None }, None),
        304 => (
            Verdict::Fail {
                detail: "If-None-Match with a bogus ETag returned 304 (unexpectedly matched)"
                    .to_string(),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("GET with a bogus If-None-Match -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

pub async fn if_match_412(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let body = match current_put_body(ctx, &u1.id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                Verdict::Error {
                    detail: "GET /Users/{id} returned no body to build a PUT from".to_string(),
                },
                None,
            )
        }
        Err(e) => return err(e),
    };
    let resp = match ctx
        .client
        .request(
            Method::PUT,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&body),
            &[("If-Match", "W/\"scimdiag-bogus\"")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        412 => (Verdict::Pass { detected: None }, None),
        200 => (
            Verdict::Fail {
                detail: "PUT with a stale If-Match returned 200 instead of 412 -- optimistic concurrency not enforced (lost-update risk)".to_string(),
            },
            None,
        ),
        400 => (
            Verdict::Fail {
                detail: "PUT with a stale If-Match returned 400 instead of 412".to_string(),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("PUT with a stale If-Match -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

pub async fn if_match_current(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let get_resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let Some(current_etag) = get_resp.header("etag").map(str::to_string) else {
        return (
            Verdict::Fail {
                detail: "GET /Users/{id} response has no ETag header".to_string(),
            },
            None,
        );
    };
    let mut body = match get_resp.body {
        Some(b) => b,
        None => {
            return (
                Verdict::Error {
                    detail: "GET /Users/{id} returned no body to build a PUT from".to_string(),
                },
                None,
            )
        }
    };
    if let Value::Object(ref mut obj) = body {
        obj.remove("groups");
        obj.insert(
            "displayName".to_string(),
            Value::String(format!("{} (if-match-current probe)", ctx.opts.prefix)),
        );
    }
    let put_resp = match ctx
        .client
        .request(
            Method::PUT,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&body),
            &[("If-Match", current_etag.as_str())],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if put_resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "PUT with the current If-Match -> {} (expected 200)",
                    put_resp.status
                ),
            },
            None,
        );
    }
    match put_resp.header("etag").map(str::to_string) {
        Some(new_etag) if new_etag != current_etag => (Verdict::Pass { detected: None }, None),
        Some(_) => (
            Verdict::Fail {
                detail: "PUT succeeded but the ETag/version did not advance".to_string(),
            },
            None,
        ),
        None => (
            Verdict::Fail {
                detail: "PUT succeeded (200) but the response has no ETag header".to_string(),
            },
            None,
        ),
    }
}

pub async fn if_match_star(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let body = match current_put_body(ctx, &u1.id).await {
        Ok(Some(b)) => b,
        Ok(None) => {
            return (
                Verdict::Error {
                    detail: "GET /Users/{id} returned no body to build a PUT from".to_string(),
                },
                None,
            )
        }
        Err(e) => return err(e),
    };
    let resp = match ctx
        .client
        .request(
            Method::PUT,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&body),
            &[("If-Match", "*")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        200 => (Verdict::Pass { detected: None }, None),
        412 => (
            Verdict::Fail {
                detail: "PUT with If-Match: * on an existing resource returned 412, expected 200 (RFC 7232 §3.1: * always matches an existing resource)".to_string(),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("PUT with If-Match: * -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

pub async fn patch_if_match(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return skip("requires fixture U1, which was not created");
    };
    let body = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "nickName",
            "value": format!("{}-patch-if-match-probe", ctx.opts.prefix)
        }]
    });
    let resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&body),
            &[("If-Match", "W/\"scimdiag-bogus\"")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        412 => (Verdict::Pass { detected: None }, None),
        200 | 204 => (
            Verdict::Fail {
                detail: format!(
                    "PATCH with a stale If-Match -> {} instead of 412 (RFC 7644 §3.14 applies If-Match to PATCH too)",
                    resp.status
                ),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("PATCH with a stale If-Match -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

/// **Consumes U3** — per the catalog ordering (§5.9 position 14), this runs
/// after every other check that needs U3 (`spc.change_password_supported`,
/// `rfc.password_never_returned`). If the stale `If-Match` is (incorrectly)
/// honoured and the DELETE actually succeeds, U3 is simply gone already —
/// `fixtures::cleanup`'s 404-is-success rule absorbs that without any
/// special-casing here.
pub async fn delete_if_match(ctx: &mut DiagContext) -> CheckResult {
    if let Some(skipped) = require_etag_support(ctx) {
        return skipped;
    }
    let u3 = { ctx.fixtures.lock().unwrap().u3.clone() };
    let Some(u3) = u3 else {
        return skip("requires fixture U3, which was not created");
    };
    let resp = match ctx
        .client
        .request(
            Method::DELETE,
            &format!("/Users/{}", u3.id),
            &[],
            None,
            &[("If-Match", "W/\"scimdiag-bogus\"")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        412 => (Verdict::Pass { detected: None }, None),
        204 => (
            Verdict::Fail {
                detail: "DELETE with a stale If-Match returned 204 instead of 412".to_string(),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("DELETE with a stale If-Match -> {other} (unexpected)"),
            },
            None,
        ),
    }
}
