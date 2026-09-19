//! Tier 2 — RFC 7644 basic conformance checks.
//!
//! `rfc.connect` and `rfc.auth` are *not* here: they run as the `preflight`
//! step in `diag::mod` because a failed connect/auth has to abort the whole
//! run (a `DiagError`), which `CheckDef::run` cannot express (it returns a
//! plain `CheckResult`, no error channel).
//!
//! The read-only members landed in PR2. The write-mode ones below
//! (`rfc.content_type` .. `rfc.delete_then_get`) landed in PR3 alongside
//! fixture provisioning (`fixtures::provision`, `runner::run_all`).
//! `rfc.password_never_returned` (PR4) rides on Tier 3's
//! `spc.change_password_supported` PATCH (`checks/spc.rs`) rather than
//! issuing its own.

use reqwest::Method;
use serde_json::{json, Value};

use crate::diag::client::ScimResponse;
use crate::diag::ctx::DiagContext;
use crate::diag::fixtures::ResourceKind;
use crate::diag::model::{CheckResult, Verdict};

const NONEXISTENT_USER_ID: &str = "00000000-0000-4000-8000-0000000diag0";

pub async fn response_content_type(ctx: &mut DiagContext) -> CheckResult {
    let resp = match ctx.client.get("/ServiceProviderConfig").await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.header("content-type") {
        Some(ct) if ct.starts_with("application/scim+json") => {
            (Verdict::Pass { detected: None }, None)
        }
        Some(ct) => (
            Verdict::Fail {
                detail: format!("Content-Type is `{ct}`, expected `application/scim+json`"),
            },
            None,
        ),
        None => (
            Verdict::Fail {
                detail: "response has no Content-Type header".to_string(),
            },
            None,
        ),
    }
}

pub async fn schemas_endpoint(ctx: &mut DiagContext) -> CheckResult {
    let resp = match ctx.client.get("/Schemas").await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("GET /Schemas -> {} (expected 200)", resp.status),
            },
            None,
        );
    }
    // Deliberately a raw-text search rather than a strict shape assertion:
    // third-party servers wrap their schema list differently, and the spec
    // only asks whether the two core URNs are present ("含む").
    let has_user = resp
        .raw
        .contains("urn:ietf:params:scim:schemas:core:2.0:User");
    let has_group = resp
        .raw
        .contains("urn:ietf:params:scim:schemas:core:2.0:Group");
    if has_user && has_group {
        (Verdict::Pass { detected: None }, None)
    } else {
        let mut missing = Vec::new();
        if !has_user {
            missing.push("core:2.0:User");
        }
        if !has_group {
            missing.push("core:2.0:Group");
        }
        (
            Verdict::Fail {
                detail: format!("Schemas response is missing: {}", missing.join(", ")),
            },
            None,
        )
    }
}

pub async fn resource_types(ctx: &mut DiagContext) -> CheckResult {
    let resp = match ctx.client.get("/ResourceTypes").await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("GET /ResourceTypes -> {} (expected 200)", resp.status),
            },
            None,
        );
    }
    let entries = resource_type_entries(&resp);
    let mut missing = Vec::new();
    for name in ["User", "Group"] {
        let ok = entries.iter().any(|e| {
            let matches_name = e.get("id").and_then(Value::as_str) == Some(name)
                || e.get("name").and_then(Value::as_str) == Some(name);
            matches_name && non_empty_str(e.get("endpoint")) && non_empty_str(e.get("schema"))
        });
        if !ok {
            missing.push(name);
        }
    }
    if missing.is_empty() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "ResourceTypes entry missing or incomplete (endpoint/schema) for: {}",
                    missing.join(", ")
                ),
            },
            None,
        )
    }
}

fn non_empty_str(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).is_some_and(|s| !s.is_empty())
}

fn resource_type_entries(resp: &ScimResponse) -> Vec<Value> {
    match resp.body.as_ref() {
        Some(Value::Array(a)) => a.clone(),
        Some(v) => v
            .pointer("/Resources")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

pub async fn list_envelope(ctx: &mut DiagContext) -> CheckResult {
    let resp = match ctx.client.get_query("/Users", &[("count", "1")]).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("GET /Users?count=1 -> {} (expected 200)", resp.status),
            },
            None,
        );
    }
    let mut missing = Vec::new();
    let has_list_schema = resp
        .ptr("/schemas")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .any(|s| s.as_str().is_some_and(|s| s.contains("ListResponse")))
        })
        .unwrap_or(false);
    if !has_list_schema {
        missing.push("schemas containing a ListResponse URN");
    }
    if resp.ptr("/totalResults").and_then(Value::as_i64).is_none() {
        missing.push("integer totalResults");
    }
    if !resp.ptr("/Resources").is_some_and(Value::is_array) {
        missing.push("array Resources");
    }
    if missing.is_empty() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!("list envelope missing: {}", missing.join(", ")),
            },
            None,
        )
    }
}

pub async fn not_found_shape(ctx: &mut DiagContext) -> CheckResult {
    let resp = match ctx
        .client
        .get(&format!("/Users/{NONEXISTENT_USER_ID}"))
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 404 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET of a nonexistent user -> {} (expected 404)",
                    resp.status
                ),
            },
            None,
        );
    }
    let schemas = resp
        .ptr("/schemas")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let is_error_shape = schemas.len() == 1
        && schemas[0].as_str() == Some("urn:ietf:params:scim:api:messages:2.0:Error");
    if is_error_shape {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "404 body is not the SCIM Error resource shape: {}",
                    resp.detail()
                ),
            },
            None,
        )
    }
}

pub async fn error_status_is_string(ctx: &mut DiagContext) -> CheckResult {
    // Re-issues the same idempotent GET rather than reusing `rfc.404_shape`'s
    // response (each `CheckDef` only gets `&mut DiagContext`, and
    // `ProbeState`'s fields are fixed by the design note to the Tier 1/3
    // cross-checks, not to this); the response is deterministic so this is
    // equivalent in outcome, just one extra round trip.
    let resp = match ctx
        .client
        .get(&format!("/Users/{NONEXISTENT_USER_ID}"))
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.ptr("/status") {
        Some(Value::String(_)) => (Verdict::Pass { detected: None }, None),
        Some(Value::Number(n)) => (
            Verdict::Fail {
                detail: format!(
                    "got \"status\": {n}   (JSON number; RFC 7644 §3.12 requires a string)"
                ),
            },
            None,
        ),
        Some(other) => (
            Verdict::Fail {
                detail: format!("\"status\" is neither a string nor a number: {other}"),
            },
            None,
        ),
        None => (
            Verdict::Skip {
                reason: "404 body has no \"status\" field to inspect; see rfc.404_shape"
                    .to_string(),
            },
            None,
        ),
    }
}

fn err(e: crate::diag::DiagError) -> CheckResult {
    (
        Verdict::Error {
            detail: e.to_string(),
        },
        None,
    )
}

/// `Location` is an absolute URL already including the tenant path prefix
/// — `ScimClient::get_absolute` uses it as-is rather than joining it onto
/// `base` a second time (which `ScimClient::get`/`request` would do, since
/// they always treat their `path` argument as relative to `base`).
pub async fn content_type(ctx: &mut DiagContext) -> CheckResult {
    let Some(p) = ctx.state.create_u1.clone() else {
        return (
            Verdict::Skip {
                reason: "requires write mode: fixture creation did not run".to_string(),
            },
            None,
        );
    };
    if p.retried_with_plain_json {
        (
            Verdict::Fail {
                detail: "application/scim+json was rejected (415); application/json was required instead"
                    .to_string(),
            },
            None,
        )
    } else {
        (Verdict::Pass { detected: None }, None)
    }
}

pub async fn create_user(ctx: &mut DiagContext) -> CheckResult {
    let Some(p) = ctx.state.create_u1.clone() else {
        return (
            Verdict::Skip {
                reason: "requires write mode: fixture creation did not run".to_string(),
            },
            None,
        );
    };
    let mut missing = Vec::new();
    if p.status != 201 {
        missing.push(format!("201 status (got {})", p.status));
    }
    if p.location.is_none() {
        missing.push("Location header".to_string());
    }
    if p.id.is_none() {
        missing.push("id".to_string());
    }
    if p.resource_type.as_deref() != Some("User") {
        missing.push(format!(
            "meta.resourceType == \"User\" (got {:?})",
            p.resource_type
        ));
    }
    if missing.is_empty() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!("POST /Users response missing/wrong: {}", missing.join(", ")),
            },
            None,
        )
    }
}

pub async fn location_roundtrip(ctx: &mut DiagContext) -> CheckResult {
    let Some(p) = ctx.state.create_u1.clone() else {
        return (
            Verdict::Skip {
                reason: "requires write mode: fixture creation did not run".to_string(),
            },
            None,
        );
    };
    let Some(location) = p.location else {
        return (
            Verdict::Skip {
                reason: "POST /Users response had no Location header (see rfc.create_user)"
                    .to_string(),
            },
            None,
        );
    };
    let Some(expected_id) = p.id else {
        return (
            Verdict::Skip {
                reason: "POST /Users response had no id (see rfc.create_user)".to_string(),
            },
            None,
        );
    };
    let resp = match ctx.client.get_absolute(&location).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("GET {location} -> {} (expected 200)", resp.status),
            },
            None,
        );
    }
    match resp.ptr("/id").and_then(Value::as_str) {
        Some(id) if id == expected_id => (Verdict::Pass { detected: None }, None),
        Some(id) => (
            Verdict::Fail {
                detail: format!("Location resolves to id {id:?}, expected {expected_id:?}"),
            },
            None,
        ),
        None => (
            Verdict::Fail {
                detail: "Location GET response has no id".to_string(),
            },
            None,
        ),
    }
}

pub async fn duplicate_username(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": u1.user_name,
        "name": { "givenName": "Scim", "familyName": "Diag" },
        "emails": [{ "value": u1.email, "type": "work", "primary": true }],
        "active": true
    });
    let resp = match ctx
        .client
        .request(Method::POST, "/Users", &[], Some(&body), &[])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        201 => {
            // Accepted a duplicate: register it for cleanup immediately
            // (before returning), same as every other 201 this tool sees.
            if let Some(id) = resp.ptr("/id").and_then(Value::as_str) {
                ctx.fixtures.lock().unwrap().created.push((
                    ResourceKind::User,
                    id.to_string(),
                    u1.user_name.clone(),
                ));
            }
            (
                Verdict::Fail {
                    detail: "duplicate userName was accepted (201) instead of rejected".to_string(),
                },
                None,
            )
        }
        409 => {
            if resp.ptr("/scimType").and_then(Value::as_str) == Some("uniqueness") {
                (Verdict::Pass { detected: None }, None)
            } else {
                (
                    Verdict::Pass { detected: None },
                    Some("409 without scimType=\"uniqueness\"".to_string()),
                )
            }
        }
        400 => (
            Verdict::Fail {
                detail: format!(
                    "duplicate userName rejected with 400, not 409: {}",
                    resp.detail()
                ),
            },
            None,
        ),
        other => (
            Verdict::Error {
                detail: format!("POST duplicate userName -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

pub async fn put_replace(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let get_resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if get_resp.status != 200 {
        return (
            Verdict::Error {
                detail: format!("GET /Users/{} -> {} (expected 200)", u1.id, get_resp.status),
            },
            None,
        );
    }
    let before_modified = get_resp.ptr("/meta/lastModified").cloned();
    let mut body = get_resp.body.clone().unwrap_or_else(|| json!({}));
    let new_display = format!("{} (put-replace probe)", ctx.opts.prefix);
    if let Value::Object(ref mut obj) = body {
        obj.insert("displayName".to_string(), json!(new_display));
        // Group membership is server-managed via the memberships table,
        // not part of what a client is expected to round-trip through PUT.
        obj.remove("groups");
    }
    let put_resp = match ctx
        .client
        .request(
            Method::PUT,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if put_resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("PUT /Users/{} -> {} (expected 200)", u1.id, put_resp.status),
            },
            None,
        );
    }
    let after_display = put_resp.ptr("/displayName").and_then(Value::as_str);
    if after_display != Some(new_display.as_str()) {
        return (
            Verdict::Fail {
                detail: format!(
                    "PUT accepted (200) but displayName was not updated: got {after_display:?}"
                ),
            },
            None,
        );
    }
    let after_modified = put_resp.ptr("/meta/lastModified").cloned();
    if before_modified.is_some() && after_modified == before_modified {
        return (
            Verdict::Fail {
                detail: "PUT accepted (200) but meta.lastModified did not advance".to_string(),
            },
            None,
        );
    }
    (Verdict::Pass { detected: None }, None)
}

pub async fn patch_add_remove(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let nickname = format!("{}-nick", ctx.opts.prefix);

    let add_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "add", "path": "nickName", "value": nickname }]
    });
    let add_resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&add_body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    ctx.state.patch_response_status = Some(add_resp.status);
    ctx.state.patch_response_had_body = Some(!add_resp.raw.trim().is_empty());

    if add_resp.status == 501 {
        ctx.state.patch_observed = Some(false);
        return (
            Verdict::Fail {
                detail: "PATCH add nickName -> 501 Not Implemented".to_string(),
            },
            Some("subsequent PATCH-dependent checks will be skipped".to_string()),
        );
    }
    if !add_resp.is_success() {
        ctx.state.patch_observed = Some(false);
        return (
            Verdict::Fail {
                detail: format!("PATCH add nickName -> {} (expected 2xx)", add_resp.status),
            },
            None,
        );
    }

    let get1 = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if get1.ptr("/nickName").and_then(Value::as_str) != Some(nickname.as_str()) {
        ctx.state.patch_observed = Some(false);
        return (
            Verdict::Fail {
                detail: "PATCH add nickName returned 2xx but GET did not reflect it".to_string(),
            },
            None,
        );
    }

    let remove_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "remove", "path": "nickName" }]
    });
    let remove_resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&remove_body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if !remove_resp.is_success() {
        ctx.state.patch_observed = Some(false);
        return (
            Verdict::Fail {
                detail: format!(
                    "PATCH remove nickName -> {} (expected 2xx)",
                    remove_resp.status
                ),
            },
            None,
        );
    }
    let get2 = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if get2.ptr("/nickName").is_some() {
        ctx.state.patch_observed = Some(false);
        return (
            Verdict::Fail {
                detail: "PATCH remove nickName returned 2xx but GET still shows it".to_string(),
            },
            None,
        );
    }

    ctx.state.patch_observed = Some(true);
    (Verdict::Pass { detected: None }, None)
}

/// Examines `rfc.patch_add_remove`'s `add` response (stashed in
/// `ctx.state`, not re-requested — the design note's decision rule says
/// "reuse the response", and a fresh PATCH would be a second write with no
/// upside).
pub async fn patch_204_or_200(ctx: &mut DiagContext) -> CheckResult {
    match (
        ctx.state.patch_response_status,
        ctx.state.patch_response_had_body,
    ) {
        (None, _) => (
            Verdict::Skip {
                reason: "requires rfc.patch_add_remove to have run".to_string(),
            },
            None,
        ),
        (Some(204), Some(true)) => (
            Verdict::Fail {
                detail: "PATCH returned 204 No Content but the response body was non-empty"
                    .to_string(),
            },
            None,
        ),
        (Some(204), _) => (Verdict::Pass { detected: None }, None),
        (Some(200), Some(false)) => (
            Verdict::Pass { detected: None },
            Some("200 with an empty body".to_string()),
        ),
        (Some(200), _) => (Verdict::Pass { detected: None }, None),
        (Some(s), _) => (
            Verdict::Skip {
                reason: format!("rfc.patch_add_remove's PATCH returned {s}, neither 200 nor 204"),
            },
            None,
        ),
    }
}

pub async fn filter_eq_username(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let filter = format!("userName eq \"{}\"", u1.user_name);
    let resp = match ctx
        .client
        .get_query("/Users", &[("filter", filter.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status == 400 {
        ctx.state.filter_observed = Some(false);
        return (
            Verdict::Fail {
                detail: "eq on userName is mandatory (RFC 7644 §3.4.2.2) but was rejected with 400"
                    .to_string(),
            },
            None,
        );
    }
    if resp.status != 200 {
        ctx.state.filter_observed = Some(false);
        return (
            Verdict::Error {
                detail: format!(
                    "GET /Users?filter=userName eq ... -> {} (unexpected)",
                    resp.status
                ),
            },
            None,
        );
    }
    let total = resp.ptr("/totalResults").and_then(Value::as_i64);
    let matches_id = resp.ptr("/Resources/0/id").and_then(Value::as_str) == Some(u1.id.as_str());
    if total == Some(1) && matches_id {
        ctx.state.filter_observed = Some(true);
        (Verdict::Pass { detected: None }, None)
    } else {
        ctx.state.filter_observed = Some(false);
        (
            Verdict::Fail {
                detail: format!(
                    "expected exactly 1 match with id {}, got totalResults={total:?}",
                    u1.id
                ),
            },
            None,
        )
    }
}

pub async fn filter_case_insensitive(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let filter = format!("userName eq \"{}\"", u1.user_name.to_uppercase());
    let resp = match ctx
        .client
        .get_query("/Users", &[("filter", filter.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET /Users?filter=userName eq \"<UPPER>\" -> {} (expected 200)",
                    resp.status
                ),
            },
            None,
        );
    }
    let found = resp
        .ptr("/Resources")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .any(|r| r.get("id").and_then(Value::as_str) == Some(u1.id.as_str()))
        })
        .unwrap_or(false);
    if found {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: "case-insensitive match on userName not honoured (RFC 7644 §3.4.2.2)"
                    .to_string(),
            },
            None,
        )
    }
}

pub async fn filter_sw(ctx: &mut DiagContext) -> CheckResult {
    let prefix = ctx.opts.prefix.clone();
    let filter = format!("userName sw \"{prefix}\"");
    let resp = match ctx
        .client
        .get_query("/Users", &[("filter", filter.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status == 400 {
        ctx.state.n_own = None;
        ctx.state.filter_observed = Some(false);
        return (
            Verdict::Fail {
                detail: "userName sw filter rejected with 400".to_string(),
            },
            None,
        );
    }
    if resp.status != 200 {
        ctx.state.n_own = None;
        return (
            Verdict::Error {
                detail: format!(
                    "GET /Users?filter=userName sw ... -> {} (unexpected)",
                    resp.status
                ),
            },
            None,
        );
    }
    ctx.state.n_own = resp.ptr("/totalResults").and_then(Value::as_i64);
    ctx.state.filter_observed = Some(true);
    (Verdict::Pass { detected: None }, None)
}

pub async fn pagination(ctx: &mut DiagContext) -> CheckResult {
    let prefix = ctx.opts.prefix.clone();
    let Some(n_own) = ctx.state.n_own else {
        return (
            Verdict::Skip {
                reason: "requires rfc.filter_sw to have observed a usable totalResults".to_string(),
            },
            None,
        );
    };
    if n_own <= 0 {
        return (
            Verdict::Skip {
                reason: "rfc.filter_sw observed no own fixtures to page through".to_string(),
            },
            None,
        );
    }
    let filter = format!("userName sw \"{prefix}\"");
    let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut totals: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut violations = Vec::new();

    let mut start_index: i64 = 1;
    while start_index <= n_own {
        let si = start_index.to_string();
        let resp = match ctx
            .client
            .get_query(
                "/Users",
                &[
                    ("filter", filter.as_str()),
                    ("startIndex", si.as_str()),
                    ("count", "1"),
                ],
            )
            .await
        {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        if resp.status != 200 {
            return (
                Verdict::Fail {
                    detail: format!(
                        "GET /Users?...&startIndex={start_index}&count=1 -> {} (expected 200)",
                        resp.status
                    ),
                },
                None,
            );
        }
        if resp.ptr("/startIndex").and_then(Value::as_i64) != Some(start_index) {
            violations.push(format!("startIndex not echoed at page {start_index}"));
        }
        if let Some(ipp) = resp.ptr("/itemsPerPage").and_then(Value::as_i64) {
            if ipp > 1 {
                violations.push(format!(
                    "itemsPerPage {ipp} exceeds requested count=1 at page {start_index}"
                ));
            }
        }
        if let Some(total) = resp.ptr("/totalResults").and_then(Value::as_i64) {
            totals.insert(total);
        }
        if let Some(items) = resp.ptr("/Resources").and_then(Value::as_array) {
            for it in items {
                if let Some(id) = it.get("id").and_then(Value::as_str) {
                    if !seen_ids.insert(id.to_string()) {
                        violations.push(format!("id {id} seen on more than one page"));
                    }
                }
            }
        }
        start_index += 1;
    }

    if seen_ids.len() as i64 != n_own {
        violations.push(format!(
            "union of pages has {} ids, expected {n_own}",
            seen_ids.len()
        ));
    }
    if totals.len() > 1 {
        violations.push(format!(
            "totalResults was not stable across pages: {totals:?}"
        ));
    }

    if violations.is_empty() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: violations.join("; "),
            },
            None,
        )
    }
}

pub async fn pagination_count_zero(ctx: &mut DiagContext) -> CheckResult {
    let prefix = ctx.opts.prefix.clone();
    let Some(n_own) = ctx.state.n_own else {
        return (
            Verdict::Skip {
                reason: "requires rfc.filter_sw to have observed a usable totalResults".to_string(),
            },
            None,
        );
    };
    let filter = format!("userName sw \"{prefix}\"");
    let resp = match ctx
        .client
        .get_query("/Users", &[("filter", filter.as_str()), ("count", "0")])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!("GET /Users?...&count=0 -> {} (expected 200)", resp.status),
            },
            None,
        );
    }
    let empty_resources = resp
        .ptr("/Resources")
        .map(|v| v.as_array().map(|a| a.is_empty()).unwrap_or(false))
        .unwrap_or(true);
    let total = resp.ptr("/totalResults").and_then(Value::as_i64);
    if empty_resources && total == Some(n_own) {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "count=0 expected empty Resources and totalResults={n_own}, got Resources empty={empty_resources}, totalResults={total:?}"
                ),
            },
            None,
        )
    }
}

pub async fn attributes_param(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let resp = match ctx
        .client
        .get_query(&format!("/Users/{}", u1.id), &[("attributes", "userName")])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET ...?attributes=userName -> {} (expected 200)",
                    resp.status
                ),
            },
            None,
        );
    }
    let has_core =
        resp.ptr("/id").is_some() && resp.ptr("/schemas").is_some() && resp.ptr("/meta").is_some();
    let has_username = resp.ptr("/userName").is_some();
    let excluded_others = resp.ptr("/name").is_none() && resp.ptr("/displayName").is_none();
    if has_core && has_username && excluded_others {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: "attributes=userName was ignored (other fields still present, or userName/core fields missing)"
                    .to_string(),
            },
            None,
        )
    }
}

pub async fn excluded_attributes(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let resp = match ctx
        .client
        .get_query(
            &format!("/Users/{}", u1.id),
            &[("excludedAttributes", "name")],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET ...?excludedAttributes=name -> {} (expected 200)",
                    resp.status
                ),
            },
            None,
        );
    }
    if resp.ptr("/name").is_none() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: "excludedAttributes=name was ignored".to_string(),
            },
            None,
        )
    }
}

pub async fn sort(ctx: &mut DiagContext) -> CheckResult {
    let prefix = ctx.opts.prefix.clone();
    let filter = format!("userName sw \"{prefix}\"");
    let desc = match ctx
        .client
        .get_query(
            "/Users",
            &[
                ("filter", filter.as_str()),
                ("sortBy", "userName"),
                ("sortOrder", "descending"),
            ],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let asc = match ctx
        .client
        .get_query(
            "/Users",
            &[
                ("filter", filter.as_str()),
                ("sortBy", "userName"),
                ("sortOrder", "ascending"),
            ],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if desc.status != 200 || asc.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET ...&sortBy=userName -> descending {} / ascending {} (expected 200/200)",
                    desc.status, asc.status
                ),
            },
            None,
        );
    }
    let ids = |r: &ScimResponse| -> Vec<String> {
        r.ptr("/Resources")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.get("id").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    let desc_ids = ids(&desc);
    let mut asc_ids = ids(&asc);
    asc_ids.reverse();

    if desc_ids.is_empty() {
        return (
            Verdict::Skip {
                reason: "no own fixtures returned to compare sort order".to_string(),
            },
            None,
        );
    }
    if desc_ids == asc_ids {
        ctx.state.sort_observed = Some(true);
        (Verdict::Pass { detected: None }, None)
    } else {
        ctx.state.sort_observed = Some(false);
        (
            Verdict::Fail {
                detail: "sortOrder ignored: descending result is not the reverse of ascending"
                    .to_string(),
            },
            None,
        )
    }
}

/// Rides on `spc.change_password_supported`'s PATCH (the catalog runs this
/// immediately after it, §5.9 position 11) rather than issuing its own PATCH
/// — a second password-change write would be a second write with no upside,
/// same reasoning as `rfc.patch_204_or_200` reusing `rfc.patch_add_remove`'s
/// response. Also does its own `GET /Users/{U3}`: a value could be stripped
/// from the PATCH response yet still leak through a subsequent read.
///
/// A `password` key showing up in either place is `Severity::Error`: unlike
/// every other Tier 2 mismatch, this is a genuine credential-disclosure
/// finding, not a conformance nuance.
pub async fn password_never_returned(ctx: &mut DiagContext) -> CheckResult {
    let Some(patch_response) = ctx.state.change_password_response.clone() else {
        return (
            Verdict::Skip {
                reason: "requires spc.change_password_supported to have run".to_string(),
            },
            None,
        );
    };
    let u3 = { ctx.fixtures.lock().unwrap().u3.clone() };
    let Some(u3) = u3 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U3, which was not created".to_string(),
            },
            None,
        );
    };

    if patch_response.get("password").is_some() {
        return (
            Verdict::Fail {
                detail: "PATCH response for the password change included a \"password\" field"
                    .to_string(),
            },
            None,
        );
    }

    let get_resp = match ctx.client.get(&format!("/Users/{}", u3.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if get_resp.ptr("/password").is_some() {
        return (
            Verdict::Fail {
                detail: "GET /Users/{id} after a password change included a \"password\" field"
                    .to_string(),
            },
            None,
        );
    }

    (Verdict::Pass { detected: None }, None)
}

/// **Must run last** (§5.9's catalog ordering): it deletes U2, which
/// `rfc.pagination`/`rfc.sort` (and anything else counting "3 own
/// fixtures") depend on.
pub async fn delete_then_get(ctx: &mut DiagContext) -> CheckResult {
    let u2 = { ctx.fixtures.lock().unwrap().u2.clone() };
    let Some(u2) = u2 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U2, which was not created".to_string(),
            },
            None,
        );
    };
    let del_resp = match ctx
        .client
        .request(Method::DELETE, &format!("/Users/{}", u2.id), &[], None, &[])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if del_resp.status != 204 {
        return (
            Verdict::Fail {
                detail: format!(
                    "DELETE /Users/{} -> {} (expected 204)",
                    u2.id, del_resp.status
                ),
            },
            None,
        );
    }
    let get_resp = match ctx.client.get(&format!("/Users/{}", u2.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if get_resp.status == 404 {
        // Already gone: drop it from `created` so it reads as an honest
        // "still needs cleanup" list to anyone inspecting it mid-run (a
        // second DELETE in `fixtures::cleanup` would be a harmless
        // 404-is-success no-op either way).
        ctx.fixtures
            .lock()
            .unwrap()
            .created
            .retain(|(k, id, _)| !(*k == ResourceKind::User && id == &u2.id));
        (Verdict::Pass { detected: None }, None)
    } else if get_resp.status == 200 {
        (
            Verdict::Fail {
                detail: "user is still readable (200) after DELETE -- soft delete / still readable"
                    .to_string(),
            },
            None,
        )
    } else {
        (
            Verdict::Error {
                detail: format!("GET after DELETE -> {} (expected 404)", get_resp.status),
            },
            None,
        )
    }
}
