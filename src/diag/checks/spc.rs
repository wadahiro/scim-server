//! Tier 3 — advertised (`ServiceProviderConfig`) vs observed behaviour.
//!
//! Every check here compares `ctx.spc` (fetched once during preflight,
//! §`diag::preflight`) against observations other checks recorded in
//! `ctx.state` — agreement is `Pass`, a mismatch is `Fail`
//! (`Severity::Warning` throughout this tier, per the design note's Tier 3
//! table preamble), and the SPC simply omitting the field being compared is
//! `Skip`. `spc.filter_max_results`, `spc.bulk_supported`, and
//! `spc.change_password_supported` are the exceptions: they issue their own
//! probe rather than only reading `ctx.state`.
//!
//! `spc.etag_supported` reads `ctx.state.etag_observed`, which
//! `etag.response_header` (Tier 4) sets — that's why the catalog runs the
//! `etag.response_header`/`matches_meta_version`/`weak_form` trio *before*
//! this module's entries (§5.9 position 4 vs position 10).

use reqwest::Method;
use serde_json::{json, Value};

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

fn no_spc() -> CheckResult {
    skip("ServiceProviderConfig response was not available (see rfc.connect)")
}

pub async fn wellformed(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    let mut missing = Vec::new();

    let has_schema_urn = spc
        .pointer("/schemas")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter().any(|s| {
                s.as_str() == Some("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")
            })
        })
        .unwrap_or(false);
    if !has_schema_urn {
        missing.push("schemas (ServiceProviderConfig URN)".to_string());
    }

    for member in [
        "patch",
        "bulk",
        "filter",
        "changePassword",
        "sort",
        "etag",
        "authenticationSchemes",
    ] {
        if spc.get(member).is_none() {
            missing.push(member.to_string());
        }
    }

    if missing.is_empty() {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!("ServiceProviderConfig missing: {}", missing.join(", ")),
            },
            None,
        )
    }
}

/// Compares one advertised `<member>.supported` boolean against an
/// observation already recorded in `ctx.state`. Shared by
/// `filter_supported`/`patch_supported`/`sort_supported`/`etag_supported`,
/// which differ only in which SPC member and which `ProbeState` field they
/// read.
fn compare_supported(
    spc: &Value,
    member: &str,
    observed: Option<bool>,
    observed_from: &str,
) -> CheckResult {
    let Some(advertised) = spc
        .pointer(&format!("/{member}/supported"))
        .and_then(Value::as_bool)
    else {
        return skip(format!(
            "ServiceProviderConfig has no {member}.supported field"
        ));
    };
    let Some(observed) = observed else {
        return skip(format!(
            "no observed {member} behaviour ({observed_from} did not run)"
        ));
    };
    if advertised == observed {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "advertised {member}.supported={advertised} but observed behaviour was {observed}"
                ),
            },
            None,
        )
    }
}

pub async fn filter_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    compare_supported(
        &spc,
        "filter",
        ctx.state.filter_observed,
        "rfc.filter_eq_username / rfc.filter_sw",
    )
}

pub async fn patch_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    compare_supported(
        &spc,
        "patch",
        ctx.state.patch_observed,
        "rfc.patch_add_remove",
    )
}

pub async fn sort_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    compare_supported(&spc, "sort", ctx.state.sort_observed, "rfc.sort")
}

pub async fn etag_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    compare_supported(
        &spc,
        "etag",
        ctx.state.etag_observed,
        "etag.response_header (tier4)",
    )
}

/// Unlike the four `*_supported` comparisons above, this one issues its own
/// probe: `GET /Users?count={maxResults+1}` and checks the server clamps
/// `itemsPerPage` to the advertised `filter.maxResults` rather than echoing
/// back whatever was requested. Read-only-safe (a plain `GET`), so
/// `needs: &[]` in the catalog.
pub async fn filter_max_results(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    let Some(max_results) = spc.pointer("/filter/maxResults").and_then(Value::as_i64) else {
        return skip("ServiceProviderConfig has no filter.maxResults field");
    };
    if max_results <= 0 {
        return skip(format!(
            "filter.maxResults is {max_results}; nothing to clamp against"
        ));
    }
    let requested = (max_results + 1).to_string();
    let resp = match ctx
        .client
        .get_query("/Users", &[("count", requested.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Fail {
                detail: format!(
                    "GET /Users?count={requested} -> {} (expected 200)",
                    resp.status
                ),
            },
            None,
        );
    }
    match resp.ptr("/itemsPerPage").and_then(Value::as_i64) {
        Some(n) if n <= max_results => (Verdict::Pass { detected: None }, None),
        Some(n) => (
            Verdict::Fail {
                detail: format!(
                    "itemsPerPage {n} exceeds advertised filter.maxResults {max_results}"
                ),
            },
            None,
        ),
        None => (
            Verdict::Fail {
                detail: "response has no itemsPerPage to compare against filter.maxResults"
                    .to_string(),
            },
            None,
        ),
    }
}

/// Never sends a real bulk payload: an empty `Operations` array is enough
/// to tell whether the endpoint exists at all (404/501) without exercising
/// bulk semantics this tool doesn't otherwise validate.
pub async fn bulk_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    let Some(advertised) = spc.pointer("/bulk/supported").and_then(Value::as_bool) else {
        return skip("ServiceProviderConfig has no bulk.supported field");
    };
    if !advertised {
        return skip("bulk.supported is false; nothing to verify");
    }
    let body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
        "Operations": []
    });
    let resp = match ctx
        .client
        .request(Method::POST, "/Bulk", &[], Some(&body), &[])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        404 | 501 => (
            Verdict::Fail {
                detail: format!(
                    "bulk.supported=true but POST /Bulk -> {} (advertised but absent)",
                    resp.status
                ),
            },
            None,
        ),
        _ => (Verdict::Pass { detected: None }, None),
    }
}

/// Stashes the PATCH response body in `ctx.state.change_password_response`
/// regardless of outcome — `rfc.password_never_returned` (catalog position
/// right after this one, §5.9) consumes it.
pub async fn change_password_supported(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    let Some(advertised) = spc
        .pointer("/changePassword/supported")
        .and_then(Value::as_bool)
    else {
        return skip("ServiceProviderConfig has no changePassword.supported field");
    };
    if !advertised {
        return skip("changePassword.supported is false; nothing to verify");
    }
    let u3 = { ctx.fixtures.lock().unwrap().u3.clone() };
    let Some(u3) = u3 else {
        return skip("requires fixture U3, which was not created");
    };
    let new_password = format!("{}-ChangePw1!", ctx.opts.prefix);
    let body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": "password", "value": new_password }]
    });
    let resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u3.id),
            &[],
            Some(&body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    ctx.state.change_password_response = Some(resp.body.clone().unwrap_or(Value::Null));

    if resp.status == 501 {
        return (
            Verdict::Fail {
                detail: "changePassword.supported=true but PATCH password -> 501 Not Implemented"
                    .to_string(),
            },
            None,
        );
    }
    if resp.status == 400 && resp.ptr("/scimType").and_then(Value::as_str) == Some("invalidValue") {
        return (
            Verdict::Fail {
                detail: "changePassword.supported=true but PATCH password -> 400 invalidValue"
                    .to_string(),
            },
            None,
        );
    }
    if !resp.is_success() {
        return (
            Verdict::Fail {
                detail: format!(
                    "changePassword.supported=true but PATCH password -> {} ({})",
                    resp.status,
                    resp.detail()
                ),
            },
            None,
        );
    }
    (Verdict::Pass { detected: None }, None)
}

/// Heuristic keyword match rather than an exact string: real SCIM servers
/// spell `authenticationSchemes[].type` inconsistently (`"oauthbearertoken"`,
/// `"oauth2"`, `"bearer"`, ...), and this tool's own scheme creation
/// (`service_provider.rs::create_authentication_schemes_for_tenant`) uses
/// yet another spelling — there is no single canonical string to match
/// exactly against.
fn auth_kind_matches(auth: crate::diag::cli::AuthKind, scheme_type: &str) -> bool {
    use crate::diag::cli::AuthKind;
    let t = scheme_type.to_lowercase();
    match auth {
        AuthKind::Bearer | AuthKind::Token => {
            t.contains("oauth") || t.contains("bearer") || t.contains("token")
        }
        AuthKind::Basic => t.contains("basic"),
        AuthKind::None => t.contains("none") || t.contains("anonymous"),
    }
}

pub async fn auth_schemes_match(ctx: &mut DiagContext) -> CheckResult {
    let Some(spc) = ctx.spc.clone() else {
        return no_spc();
    };
    let Some(schemes) = spc
        .pointer("/authenticationSchemes")
        .and_then(Value::as_array)
    else {
        return skip("ServiceProviderConfig has no authenticationSchemes field");
    };
    if schemes.is_empty() && ctx.opts.auth == crate::diag::cli::AuthKind::None {
        return (Verdict::Pass { detected: None }, None);
    }
    let types: Vec<&str> = schemes
        .iter()
        .filter_map(|s| s.get("type").and_then(Value::as_str))
        .collect();
    if types.iter().any(|t| auth_kind_matches(ctx.opts.auth, t)) {
        (Verdict::Pass { detected: None }, None)
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "--auth {:?} was used, but authenticationSchemes advertises only: {}",
                    ctx.opts.auth,
                    types.join(", ")
                ),
            },
            None,
        )
    }
}
