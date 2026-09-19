//! Tier 1 — the 7 `CompatibilityConfig` knobs (8 checks: `groups_consistency`
//! is an extra `Severity::Info` observation with no knob of its own, folded
//! in between `include_user_groups` and the two group-filter checks per the
//! catalog table).

use reqwest::Method;
use serde_json::{json, Value};

use crate::diag::ctx::DiagContext;
use crate::diag::model::{CheckResult, KnobValue, Verdict};

fn err(e: crate::diag::DiagError) -> CheckResult {
    (
        Verdict::Error {
            detail: e.to_string(),
        },
        None,
    )
}

#[derive(PartialEq, Eq, Debug)]
enum Class {
    Rfc3339,
    Epoch,
    Unknown,
}

fn classify(v: &Value) -> Class {
    match v {
        Value::Number(_) => Class::Epoch,
        Value::String(s)
            if s.chars().all(|c| c.is_ascii_digit()) && (10..=16).contains(&s.len()) =>
        {
            Class::Epoch
        }
        Value::String(s) if chrono::DateTime::parse_from_rfc3339(s).is_ok() => Class::Rfc3339,
        _ => Class::Unknown,
    }
}

/// `needs: &[]` deliberately (see `checks::mod::catalog`): this one has to
/// keep working in read-only mode by falling back to whatever the first
/// item of a plain `GET /Users?count=1` looks like, so it can't gate on
/// `Need::U1`/`Need::Writes` like the rest of Tier 1.
pub async fn meta_datetime_format(ctx: &mut DiagContext) -> CheckResult {
    let (u1, g1) = {
        let fx = ctx.fixtures.lock().unwrap();
        (fx.u1.clone(), fx.g1.clone())
    };

    let mut samples: Vec<(String, Value)> = Vec::new();

    if let Some(u1) = &u1 {
        match ctx.client.get(&format!("/Users/{}", u1.id)).await {
            Ok(resp) if resp.status == 200 => {
                if let Some(c) = resp.ptr("/meta/created") {
                    samples.push(("User.meta.created".to_string(), c.clone()));
                }
                if let Some(m) = resp.ptr("/meta/lastModified") {
                    samples.push(("User.meta.lastModified".to_string(), m.clone()));
                }
            }
            Ok(_) | Err(_) => {}
        }
    }
    if let Some(g1) = &g1 {
        if let Ok(resp) = ctx.client.get(&format!("/Groups/{}", g1.id)).await {
            if resp.status == 200 {
                if let Some(c) = resp.ptr("/meta/created") {
                    samples.push(("Group.meta.created".to_string(), c.clone()));
                }
                if let Some(m) = resp.ptr("/meta/lastModified") {
                    samples.push(("Group.meta.lastModified".to_string(), m.clone()));
                }
            }
        }
    }

    if samples.is_empty() {
        if let Ok(resp) = ctx.client.get_query("/Users", &[("count", "1")]).await {
            if resp.status == 200 {
                if let Some(first) = resp.ptr("/Resources/0") {
                    if let Some(c) = first.pointer("/meta/created") {
                        samples.push(("Resources[0].meta.created".to_string(), c.clone()));
                    }
                    if let Some(m) = first.pointer("/meta/lastModified") {
                        samples.push(("Resources[0].meta.lastModified".to_string(), m.clone()));
                    }
                }
            }
        }
    }

    if samples.is_empty() {
        return (
            Verdict::Skip {
                reason: "no resource available to inspect in read-only mode".to_string(),
            },
            None,
        );
    }

    let classes: Vec<(&str, Class)> = samples
        .iter()
        .map(|(label, v)| (label.as_str(), classify(v)))
        .collect();

    if let Some((label, _)) = classes.iter().find(|(_, c)| *c == Class::Unknown) {
        let v = samples.iter().find(|(l, _)| l == label).unwrap().1.clone();
        return (
            Verdict::Fail {
                detail: format!("unrecognised datetime encoding in {label}: {v}"),
            },
            None,
        );
    }
    let all_rfc = classes.iter().all(|(_, c)| *c == Class::Rfc3339);
    let all_epoch = classes.iter().all(|(_, c)| *c == Class::Epoch);
    if all_rfc {
        (
            Verdict::Pass {
                detected: Some(KnobValue::Str("rfc3339".to_string())),
            },
            None,
        )
    } else if all_epoch {
        (
            Verdict::Quirk {
                detected: KnobValue::Str("epoch".to_string()),
            },
            None,
        )
    } else {
        let seen: Vec<String> = samples.iter().map(|(l, v)| format!("{l}={v}")).collect();
        (
            Verdict::Fail {
                detail: "inconsistent datetime encoding between fields/resources".to_string(),
            },
            Some(seen.join(", ")),
        )
    }
}

pub async fn show_empty_groups_members(ctx: &mut DiagContext) -> CheckResult {
    let g2 = { ctx.fixtures.lock().unwrap().g2.clone() };
    let Some(g2) = g2 else {
        return (
            Verdict::Skip {
                reason: "requires fixture G2, which was not created".to_string(),
            },
            None,
        );
    };
    let resp = match ctx.client.get(&format!("/Groups/{}", g2.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Error {
                detail: format!("GET /Groups/{} -> {} (expected 200)", g2.id, resp.status),
            },
            None,
        );
    }
    match resp.ptr("/members") {
        Some(_) => (
            Verdict::Pass {
                detected: Some(KnobValue::Bool(true)),
            },
            None,
        ),
        None => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            None,
        ),
    }
}

pub async fn include_user_groups(ctx: &mut DiagContext) -> CheckResult {
    let (u1, g1) = {
        let fx = ctx.fixtures.lock().unwrap();
        (fx.u1.clone(), fx.g1.clone())
    };
    let (Some(u1), Some(g1)) = (u1, g1) else {
        return (
            Verdict::Skip {
                reason: "requires fixtures U1 and G1, which were not created".to_string(),
            },
            None,
        );
    };
    let resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    if resp.status != 200 {
        return (
            Verdict::Error {
                detail: format!("GET /Users/{} -> {} (expected 200)", u1.id, resp.status),
            },
            None,
        );
    }
    match resp.ptr("/groups") {
        None => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            None,
        ),
        Some(groups) => {
            let has_g1 = groups
                .as_array()
                .map(|a| {
                    a.iter()
                        .any(|g| g.get("value").and_then(Value::as_str) == Some(g1.id.as_str()))
                })
                .unwrap_or(false);
            if has_g1 {
                (
                    Verdict::Pass {
                        detected: Some(KnobValue::Bool(true)),
                    },
                    None,
                )
            } else {
                (
                    Verdict::Fail {
                        detail: "groups returned but the known membership is not reflected"
                            .to_string(),
                    },
                    None,
                )
            }
        }
    }
}

/// No knob of its own (`Severity::Info`) — checks that the "empty
/// `groups`/`members` display" behaviour is symmetric between User and
/// Group, which `show_empty_groups_members`/`include_user_groups` can't
/// individually tell apart from a real asymmetry in the target server.
pub async fn groups_consistency(ctx: &mut DiagContext) -> CheckResult {
    let (u2, g2) = {
        let fx = ctx.fixtures.lock().unwrap();
        (fx.u2.clone(), fx.g2.clone())
    };
    let (Some(u2), Some(g2)) = (u2, g2) else {
        return (
            Verdict::Skip {
                reason: "requires fixtures U2 and G2, which were not created".to_string(),
            },
            None,
        );
    };
    let u2_resp = match ctx.client.get(&format!("/Users/{}", u2.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let g2_resp = match ctx.client.get(&format!("/Groups/{}", g2.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let u2_groups_absent = u2_resp.ptr("/groups").is_none();
    let g2_members_is_empty_array = g2_resp
        .ptr("/members")
        .map(|v| v == &Value::Array(vec![]))
        .unwrap_or(false);

    if u2_groups_absent && g2_members_is_empty_array {
        (
            Verdict::Pass { detected: None },
            Some(
                "asymmetric by design: User.groups is omitted when empty, but Group.members is an explicit empty array — not expressible as a single knob"
                    .to_string(),
            ),
        )
    } else {
        (Verdict::Pass { detected: None }, None)
    }
}

pub async fn support_group_members_filter(ctx: &mut DiagContext) -> CheckResult {
    let (u1, g1) = {
        let fx = ctx.fixtures.lock().unwrap();
        (fx.u1.clone(), fx.g1.clone())
    };
    let (Some(u1), Some(g1)) = (u1, g1) else {
        return (
            Verdict::Skip {
                reason: "requires fixtures U1 and G1, which were not created".to_string(),
            },
            None,
        );
    };
    let filter = format!("members[value eq \"{}\"]", u1.id);
    let resp = match ctx
        .client
        .get_query("/Groups", &[("filter", filter.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        400 => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            None,
        ),
        501 => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            Some("returned 501 not 400".to_string()),
        ),
        200 => {
            let has_g1 = resp
                .ptr("/Resources")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .any(|g| g.get("id").and_then(Value::as_str) == Some(g1.id.as_str()))
                })
                .unwrap_or(false);
            if has_g1 {
                (
                    Verdict::Pass {
                        detected: Some(KnobValue::Bool(true)),
                    },
                    None,
                )
            } else {
                (
                    Verdict::Fail {
                        detail: "filter accepted but did not return the known containing group"
                            .to_string(),
                    },
                    None,
                )
            }
        }
        other => (
            Verdict::Error {
                detail: format!("GET /Groups?filter=members[...] -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

pub async fn support_group_displayname_filter(ctx: &mut DiagContext) -> CheckResult {
    let g1 = { ctx.fixtures.lock().unwrap().g1.clone() };
    let Some(g1) = g1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture G1, which was not created".to_string(),
            },
            None,
        );
    };
    let filter = format!("displayName eq \"{}\"", g1.display_name);
    let resp = match ctx
        .client
        .get_query("/Groups", &[("filter", filter.as_str())])
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match resp.status {
        400 => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            None,
        ),
        501 => (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            Some("returned 501 not 400".to_string()),
        ),
        200 => {
            let has_g1 = resp
                .ptr("/Resources")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .any(|g| g.get("id").and_then(Value::as_str) == Some(g1.id.as_str()))
                })
                .unwrap_or(false);
            if has_g1 {
                (
                    Verdict::Pass {
                        detected: Some(KnobValue::Bool(true)),
                    },
                    None,
                )
            } else {
                (
                    Verdict::Fail {
                        detail: "filter accepted but did not return the known containing group"
                            .to_string(),
                    },
                    None,
                )
            }
        }
        other => (
            Verdict::Error {
                detail: format!("GET /Groups?filter=displayName eq ... -> {other} (unexpected)"),
            },
            None,
        ),
    }
}

fn patch_add_value(attr: &str, phone_or_email: &str) -> Value {
    if attr == "emails" {
        json!([{ "value": phone_or_email, "type": "work", "primary": true }])
    } else {
        json!([{ "value": phone_or_email, "type": "work" }])
    }
}

pub async fn support_patch_replace_empty_array(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let attr = ctx.opts.probe_attribute.attr_name();
    let seed = if attr == "emails" {
        u1.email.clone()
    } else {
        "+15555550100".to_string()
    };

    let add_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "add", "path": attr, "value": patch_add_value(attr, &seed) }]
    });
    if let Err(e) = ctx
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
        return err(e);
    }

    let clear_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": attr, "value": [] }]
    });
    let clear_resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&clear_body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    if clear_resp.status == 400 {
        return (
            Verdict::Quirk {
                detected: KnobValue::Bool(false),
            },
            None,
        );
    }
    if !clear_resp.is_success() {
        return (
            Verdict::Error {
                detail: format!(
                    "PATCH replace {attr}=[] -> {} (unexpected)",
                    clear_resp.status
                ),
            },
            None,
        );
    }

    let get_resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    let cleared = match get_resp.ptr(&format!("/{attr}")) {
        None => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(_) => false,
    };
    if cleared {
        (
            Verdict::Pass {
                detected: Some(KnobValue::Bool(true)),
            },
            None,
        )
    } else {
        (
            Verdict::Fail {
                detail: format!(
                    "PATCH replace {attr}=[] returned 2xx but the attribute was not cleared"
                ),
            },
            None,
        )
    }
}

pub async fn support_patch_replace_empty_value(ctx: &mut DiagContext) -> CheckResult {
    let u1 = { ctx.fixtures.lock().unwrap().u1.clone() };
    let Some(u1) = u1 else {
        return (
            Verdict::Skip {
                reason: "requires fixture U1, which was not created".to_string(),
            },
            None,
        );
    };
    let attr = ctx.opts.probe_attribute.attr_name();
    let seed = if attr == "emails" {
        u1.email.clone()
    } else {
        "+15555550100".to_string()
    };

    let add_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "add", "path": attr, "value": patch_add_value(attr, &seed) }]
    });
    if let Err(e) = ctx
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
        return err(e);
    }

    let clear_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{ "op": "replace", "path": attr, "value": [{ "value": "" }] }]
    });
    let clear_resp = match ctx
        .client
        .request(
            Method::PATCH,
            &format!("/Users/{}", u1.id),
            &[],
            Some(&clear_body),
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => return err(e),
    };

    if clear_resp.status == 400 {
        // Matches this tool's own default (`support_patch_replace_empty_value: false`).
        return (
            Verdict::Pass {
                detected: Some(KnobValue::Bool(false)),
            },
            None,
        );
    }
    if !clear_resp.is_success() {
        return (
            Verdict::Error {
                detail: format!(
                    "PATCH replace {attr}=[{{\"value\":\"\"}}] -> {} (unexpected)",
                    clear_resp.status
                ),
            },
            None,
        );
    }

    let get_resp = match ctx.client.get(&format!("/Users/{}", u1.id)).await {
        Ok(r) => r,
        Err(e) => return err(e),
    };
    match get_resp.ptr(&format!("/{attr}")) {
        None => (
            Verdict::Quirk {
                detected: KnobValue::Bool(true),
            },
            None,
        ),
        Some(Value::Array(a)) if a.is_empty() => (
            Verdict::Quirk {
                detected: KnobValue::Bool(true),
            },
            None,
        ),
        Some(Value::Array(a))
            if a.len() == 1
                && a[0].as_object().map(|o| o.len()) == Some(1)
                && a[0].get("value").and_then(Value::as_str) == Some("") =>
        {
            (
                Verdict::Fail {
                    detail: "accepted (2xx) and stored the garbage empty value verbatim".to_string(),
                },
                None,
            )
        }
        Some(_) => (
            Verdict::Fail {
                detail: "accepted (2xx) but the resulting attribute state is neither cleared nor the stored garbage-value pattern".to_string(),
            },
            None,
        ),
    }
}
