//! Executes a generated [`DerivedAxis`] list against a live server. Ported
//! from `feat/rfc-extract`'s `crates/scim-conformance/src/matrix/exec.rs` --
//! the request-construction logic (`set_attr`, `patch_body`,
//! `build_patch_request`, `container_is_readonly`,
//! `patch_targets_decl_precisely`, `valid_value_for`, `wrong_value_for`,
//! `forged_value_for`, `values_match`, `first_writable_subattr`,
//! `immutable_post_payload`) is taken over close to 1:1, since these are the
//! pure functions `tests/diagnose_derived_matrix_test.rs`'s targeting
//! invariant depends on being the *exact* functions a live run calls, not a
//! parallel reimplementation. What's adapted: `Outcome`/`Verdict` on that
//! branch becomes this crate's `Observation`/`Value` -- each executor below
//! classifies its own findings against its `DerivedAxis::known` vocabulary
//! and lets `DerivedAxis::is_fault` (not a value baked into the probe)
//! decide whether a given token is a fault, the same division of labour as
//! `crate::axes`'s seven static probes.
//!
//! Every "hard-won detail" from the source branch is carried across:
//! - A readOnly attribute's PATCH judgement uses RFC 7644 §3.5.2 / Table 9
//!   (`scimType: mutability`), not POST/PUT's "silently ignored is
//!   correct" rule (§3.3 / §3.5.1) -- see `exec_readonly`.
//! - A readOnly sub-attribute of a ReadWrite multi-valued complex attribute
//!   (only `Group.members.display` today) is targeted with a value filter
//!   (`members[value eq "<id>"].display`), never by replacing the whole
//!   container -- see `container_is_readonly`/`patch_targets_decl_precisely`/
//!   `build_patch_request`.
//! - A forged `Group.members[]` / `User.groups[]` value is judged on both
//!   the POST response and a follow-up GET -- one known provider behaviour
//!   echoes only in the create response, not a subsequent read.

use serde_json::{json, Value as Json};

use super::derive::{
    is_container_skip, is_group_member_ref, is_group_member_subattr, DerivedAxis, Method,
};
use crate::axis::{Observation, Unobservable, Value};
use crate::capability::{self, Capability};
use crate::client::{truncate, ScimClient};
use crate::fixtures::{
    body_of, cleanup, is_2xx, safe, short_uid, Bookkeeping, GROUP_URN, PATCHOP_URN, USER_URN,
};
use crate::schema::{AttrDecl, AttrType, Mutability, Resource, Returned};

pub const ENTERPRISE_URN: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

fn resource_endpoint(resource: Resource) -> &'static str {
    resource.endpoint()
}

fn make_baseline(resource: Resource) -> Json {
    match resource {
        Resource::User | Resource::EnterpriseUser => json!({
            "schemas": [USER_URN],
            "userName": format!("u-{}", short_uid()),
        }),
        Resource::Group => json!({
            "schemas": [GROUP_URN],
            "displayName": format!("g-{}", short_uid()),
        }),
    }
}

// -------------------------------------------------------- payload plumbing

fn ensure_enterprise(payload: &mut Json) -> &mut Json {
    let obj = payload.as_object_mut().expect("payload must be an object");
    let schemas = obj
        .entry("schemas")
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .expect("schemas must be an array");
    if !schemas.iter().any(|s| s.as_str() == Some(ENTERPRISE_URN)) {
        schemas.push(json!(ENTERPRISE_URN));
    }
    obj.entry(ENTERPRISE_URN).or_insert_with(|| json!({}))
}

fn path_segments(decl: &AttrDecl) -> Vec<&str> {
    decl.path.split('.').collect()
}

fn set_attr_with_companion(
    payload: &mut Json,
    decl: &AttrDecl,
    value: Json,
    companion: Option<Json>,
) {
    let target = if decl.resource == Resource::EnterpriseUser {
        ensure_enterprise(payload)
    } else {
        payload
    };
    let segs = path_segments(decl);
    if segs.len() == 1 {
        target[segs[0]] = value;
        return;
    }
    let top = segs[0];
    let sub = segs[1];
    let mut obj = serde_json::Map::new();
    obj.insert(sub.to_string(), value);
    if let Some(c) = companion {
        if sub != "value" {
            obj.insert("value".to_string(), c);
        }
    }
    if decl.top_multi_valued {
        target[top] = json!([Json::Object(obj)]);
    } else {
        target[top] = Json::Object(obj);
    }
}

fn set_attr(payload: &mut Json, decl: &AttrDecl, value: Json) {
    set_attr_with_companion(payload, decl, value, None);
}

fn get_attr(resource_json: &Json, decl: &AttrDecl) -> (bool, Json) {
    let target: &Json = if decl.resource == Resource::EnterpriseUser {
        match resource_json.get(ENTERPRISE_URN) {
            Some(v) if !v.is_null() => v,
            _ => return (false, Json::Null),
        }
    } else {
        resource_json
    };
    let segs = path_segments(decl);
    if segs.len() == 1 {
        return match target.get(segs[0]) {
            Some(v) if !v.is_null() => (true, v.clone()),
            _ => (false, Json::Null),
        };
    }
    let top = segs[0];
    let sub = segs[1];
    let container = match target.get(top) {
        Some(v) if !v.is_null() => v,
        _ => return (false, Json::Null),
    };
    if decl.top_multi_valued {
        if let Some(first) = container.as_array().and_then(|a| a.first()) {
            if let Some(v) = first.get(sub) {
                if !v.is_null() {
                    return (true, v.clone());
                }
            }
        }
        (false, Json::Null)
    } else {
        match container.get(sub) {
            Some(v) if !v.is_null() => (true, v.clone()),
            _ => (false, Json::Null),
        }
    }
}

fn dotted_path(decl: &AttrDecl) -> String {
    if decl.resource == Resource::EnterpriseUser {
        format!("{}:{}", ENTERPRISE_URN, decl.path)
    } else {
        decl.path.clone()
    }
}

/// True when `decl.top()`'s own (depth-1) attribute declaration is itself
/// `readOnly`. Distinguishes `User.groups.*` (the container `groups` is
/// readOnly, so a coarse `path: "groups"` PATCH already exercises the
/// *container's* mutability rule and is a sound probe) from
/// `Group.members.display` (the container `members` is ReadWrite, so a
/// coarse `path: "members"` replace is a legitimate write of a ReadWrite
/// attribute and proves nothing about `display`'s mutability).
fn container_is_readonly(decl: &AttrDecl, universe: &[&AttrDecl]) -> bool {
    let top = decl.top();
    universe.iter().any(|d| {
        d.resource == decl.resource
            && d.depth() == 1
            && d.path == top
            && d.mutability == Mutability::ReadOnly
    })
}

fn filter_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn patch_path(decl: &AttrDecl) -> String {
    let segs = path_segments(decl);
    if segs.len() > 1 && decl.top_multi_valued {
        let top = segs[0];
        if decl.resource == Resource::EnterpriseUser {
            format!("{}:{}", ENTERPRISE_URN, top)
        } else {
            top.to_string()
        }
    } else {
        dotted_path(decl)
    }
}

fn patch_value_for(decl: &AttrDecl, value: Json) -> Json {
    let segs = path_segments(decl);
    if segs.len() > 1 && decl.top_multi_valued {
        let sub = segs[1];
        json!([{ sub: value }])
    } else {
        value
    }
}

fn patch_body(decl: &AttrDecl, value: Json) -> Json {
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            { "op": "replace", "path": patch_path(decl), "value": patch_value_for(decl, value) }
        ],
    })
}

/// Whether a PATCH `replace` naming [`patch_path`]'s output as its `path`
/// actually isolates `decl.path`'s own characteristic -- see this module's
/// doc comment's "hard-won details" list.
pub fn patch_targets_decl_precisely(decl: &AttrDecl, universe: &[&AttrDecl]) -> bool {
    !(decl.depth() > 1 && decl.top_multi_valued) || container_is_readonly(decl, universe)
}

fn value_filtered_patch_request(decl: &AttrDecl, filter_value: &Json, new_value: Json) -> Json {
    let segs = path_segments(decl);
    let sub = segs[1];
    let filter_str = match filter_value {
        Json::String(s) => s.clone(),
        other => other.to_string(),
    };
    let top_prefixed = if decl.resource == Resource::EnterpriseUser {
        format!("{}:{}", ENTERPRISE_URN, segs[0])
    } else {
        segs[0].to_string()
    };
    let path = format!(
        "{top_prefixed}[value eq \"{}\"].{sub}",
        filter_escape(&filter_str)
    );
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            { "op": "replace", "path": path, "value": new_value }
        ],
    })
}

/// The outcome of composing the PATCH request for one derived instance.
///
/// `Unavailable` is not a failure: it is the honest answer when no request
/// can isolate the declared attribute, and the caller must report the
/// instance `Unobservable` rather than judging a request that proves
/// nothing (see `build_patch_request`).
pub enum PatchRequestPlan {
    Body(Json),
    Unavailable(&'static str),
}

/// Composes the PATCH request for one derived instance -- the single entry
/// point the executors use, so the targeting invariant in
/// `tests/diagnose_derived_matrix_test.rs` can assert against *this*
/// function rather than a copy of its logic. Duplicating the rule in the
/// test would let production drift away from it unnoticed, which is exactly
/// the failure the invariant exists to catch.
pub fn build_patch_request(
    decl: &AttrDecl,
    universe: &[&AttrDecl],
    filter_value: Option<&Json>,
    new_value: Json,
) -> PatchRequestPlan {
    if patch_targets_decl_precisely(decl, universe) {
        PatchRequestPlan::Body(patch_body(decl, new_value))
    } else {
        match filter_value {
            Some(fv) => PatchRequestPlan::Body(value_filtered_patch_request(decl, fv, new_value)),
            None => PatchRequestPlan::Unavailable(
                "cannot target a sub-attribute of a ReadWrite/Immutable multi-valued complex \
                 attribute via PATCH without a resolvable identifying value to filter on",
            ),
        }
    }
}

fn values_match(decl: &AttrDecl, sent: &Json, got: &Json) -> bool {
    if is_group_member_ref(decl) && decl.last() == "$ref" {
        if let (Some(g), Some(s)) = (got.as_str(), sent.as_str()) {
            return g.trim_end_matches('/').ends_with(s.trim_end_matches('/'));
        }
        return false;
    }
    sent == got
}

fn valid_value_for(decl: &AttrDecl) -> Json {
    match decl.path.as_str() {
        "emails.value" => return json!(format!("user-{}@example.com", short_uid())),
        "photos.value" => return json!("http://example.com/photo.jpg"),
        "profileUrl" => return json!("http://example.com/profile"),
        "timezone" => return json!("America/New_York"),
        "locale" => return json!("en-US"),
        "x509Certificates.value" => return json!("M".repeat(120)),
        "members.$ref" => return json!(format!("/Users/{}", short_uid())),
        "manager.value" => return json!(format!("manager-{}", short_uid())),
        _ => {}
    }
    if let Some(first) = decl.canonical_values.as_ref().and_then(|c| c.first()) {
        return json!(first);
    }
    if decl.last() == "type" && decl.r#type == AttrType::String {
        return json!("work");
    }
    match decl.r#type {
        AttrType::String => json!(format!("Valid-{}", short_uid())),
        AttrType::Boolean => json!(true),
        AttrType::Integer => json!(42),
        AttrType::Decimal => json!(4.2),
        AttrType::DateTime => json!("2024-01-01T00:00:00Z"),
        AttrType::Reference => json!(format!("http://example.com/ref/{}", short_uid())),
        AttrType::Complex | AttrType::Binary => json!(format!("Valid-{}", short_uid())),
    }
}

fn wrong_value_for(decl: &AttrDecl) -> Json {
    match decl.r#type {
        AttrType::String => json!(123),
        AttrType::Boolean => json!("yes"),
        AttrType::Integer | AttrType::Decimal => json!("x"),
        AttrType::DateTime => json!(123),
        AttrType::Reference => json!(123),
        AttrType::Complex => json!("flat"),
        AttrType::Binary => json!(123),
    }
}

fn forged_value_for(decl: &AttrDecl) -> Json {
    match decl.r#type {
        AttrType::String => json!(format!("FORGED-{}", short_uid())),
        AttrType::Boolean => json!(true),
        AttrType::Integer => json!(999999),
        AttrType::Decimal => json!(9.99),
        AttrType::DateTime => json!("2001-01-01T00:00:00Z"),
        AttrType::Reference => json!("http://forged.example.com/ref"),
        AttrType::Complex | AttrType::Binary => json!(format!("FORGED-{}", short_uid())),
    }
}

/// The first writable sub-attribute of a top-level complex attribute (JSON
/// declaration order), used to exercise `type_valid` for attributes whose
/// own value is never a bare scalar.
fn first_writable_subattr<'a>(
    universe: &[&'a AttrDecl],
    parent: &AttrDecl,
) -> Option<&'a AttrDecl> {
    universe
        .iter()
        .find(|d| {
            d.resource == parent.resource
                && d.parent.as_deref() == Some(parent.path.as_str())
                && d.mutability != Mutability::ReadOnly
        })
        .copied()
}

/// Builds the baseline creation payload `exec_immutable`'s `PostCreate` leg
/// sends. Returns `(payload, value_actually_placed, member_filter_value)`.
fn immutable_post_payload(
    decl: &AttrDecl,
    mut valid_val: Json,
    companion_id: Option<&str>,
) -> (Json, Json, Option<Json>) {
    let mut payload = make_baseline(decl.resource);
    let mut member_filter_value: Option<Json> = None;
    if is_group_member_subattr(decl) && decl.last() != "value" {
        let sub = path_segments(decl)[1];
        if decl.last() == "$ref" {
            if let Some(id) = companion_id {
                valid_val = json!(format!("/Users/{id}"));
            }
        }
        let mut elem = serde_json::Map::new();
        elem.insert(sub.to_string(), valid_val.clone());
        if let Some(id) = companion_id {
            elem.insert("value".to_string(), json!(id));
            member_filter_value = Some(json!(id));
        }
        payload["members"] = json!([Json::Object(elem)]);
    } else {
        set_attr(&mut payload, decl, valid_val.clone());
        if decl.last() == "value" {
            member_filter_value = Some(valid_val.clone());
        }
    }
    (payload, valid_val, member_filter_value)
}

async fn fresh_user_id(client: &ScimClient, bk: &mut Bookkeeping) -> Option<String> {
    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if is_2xx(r.status) {
        let id = r.id()?;
        bk.note("/Users", id.clone());
        Some(id)
    } else {
        None
    }
}

async fn fresh_group_id(client: &ScimClient, bk: &mut Bookkeeping) -> Option<String> {
    let r = safe(client.post("/Groups", &make_baseline(Resource::Group))).await;
    if is_2xx(r.status) {
        let id = r.id()?;
        bk.note("/Groups", id.clone());
        Some(id)
    } else {
        None
    }
}

async fn companion_value(parent: &str, client: &ScimClient, bk: &mut Bookkeeping) -> Option<Json> {
    match parent {
        "members" => fresh_user_id(client, bk).await.map(|id| json!(id)),
        "groups" => fresh_group_id(client, bk).await.map(|id| json!(id)),
        "manager" => fresh_user_id(client, bk).await.map(|id| json!(id)),
        _ => None,
    }
}

async fn member_ref_override(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Option<Json> {
    let uid = fresh_user_id(client, bk).await?;
    if decl.last() == "$ref" {
        Some(json!(format!("/Users/{}", uid)))
    } else {
        Some(json!(uid))
    }
}

// ------------------------------------------------------------ row helpers

fn known(instance: &DerivedAxis, token: &str) -> Value {
    match instance.known.iter().find(|k| **k == token) {
        Some(k) => Value::Known(k),
        None => Value::Unknown(token.to_string()),
    }
}

fn obs(instance: &DerivedAxis, token: &str, detail: impl Into<String>) -> Observation {
    Observation {
        axis: instance.id.clone(),
        value: known(instance, token),
        evidence: Vec::new(),
        detail: detail.into(),
    }
}

fn obs_with_evidence(
    instance: &DerivedAxis,
    token: &str,
    detail: impl Into<String>,
    evidence: Vec<crate::client::Exchange>,
) -> Observation {
    Observation {
        axis: instance.id.clone(),
        value: known(instance, token),
        evidence,
        detail: detail.into(),
    }
}

fn unobservable(instance: &DerivedAxis, u: Unobservable) -> Observation {
    Observation {
        axis: instance.id.clone(),
        value: Value::Unobservable(u),
        evidence: Vec::new(),
        detail: String::new(),
    }
}

fn na(instance: &DerivedAxis, detail: impl Into<String>) -> Observation {
    obs(instance, "not_applicable", detail)
}

// -------------------------------------------------------------- readOnly

async fn exec_readonly(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_gated: bool,
    universe: &[&AttrDecl],
) -> Vec<Observation> {
    let decl = &group[0].decl;

    if is_container_skip(decl) {
        return vec![na(
            &group[0],
            "complex container decomposed into per-subattribute readOnly checks",
        )];
    }

    let endpoint = resource_endpoint(decl.resource);
    let forged = forged_value_for(decl);
    let by_method = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };

    let companion = if decl.depth() > 1 && decl.last() != "value" {
        match &decl.parent {
            Some(p) => companion_value(p, client, bk).await,
            None => None,
        }
    } else {
        None
    };

    let mut payload = make_baseline(decl.resource);
    set_attr_with_companion(&mut payload, decl, forged.clone(), companion.clone());
    let r = safe(client.post(endpoint, &payload)).await;
    if !is_2xx(r.status) {
        let msg = format!(
            "baseline POST failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        );
        return group
            .iter()
            .map(|a| unobservable(a, Unobservable::ProbeFailed(msg.clone())))
            .collect();
    }
    let rj = body_of(&r);
    let (ok, val) = get_attr(&rj, decl);
    let mut rows = Vec::new();
    let post_axis = by_method(Method::Post);
    let mut post_row = if !ok || val != forged {
        obs_with_evidence(
            post_axis,
            "ignored",
            format!("forged={forged:?} ignored; actual={val:?} present={ok}"),
            vec![r.exchange.clone()],
        )
    } else {
        obs_with_evidence(
            post_axis,
            "leaked",
            format!("forged value {forged:?} took effect on POST"),
            vec![r.exchange.clone()],
        )
    };

    let Some(rid) = rj.get("id").and_then(|v| v.as_str()).map(String::from) else {
        rows.push(post_row);
        rows.push(unobservable(
            by_method(Method::Put),
            Unobservable::ProbeFailed("no id from baseline POST".into()),
        ));
        rows.push(unobservable(
            by_method(Method::Patch),
            Unobservable::ProbeFailed("no id from baseline POST".into()),
        ));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    // A forged value that only shows up on a follow-up GET (not the POST
    // response itself) is just as much a leak -- known behaviour on
    // Group.members / User.groups reference lists.
    if matches!(decl.top(), "members" | "groups")
        && matches!(post_row.value, Value::Known("ignored"))
    {
        let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
        let (gok, gval) = get_attr(&body_of(&getr), decl);
        if gok && gval == forged {
            post_row = obs_with_evidence(
                post_axis,
                "leaked",
                format!(
                    "forged value {forged:?} absent from the POST response but present on \
                     a follow-up GET"
                ),
                vec![r.exchange.clone(), getr.exchange.clone()],
            );
        }
    }
    rows.push(post_row);

    let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let current = body_of(&getr);
    let mut put_body = current.clone();
    if !put_body.is_object() {
        put_body = json!({});
    }
    set_attr_with_companion(&mut put_body, decl, forged.clone(), companion.clone());
    let r2 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    let put_axis = by_method(Method::Put);
    if !is_2xx(r2.status) {
        rows.push(unobservable(
            put_axis,
            Unobservable::ProbeFailed(format!(
                "PUT failed: {} {}",
                r2.status,
                truncate(&r2.raw, 200)
            )),
        ));
    } else {
        let (ok2, val2) = get_attr(&body_of(&r2), decl);
        if !ok2 || val2 != forged {
            rows.push(obs_with_evidence(
                put_axis,
                "ignored",
                format!("forged={forged:?} ignored; actual={val2:?} present={ok2}"),
                vec![r2.exchange.clone()],
            ));
        } else {
            rows.push(obs_with_evidence(
                put_axis,
                "leaked",
                format!("forged value {forged:?} took effect on PUT"),
                vec![r2.exchange.clone()],
            ));
        }
    }

    let patch_axis = by_method(Method::Patch);
    if patch_gated {
        rows.push(unobservable(
            patch_axis,
            Unobservable::CapabilityNotAdvertised("patch"),
        ));
        return rows;
    }

    // RFC 7644 §3.5.2 is stricter than POST's §3.3 / PUT's §3.5.1 "ignore"
    // rule: a PATCH "MUST NOT modify" a readOnly attribute, and the
    // response must be a 400 with scimType=mutability (Table 9) -- silently
    // ignoring the forged value on PATCH is *not* conformant here, unlike
    // POST/PUT.
    let precise = patch_targets_decl_precisely(decl, universe);
    let patch_forged = if precise {
        forged.clone()
    } else {
        forged_value_for(decl)
    };
    let filter_value: Option<Json> = if precise {
        None
    } else {
        let segs = path_segments(decl);
        if segs[1] == "value" {
            Some(forged.clone())
        } else {
            companion.clone()
        }
    };
    let patch_request =
        match build_patch_request(decl, universe, filter_value.as_ref(), patch_forged.clone()) {
            PatchRequestPlan::Body(req) => req,
            PatchRequestPlan::Unavailable(reason) => {
                rows.push(unobservable(
                    patch_axis,
                    Unobservable::ProbeFailed(reason.to_string()),
                ));
                return rows;
            }
        };

    let sent_path = patch_request["Operations"][0]["path"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let r3 = safe(client.patch(&format!("{endpoint}/{rid}"), &patch_request)).await;
    let scim_type = r3.scim_type();
    let evidence = vec![r3.exchange.clone()];
    if r3.status == 400 && scim_type.as_deref() == Some("mutability") {
        rows.push(obs_with_evidence(
            patch_axis,
            "rejected_mutability",
            format!(
                "PATCH path={sent_path:?}: status=400 scimType=mutability; rejected per RFC \
                 7644 §3.5.2 / Table 9's mutability row: {}",
                truncate(&r3.raw, 150)
            ),
            evidence,
        ));
    } else if r3.status == 400 {
        rows.push(obs_with_evidence(
            patch_axis,
            "rejected_wrong_scimtype",
            format!(
                "PATCH path={sent_path:?}: status=400 scimType={:?}; rejected but with the \
                 wrong scimType -- RFC 7644 §3.5.2 / Table 9 requires \"mutability\": {}",
                scim_type,
                truncate(&r3.raw, 150)
            ),
            evidence,
        ));
    } else if is_2xx(r3.status) {
        let (ok3, val3) = get_attr(&body_of(&r3), decl);
        if !ok3 || val3 != patch_forged {
            rows.push(obs_with_evidence(
                patch_axis,
                "ignored",
                format!(
                    "PATCH path={sent_path:?}: status={} ignored instead of rejected with 400 \
                     scimType=mutability per RFC 7644 §3.5.2",
                    r3.status
                ),
                evidence,
            ));
        } else {
            rows.push(obs_with_evidence(
                patch_axis,
                "applied",
                format!(
                    "PATCH path={sent_path:?}: status={} applied; forged value {patch_forged:?} \
                     took effect instead of being rejected with 400 scimType=mutability per RFC \
                     7644 §3.5.2",
                    r3.status
                ),
                evidence,
            ));
        }
    } else {
        rows.push(unobservable(
            patch_axis,
            Unobservable::ProbeFailed(format!(
                "unexpected status {}: {}",
                r3.status,
                truncate(&r3.raw, 200)
            )),
        ));
    }
    rows
}

// ------------------------------------------------------------- immutable

async fn exec_immutable(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_gated: bool,
    universe: &[&AttrDecl],
) -> Vec<Observation> {
    let decl = &group[0].decl;
    let by_method = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };
    let endpoint = resource_endpoint(decl.resource);

    let mut valid_val = valid_value_for(decl);
    if is_group_member_ref(decl) && decl.last() == "value" {
        if let Some(v) = member_ref_override(decl, client, bk).await {
            valid_val = v;
        }
    }
    let real_id = if is_group_member_subattr(decl) && decl.last() != "value" {
        fresh_user_id(client, bk).await
    } else {
        None
    };
    let (payload, valid_val, member_filter_value) =
        immutable_post_payload(decl, valid_val, real_id.as_deref());

    let r = safe(client.post(endpoint, &payload)).await;
    if !is_2xx(r.status) {
        let msg = format!(
            "creation with immutable attribute set failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        );
        return group
            .iter()
            .map(|a| unobservable(a, Unobservable::ProbeFailed(msg.clone())))
            .collect();
    }
    let rj = body_of(&r);
    let (ok, val) = get_attr(&rj, decl);
    let mut rows = Vec::new();
    let create_axis = by_method(Method::PostCreate);
    if ok && values_match(decl, &valid_val, &val) {
        rows.push(obs_with_evidence(
            create_axis,
            "accepted",
            format!("value {valid_val:?} accepted at creation (observed {val:?})"),
            vec![r.exchange.clone()],
        ));
    } else {
        rows.push(obs_with_evidence(
            create_axis,
            "rejected_or_dropped",
            format!("value not accepted/persisted at creation: got {val:?} present={ok}"),
            vec![r.exchange.clone()],
        ));
    }

    let Some(rid) = rj.get("id").and_then(|v| v.as_str()).map(String::from) else {
        rows.push(unobservable(
            by_method(Method::PatchChange),
            Unobservable::ProbeFailed("no id from creation".into()),
        ));
        rows.push(unobservable(
            by_method(Method::PutChange),
            Unobservable::ProbeFailed("no id from creation".into()),
        ));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    let patch_axis = by_method(Method::PatchChange);
    if patch_gated {
        rows.push(unobservable(
            patch_axis,
            Unobservable::CapabilityNotAdvertised("patch"),
        ));
    } else {
        let changed = forged_value_for(decl);
        let request = match build_patch_request(
            decl,
            universe,
            member_filter_value.as_ref(),
            changed.clone(),
        ) {
            PatchRequestPlan::Body(req) => req,
            PatchRequestPlan::Unavailable(reason) => {
                rows.push(unobservable(
                    patch_axis,
                    Unobservable::ProbeFailed(reason.to_string()),
                ));
                rows.push(
                    exec_immutable_put_change(
                        by_method(Method::PutChange),
                        decl,
                        client,
                        &rid,
                        endpoint,
                    )
                    .await,
                );
                return rows;
            }
        };
        let r2 = safe(client.patch(&format!("{endpoint}/{rid}"), &request)).await;
        let evidence = vec![r2.exchange.clone()];
        if r2.status == 400 || r2.status == 409 {
            rows.push(obs_with_evidence(
                patch_axis,
                "rejected",
                format!("change correctly rejected with status {}", r2.status),
                evidence,
            ));
        } else if is_2xx(r2.status) {
            let (ok2, val2) = get_attr(&body_of(&r2), decl);
            if ok2 && values_match(decl, &changed, &val2) {
                rows.push(obs_with_evidence(
                    patch_axis,
                    "changed",
                    format!("immutable value changed via PATCH to {val2:?}"),
                    evidence,
                ));
            } else {
                rows.push(obs_with_evidence(
                    patch_axis,
                    "ignored",
                    format!("PATCH returned 200 but value unchanged: {val2:?}"),
                    evidence,
                ));
            }
        } else {
            rows.push(unobservable(
                patch_axis,
                Unobservable::ProbeFailed(format!(
                    "unexpected status {}: {}",
                    r2.status,
                    truncate(&r2.raw, 200)
                )),
            ));
        }
    }

    rows.push(
        exec_immutable_put_change(by_method(Method::PutChange), decl, client, &rid, endpoint).await,
    );
    rows
}

async fn exec_immutable_put_change(
    axis: &DerivedAxis,
    decl: &AttrDecl,
    client: &ScimClient,
    rid: &str,
    endpoint: &str,
) -> Observation {
    let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let current = body_of(&getr);
    if !current.is_object() {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("could not re-fetch resource before PUT".into()),
        );
    }
    let mut put_body = current;
    let changed2 = forged_value_for(decl);
    set_attr(&mut put_body, decl, changed2.clone());
    let r3 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    let evidence = vec![r3.exchange.clone()];
    if r3.status == 400 || r3.status == 409 {
        obs_with_evidence(
            axis,
            "rejected",
            format!("change correctly rejected with status {}", r3.status),
            evidence,
        )
    } else if is_2xx(r3.status) {
        let (ok3, val3) = get_attr(&body_of(&r3), decl);
        if ok3 && values_match(decl, &changed2, &val3) {
            obs_with_evidence(
                axis,
                "changed",
                format!("immutable value changed via PUT to {val3:?}"),
                evidence,
            )
        } else {
            obs_with_evidence(
                axis,
                "ignored",
                format!("PUT returned 200 but value unchanged: {val3:?}"),
                evidence,
            )
        }
    } else {
        unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "unexpected status {}: {}",
                r3.status,
                truncate(&r3.raw, 200)
            )),
        )
    }
}

// -------------------------------------------------------------- required

async fn exec_required(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Vec<Observation> {
    let decl = &group[0].decl;
    if decl.mutability == Mutability::ReadOnly {
        return vec![na(
            &group[0],
            "attribute is server-generated (readOnly); client omission at creation is normal",
        )];
    }
    let by_method = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };
    let endpoint = resource_endpoint(decl.resource);
    let mut rows = Vec::new();

    let mut payload = make_baseline(decl.resource);
    if decl.depth() == 1 {
        if let Some(o) = payload.as_object_mut() {
            o.remove(&decl.path);
        }
    }
    let r = safe(client.post(endpoint, &payload)).await;
    let post_axis = by_method(Method::PostOmit);
    if r.status == 400 {
        rows.push(obs_with_evidence(
            post_axis,
            "rejected_400",
            format!("correctly rejected: {}", truncate(&r.raw, 150)),
            vec![r.exchange.clone()],
        ));
    } else {
        rows.push(obs_with_evidence(
            post_axis,
            "accepted",
            format!("expected 400, got {}: {}", r.status, truncate(&r.raw, 150)),
            vec![r.exchange.clone()],
        ));
    }

    let good = make_baseline(decl.resource);
    let r2 = safe(client.post(endpoint, &good)).await;
    let put_axis = by_method(Method::PutOmit);
    if !is_2xx(r2.status) {
        rows.push(unobservable(
            put_axis,
            Unobservable::ProbeFailed("could not create baseline resource".into()),
        ));
        return rows;
    }
    let rj2 = body_of(&r2);
    let rid = rj2
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    bk.note(endpoint, rid.clone());
    let mut put_body = rj2.clone();
    if let Some(o) = put_body.as_object_mut() {
        o.remove(decl.path.as_str());
    }
    let r3 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    if r3.status == 400 {
        rows.push(obs_with_evidence(
            put_axis,
            "rejected_400",
            format!("correctly rejected: {}", truncate(&r3.raw, 150)),
            vec![r3.exchange.clone()],
        ));
    } else {
        rows.push(obs_with_evidence(
            put_axis,
            "accepted",
            format!(
                "expected 400, got {}: {}",
                r3.status,
                truncate(&r3.raw, 150)
            ),
            vec![r3.exchange.clone()],
        ));
    }
    rows
}

// -------------------------------------------------------------- caseExact

async fn exec_caseexact(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Vec<Observation> {
    let decl = &group[0].decl;
    let skip = decl.mutability == Mutability::ReadOnly
        || decl.returned == Returned::Never
        || is_group_member_ref(decl);
    if skip {
        return vec![na(
            &group[0],
            "attribute is readOnly, never-returned, or a member reference; case preservation \
             cannot be isolated via client write + read",
        )];
    }
    let axis = &group[0];
    let endpoint = resource_endpoint(decl.resource);
    let mixed = json!(format!("MiXeD-{}-CaSe", short_uid()));
    let mut payload = make_baseline(decl.resource);
    set_attr(&mut payload, decl, mixed.clone());
    let r = safe(client.post(endpoint, &payload)).await;
    if !is_2xx(r.status) {
        return vec![unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "create failed: {} {}",
                r.status,
                truncate(&r.raw, 150)
            )),
        )];
    }
    if let Some(id) = r.id() {
        bk.note(endpoint, id);
    }
    let (ok, val) = get_attr(&body_of(&r), decl);
    let evidence = vec![r.exchange.clone()];
    if ok && val == mixed {
        vec![obs_with_evidence(
            axis,
            "preserved",
            format!("case preserved: {val:?}"),
            evidence,
        )]
    } else {
        vec![obs_with_evidence(
            axis,
            "not_preserved",
            format!("case not preserved: sent {mixed:?}, got {val:?}"),
            evidence,
        )]
    }
}

// ------------------------------------------------------------- uniqueness

async fn exec_uniqueness(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_gated: bool,
) -> Vec<Observation> {
    let decl = &group[0].decl;
    if decl.mutability == Mutability::ReadOnly {
        return vec![na(
            &group[0],
            "attribute is server-assigned (readOnly); client cannot set its value to force a duplicate",
        )];
    }
    let by_method = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };
    let endpoint = resource_endpoint(decl.resource);
    let mut rows = Vec::new();

    let dup1 = json!(format!("dup-{}", short_uid()));
    let mut pa = make_baseline(decl.resource);
    set_attr(&mut pa, decl, dup1.clone());
    if let Some(id) = safe(client.post(endpoint, &pa)).await.id() {
        bk.note(endpoint, id);
    }
    let mut pb = make_baseline(decl.resource);
    set_attr(&mut pb, decl, dup1.clone());
    let rb = safe(client.post(endpoint, &pb)).await;
    if let Some(id) = rb.id() {
        bk.note(endpoint, id);
    }
    let post_axis = by_method(Method::PostDuplicate);
    let evidence = vec![rb.exchange.clone()];
    if rb.status == 400 || rb.status == 409 {
        rows.push(obs_with_evidence(
            post_axis,
            "rejected_duplicate",
            format!("status={} scimType={:?}", rb.status, rb.scim_type()),
            evidence,
        ));
    } else {
        rows.push(obs_with_evidence(
            post_axis,
            "accepted_duplicate",
            format!(
                "expected 400/409, got {}: {}",
                rb.status,
                truncate(&rb.raw, 150)
            ),
            evidence,
        ));
    }

    let dup2 = json!(format!("dup-{}", short_uid()));
    let mut pa2 = make_baseline(decl.resource);
    set_attr(&mut pa2, decl, dup2.clone());
    if let Some(id) = safe(client.post(endpoint, &pa2)).await.id() {
        bk.note(endpoint, id);
    }
    let pc = make_baseline(decl.resource);
    let rc = safe(client.post(endpoint, &pc)).await;
    let put_axis = by_method(Method::PutDuplicate);
    if !is_2xx(rc.status) {
        rows.push(unobservable(
            put_axis,
            Unobservable::ProbeFailed("could not create baseline C".into()),
        ));
    } else {
        let cid = rc.id().unwrap_or_default();
        bk.note(endpoint, cid.clone());
        let mut put_body = body_of(&rc);
        set_attr(&mut put_body, decl, dup2.clone());
        let r_put = safe(client.put(&format!("{endpoint}/{cid}"), &put_body)).await;
        let evidence = vec![r_put.exchange.clone()];
        if r_put.status == 400 || r_put.status == 409 {
            rows.push(obs_with_evidence(
                put_axis,
                "rejected_duplicate",
                format!("status={} scimType={:?}", r_put.status, r_put.scim_type()),
                evidence,
            ));
        } else {
            rows.push(obs_with_evidence(
                put_axis,
                "accepted_duplicate",
                format!(
                    "expected 400/409, got {}: {}",
                    r_put.status,
                    truncate(&r_put.raw, 150)
                ),
                evidence,
            ));
        }
    }

    let patch_axis = by_method(Method::PatchDuplicate);
    if patch_gated {
        rows.push(unobservable(
            patch_axis,
            Unobservable::CapabilityNotAdvertised("patch"),
        ));
        return rows;
    }

    let dup3 = json!(format!("dup-{}", short_uid()));
    let mut pa3 = make_baseline(decl.resource);
    set_attr(&mut pa3, decl, dup3.clone());
    if let Some(id) = safe(client.post(endpoint, &pa3)).await.id() {
        bk.note(endpoint, id);
    }
    let pd = make_baseline(decl.resource);
    let rd = safe(client.post(endpoint, &pd)).await;
    if !is_2xx(rd.status) {
        rows.push(unobservable(
            patch_axis,
            Unobservable::ProbeFailed("could not create baseline D".into()),
        ));
    } else {
        let did = rd.id().unwrap_or_default();
        bk.note(endpoint, did.clone());
        let r_patch = safe(client.patch(
            &format!("{endpoint}/{did}"),
            &patch_body(decl, dup3.clone()),
        ))
        .await;
        let evidence = vec![r_patch.exchange.clone()];
        if r_patch.status == 400 || r_patch.status == 409 {
            rows.push(obs_with_evidence(
                patch_axis,
                "rejected_duplicate",
                format!(
                    "status={} scimType={:?}",
                    r_patch.status,
                    r_patch.scim_type()
                ),
                evidence,
            ));
        } else {
            rows.push(obs_with_evidence(
                patch_axis,
                "accepted_duplicate",
                format!(
                    "expected 400/409, got {}: {}",
                    r_patch.status,
                    truncate(&r_patch.raw, 150)
                ),
                evidence,
            ));
        }
    }
    rows
}

// --------------------------------------------------------- returned:never

async fn exec_returned_never(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_gated: bool,
) -> Vec<Observation> {
    let decl = &group[0].decl;
    let by_method = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };

    if is_container_skip(decl) {
        // Not a genuine `Method::NA` cell -- these instances' method is
        // POST/GET/PUT/PATCH with `RN_KNOWN`'s vocabulary, so `na()`'s
        // "not_applicable" token (from `NA_KNOWN`) would render as a
        // spurious `Value::Unknown` rather than the true "cannot observe".
        let msg = "complex container with declared sub-attributes; forging a bare scalar into \
                    it is not a well-formed probe -- see mutability_readonly's per-subattribute \
                    decomposition instead";
        return group
            .iter()
            .map(|a| unobservable(a, Unobservable::ProbeFailed(msg.to_string())))
            .collect();
    }

    let endpoint = resource_endpoint(decl.resource);
    let mut rows = Vec::new();
    let val = json!(format!("S3cr3t-{}!", short_uid()));
    let mut payload = make_baseline(decl.resource);
    set_attr(&mut payload, decl, val.clone());
    let r = safe(client.post(endpoint, &payload)).await;
    let (ok, _) = get_attr(&body_of(&r), decl);
    rows.push(obs_with_evidence(
        by_method(Method::Post),
        if ok { "leaked" } else { "absent_from_response" },
        format!("present_in_response={ok}"),
        vec![r.exchange.clone()],
    ));

    let Some(rid) = r.id() else {
        rows.push(unobservable(
            by_method(Method::Get),
            Unobservable::ProbeFailed("no id from create".into()),
        ));
        rows.push(unobservable(
            by_method(Method::Put),
            Unobservable::ProbeFailed("no id from create".into()),
        ));
        rows.push(unobservable(
            by_method(Method::Patch),
            Unobservable::ProbeFailed("no id from create".into()),
        ));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    let rg = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let (okg, _) = get_attr(&body_of(&rg), decl);
    rows.push(obs_with_evidence(
        by_method(Method::Get),
        if okg {
            "leaked"
        } else {
            "absent_from_response"
        },
        format!("present_in_response={okg}"),
        vec![rg.exchange.clone()],
    ));

    let mut put_body = body_of(&rg);
    set_attr(
        &mut put_body,
        decl,
        json!(format!("{}-2", val.as_str().unwrap_or_default())),
    );
    let rp = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    let (okp, _) = get_attr(&body_of(&rp), decl);
    rows.push(obs_with_evidence(
        by_method(Method::Put),
        if okp {
            "leaked"
        } else {
            "absent_from_response"
        },
        format!("present_in_response={okp}"),
        vec![rp.exchange.clone()],
    ));

    let patch_axis = by_method(Method::Patch);
    if patch_gated {
        rows.push(unobservable(
            patch_axis,
            Unobservable::CapabilityNotAdvertised("patch"),
        ));
        return rows;
    }

    let rpa = safe(client.patch(
        &format!("{endpoint}/{rid}"),
        &patch_body(
            decl,
            json!(format!("{}-3", val.as_str().unwrap_or_default())),
        ),
    ))
    .await;
    let (okpa, _) = get_attr(&body_of(&rpa), decl);
    rows.push(obs_with_evidence(
        patch_axis,
        if okpa {
            "leaked"
        } else {
            "absent_from_response"
        },
        format!("present_in_response={okpa}"),
        vec![rpa.exchange.clone()],
    ));
    rows
}

// --------------------------------------------------------- type conformance

async fn type_wrong_check(
    axis: &DerivedAxis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    verb: Method,
) -> Observation {
    let decl = &axis.decl;
    let endpoint = resource_endpoint(decl.resource);
    let wrong = wrong_value_for(decl);

    match verb {
        Method::Post => {
            let mut payload = make_baseline(decl.resource);
            let companion = if is_group_member_subattr(decl) && decl.last() != "value" {
                companion_value("members", client, bk).await
            } else {
                None
            };
            set_attr_with_companion(&mut payload, decl, wrong.clone(), companion);
            let r = safe(client.post(endpoint, &payload)).await;
            if let Some(id) = r.id() {
                bk.note(endpoint, id);
            }
            let evidence = vec![r.exchange.clone()];
            if r.status == 400 {
                obs_with_evidence(
                    axis,
                    "rejected_400",
                    format!(
                        "wrong-typed value {wrong:?} rejected with 400 scimType={:?}",
                        r.scim_type()
                    ),
                    evidence,
                )
            } else {
                obs_with_evidence(
                    axis,
                    "accepted",
                    format!(
                        "wrong-typed value {wrong:?} not rejected: status={} body={}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                    evidence,
                )
            }
        }
        Method::Put => {
            let baseline = make_baseline(decl.resource);
            let rc = safe(client.post(endpoint, &baseline)).await;
            if !is_2xx(rc.status) {
                return unobservable(
                    axis,
                    Unobservable::ProbeFailed(format!(
                        "could not create baseline for PUT probe: {} {}",
                        rc.status,
                        truncate(&rc.raw, 150)
                    )),
                );
            }
            let rid = rc.id().unwrap_or_default();
            bk.note(endpoint, rid.clone());
            let mut put_body = body_of(&rc);
            let companion = if is_group_member_subattr(decl) && decl.last() != "value" {
                companion_value("members", client, bk).await
            } else {
                None
            };
            set_attr_with_companion(&mut put_body, decl, wrong.clone(), companion);
            let r = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
            let evidence = vec![r.exchange.clone()];
            if r.status == 400 {
                obs_with_evidence(
                    axis,
                    "rejected_400",
                    format!(
                        "wrong-typed value {wrong:?} rejected with 400 scimType={:?}",
                        r.scim_type()
                    ),
                    evidence,
                )
            } else {
                obs_with_evidence(
                    axis,
                    "accepted",
                    format!(
                        "wrong-typed value {wrong:?} not rejected: status={} body={}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                    evidence,
                )
            }
        }
        _ => unreachable!("type_wrong_check only ever called with Post/Put"),
    }
}

async fn type_valid_check(
    axis: &DerivedAxis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    verb: Method,
    universe: &[&AttrDecl],
) -> Observation {
    let decl = &axis.decl;
    let endpoint = resource_endpoint(decl.resource);

    if decl.returned == Returned::Never {
        // Unlike the genuine `Method::NA` cells (whose `known` vocabulary
        // is `NA_KNOWN`), this instance's method is POST/PUT with
        // `TV_KNOWN` -- "not_applicable" isn't in that vocabulary, so
        // `na()` here would render as a spurious `Value::Unknown` (a false
        // discovery signal) rather than what it actually is: genuinely
        // unobservable.
        return unobservable(
            axis,
            Unobservable::ProbeFailed(
                "attribute is returned:never; a valid-value round trip cannot be observed in \
                 any response"
                    .to_string(),
            ),
        );
    }

    if decl.r#type == AttrType::Complex && decl.depth() == 1 {
        let Some(temp) = first_writable_subattr(universe, decl) else {
            return unobservable(
                axis,
                Unobservable::ProbeFailed(
                    "no writable sub-attribute available to exercise a valid round trip"
                        .to_string(),
                ),
            );
        };
        let mut valid = valid_value_for(temp);
        if is_group_member_ref(temp) && temp.last() == "value" {
            if let Some(v) = member_ref_override(temp, client, bk).await {
                valid = v;
            }
        }
        return match verb {
            Method::Post => {
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, temp, valid.clone());
                let r = safe(client.post(endpoint, &payload)).await;
                if let Some(id) = r.id() {
                    bk.note(endpoint, id);
                }
                let evidence = vec![r.exchange.clone()];
                if !is_2xx(r.status) {
                    unobservable(
                        axis,
                        Unobservable::ProbeFailed(format!(
                            "valid nested value under {} rejected: {} {}",
                            temp.path,
                            r.status,
                            truncate(&r.raw, 150)
                        )),
                    )
                } else {
                    let (ok, got) = get_attr(&body_of(&r), temp);
                    if ok && values_match(temp, &valid, &got) {
                        obs_with_evidence(
                            axis,
                            "round_tripped",
                            format!("round-tripped via {}: {got:?}", temp.path),
                            evidence,
                        )
                    } else {
                        obs_with_evidence(
                            axis,
                            "mismatch",
                            format!(
                                "expected {valid:?} at {}, got {got:?} present={ok}",
                                temp.path
                            ),
                            evidence,
                        )
                    }
                }
            }
            Method::Put => {
                let baseline = make_baseline(decl.resource);
                let rc = safe(client.post(endpoint, &baseline)).await;
                if !is_2xx(rc.status) {
                    return unobservable(
                        axis,
                        Unobservable::ProbeFailed("could not create baseline for PUT probe".into()),
                    );
                }
                let rid = rc.id().unwrap_or_default();
                bk.note(endpoint, rid.clone());
                let mut put_body = body_of(&rc);
                set_attr(&mut put_body, temp, valid.clone());
                let r = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
                let evidence = vec![r.exchange.clone()];
                if !is_2xx(r.status) {
                    unobservable(
                        axis,
                        Unobservable::ProbeFailed(format!(
                            "valid nested value under {} rejected: {} {}",
                            temp.path,
                            r.status,
                            truncate(&r.raw, 150)
                        )),
                    )
                } else {
                    let (ok, got) = get_attr(&body_of(&r), temp);
                    if ok && values_match(temp, &valid, &got) {
                        obs_with_evidence(
                            axis,
                            "round_tripped",
                            format!("round-tripped via {}: {got:?}", temp.path),
                            evidence,
                        )
                    } else {
                        obs_with_evidence(
                            axis,
                            "mismatch",
                            format!(
                                "expected {valid:?} at {}, got {got:?} present={ok}",
                                temp.path
                            ),
                            evidence,
                        )
                    }
                }
            }
            _ => unreachable!(),
        };
    }

    let mut sent = valid_value_for(decl);
    if is_group_member_ref(decl) && decl.last() == "value" {
        if let Some(v) = member_ref_override(decl, client, bk).await {
            sent = v;
        }
    }
    let mut expected = sent.clone();
    let companion_for = |d: &AttrDecl| is_group_member_subattr(d) && d.last() != "value";

    match verb {
        Method::Post => {
            let mut payload = make_baseline(decl.resource);
            let mut companion = None;
            if companion_for(decl) {
                let real_id = fresh_user_id(client, bk).await;
                if decl.last() == "$ref" {
                    if let Some(id) = &real_id {
                        expected = json!(format!("/Users/{id}"));
                    }
                }
                companion = real_id.map(|id| json!(id));
            }
            set_attr_with_companion(&mut payload, decl, sent.clone(), companion);
            let r = safe(client.post(endpoint, &payload)).await;
            if let Some(id) = r.id() {
                bk.note(endpoint, id);
            }
            let evidence = vec![r.exchange.clone()];
            if !is_2xx(r.status) {
                unobservable(
                    axis,
                    Unobservable::ProbeFailed(format!(
                        "valid value {sent:?} rejected unexpectedly: {} {}",
                        r.status,
                        truncate(&r.raw, 150)
                    )),
                )
            } else {
                let (ok, got) = get_attr(&body_of(&r), decl);
                if ok && values_match(decl, &expected, &got) {
                    obs_with_evidence(
                        axis,
                        "round_tripped",
                        format!("round-tripped: {got:?}"),
                        evidence,
                    )
                } else {
                    obs_with_evidence(
                        axis,
                        "mismatch",
                        format!("expected {expected:?}, got {got:?} present={ok}"),
                        evidence,
                    )
                }
            }
        }
        Method::Put => {
            let baseline = make_baseline(decl.resource);
            let rc = safe(client.post(endpoint, &baseline)).await;
            if !is_2xx(rc.status) {
                return unobservable(
                    axis,
                    Unobservable::ProbeFailed("could not create baseline for PUT probe".into()),
                );
            }
            let rid = rc.id().unwrap_or_default();
            bk.note(endpoint, rid.clone());
            let mut put_body = body_of(&rc);
            let mut companion = None;
            if companion_for(decl) {
                let real_id = fresh_user_id(client, bk).await;
                if decl.last() == "$ref" {
                    if let Some(id) = &real_id {
                        expected = json!(format!("/Users/{id}"));
                    }
                }
                companion = real_id.map(|id| json!(id));
            }
            set_attr_with_companion(&mut put_body, decl, sent.clone(), companion);
            let r = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
            let evidence = vec![r.exchange.clone()];
            if !is_2xx(r.status) {
                unobservable(
                    axis,
                    Unobservable::ProbeFailed(format!(
                        "valid value {sent:?} rejected unexpectedly: {} {}",
                        r.status,
                        truncate(&r.raw, 150)
                    )),
                )
            } else {
                let (ok, got) = get_attr(&body_of(&r), decl);
                if ok && values_match(decl, &expected, &got) {
                    obs_with_evidence(
                        axis,
                        "round_tripped",
                        format!("round-tripped: {got:?}"),
                        evidence,
                    )
                } else {
                    obs_with_evidence(
                        axis,
                        "mismatch",
                        format!("expected {expected:?}, got {got:?} present={ok}"),
                        evidence,
                    )
                }
            }
        }
        _ => unreachable!(),
    }
}

async fn exec_type_wrong(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Vec<Observation> {
    let by = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };
    vec![
        type_wrong_check(by(Method::Post), client, bk, Method::Post).await,
        type_wrong_check(by(Method::Put), client, bk, Method::Put).await,
    ]
}

async fn exec_type_valid(
    group: &[DerivedAxis],
    client: &ScimClient,
    bk: &mut Bookkeeping,
    universe: &[&AttrDecl],
) -> Vec<Observation> {
    let by = |m: Method| {
        group
            .iter()
            .find(|a| a.method == m)
            .expect("cell must exist")
    };
    vec![
        type_valid_check(by(Method::Post), client, bk, Method::Post, universe).await,
        type_valid_check(by(Method::Put), client, bk, Method::Put, universe).await,
    ]
}

// ------------------------------------------------------------------- driver

fn ordered_unique_decls(axes: &[DerivedAxis]) -> Vec<&AttrDecl> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for a in axes {
        let key = (a.decl.resource, a.decl.path.as_str());
        if seen.insert(key) {
            out.push(&a.decl);
        }
    }
    out
}

/// Note: unlike the source branch's `cells_from_decls`, whose single loop
/// over `decls` interleaves `TypeWrong`/`TypeValid` cells for the same
/// declaration back-to-back (so a combined group naturally spans both),
/// this crate's `expand_all` runs each family's own `expand` as a
/// *separate* full pass over `decls` (`crate::matrix::derive::expand_all`),
/// so `type_wrong`'s and `type_valid`'s instances for the same attribute
/// are never adjacent in the flattened list. They're therefore kept as two
/// distinct group kinds here (7 and 8), each handled independently, rather
/// than the source's single `exec_type` that answers both at once.
fn group_kind(family_id: &str) -> u8 {
    match family_id {
        "mutability_readonly" => 1,
        "mutability_immutable" => 2,
        "required" => 3,
        "case_exact" => 4,
        "uniqueness" => 5,
        "returned_never" => 6,
        "type_wrong" => 7,
        "type_valid" => 8,
        other => unreachable!("unknown derived family id {other}"),
    }
}

/// Runs every instance in `axes` against `client`, and returns one
/// [`Observation`] per instance (same order, same length). Instances are
/// grouped by `(resource, attribute path, family group)` -- the unit that
/// shares HTTP round trips (e.g. `mutability_readonly`'s POST/PUT/PATCH
/// triad probes the same created resource) -- before running the shared
/// per-family routine, exactly like the source branch's `run_cells`.
///
/// Every resource this run creates is deleted best-effort afterward.
pub async fn run_derived_family(client: &mut ScimClient, axes: &[DerivedAxis]) -> Vec<Observation> {
    let caps = capability::fetch(client).await;
    let patch_gated = caps.get(Capability::Patch) == Some(false);

    let universe = ordered_unique_decls(axes);
    let mut bk = Bookkeeping::new();

    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < axes.len() {
        let start = i;
        let key = (
            axes[i].decl.resource,
            axes[i].decl.path.clone(),
            group_kind(axes[i].family_id),
        );
        i += 1;
        while i < axes.len()
            && axes[i].decl.resource == key.0
            && axes[i].decl.path == key.1
            && group_kind(axes[i].family_id) == key.2
        {
            i += 1;
        }
        groups.push((start, i));
    }

    let mut observations: Vec<Observation> = Vec::with_capacity(axes.len());
    for (start, end) in groups {
        let group = &axes[start..end];
        let family_kind = group_kind(group[0].family_id);
        let rows: Vec<Observation> = match family_kind {
            1 => exec_readonly(group, client, &mut bk, patch_gated, &universe).await,
            2 => exec_immutable(group, client, &mut bk, patch_gated, &universe).await,
            3 => exec_required(group, client, &mut bk).await,
            4 => exec_caseexact(group, client, &mut bk).await,
            5 => exec_uniqueness(group, client, &mut bk, patch_gated).await,
            6 => exec_returned_never(group, client, &mut bk, patch_gated).await,
            7 => exec_type_wrong(group, client, &mut bk).await,
            8 => exec_type_valid(group, client, &mut bk, &universe).await,
            _ => unreachable!(),
        };
        debug_assert_eq!(rows.len(), group.len());
        observations.extend(rows);
    }

    cleanup(client, &bk).await;
    observations
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Returned, Uniqueness as U};

    fn string_decl(path: &str) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: path.to_string(),
            parent: None,
            r#type: AttrType::String,
            mutability: Mutability::ReadWrite,
            returned: Returned::Default,
            uniqueness: U::None,
            case_exact: false,
            required: false,
            multi_valued: false,
            top_multi_valued: false,
            canonical_values: None,
            has_sub_attributes: false,
        }
    }

    #[test]
    fn wrong_value_matches_the_pinned_per_type_table() {
        let mut d = string_decl("x");
        d.r#type = AttrType::String;
        assert_eq!(wrong_value_for(&d), json!(123));
        d.r#type = AttrType::Boolean;
        assert_eq!(wrong_value_for(&d), json!("yes"));
    }

    #[test]
    fn set_attr_wraps_multivalued_sub_attributes_in_an_array() {
        let mut d = string_decl("emails.value");
        d.parent = Some("emails".to_string());
        d.top_multi_valued = true;
        let mut payload = json!({});
        set_attr(&mut payload, &d, json!("a@example.com"));
        assert_eq!(payload, json!({"emails": [{"value": "a@example.com"}]}));
        let (ok, v) = get_attr(&payload, &d);
        assert!(ok);
        assert_eq!(v, json!("a@example.com"));
    }

    #[test]
    fn enterprise_user_fields_are_scoped_under_the_extension_urn() {
        let mut d = string_decl("employeeNumber");
        d.resource = Resource::EnterpriseUser;
        let mut payload = json!({"schemas": [USER_URN]});
        set_attr(&mut payload, &d, json!("123"));
        assert_eq!(payload["schemas"], json!([USER_URN, ENTERPRISE_URN]));
        assert_eq!(payload[ENTERPRISE_URN]["employeeNumber"], json!("123"));
    }
}
