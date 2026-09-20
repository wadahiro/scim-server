//! Executes a generated [`Cell`] matrix against a live server. Ported 1:1
//! from the Python prototype's `lib.py`/`checks.py`, then extended per the
//! rules recorded during evaluation (see module docs in `matrix::cells`):
//! type checks run on POST and PUT (prototype: POST only), immutable runs
//! on PATCH and PUT, and readOnly forging of `members`/`groups` reference
//! lists is judged on both the POST response and a follow-up GET.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use super::cells::{is_container_skip, is_group_member_ref, is_group_member_subattr};
use super::{Cell, Characteristic, Method, Outcome, Verdict};
use crate::basis;
use crate::capability;
use crate::client::{truncate, ScimClient, ScimResponse};
use crate::schema::{AttrDecl, AttrType, Mutability, Resource, Returned};

pub(crate) const USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub(crate) const GROUP_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub(crate) const ENTERPRISE_URN: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
pub(crate) const PATCHOP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub(crate) fn short_uid() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}{:04x}", t as u32, n as u16)
}

/// Every id this run created, so `run_cells` can best-effort delete them
/// afterward (a 404 on delete counts as success). Also used by
/// `crate::probes`, which creates its own fixtures and reuses this same
/// bookkeeping/cleanup mechanism rather than reimplementing it.
pub(crate) struct Bookkeeping {
    created: Vec<(&'static str, String)>,
}

impl Bookkeeping {
    pub(crate) fn new() -> Self {
        Bookkeeping {
            created: Vec::new(),
        }
    }

    pub(crate) fn note(&mut self, endpoint: &'static str, id: String) {
        self.created.push((endpoint, id));
    }
}

// ------------------------------------------------------------- HTTP helpers

/// Runs a client call, turning a transport error into a synthetic response
/// (status 0) instead of panicking — mirrors the Python client, which never
/// raises: a socket-level failure still produces a `Resp`.
pub(crate) async fn safe(
    fut: impl std::future::Future<Output = Result<ScimResponse, crate::client::Error>>,
) -> ScimResponse {
    match fut.await {
        Ok(r) => r,
        Err(e) => ScimResponse {
            status: 0,
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            raw: e.to_string(),
            exchange: crate::client::Exchange {
                method: String::new(),
                url: String::new(),
                status: None,
                elapsed_ms: 0,
                request_body: None,
                response_body: None,
            },
        },
    }
}

pub(crate) fn body_of(r: &ScimResponse) -> Value {
    r.body.clone().unwrap_or(Value::Null)
}

pub(crate) fn is_2xx(status: u16) -> bool {
    (200..300).contains(&status)
}

// -------------------------------------------------------- payload plumbing

fn ensure_enterprise(payload: &mut Value) -> &mut Value {
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

pub(crate) fn make_baseline(resource: Resource) -> Value {
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

fn path_segments(decl: &AttrDecl) -> Vec<&str> {
    decl.path.split('.').collect()
}

/// Sets `value` at `decl`'s location, optionally pairing it with a
/// `companion` value for the sibling sub-attribute named `value` (only
/// meaningful when `decl` itself is not that sibling). This generalizes the
/// prototype's Group.members-specific pairing (`set_member_attr`) to any
/// complex attribute with a `value` sibling (`members`, `groups`,
/// `manager`) — see RFC 7644 §3.3 basis notes on why a lone readOnly
/// sub-attribute forge is not always a well-formed write.
fn set_attr_with_companion(
    payload: &mut Value,
    decl: &AttrDecl,
    value: Value,
    companion: Option<Value>,
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
        target[top] = json!([Value::Object(obj)]);
    } else {
        target[top] = Value::Object(obj);
    }
}

fn set_attr(payload: &mut Value, decl: &AttrDecl, value: Value) {
    set_attr_with_companion(payload, decl, value, None);
}

fn get_attr(resource_json: &Value, decl: &AttrDecl) -> (bool, Value) {
    let target: &Value = if decl.resource == Resource::EnterpriseUser {
        match resource_json.get(ENTERPRISE_URN) {
            Some(v) if !v.is_null() => v,
            _ => return (false, Value::Null),
        }
    } else {
        resource_json
    };
    let segs = path_segments(decl);
    if segs.len() == 1 {
        return match target.get(segs[0]) {
            Some(v) if !v.is_null() => (true, v.clone()),
            _ => (false, Value::Null),
        };
    }
    let top = segs[0];
    let sub = segs[1];
    let container = match target.get(top) {
        Some(v) if !v.is_null() => v,
        _ => return (false, Value::Null),
    };
    if decl.top_multi_valued {
        if let Some(first) = container.as_array().and_then(|a| a.first()) {
            if let Some(v) = first.get(sub) {
                if !v.is_null() {
                    return (true, v.clone());
                }
            }
        }
        (false, Value::Null)
    } else {
        match container.get(sub) {
            Some(v) if !v.is_null() => (true, v.clone()),
            _ => (false, Value::Null),
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

/// PATCH `path`: container-level when it's a sub-attribute of a
/// multi-valued complex attribute (no per-element filter target exists
/// during a forge probe), full dotted path otherwise.
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

fn patch_value_for(decl: &AttrDecl, value: Value) -> Value {
    let segs = path_segments(decl);
    if segs.len() > 1 && decl.top_multi_valued {
        let sub = segs[1];
        json!([{ sub: value }])
    } else {
        value
    }
}

fn patch_body(decl: &AttrDecl, value: Value) -> Value {
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            { "op": "replace", "path": patch_path(decl), "value": patch_value_for(decl, value) }
        ],
    })
}

fn resource_endpoint(resource: Resource) -> &'static str {
    resource.endpoint()
}

fn values_match(decl: &AttrDecl, sent: &Value, got: &Value) -> bool {
    if is_group_member_ref(decl) && decl.last() == "$ref" {
        if let (Some(g), Some(s)) = (got.as_str(), sent.as_str()) {
            return g.trim_end_matches('/').ends_with(s.trim_end_matches('/'));
        }
        return false;
    }
    sent == got
}

fn valid_value_for(decl: &AttrDecl) -> Value {
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

/// Wrong-typed value per declared type. Matches RFC 7643 §2.3's data-type
/// list; one deliberately-mistyped literal per type (see plan T9b).
fn wrong_value_for(decl: &AttrDecl) -> Value {
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

fn forged_value_for(decl: &AttrDecl) -> Value {
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

pub(crate) async fn fresh_user_id(client: &ScimClient, bk: &mut Bookkeeping) -> Option<String> {
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

/// A resolvable value for the `value` sibling of a complex attribute that
/// forges another sub-attribute (`checks.py`'s `set_member_attr`,
/// generalized beyond `Group.members` to `User.groups` and `manager`).
async fn companion_value(parent: &str, client: &ScimClient, bk: &mut Bookkeeping) -> Option<Value> {
    match parent {
        "members" => fresh_user_id(client, bk).await.map(|id| json!(id)),
        "groups" => fresh_group_id(client, bk).await.map(|id| json!(id)),
        "manager" => fresh_user_id(client, bk).await.map(|id| json!(id)),
        _ => None,
    }
}

/// A real, resolvable value for `Group.members.value` / `.$ref`, or `None`
/// if a throwaway User couldn't be created.
async fn member_ref_override(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Option<Value> {
    let uid = fresh_user_id(client, bk).await?;
    if decl.last() == "$ref" {
        Some(json!(format!("/Users/{}", uid)))
    } else {
        Some(json!(uid))
    }
}

// ------------------------------------------------------------- row helpers

fn outcome(
    decl: &AttrDecl,
    characteristic: Characteristic,
    method: Method,
    verdict: Verdict,
    detail: impl Into<String>,
) -> Outcome {
    Outcome {
        attribute: decl.path.clone(),
        schema: decl.schema.clone(),
        resource: decl.resource,
        characteristic,
        method,
        verdict,
        basis: basis::basis_for(characteristic, method),
        detail: detail.into(),
    }
}

fn skip(
    decl: &AttrDecl,
    characteristic: Characteristic,
    method: Method,
    detail: impl Into<String>,
) -> Outcome {
    outcome(decl, characteristic, method, Verdict::Skip, detail)
}

fn pass(
    decl: &AttrDecl,
    characteristic: Characteristic,
    method: Method,
    detail: impl Into<String>,
) -> Outcome {
    outcome(decl, characteristic, method, Verdict::Pass, detail)
}

fn fail(
    decl: &AttrDecl,
    characteristic: Characteristic,
    method: Method,
    detail: impl Into<String>,
) -> Outcome {
    outcome(decl, characteristic, method, Verdict::Fail, detail)
}

fn error(
    decl: &AttrDecl,
    characteristic: Characteristic,
    method: Method,
    detail: impl Into<String>,
) -> Outcome {
    outcome(decl, characteristic, method, Verdict::Error, detail)
}

// -------------------------------------------------------------- readOnly

async fn exec_readonly(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_skip: Option<Outcome>,
) -> Vec<Outcome> {
    use Characteristic::MutabilityReadOnly as RO;

    if is_container_skip(decl) {
        return vec![skip(
            decl,
            RO,
            Method::NA,
            "complex container decomposed into per-subattribute readOnly checks",
        )];
    }

    let endpoint = resource_endpoint(decl.resource);
    let forged = forged_value_for(decl);

    // Rule 4: forging a non-"value" sub-attribute of a complex also sends
    // a resolvable "value" so the write is well-formed (mirrors the
    // prototype's Group.members-specific pairing, generalized).
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
        return vec![
            error(decl, RO, Method::Post, msg.clone()),
            error(decl, RO, Method::Put, msg.clone()),
            error(decl, RO, Method::Patch, msg),
        ];
    }
    let rj = body_of(&r);
    let (ok, val) = get_attr(&rj, decl);
    let mut rows = Vec::new();
    if !ok || val != forged {
        rows.push(pass(
            decl,
            RO,
            Method::Post,
            format!("forged={forged:?} ignored; actual={val:?} present={ok}"),
        ));
    } else {
        rows.push(fail(
            decl,
            RO,
            Method::Post,
            format!("forged value {forged:?} took effect on POST"),
        ));
    }

    let Some(rid) = rj.get("id").and_then(|v| v.as_str()).map(String::from) else {
        rows.push(error(decl, RO, Method::Put, "no id from baseline POST"));
        rows.push(error(decl, RO, Method::Patch, "no id from baseline POST"));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    // Rule 5: for the Group.members / User.groups reference-list
    // sub-attributes, a forged value that only shows up on a follow-up GET
    // (not the POST response itself) is just as much a leak.
    if matches!(decl.top(), "members" | "groups") {
        if let Verdict::Pass = rows[0].verdict {
            let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
            let (gok, gval) = get_attr(&body_of(&getr), decl);
            if gok && gval == forged {
                rows[0] = fail(
                    decl,
                    RO,
                    Method::Post,
                    format!("forged value {forged:?} absent from the POST response but present on a follow-up GET"),
                );
            }
        }
    }

    let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let current = body_of(&getr);
    let mut put_body = current.clone();
    if !put_body.is_object() {
        put_body = json!({});
    }
    set_attr_with_companion(&mut put_body, decl, forged.clone(), companion.clone());
    let r2 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    if !is_2xx(r2.status) {
        rows.push(error(
            decl,
            RO,
            Method::Put,
            format!("PUT failed: {} {}", r2.status, truncate(&r2.raw, 200)),
        ));
    } else {
        let (ok2, val2) = get_attr(&body_of(&r2), decl);
        if !ok2 || val2 != forged {
            rows.push(pass(
                decl,
                RO,
                Method::Put,
                format!("forged={forged:?} ignored; actual={val2:?} present={ok2}"),
            ));
        } else {
            rows.push(fail(
                decl,
                RO,
                Method::Put,
                format!("forged value {forged:?} took effect on PUT"),
            ));
        }
    }

    if let Some(gated) = patch_skip {
        rows.push(gated);
        return rows;
    }

    // RFC 7644 §3.5.2 (L1886-1894) is stricter than POST's §3.3 / PUT's
    // §3.5.1 "ignore" rule: a PATCH "MUST NOT modify" a readOnly attribute,
    // and a non-compatible operation "SHALL return the appropriate HTTP
    // response status code and a JSON detail error response as defined in
    // Section 3.12" -- Table 9's `mutability` row names that response as
    // 400 with `scimType: "mutability"`. So, unlike POST/PUT, silently
    // ignoring the forged value on PATCH is *not* conformant: only a 400
    // with the right `scimType` passes.
    let r3 = safe(client.patch(
        &format!("{endpoint}/{rid}"),
        &patch_body(decl, forged.clone()),
    ))
    .await;
    let scim_type = r3.scim_type();
    if r3.status == 400 && scim_type.as_deref() == Some("mutability") {
        rows.push(pass(
            decl,
            RO,
            Method::Patch,
            format!(
                "status=400 scimType=mutability; PATCH of readOnly attribute rejected per RFC \
                 7644 §3.5.2 / Table 9's mutability row: {}",
                truncate(&r3.raw, 150)
            ),
        ));
    } else if r3.status == 400 {
        let st = scim_type.as_deref().unwrap_or("none");
        rows.push(fail(
            decl,
            RO,
            Method::Patch,
            format!(
                "status=400 scimType={st}; rejected but with the wrong scimType -- RFC 7644 \
                 §3.5.2 / Table 9 requires \"mutability\": {}",
                truncate(&r3.raw, 150)
            ),
        ));
    } else if is_2xx(r3.status) {
        let (ok3, val3) = get_attr(&body_of(&r3), decl);
        if !ok3 || val3 != forged {
            rows.push(fail(
                decl,
                RO,
                Method::Patch,
                format!(
                    "status={} ignored; forged={forged:?} silently dropped (actual={val3:?} \
                     present={ok3}) instead of being rejected with 400 scimType=mutability per \
                     RFC 7644 §3.5.2",
                    r3.status
                ),
            ));
        } else {
            rows.push(fail(
                decl,
                RO,
                Method::Patch,
                format!(
                    "status={} applied; forged value {forged:?} took effect on PATCH instead of \
                     being rejected with 400 scimType=mutability per RFC 7644 §3.5.2",
                    r3.status
                ),
            ));
        }
    } else {
        rows.push(error(
            decl,
            RO,
            Method::Patch,
            format!(
                "unexpected status {}: {}",
                r3.status,
                truncate(&r3.raw, 200)
            ),
        ));
    }
    rows
}

// ------------------------------------------------------------- immutable

async fn exec_immutable(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_skip: Option<Outcome>,
) -> Vec<Outcome> {
    use Characteristic::MutabilityImmutable as IM;

    let endpoint = resource_endpoint(decl.resource);
    let mut valid_val = valid_value_for(decl);
    if is_group_member_ref(decl) && decl.last() == "value" {
        if let Some(v) = member_ref_override(decl, client, bk).await {
            valid_val = v;
        }
    }

    let mut payload = make_baseline(decl.resource);
    if is_group_member_subattr(decl) && decl.last() != "value" {
        let sub = path_segments(decl)[1];
        let mut elem = serde_json::Map::new();
        elem.insert(sub.to_string(), valid_val.clone());
        let real_id = fresh_user_id(client, bk).await;
        if let Some(id) = &real_id {
            elem.insert("value".to_string(), json!(id));
        }
        payload["members"] = json!([Value::Object(elem)]);
        if decl.last() == "$ref" {
            if let Some(id) = &real_id {
                valid_val = json!(format!("/Users/{id}"));
            }
        }
    } else {
        set_attr(&mut payload, decl, valid_val.clone());
    }

    let r = safe(client.post(endpoint, &payload)).await;
    if !is_2xx(r.status) {
        let msg = format!(
            "creation with immutable attribute set failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        );
        return vec![
            error(decl, IM, Method::PostCreate, msg.clone()),
            error(decl, IM, Method::PatchChange, msg.clone()),
            error(decl, IM, Method::PutChange, msg),
        ];
    }
    let rj = body_of(&r);
    let (ok, val) = get_attr(&rj, decl);
    let mut rows = Vec::new();
    if ok && values_match(decl, &valid_val, &val) {
        rows.push(pass(
            decl,
            IM,
            Method::PostCreate,
            format!("value {valid_val:?} accepted at creation (observed {val:?})"),
        ));
    } else {
        rows.push(fail(
            decl,
            IM,
            Method::PostCreate,
            format!("value not accepted/persisted at creation: got {val:?} present={ok}"),
        ));
    }

    let Some(rid) = rj.get("id").and_then(|v| v.as_str()).map(String::from) else {
        rows.push(error(decl, IM, Method::PatchChange, "no id from creation"));
        rows.push(error(decl, IM, Method::PutChange, "no id from creation"));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    match patch_skip {
        Some(gated) => rows.push(gated),
        None => rows.push(exec_immutable_patch_change(decl, client, &rid, endpoint).await),
    }
    rows.push(exec_immutable_put_change(decl, client, &rid, endpoint).await);
    rows
}

async fn exec_immutable_patch_change(
    decl: &AttrDecl,
    client: &ScimClient,
    rid: &str,
    endpoint: &str,
) -> Outcome {
    use Characteristic::MutabilityImmutable as IM;

    let changed = forged_value_for(decl);
    let r2 = safe(client.patch(
        &format!("{endpoint}/{rid}"),
        &patch_body(decl, changed.clone()),
    ))
    .await;
    if r2.status == 400 || r2.status == 409 {
        pass(
            decl,
            IM,
            Method::PatchChange,
            format!("change correctly rejected with status {}", r2.status),
        )
    } else if is_2xx(r2.status) {
        let (ok2, val2) = get_attr(&body_of(&r2), decl);
        if ok2 && values_match(decl, &changed, &val2) {
            fail(
                decl,
                IM,
                Method::PatchChange,
                format!("immutable value changed via PATCH to {val2:?}"),
            )
        } else {
            pass(
                decl,
                IM,
                Method::PatchChange,
                format!("PATCH returned 200 but value unchanged: {val2:?}"),
            )
        }
    } else {
        error(
            decl,
            IM,
            Method::PatchChange,
            format!(
                "unexpected status {}: {}",
                r2.status,
                truncate(&r2.raw, 200)
            ),
        )
    }
}

/// PUT-change: same probe as [`exec_immutable_patch_change`], via a full
/// replace instead of PATCH. Never gated: PUT requires no capability.
async fn exec_immutable_put_change(
    decl: &AttrDecl,
    client: &ScimClient,
    rid: &str,
    endpoint: &str,
) -> Outcome {
    use Characteristic::MutabilityImmutable as IM;

    let getr = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let current = body_of(&getr);
    if !current.is_object() {
        return error(
            decl,
            IM,
            Method::PutChange,
            "could not re-fetch resource before PUT",
        );
    }
    let mut put_body = current;
    let changed2 = forged_value_for(decl);
    set_attr(&mut put_body, decl, changed2.clone());
    let r3 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    if r3.status == 400 || r3.status == 409 {
        pass(
            decl,
            IM,
            Method::PutChange,
            format!("change correctly rejected with status {}", r3.status),
        )
    } else if is_2xx(r3.status) {
        let (ok3, val3) = get_attr(&body_of(&r3), decl);
        if ok3 && values_match(decl, &changed2, &val3) {
            fail(
                decl,
                IM,
                Method::PutChange,
                format!("immutable value changed via PUT to {val3:?}"),
            )
        } else {
            pass(
                decl,
                IM,
                Method::PutChange,
                format!("PUT returned 200 but value unchanged: {val3:?}"),
            )
        }
    } else {
        error(
            decl,
            IM,
            Method::PutChange,
            format!(
                "unexpected status {}: {}",
                r3.status,
                truncate(&r3.raw, 200)
            ),
        )
    }
}

// -------------------------------------------------------------- required

async fn exec_required(decl: &AttrDecl, client: &ScimClient, bk: &mut Bookkeeping) -> Vec<Outcome> {
    use Characteristic::Required as REQ;

    if decl.mutability == Mutability::ReadOnly {
        return vec![skip(
            decl,
            REQ,
            Method::NA,
            "attribute is server-generated (readOnly); client omission at creation is normal, not a violation",
        )];
    }
    let endpoint = resource_endpoint(decl.resource);
    let mut rows = Vec::new();

    let mut payload = make_baseline(decl.resource);
    if decl.depth() == 1 {
        if let Some(obj) = payload.as_object_mut() {
            obj.remove(&decl.path);
        }
    }
    let r = safe(client.post(endpoint, &payload)).await;
    if r.status == 400 {
        rows.push(pass(
            decl,
            REQ,
            Method::PostOmit,
            format!("correctly rejected: {}", truncate(&r.raw, 150)),
        ));
    } else {
        rows.push(fail(
            decl,
            REQ,
            Method::PostOmit,
            format!("expected 400, got {}: {}", r.status, truncate(&r.raw, 150)),
        ));
    }

    let good = make_baseline(decl.resource);
    let r2 = safe(client.post(endpoint, &good)).await;
    if !is_2xx(r2.status) {
        rows.push(error(
            decl,
            REQ,
            Method::PutOmit,
            "could not create baseline resource",
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
    if let Some(obj) = put_body.as_object_mut() {
        obj.remove(decl.path.as_str());
    }
    let r3 = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    if r3.status == 400 {
        rows.push(pass(
            decl,
            REQ,
            Method::PutOmit,
            format!("correctly rejected: {}", truncate(&r3.raw, 150)),
        ));
    } else {
        rows.push(fail(
            decl,
            REQ,
            Method::PutOmit,
            format!(
                "expected 400, got {}: {}",
                r3.status,
                truncate(&r3.raw, 150)
            ),
        ));
    }
    rows
}

// -------------------------------------------------------------- caseExact

async fn exec_caseexact(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Vec<Outcome> {
    use Characteristic::CaseExact as CE;

    if decl.mutability == Mutability::ReadOnly || decl.returned == Returned::Never {
        return vec![skip(
            decl,
            CE,
            Method::NA,
            "attribute is readOnly or never-returned; case preservation cannot be verified via client write + read",
        )];
    }
    if is_group_member_ref(decl) {
        return vec![skip(
            decl,
            CE,
            Method::NA,
            "members.value/$ref must reference an existing User/Group id (server-generated ids are always lowercase); \
             a mixed-case probe cannot resolve to an existing member, so case preservation cannot be isolated from the \
             existence check",
        )];
    }
    let endpoint = resource_endpoint(decl.resource);
    let mixed = json!(format!("MiXeD-{}-CaSe", short_uid()));
    let mut payload = make_baseline(decl.resource);
    set_attr(&mut payload, decl, mixed.clone());
    let r = safe(client.post(endpoint, &payload)).await;
    if !is_2xx(r.status) {
        return vec![error(
            decl,
            CE,
            Method::Post,
            format!("create failed: {} {}", r.status, truncate(&r.raw, 150)),
        )];
    }
    if let Some(id) = r.id() {
        bk.note(endpoint, id);
    }
    let (ok, val) = get_attr(&body_of(&r), decl);
    if ok && val == mixed {
        vec![pass(
            decl,
            CE,
            Method::Post,
            format!("case preserved: {val:?}"),
        )]
    } else {
        vec![fail(
            decl,
            CE,
            Method::Post,
            format!("case not preserved: sent {mixed:?}, got {val:?}"),
        )]
    }
}

// ------------------------------------------------------------- uniqueness

async fn exec_uniqueness(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_skip: Option<Outcome>,
) -> Vec<Outcome> {
    use Characteristic::Uniqueness as UQ;

    if decl.mutability == Mutability::ReadOnly {
        return vec![skip(
            decl,
            UQ,
            Method::NA,
            "attribute is server-assigned (readOnly); client cannot set its value to force a duplicate",
        )];
    }
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
    let st_b = rb.scim_type();
    if rb.status == 400 || rb.status == 409 {
        rows.push(pass(
            decl,
            UQ,
            Method::PostDuplicate,
            format!("status={} scimType={:?}", rb.status, st_b),
        ));
    } else {
        rows.push(fail(
            decl,
            UQ,
            Method::PostDuplicate,
            format!(
                "expected 400/409, got {}: {}",
                rb.status,
                truncate(&rb.raw, 150)
            ),
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
    if !is_2xx(rc.status) {
        rows.push(error(
            decl,
            UQ,
            Method::PutDuplicate,
            "could not create baseline C",
        ));
    } else {
        let cid = rc.id().unwrap_or_default();
        bk.note(endpoint, cid.clone());
        let mut put_body = body_of(&rc);
        set_attr(&mut put_body, decl, dup2.clone());
        let r_put = safe(client.put(&format!("{endpoint}/{cid}"), &put_body)).await;
        let st_put = r_put.scim_type();
        if r_put.status == 400 || r_put.status == 409 {
            rows.push(pass(
                decl,
                UQ,
                Method::PutDuplicate,
                format!("status={} scimType={:?}", r_put.status, st_put),
            ));
        } else {
            rows.push(fail(
                decl,
                UQ,
                Method::PutDuplicate,
                format!(
                    "expected 400/409, got {}: {}",
                    r_put.status,
                    truncate(&r_put.raw, 150)
                ),
            ));
        }
    }

    if let Some(gated) = patch_skip {
        rows.push(gated);
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
        rows.push(error(
            decl,
            UQ,
            Method::PatchDuplicate,
            "could not create baseline D",
        ));
    } else {
        let did = rd.id().unwrap_or_default();
        bk.note(endpoint, did.clone());
        let r_patch = safe(client.patch(
            &format!("{endpoint}/{did}"),
            &patch_body(decl, dup3.clone()),
        ))
        .await;
        let st_patch = r_patch.scim_type();
        if r_patch.status == 400 || r_patch.status == 409 {
            rows.push(pass(
                decl,
                UQ,
                Method::PatchDuplicate,
                format!("status={} scimType={:?}", r_patch.status, st_patch),
            ));
        } else {
            rows.push(fail(
                decl,
                UQ,
                Method::PatchDuplicate,
                format!(
                    "expected 400/409, got {}: {}",
                    r_patch.status,
                    truncate(&r_patch.raw, 150)
                ),
            ));
        }
    }
    rows
}

// --------------------------------------------------------- returned:never

async fn exec_returned_never(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    patch_skip: Option<Outcome>,
) -> Vec<Outcome> {
    use Characteristic::ReturnedNever as RN;

    let endpoint = resource_endpoint(decl.resource);
    let mut rows = Vec::new();
    let val = json!(format!("S3cr3t-{}!", short_uid()));
    let mut payload = make_baseline(decl.resource);
    set_attr(&mut payload, decl, val.clone());
    let r = safe(client.post(endpoint, &payload)).await;
    let (ok, _) = get_attr(&body_of(&r), decl);
    rows.push(outcome(
        decl,
        RN,
        Method::Post,
        if ok { Verdict::Fail } else { Verdict::Pass },
        format!("present_in_response={ok}"),
    ));

    let Some(rid) = r.id() else {
        rows.push(error(decl, RN, Method::Get, "no id from create"));
        rows.push(error(decl, RN, Method::Put, "no id from create"));
        rows.push(error(decl, RN, Method::Patch, "no id from create"));
        return rows;
    };
    bk.note(endpoint, rid.clone());

    let rg = safe(client.get(&format!("{endpoint}/{rid}"))).await;
    let (okg, _) = get_attr(&body_of(&rg), decl);
    rows.push(outcome(
        decl,
        RN,
        Method::Get,
        if okg { Verdict::Fail } else { Verdict::Pass },
        format!("present_in_response={okg}"),
    ));

    let mut put_body = body_of(&rg);
    set_attr(
        &mut put_body,
        decl,
        json!(format!("{}-2", val.as_str().unwrap_or_default())),
    );
    let rp = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
    let (okp, _) = get_attr(&body_of(&rp), decl);
    rows.push(outcome(
        decl,
        RN,
        Method::Put,
        if okp { Verdict::Fail } else { Verdict::Pass },
        format!("present_in_response={okp}"),
    ));

    if let Some(gated) = patch_skip {
        rows.push(gated);
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
    rows.push(outcome(
        decl,
        RN,
        Method::Patch,
        if okpa { Verdict::Fail } else { Verdict::Pass },
        format!("present_in_response={okpa}"),
    ));
    rows
}

// --------------------------------------------------------- type conformance

/// The first writable sub-attribute of a top-level complex attribute (JSON
/// declaration order), used to exercise `type_valid` for attributes whose
/// own value is never a bare scalar (`checks.py`'s decomposition branch).
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

async fn type_wrong_check(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    verb: Method,
) -> Outcome {
    use Characteristic::TypeWrong as TW;

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
            if r.status == 400 {
                pass(
                    decl,
                    TW,
                    Method::Post,
                    format!(
                        "wrong-typed value {wrong:?} rejected with 400 scimType={:?}",
                        r.scim_type()
                    ),
                )
            } else {
                fail(
                    decl,
                    TW,
                    Method::Post,
                    format!(
                        "wrong-typed value {wrong:?} not rejected: status={} body={}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                )
            }
        }
        Method::Put => {
            let baseline = make_baseline(decl.resource);
            let rc = safe(client.post(endpoint, &baseline)).await;
            if !is_2xx(rc.status) {
                return error(
                    decl,
                    TW,
                    Method::Put,
                    format!(
                        "could not create baseline for PUT probe: {} {}",
                        rc.status,
                        truncate(&rc.raw, 150)
                    ),
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
            if r.status == 400 {
                pass(
                    decl,
                    TW,
                    Method::Put,
                    format!(
                        "wrong-typed value {wrong:?} rejected with 400 scimType={:?}",
                        r.scim_type()
                    ),
                )
            } else {
                fail(
                    decl,
                    TW,
                    Method::Put,
                    format!(
                        "wrong-typed value {wrong:?} not rejected: status={} body={}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                )
            }
        }
        _ => unreachable!("type_wrong_check only ever called with Post/Put"),
    }
}

async fn type_valid_check(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    verb: Method,
    universe: &[&AttrDecl],
) -> Outcome {
    use Characteristic::TypeValid as TV;

    let endpoint = resource_endpoint(decl.resource);

    if decl.returned == Returned::Never {
        return skip(decl, TV, verb, "attribute is returned:never; a valid-value round trip cannot be observed in any response");
    }

    if decl.r#type == AttrType::Complex && decl.depth() == 1 {
        let Some(temp) = first_writable_subattr(universe, decl) else {
            return skip(
                decl,
                TV,
                verb,
                "no writable sub-attribute available to exercise a valid round trip",
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
                if !is_2xx(r.status) {
                    error(
                        decl,
                        TV,
                        Method::Post,
                        format!(
                            "valid nested value under {} rejected: {} {}",
                            temp.path,
                            r.status,
                            truncate(&r.raw, 150)
                        ),
                    )
                } else {
                    let (ok, got) = get_attr(&body_of(&r), temp);
                    if ok && values_match(temp, &valid, &got) {
                        pass(
                            decl,
                            TV,
                            Method::Post,
                            format!("round-tripped via {}: {got:?}", temp.path),
                        )
                    } else {
                        fail(
                            decl,
                            TV,
                            Method::Post,
                            format!(
                                "expected {valid:?} at {}, got {got:?} present={ok}",
                                temp.path
                            ),
                        )
                    }
                }
            }
            Method::Put => {
                let baseline = make_baseline(decl.resource);
                let rc = safe(client.post(endpoint, &baseline)).await;
                if !is_2xx(rc.status) {
                    return error(
                        decl,
                        TV,
                        Method::Put,
                        "could not create baseline for PUT probe",
                    );
                }
                let rid = rc.id().unwrap_or_default();
                bk.note(endpoint, rid.clone());
                let mut put_body = body_of(&rc);
                set_attr(&mut put_body, temp, valid.clone());
                let r = safe(client.put(&format!("{endpoint}/{rid}"), &put_body)).await;
                if !is_2xx(r.status) {
                    error(
                        decl,
                        TV,
                        Method::Put,
                        format!(
                            "valid nested value under {} rejected: {} {}",
                            temp.path,
                            r.status,
                            truncate(&r.raw, 150)
                        ),
                    )
                } else {
                    let (ok, got) = get_attr(&body_of(&r), temp);
                    if ok && values_match(temp, &valid, &got) {
                        pass(
                            decl,
                            TV,
                            Method::Put,
                            format!("round-tripped via {}: {got:?}", temp.path),
                        )
                    } else {
                        fail(
                            decl,
                            TV,
                            Method::Put,
                            format!(
                                "expected {valid:?} at {}, got {got:?} present={ok}",
                                temp.path
                            ),
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

    // `members.$ref` (and any future `.$ref` sibling) is always
    // re-derived by this server from the member's `value`, never echoed
    // verbatim (see `values_match`) — so once a real companion `value` is
    // minted below, the *expected* round-tripped value is derived from
    // that companion, while the *sent* `$ref` stays whatever
    // `valid_value_for` produced (a probe value, not a prediction).
    let mut expected = sent.clone();
    let companion_for = |decl: &AttrDecl| is_group_member_subattr(decl) && decl.last() != "value";

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
            if !is_2xx(r.status) {
                error(
                    decl,
                    TV,
                    Method::Post,
                    format!(
                        "valid value {sent:?} rejected unexpectedly: {} {}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                )
            } else {
                let (ok, got) = get_attr(&body_of(&r), decl);
                if ok && values_match(decl, &expected, &got) {
                    pass(decl, TV, Method::Post, format!("round-tripped: {got:?}"))
                } else {
                    fail(
                        decl,
                        TV,
                        Method::Post,
                        format!("expected {expected:?}, got {got:?} present={ok}"),
                    )
                }
            }
        }
        Method::Put => {
            let baseline = make_baseline(decl.resource);
            let rc = safe(client.post(endpoint, &baseline)).await;
            if !is_2xx(rc.status) {
                return error(
                    decl,
                    TV,
                    Method::Put,
                    "could not create baseline for PUT probe",
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
            if !is_2xx(r.status) {
                error(
                    decl,
                    TV,
                    Method::Put,
                    format!(
                        "valid value {sent:?} rejected unexpectedly: {} {}",
                        r.status,
                        truncate(&r.raw, 150)
                    ),
                )
            } else {
                let (ok, got) = get_attr(&body_of(&r), decl);
                if ok && values_match(decl, &expected, &got) {
                    pass(decl, TV, Method::Put, format!("round-tripped: {got:?}"))
                } else {
                    fail(
                        decl,
                        TV,
                        Method::Put,
                        format!("expected {expected:?}, got {got:?} present={ok}"),
                    )
                }
            }
        }
        _ => unreachable!(),
    }
}

async fn exec_type(
    decl: &AttrDecl,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    universe: &[&AttrDecl],
) -> Vec<Outcome> {
    vec![
        type_wrong_check(decl, client, bk, Method::Post).await,
        type_wrong_check(decl, client, bk, Method::Put).await,
        type_valid_check(decl, client, bk, Method::Post, universe).await,
        type_valid_check(decl, client, bk, Method::Put, universe).await,
    ]
}

// ------------------------------------------------------------------- driver

/// Builds the set of unique `AttrDecl`s referenced by `cells`, in
/// first-seen order (which is the document order `decls_from_schemas`
/// produced them in, since `cells_from_decls` visits decls in that same
/// order and every decl contributes at least one cell).
fn ordered_unique_decls(cells: &[Cell]) -> Vec<&AttrDecl> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for c in cells {
        let key = (c.decl.resource, c.decl.path.as_str());
        if seen.insert(key) {
            out.push(&c.decl);
        }
    }
    out
}

/// Runs every cell in `cells` against the server `client` talks to, and
/// returns one [`Outcome`] per cell (same order, same length). Cells are
/// grouped by `(resource, attribute path, characteristic)` — the unit that
/// shares HTTP round trips (e.g. the `mutability_readOnly` POST/PUT/PATCH
/// triad probes the same created resource) — before running the shared
/// per-characteristic routine, so a single resource creation is reused
/// across its whole triad exactly like the Python prototype.
///
/// Every resource this run creates is deleted best-effort afterward (a 404
/// on delete counts as success).
pub async fn run_cells(client: &mut ScimClient, cells: &[Cell]) -> Vec<Outcome> {
    // Gating happens before execution (T9c): a provider that advertises
    // `patch.supported: false` never receives the PATCH-family request a
    // readOnly/immutable/uniqueness triad would otherwise send for its
    // last row. `capability::gate` is the single source of truth for that
    // decision (also unit-tested and integration-tested against a stub in
    // isolation, with no execution at all); here its per-cell verdict is
    // consulted once per group to decide whether that group's one
    // PATCH-family HTTP call should be skipped.
    let caps = capability::fetch(client).await;
    let gated = capability::gate(cells, &caps);

    let universe = ordered_unique_decls(cells);
    let mut bk = Bookkeeping::new();

    // Group contiguous cells sharing (resource, path, group_kind).
    // `TypeWrong` and `TypeValid` collapse into one group: `exec_type`
    // answers both characteristics in a single 4-row call (matching how
    // `cells_from_decls` emits them back to back for the same decl), so
    // grouping by raw `characteristic` would call it twice and produce
    // twice as many rows as either half-group declared.
    fn group_kind(c: Characteristic) -> u8 {
        match c {
            Characteristic::TypeWrong | Characteristic::TypeValid => 0,
            Characteristic::MutabilityReadOnly => 1,
            Characteristic::MutabilityImmutable => 2,
            Characteristic::Required => 3,
            Characteristic::CaseExact => 4,
            Characteristic::Uniqueness => 5,
            Characteristic::ReturnedNever => 6,
        }
    }

    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;
    while i < cells.len() {
        let start = i;
        let key = (
            cells[i].decl.resource,
            cells[i].decl.path.clone(),
            group_kind(cells[i].characteristic),
        );
        i += 1;
        while i < cells.len()
            && cells[i].decl.resource == key.0
            && cells[i].decl.path == key.1
            && group_kind(cells[i].characteristic) == key.2
        {
            i += 1;
        }
        groups.push((start, i));
    }

    let mut outcomes: Vec<Outcome> = Vec::with_capacity(cells.len());
    for (start, end) in groups {
        let group = &cells[start..end];
        let decl = &group[0].decl;
        let characteristic = group[0].characteristic;
        // The one cell in this group (if any) that `capability::gate`
        // decided to skip -- always the group's single PATCH-family cell,
        // since that's the only `requires_capability` the matrix sets.
        let patch_skip: Option<Outcome> = (start..end).find_map(|idx| match &gated[idx] {
            capability::Gated::Skip(o) if cells[idx].requires_capability.is_some() => {
                Some(o.clone())
            }
            _ => None,
        });
        let rows: Vec<Outcome> = match characteristic {
            Characteristic::MutabilityReadOnly => {
                exec_readonly(decl, client, &mut bk, patch_skip).await
            }
            Characteristic::MutabilityImmutable => {
                exec_immutable(decl, client, &mut bk, patch_skip).await
            }
            Characteristic::Required => exec_required(decl, client, &mut bk).await,
            Characteristic::CaseExact => exec_caseexact(decl, client, &mut bk).await,
            Characteristic::Uniqueness => exec_uniqueness(decl, client, &mut bk, patch_skip).await,
            Characteristic::ReturnedNever => {
                exec_returned_never(decl, client, &mut bk, patch_skip).await
            }
            Characteristic::TypeWrong | Characteristic::TypeValid => {
                exec_type(decl, client, &mut bk, &universe).await
            }
        };
        debug_assert_eq!(
            rows.len(),
            group.len(),
            "executor for {:?} {:?} produced {} rows but the matrix declared {}",
            decl.path,
            characteristic,
            rows.len(),
            group.len()
        );
        for (cell, row) in group.iter().zip(rows) {
            debug_assert_eq!(cell.method, row.method);
            outcomes.push(row);
        }
    }

    cleanup(client, &bk).await;
    outcomes
}

pub(crate) async fn cleanup(client: &ScimClient, bk: &Bookkeeping) {
    // Dedup: the same id may have been noted more than once (e.g. a
    // duplicate-detection probe creates several resources that are each
    // noted once, which is fine; re-deleting the same id twice is also
    // fine — a second DELETE 404s, which counts as success).
    let mut done: HashMap<(&'static str, &str), ()> = HashMap::new();
    for (endpoint, id) in &bk.created {
        if done.insert((*endpoint, id.as_str()), ()).is_some() {
            continue;
        }
        let r = safe(client.delete(&format!("{endpoint}/{id}"))).await;
        // 404 counts as success (already gone, or never really created).
        let _ = r.status;
    }
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
        d.r#type = AttrType::Integer;
        assert_eq!(wrong_value_for(&d), json!("x"));
        d.r#type = AttrType::Decimal;
        assert_eq!(wrong_value_for(&d), json!("x"));
        d.r#type = AttrType::DateTime;
        assert_eq!(wrong_value_for(&d), json!(123));
        d.r#type = AttrType::Reference;
        assert_eq!(wrong_value_for(&d), json!(123));
        d.r#type = AttrType::Complex;
        assert_eq!(wrong_value_for(&d), json!("flat"));
        d.r#type = AttrType::Binary;
        assert_eq!(wrong_value_for(&d), json!(123));
    }

    #[test]
    fn valid_value_prefers_canonical_values() {
        let mut d = string_decl("emails.type");
        d.canonical_values = Some(vec!["work".to_string(), "home".to_string()]);
        assert_eq!(valid_value_for(&d), json!("work"));
    }

    #[test]
    fn valid_value_uses_special_valid_overrides() {
        let d = string_decl("profileUrl");
        assert_eq!(valid_value_for(&d), json!("http://example.com/profile"));
        let d = string_decl("locale");
        assert_eq!(valid_value_for(&d), json!("en-US"));
    }

    #[test]
    fn forged_and_valid_values_are_distinguishable_strings() {
        let d = string_decl("displayName");
        let forged = forged_value_for(&d);
        let valid = valid_value_for(&d);
        assert!(forged.as_str().unwrap().starts_with("FORGED-"));
        assert!(valid.as_str().unwrap().starts_with("Valid-"));
        assert_ne!(forged, valid);
    }

    #[test]
    fn short_uid_is_unique_across_calls() {
        let a = short_uid();
        let b = short_uid();
        assert_ne!(a, b);
    }

    #[test]
    fn set_attr_and_get_attr_round_trip_a_top_level_scalar() {
        let d = string_decl("userName");
        let mut payload = json!({});
        set_attr(&mut payload, &d, json!("alice"));
        let (ok, v) = get_attr(&payload, &d);
        assert!(ok);
        assert_eq!(v, json!("alice"));
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
    fn set_attr_with_companion_pairs_sibling_value() {
        let mut d = string_decl("members.display");
        d.resource = Resource::Group;
        d.parent = Some("members".to_string());
        d.top_multi_valued = true;
        let mut payload = json!({});
        set_attr_with_companion(
            &mut payload,
            &d,
            json!("Forged Name"),
            Some(json!("real-id")),
        );
        assert_eq!(
            payload,
            json!({"members": [{"display": "Forged Name", "value": "real-id"}]})
        );
    }

    #[test]
    fn enterprise_user_fields_are_scoped_under_the_extension_urn() {
        let mut d = string_decl("employeeNumber");
        d.resource = Resource::EnterpriseUser;
        let mut payload = json!({"schemas": [USER_URN]});
        set_attr(&mut payload, &d, json!("123"));
        assert_eq!(payload["schemas"], json!([USER_URN, ENTERPRISE_URN]));
        assert_eq!(payload[ENTERPRISE_URN]["employeeNumber"], json!("123"));
        let (ok, v) = get_attr(&payload, &d);
        assert!(ok);
        assert_eq!(v, json!("123"));
    }
}
