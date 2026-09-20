//! Protocol probes (T10c): non-schema-driven checks that catch what the
//! schema-driven matrix (`crate::matrix`) can't see. The matrix derives
//! everything from `GET /Schemas`'s per-attribute declarations, so it's
//! blind to behavior that lives in how the *protocol* is wired up rather
//! than in any single attribute's declared characteristics -- e.g. whether
//! `meta.created` is rendered as an RFC 3339 string or an epoch integer, or
//! whether a `filter=members[value eq "..."]` query is honored at all.
//!
//! Each probe creates its own fixtures and records their ids in a
//! [`Bookkeeping`](crate::matrix::exec::Bookkeeping) exactly the way
//! `crate::matrix::exec::run_cells` does, so [`run_all`] cleans everything
//! up the same best-effort way at the end of a run.

use serde_json::{json, Value};

use crate::basis;
use crate::capability::{self, Capabilities, Capability};
use crate::client::{truncate, ScimClient};
use crate::matrix::exec::{
    body_of, cleanup, fresh_user_id, is_2xx, make_baseline, safe, short_uid, Bookkeeping,
    GROUP_URN, PATCHOP_URN, USER_URN,
};
use crate::matrix::{Characteristic, Method, Outcome, Verdict};
use crate::schema::Resource;

/// The fixed (resource, attribute, schema, characteristic, method) identity
/// of one probe's output row, factored out so each probe's several possible
/// outcomes (pass/fail/skip/error) don't have to repeat it.
struct ProbeKey {
    resource: Resource,
    attribute: &'static str,
    schema: &'static str,
    characteristic: Characteristic,
    method: Method,
}

impl ProbeKey {
    /// A PASS/FAIL row with a canonical `observed` token (see module docs
    /// on `crate::matrix::Outcome::observed`).
    fn row(&self, verdict: Verdict, observed: &str, detail: impl Into<String>) -> Outcome {
        self.raw(verdict, Some(observed.to_string()), detail)
    }

    /// A SKIP row (no request sent -- gated on a capability).
    fn skip(&self, detail: impl Into<String>) -> Outcome {
        self.raw(Verdict::Skip, None, detail)
    }

    /// The probe itself misbehaved (a fixture couldn't be created, an
    /// unexpected status came back). Never a finding.
    fn error(&self, detail: impl Into<String>) -> Outcome {
        self.raw(Verdict::Error, None, detail)
    }

    fn raw(
        &self,
        verdict: Verdict,
        observed: Option<String>,
        detail: impl Into<String>,
    ) -> Outcome {
        Outcome {
            attribute: self.attribute.to_string(),
            schema: self.schema.to_string(),
            resource: self.resource,
            characteristic: self.characteristic,
            method: self.method,
            verdict,
            basis: basis::for_characteristic(self.characteristic),
            detail: detail.into(),
            observed,
            secondary: Vec::new(),
        }
    }
}

fn is_rfc3339(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// ---------------------------------------------------------- meta_datetime

/// RFC 7643 §2.3.5 / §3.1: `meta.created`/`meta.lastModified` must be a
/// `DateTime`, i.e. a valid xsd:dateTime (RFC 3339-ish) string -- not an
/// epoch integer. Checked on both the POST response and a follow-up GET.
async fn probe_meta_datetime(client: &ScimClient, bk: &mut Bookkeeping) -> Outcome {
    let key = ProbeKey {
        resource: Resource::User,
        attribute: "meta.created,meta.lastModified",
        schema: USER_URN,
        characteristic: Characteristic::ProbeMetaDatetime,
        method: Method::Post,
    };

    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if !is_2xx(r.status) {
        return key.error(format!(
            "baseline POST failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        ));
    }
    let rj = body_of(&r);
    let Some(id) = r.id() else {
        return key.error("baseline POST succeeded but returned no id");
    };
    bk.note("/Users", id.clone());

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    let gj = body_of(&getr);

    let values: [Option<&str>; 4] = [
        rj.pointer("/meta/created").and_then(Value::as_str),
        rj.pointer("/meta/lastModified").and_then(Value::as_str),
        gj.pointer("/meta/created").and_then(Value::as_str),
        gj.pointer("/meta/lastModified").and_then(Value::as_str),
    ];

    if values.iter().all(|v| v.is_some_and(is_rfc3339)) {
        key.row(
            Verdict::Pass,
            "rfc3339",
            format!("meta.created/lastModified parse as RFC 3339 in the POST response and a follow-up GET: {values:?}"),
        )
    } else if values.iter().all(|v| v.is_some_and(is_all_digits)) {
        key.row(
            Verdict::Fail,
            "epoch",
            format!("meta.created/lastModified are digit strings (epoch milliseconds), not RFC 3339: {values:?}"),
        )
    } else {
        key.row(
            Verdict::Fail,
            "unrecognised",
            format!("meta.created/lastModified did not parse as RFC 3339 or epoch: {values:?}"),
        )
    }
}

// ----------------------------------------------------- empty_members_shape

/// RFC 7643 §2.5: unassigned, null, and an empty array are equivalent
/// states for a multi-valued attribute -- a Group created without
/// `members` may render it either as `[]` or omit it; both conform. This
/// probe only records which shape the server chose (both verdicts are
/// PASS); `show_empty_groups_members: false` is expected to flip the
/// `observed` token without changing the verdict.
async fn probe_empty_members_shape(client: &ScimClient, bk: &mut Bookkeeping) -> Outcome {
    let key = ProbeKey {
        resource: Resource::Group,
        attribute: "members",
        schema: GROUP_URN,
        characteristic: Characteristic::ProbeEmptyMembersShape,
        method: Method::Post,
    };

    let r = safe(client.post("/Groups", &make_baseline(Resource::Group))).await;
    if !is_2xx(r.status) {
        return key.error(format!(
            "baseline POST failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        ));
    }
    let Some(id) = r.id() else {
        return key.error("baseline POST succeeded but returned no id");
    };
    bk.note("/Groups", id.clone());

    let getr = safe(client.get(&format!("/Groups/{id}"))).await;
    let gj = body_of(&getr);
    match gj.get("members") {
        None => key.row(
            Verdict::Pass,
            "absent",
            "members omitted entirely for a Group created without members",
        ),
        Some(Value::Array(a)) if a.is_empty() => key.row(
            Verdict::Pass,
            "empty_array",
            "members rendered as [] for a Group created without members",
        ),
        Some(other) => key.row(
            Verdict::Fail,
            "non_empty",
            format!("expected members absent or [], got {other:?}"),
        ),
    }
}

// --------------------------------------------------- user_groups_presence

/// RFC 7643 §4.1.2 (`groups`) / §7 (`returned: default`): a User with real
/// Group membership is expected to render `groups` by default, not omit
/// it.
async fn probe_user_groups_presence(client: &ScimClient, bk: &mut Bookkeeping) -> Outcome {
    let key = ProbeKey {
        resource: Resource::User,
        attribute: "groups",
        schema: USER_URN,
        characteristic: Characteristic::ProbeUserGroupsPresence,
        method: Method::Get,
    };

    let Some(uid) = fresh_user_id(client, bk).await else {
        return key.error("could not create fixture User");
    };
    let mut gpayload = make_baseline(Resource::Group);
    gpayload["members"] = json!([{ "value": uid }]);
    let gr = safe(client.post("/Groups", &gpayload)).await;
    if !is_2xx(gr.status) {
        return key.error(format!(
            "fixture Group POST failed: {} {}",
            gr.status,
            truncate(&gr.raw, 200)
        ));
    }
    let Some(gid) = gr.id() else {
        return key.error("fixture Group POST succeeded but returned no id");
    };
    bk.note("/Groups", gid.clone());

    let getr = safe(client.get(&format!("/Users/{uid}"))).await;
    let uj = body_of(&getr);
    let found = uj
        .get("groups")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|g| g.get("value").and_then(Value::as_str) == Some(gid.as_str()))
        });

    if found {
        key.row(
            Verdict::Pass,
            "present",
            format!("User.groups contains {gid} after Group membership was created"),
        )
    } else {
        key.row(
            Verdict::Fail,
            "absent",
            format!("User.groups does not contain {gid}: {uj}"),
        )
    }
}

// ------------------------------------------------ group_{members,displayname}_filter

/// Runs `GET /Groups?filter=<filter>` and classifies the response into the
/// three-way rule shared by `group_members_filter` and
/// `group_displayname_filter`: 200 with the expected Group present ->
/// PASS; a 400 rejection -> FAIL (`status=400`); 200 without it -> FAIL
/// (`missing`).
///
/// Filtering itself is OPTIONAL (RFC 7644 §3.4.2.2, L926: "Filtering is an
/// OPTIONAL parameter for SCIM service providers"), discoverable via
/// `ServiceProviderConfig`'s `filter.supported` (same section, L927-929).
/// A provider that has explicitly declared `filter.supported: false` is
/// not violating anything by rejecting *any* filter, this one included --
/// callers gate on that (`Capability::Filter`) before calling this
/// function, so a 400 that reaches here is judged against a provider that
/// (at minimum) hasn't disclaimed filtering altogether.
async fn run_group_filter_probe(
    client: &ScimClient,
    key: &ProbeKey,
    filter: &str,
    expect_group_id: &str,
) -> Outcome {
    let r = safe(client.get_query("/Groups", &[("filter", filter)])).await;
    if r.status == 400 {
        return key.row(
            Verdict::Fail,
            "status=400",
            format!(
                "filter={filter} rejected with 400: {}",
                truncate(&r.raw, 150)
            ),
        );
    }
    if r.status != 200 {
        return key.error(format!(
            "unexpected status {} for filter={filter}: {}",
            r.status,
            truncate(&r.raw, 200)
        ));
    }
    let body = body_of(&r);
    let found = body
        .pointer("/Resources")
        .and_then(Value::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|g| g.get("id").and_then(Value::as_str) == Some(expect_group_id))
        });
    if found {
        key.row(
            Verdict::Pass,
            "present",
            format!("filter={filter} returned {expect_group_id}"),
        )
    } else {
        key.row(
            Verdict::Fail,
            "missing",
            format!("filter={filter} returned 200 without {expect_group_id}: {body}"),
        )
    }
}

/// RFC 7644 §3.4.2.2: a well-formed filter (per Figure 1's ABNF) must be
/// processed, not rejected with `invalidFilter` -- that scimType is for
/// syntax the server can't parse (Table 9), not a feature the server
/// chooses not to support. This exact spelling,
/// `members[value eq "<id>"]`, is this server's documented Group-members
/// filter (`CLAUDE.md`, `support_group_members_filter`).
///
/// Filtering as a whole is OPTIONAL (§3.4.2.2 L926) and its support is
/// meant to be discovered via `ServiceProviderConfig.filter.supported`
/// (§3.4.2.2 L927-929), so a provider that has explicitly advertised
/// `filter.supported: false` is not violating this rule by rejecting this
/// filter -- gated on `Capability::Filter` (`caps`) before this probe
/// sends anything, the same pattern `matrix::capability::gate` uses for
/// PATCH-family cells. Distinct from this server's own
/// `support_group_members_filter` compatibility knob, which has no RFC
/// discovery mechanism at all and so cannot be gated on generically by a
/// conformance tool meant to run against any SCIM server.
async fn probe_group_members_filter(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Outcome {
    let key = ProbeKey {
        resource: Resource::Group,
        attribute: "members",
        schema: GROUP_URN,
        characteristic: Characteristic::ProbeGroupMembersFilter,
        method: Method::Get,
    };
    if caps.get(Capability::Filter) == Some(false) {
        return key.skip("filter.supported=false");
    }

    let Some(uid) = fresh_user_id(client, bk).await else {
        return key.error("could not create fixture User");
    };
    let mut gpayload = make_baseline(Resource::Group);
    gpayload["members"] = json!([{ "value": uid }]);
    let gr = safe(client.post("/Groups", &gpayload)).await;
    if !is_2xx(gr.status) {
        return key.error(format!(
            "fixture Group POST failed: {} {}",
            gr.status,
            truncate(&gr.raw, 200)
        ));
    }
    let Some(gid) = gr.id() else {
        return key.error("fixture Group POST succeeded but returned no id");
    };
    bk.note("/Groups", gid.clone());

    let filter = format!(r#"members[value eq "{uid}"]"#);
    run_group_filter_probe(client, &key, &filter, &gid).await
}

/// RFC 7644 §3.4.2.2, same rule (and same `filter.supported` gating) as
/// [`probe_group_members_filter`], for a `displayName eq "<name>"` filter
/// (`support_group_displayname_filter`).
async fn probe_group_displayname_filter(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Outcome {
    let key = ProbeKey {
        resource: Resource::Group,
        attribute: "displayName",
        schema: GROUP_URN,
        characteristic: Characteristic::ProbeGroupDisplaynameFilter,
        method: Method::Get,
    };
    if caps.get(Capability::Filter) == Some(false) {
        return key.skip("filter.supported=false");
    }

    let display_name = format!("g-{}", short_uid());
    let payload = json!({ "schemas": [GROUP_URN], "displayName": display_name });
    let gr = safe(client.post("/Groups", &payload)).await;
    if !is_2xx(gr.status) {
        return key.error(format!(
            "fixture Group POST failed: {} {}",
            gr.status,
            truncate(&gr.raw, 200)
        ));
    }
    let Some(gid) = gr.id() else {
        return key.error("fixture Group POST succeeded but returned no id");
    };
    bk.note("/Groups", gid.clone());

    let filter = format!(r#"displayName eq "{display_name}""#);
    run_group_filter_probe(client, &key, &filter, &gid).await
}

// ------------------------------------------- patch_replace_empty_{array,value}

fn patch_replace_phone_numbers(value: Value) -> Value {
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [{ "op": "replace", "path": "phoneNumbers", "value": value }],
    })
}

async fn create_user_with_phone_number(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Result<String, Outcome> {
    let key_for_error = ProbeKey {
        resource: Resource::User,
        attribute: "phoneNumbers",
        schema: USER_URN,
        // Only used for the `error()` shorthand below; the caller
        // overwrites `characteristic`/`method` on its own returned rows.
        characteristic: Characteristic::ProbePatchReplaceEmptyArray,
        method: Method::Patch,
    };
    let mut payload = make_baseline(Resource::User);
    payload["phoneNumbers"] = json!([{ "value": "+15555550100" }]);
    let r = safe(client.post("/Users", &payload)).await;
    if !is_2xx(r.status) {
        return Err(key_for_error.error(format!(
            "fixture POST (with a phoneNumbers value) failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        )));
    }
    let Some(id) = r.id() else {
        return Err(key_for_error.error("fixture POST succeeded but returned no id"));
    };
    bk.note("/Users", id.clone());
    Ok(id)
}

/// RFC 7644 §3.5.2.3: "If the target location is a multi-valued attribute
/// and no filter is specified, the attribute and all values are replaced" --
/// replacing with `[]` clears it. Gated on `patch.supported` (T9c).
async fn probe_patch_replace_empty_array(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Outcome {
    let key = ProbeKey {
        resource: Resource::User,
        attribute: "phoneNumbers",
        schema: USER_URN,
        characteristic: Characteristic::ProbePatchReplaceEmptyArray,
        method: Method::Patch,
    };
    if caps.get(Capability::Patch) == Some(false) {
        return key.skip("patch.supported=false");
    }

    let id = match create_user_with_phone_number(client, bk).await {
        Ok(id) => id,
        Err(o) => return o,
    };

    let pr = safe(client.patch(
        &format!("/Users/{id}"),
        &patch_replace_phone_numbers(json!([])),
    ))
    .await;
    if pr.status == 400 {
        return key.row(
            Verdict::Fail,
            "status=400",
            format!(
                "PATCH replace phoneNumbers with [] rejected: {}",
                truncate(&pr.raw, 150)
            ),
        );
    }
    if !is_2xx(pr.status) {
        return key.error(format!(
            "unexpected status {}: {}",
            pr.status,
            truncate(&pr.raw, 200)
        ));
    }

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    let gj = body_of(&getr);
    let cleared = match gj.get("phoneNumbers") {
        None => true,
        Some(Value::Array(a)) => a.is_empty(),
        Some(_) => false,
    };
    if cleared {
        key.row(
            Verdict::Pass,
            "cleared",
            "phoneNumbers absent or [] after PATCH replace with []",
        )
    } else {
        key.row(
            Verdict::Fail,
            "not_cleared",
            format!(
                "phoneNumbers still present after PATCH replace with []: {:?}",
                gj.get("phoneNumbers")
            ),
        )
    }
}

/// RFC 7644 §3.5.2.3 replace, for the non-standard `[{"value":""}]`
/// clearing pattern some legacy clients send. Rejecting it outright is
/// permissible validation (PASS); accepting it and storing the value
/// verbatim is a literal "replace" (PASS, `stored_as_sent`); accepting it
/// and *clearing* the attribute means the server silently reinterpreted
/// "replace" as "clear" for this one non-standard spelling -- not the
/// operation RFC 7644 describes (FAIL, `cleared`). Gated on
/// `patch.supported` (T9c).
async fn probe_patch_replace_empty_value(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Outcome {
    let key = ProbeKey {
        resource: Resource::User,
        attribute: "phoneNumbers",
        schema: USER_URN,
        characteristic: Characteristic::ProbePatchReplaceEmptyValue,
        method: Method::Patch,
    };
    if caps.get(Capability::Patch) == Some(false) {
        return key.skip("patch.supported=false");
    }

    let id = match create_user_with_phone_number(client, bk).await {
        Ok(id) => id,
        Err(mut o) => {
            o.characteristic = Characteristic::ProbePatchReplaceEmptyValue;
            o.basis = basis::for_characteristic(o.characteristic);
            return o;
        }
    };

    let pr = safe(client.patch(
        &format!("/Users/{id}"),
        &patch_replace_phone_numbers(json!([{ "value": "" }])),
    ))
    .await;
    if pr.status == 400 {
        return key.row(
            Verdict::Pass,
            "status=400",
            format!(
                "PATCH replace phoneNumbers with [{{\"value\":\"\"}}] rejected: {}",
                truncate(&pr.raw, 150)
            ),
        );
    }
    if !is_2xx(pr.status) {
        return key.error(format!(
            "unexpected status {}: {}",
            pr.status,
            truncate(&pr.raw, 200)
        ));
    }

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    let gj = body_of(&getr);
    match gj.get("phoneNumbers") {
        Some(Value::Array(a))
            if a.len() == 1 && a[0].get("value").and_then(Value::as_str) == Some("") =>
        {
            key.row(
                Verdict::Pass,
                "stored_as_sent",
                "phoneNumbers stored as [{\"value\":\"\"}] verbatim -- a literal replace",
            )
        }
        None => key.row(
            Verdict::Fail,
            "cleared",
            "phoneNumbers was removed entirely -- the server rewrote replace as clear",
        ),
        Some(Value::Array(a)) if a.is_empty() => key.row(
            Verdict::Fail,
            "cleared",
            "phoneNumbers was replaced with [] -- the server rewrote replace as clear",
        ),
        other => key.row(
            Verdict::Fail,
            "unexpected",
            format!("unexpected phoneNumbers shape after replace: {other:?}"),
        ),
    }
}

// ------------------------------------------------------------------- driver

/// Runs all 7 protocol probes, in this fixed order, against `client`.
/// Deterministic: no probe depends on another's outcome, only (for the two
/// PATCH probes) on the provider's own advertised `patch.supported`.
/// Cleans up every fixture it created afterward, the same best-effort way
/// `crate::matrix::exec::run_cells` does.
pub async fn run_all(client: &mut ScimClient) -> Vec<Outcome> {
    let caps = capability::fetch(client).await;
    let mut bk = Bookkeeping::new();

    let outcomes = vec![
        probe_meta_datetime(client, &mut bk).await,
        probe_empty_members_shape(client, &mut bk).await,
        probe_user_groups_presence(client, &mut bk).await,
        probe_group_members_filter(client, &mut bk, &caps).await,
        probe_group_displayname_filter(client, &mut bk, &caps).await,
        probe_patch_replace_empty_array(client, &mut bk, &caps).await,
        probe_patch_replace_empty_value(client, &mut bk, &caps).await,
    ];

    cleanup(client, &bk).await;
    outcomes
}
