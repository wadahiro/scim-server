//! The seven behavioural axes: `scim-server`'s seven `CompatibilityConfig`
//! knobs (`src/config.rs`, documented in `CLAUDE.md`), each traced back to
//! the real provider behaviour it exists to emulate.
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/probes.rs`
//! -- the HTTP-probing logic per axis is taken over close to 1:1; what
//! changes is the *shape* of the result. That branch's probes returned a
//! schema-matrix `Outcome` (`Verdict::{Pass,Fail,Skip,Error}` against a
//! single fixed expectation). This crate's axes instead classify the
//! observed value against `Axis::known` (see `crate::axis::Value`) and let
//! `crate::render` decide, per axis, whether a given value is a fault --
//! using each axis's own `RfcPosition` rather than a single verdict baked
//! into the probe.

use serde_json::{json, Value as Json};

use crate::axis::{Axis, Cost, Observation, Unobservable, Value};
use crate::capability::{Capabilities, Capability};
use crate::client::{truncate, ScimClient};
use crate::fixtures::{
    body_of, cleanup, fresh_user_id, is_2xx, make_baseline, safe, short_uid, Bookkeeping,
    GROUP_URN, PATCHOP_URN,
};
use crate::rfc::{Keyword, RfcPosition};
use crate::schema::Resource;

fn is_rfc3339(s: &str) -> bool {
    chrono::DateTime::parse_from_rfc3339(s).is_ok()
}

fn is_all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

// --------------------------------------------------------------- registry

pub const META_DATETIME_FORMAT: Axis = Axis {
    id: "meta_datetime_format",
    about: "how meta.created / meta.lastModified are rendered",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_META_DATETIME,
        keyword: Keyword::Must,
        expected: "rfc3339",
    },
    knob: Some("meta_datetime_format"),
    cost: Cost::NeedsUser,
    known: &["rfc3339", "epoch"],
};

pub const EMPTY_MULTIVALUED_RENDERING: Axis = Axis {
    id: "empty_multivalued_rendering",
    about: "whether an empty Group.members is rendered as [] or omitted",
    rfc: RfcPosition::Permitted {
        basis: crate::rfc::PROBE_EMPTY_MEMBERS_SHAPE,
    },
    knob: Some("show_empty_groups_members"),
    cost: Cost::NeedsUserAndGroup,
    known: &["empty_array", "omitted"],
};

pub const USER_GROUPS_PRESENCE: Axis = Axis {
    id: "user_groups_presence",
    about: "whether User.groups appears for a User with known Group membership",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_USER_GROUPS_PRESENCE,
        keyword: Keyword::Should,
        expected: "present",
    },
    knob: Some("include_user_groups"),
    cost: Cost::NeedsUserAndGroup,
    known: &["present", "absent"],
};

pub const GROUP_MEMBERS_FILTER: Axis = Axis {
    id: "group_members_filter",
    about: "whether filter=members[value eq \"...\"] is processed",
    rfc: RfcPosition::Silent,
    knob: Some("support_group_members_filter"),
    cost: Cost::NeedsUserAndGroup,
    known: &["processed", "rejected_400"],
};

pub const GROUP_DISPLAYNAME_FILTER: Axis = Axis {
    id: "group_displayname_filter",
    about: "whether filter=displayName eq \"...\" is processed",
    rfc: RfcPosition::Silent,
    knob: Some("support_group_displayname_filter"),
    cost: Cost::NeedsUserAndGroup,
    known: &["processed", "rejected_400"],
};

pub const PATCH_REPLACE_EMPTY_ARRAY: Axis = Axis {
    id: "patch_replace_empty_array",
    about: "whether PATCH replace with value: [] clears a multi-valued attribute",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_PATCH_REPLACE_EMPTY_ARRAY,
        keyword: Keyword::Must,
        expected: "cleared",
    },
    knob: Some("support_patch_replace_empty_array"),
    cost: Cost::NeedsUser,
    known: &["cleared", "rejected_400", "not_cleared"],
};

pub const PATCH_REPLACE_EMPTY_VALUE: Axis = Axis {
    id: "patch_replace_empty_value",
    about: "whether PATCH replace with value: [{\"value\":\"\"}] clears a multi-valued attribute",
    rfc: RfcPosition::Silent,
    knob: Some("support_patch_replace_empty_value"),
    cost: Cost::NeedsUser,
    known: &["stored_as_sent", "rejected_400", "cleared"],
};

/// All seven axes, in the fixed order they're probed in ([`run_all`]) and
/// reported in (`crate::render`).
pub const AXES: &[Axis] = &[
    META_DATETIME_FORMAT,
    EMPTY_MULTIVALUED_RENDERING,
    USER_GROUPS_PRESENCE,
    GROUP_MEMBERS_FILTER,
    GROUP_DISPLAYNAME_FILTER,
    PATCH_REPLACE_EMPTY_ARRAY,
    PATCH_REPLACE_EMPTY_VALUE,
];

// ---------------------------------------------------------------- probes

fn known_or_unknown(axis: &Axis, token: &str) -> Value {
    match axis.known.iter().find(|k| **k == token) {
        Some(k) => Value::Known(k),
        None => Value::Unknown(token.to_string()),
    }
}

fn unobservable(axis: &Axis, u: Unobservable) -> Observation {
    Observation {
        axis: axis.id,
        value: Value::Unobservable(u),
        evidence: Vec::new(),
        detail: String::new(),
    }
}

pub(crate) async fn probe_meta_datetime_format(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    let axis = &META_DATETIME_FORMAT;
    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if !is_2xx(r.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "baseline POST failed: {} {}",
                r.status,
                truncate(&r.raw, 200)
            ))),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    }
    let rj = body_of(&r);
    let Some(id) = r.id() else {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "baseline POST succeeded but returned no id".to_string(),
            )),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    };
    bk.note("/Users", id.clone());

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    let gj = body_of(&getr);

    let values: [Option<&str>; 4] = [
        rj.pointer("/meta/created").and_then(Json::as_str),
        rj.pointer("/meta/lastModified").and_then(Json::as_str),
        gj.pointer("/meta/created").and_then(Json::as_str),
        gj.pointer("/meta/lastModified").and_then(Json::as_str),
    ];
    let evidence = vec![r.exchange.clone(), getr.exchange.clone()];

    let (token, detail) = if values.iter().all(|v| v.is_some_and(is_rfc3339)) {
        (
            "rfc3339".to_string(),
            format!("meta.created/lastModified parse as RFC 3339: {values:?}"),
        )
    } else if values.iter().all(|v| v.is_some_and(is_all_digits)) {
        (
            "epoch".to_string(),
            format!("meta.created/lastModified are digit strings (epoch milliseconds): {values:?}"),
        )
    } else {
        (
            format!("unrecognised:{values:?}"),
            format!("meta.created/lastModified did not parse as RFC 3339 or epoch: {values:?}"),
        )
    };

    Observation {
        axis: axis.id,
        value: known_or_unknown(axis, &token),
        evidence,
        detail,
    }
}

pub(crate) async fn probe_empty_multivalued_rendering(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    let axis = &EMPTY_MULTIVALUED_RENDERING;
    let r = safe(client.post("/Groups", &make_baseline(Resource::Group))).await;
    if !is_2xx(r.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "baseline POST failed: {} {}",
                r.status,
                truncate(&r.raw, 200)
            ))),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    }
    let Some(id) = r.id() else {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "baseline POST succeeded but returned no id".to_string(),
            )),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    };
    bk.note("/Groups", id.clone());

    let getr = safe(client.get(&format!("/Groups/{id}"))).await;
    let gj = body_of(&getr);
    let evidence = vec![r.exchange.clone(), getr.exchange.clone()];

    match gj.get("members") {
        None => Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "omitted"),
            evidence,
            detail: "members omitted entirely for a Group created without members".to_string(),
        },
        Some(Json::Array(a)) if a.is_empty() => Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "empty_array"),
            evidence,
            detail: "members rendered as [] for a Group created without members".to_string(),
        },
        Some(other) => Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "expected members absent or [], got {other:?}"
            ))),
            evidence,
            detail: String::new(),
        },
    }
}

pub(crate) async fn probe_user_groups_presence(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    let axis = &USER_GROUPS_PRESENCE;
    let Some(uid) = fresh_user_id(client, bk).await else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("could not create fixture User".to_string()),
        );
    };
    let mut gpayload = make_baseline(Resource::Group);
    gpayload["members"] = json!([{ "value": uid }]);
    let gr = safe(client.post("/Groups", &gpayload)).await;
    if !is_2xx(gr.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "fixture Group POST failed: {} {}",
                gr.status,
                truncate(&gr.raw, 200)
            ))),
            evidence: vec![gr.exchange.clone()],
            detail: String::new(),
        };
    }
    let Some(gid) = gr.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture Group POST succeeded but returned no id".into()),
        );
    };
    bk.note("/Groups", gid.clone());

    let getr = safe(client.get(&format!("/Users/{uid}"))).await;
    let uj = body_of(&getr);
    let found = uj
        .get("groups")
        .and_then(Json::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|g| g.get("value").and_then(Json::as_str) == Some(gid.as_str()))
        });
    let evidence = vec![gr.exchange.clone(), getr.exchange.clone()];

    if found {
        Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "present"),
            evidence,
            detail: format!("User.groups contains {gid} after Group membership was created"),
        }
    } else {
        Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "absent"),
            evidence,
            detail: format!("User.groups does not contain {gid}: {uj}"),
        }
    }
}

/// Shared logic for `group_members_filter` and `group_displayname_filter`:
/// `GET /Groups?filter=<filter>` classifies into `processed` (200, expected
/// Group present), `rejected_400` (400 -- may or may not be a real fault,
/// judged by the caller's `RfcPosition`), or unobservable (anything else).
async fn run_group_filter_probe(
    axis: &Axis,
    client: &ScimClient,
    filter: &str,
    expect_group_id: &str,
    setup_evidence: Vec<crate::client::Exchange>,
) -> Observation {
    let r = safe(client.get_query("/Groups", &[("filter", filter)])).await;
    let mut evidence = setup_evidence;
    evidence.push(r.exchange.clone());

    if r.status == 400 {
        return Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "rejected_400"),
            evidence,
            detail: format!(
                "filter={filter} rejected with 400: {}",
                truncate(&r.raw, 150)
            ),
        };
    }
    if r.status != 200 {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "unexpected status {} for filter={filter}: {}",
                r.status,
                truncate(&r.raw, 200)
            ))),
            evidence,
            detail: String::new(),
        };
    }
    let body = body_of(&r);
    let found = body
        .pointer("/Resources")
        .and_then(Json::as_array)
        .is_some_and(|arr| {
            arr.iter()
                .any(|g| g.get("id").and_then(Json::as_str) == Some(expect_group_id))
        });
    if found {
        Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "processed"),
            evidence,
            detail: format!("filter={filter} returned {expect_group_id}"),
        }
    } else {
        Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "filter={filter} returned 200 without {expect_group_id}: {body}"
            ))),
            evidence,
            detail: String::new(),
        }
    }
}

pub(crate) async fn probe_group_members_filter(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &GROUP_MEMBERS_FILTER;
    if caps.get(Capability::Filter) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("filter"));
    }

    let Some(uid) = fresh_user_id(client, bk).await else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("could not create fixture User".to_string()),
        );
    };
    let mut gpayload = make_baseline(Resource::Group);
    gpayload["members"] = json!([{ "value": uid }]);
    let gr = safe(client.post("/Groups", &gpayload)).await;
    if !is_2xx(gr.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "fixture Group POST failed: {} {}",
                gr.status,
                truncate(&gr.raw, 200)
            ))),
            evidence: vec![gr.exchange.clone()],
            detail: String::new(),
        };
    }
    let Some(gid) = gr.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture Group POST succeeded but returned no id".into()),
        );
    };
    bk.note("/Groups", gid.clone());

    let filter = format!(r#"members[value eq "{uid}"]"#);
    run_group_filter_probe(axis, client, &filter, &gid, vec![gr.exchange.clone()]).await
}

pub(crate) async fn probe_group_displayname_filter(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &GROUP_DISPLAYNAME_FILTER;
    if caps.get(Capability::Filter) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("filter"));
    }

    let display_name = format!("g-{}", short_uid());
    let payload = json!({ "schemas": [GROUP_URN], "displayName": display_name });
    let gr = safe(client.post("/Groups", &payload)).await;
    if !is_2xx(gr.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "fixture Group POST failed: {} {}",
                gr.status,
                truncate(&gr.raw, 200)
            ))),
            evidence: vec![gr.exchange.clone()],
            detail: String::new(),
        };
    }
    let Some(gid) = gr.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture Group POST succeeded but returned no id".into()),
        );
    };
    bk.note("/Groups", gid.clone());

    let filter = format!(r#"displayName eq "{display_name}""#);
    run_group_filter_probe(axis, client, &filter, &gid, vec![gr.exchange.clone()]).await
}

fn patch_replace_phone_numbers(value: Json) -> Json {
    json!({
        "schemas": [PATCHOP_URN],
        "Operations": [{ "op": "replace", "path": "phoneNumbers", "value": value }],
    })
}

async fn create_user_with_phone_number(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Result<(String, crate::client::Exchange), String> {
    let mut payload = make_baseline(Resource::User);
    payload["phoneNumbers"] = json!([{ "value": "+15555550100" }]);
    let r = safe(client.post("/Users", &payload)).await;
    if !is_2xx(r.status) {
        return Err(format!(
            "fixture POST (with a phoneNumbers value) failed: {} {}",
            r.status,
            truncate(&r.raw, 200)
        ));
    }
    let Some(id) = r.id() else {
        return Err("fixture POST succeeded but returned no id".to_string());
    };
    bk.note("/Users", id.clone());
    Ok((id, r.exchange.clone()))
}

pub(crate) async fn probe_patch_replace_empty_array(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &PATCH_REPLACE_EMPTY_ARRAY;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }

    let (id, setup_exchange) = match create_user_with_phone_number(client, bk).await {
        Ok(v) => v,
        Err(msg) => return unobservable(axis, Unobservable::ProbeFailed(msg)),
    };

    let pr = safe(client.patch(
        &format!("/Users/{id}"),
        &patch_replace_phone_numbers(json!([])),
    ))
    .await;
    let mut evidence = vec![setup_exchange, pr.exchange.clone()];

    if pr.status == 400 {
        return Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "rejected_400"),
            evidence,
            detail: format!(
                "PATCH replace phoneNumbers with [] rejected: {}",
                truncate(&pr.raw, 150)
            ),
        };
    }
    if !is_2xx(pr.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "unexpected status {}: {}",
                pr.status,
                truncate(&pr.raw, 200)
            ))),
            evidence,
            detail: String::new(),
        };
    }

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    evidence.push(getr.exchange.clone());
    let gj = body_of(&getr);
    let cleared = match gj.get("phoneNumbers") {
        None => true,
        Some(Json::Array(a)) => a.is_empty(),
        Some(_) => false,
    };
    if cleared {
        Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers absent or [] after PATCH replace with []".to_string(),
        }
    } else {
        Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "not_cleared"),
            evidence,
            detail: format!(
                "phoneNumbers still present after PATCH replace with []: {:?}",
                gj.get("phoneNumbers")
            ),
        }
    }
}

pub(crate) async fn probe_patch_replace_empty_value(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &PATCH_REPLACE_EMPTY_VALUE;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }

    let (id, setup_exchange) = match create_user_with_phone_number(client, bk).await {
        Ok(v) => v,
        Err(msg) => return unobservable(axis, Unobservable::ProbeFailed(msg)),
    };

    let pr = safe(client.patch(
        &format!("/Users/{id}"),
        &patch_replace_phone_numbers(json!([{ "value": "" }])),
    ))
    .await;
    let mut evidence = vec![setup_exchange, pr.exchange.clone()];

    if pr.status == 400 {
        return Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "rejected_400"),
            evidence,
            detail: format!(
                "PATCH replace phoneNumbers with [{{\"value\":\"\"}}] rejected: {}",
                truncate(&pr.raw, 150)
            ),
        };
    }
    if !is_2xx(pr.status) {
        return Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "unexpected status {}: {}",
                pr.status,
                truncate(&pr.raw, 200)
            ))),
            evidence,
            detail: String::new(),
        };
    }

    let getr = safe(client.get(&format!("/Users/{id}"))).await;
    evidence.push(getr.exchange.clone());
    let gj = body_of(&getr);
    match gj.get("phoneNumbers") {
        Some(Json::Array(a))
            if a.len() == 1 && a[0].get("value").and_then(Json::as_str) == Some("") =>
        {
            Observation {
                axis: axis.id,
                value: known_or_unknown(axis, "stored_as_sent"),
                evidence,
                detail: "phoneNumbers stored as [{\"value\":\"\"}] verbatim -- a literal replace"
                    .to_string(),
            }
        }
        None => Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers was removed entirely -- the server rewrote replace as clear"
                .to_string(),
        },
        Some(Json::Array(a)) if a.is_empty() => Observation {
            axis: axis.id,
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers was replaced with [] -- the server rewrote replace as clear"
                .to_string(),
        },
        other => Observation {
            axis: axis.id,
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "unexpected phoneNumbers shape after replace: {other:?}"
            ))),
            evidence,
            detail: String::new(),
        },
    }
}

/// Runs all seven axis probes, in the fixed [`AXES`] order, against
/// `client`. Deterministic: no probe depends on another's outcome, only
/// (for the two filter probes and the two PATCH probes) on the provider's
/// own advertised capabilities. Cleans up every fixture it created
/// afterward, best-effort, the same way `crate::runner`'s caller expects.
///
/// Callers that only want the `Cost::DiscoveryOnly` subset, or that want
/// to skip capability-gated axes without spending a probe on them, should
/// use `crate::runner::run` instead -- this function always runs the full
/// set and is meant for testing/direct use where the caller already knows
/// writes are allowed.
pub async fn run_all(client: &mut ScimClient) -> Vec<Observation> {
    let caps = capability_or_unknown(client).await;
    let mut bk = Bookkeeping::new();

    let observations = vec![
        probe_meta_datetime_format(client, &mut bk).await,
        probe_empty_multivalued_rendering(client, &mut bk).await,
        probe_user_groups_presence(client, &mut bk).await,
        probe_group_members_filter(client, &mut bk, &caps).await,
        probe_group_displayname_filter(client, &mut bk, &caps).await,
        probe_patch_replace_empty_array(client, &mut bk, &caps).await,
        probe_patch_replace_empty_value(client, &mut bk, &caps).await,
    ];

    cleanup(client, &bk).await;
    observations
}

async fn capability_or_unknown(client: &ScimClient) -> Capabilities {
    crate::capability::fetch(client).await
}
