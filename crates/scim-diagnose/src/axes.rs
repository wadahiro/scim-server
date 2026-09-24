//! The sixteen static behavioural axes: `scim-server`'s seven
//! `CompatibilityConfig` knobs (`src/config.rs`, documented in
//! `CLAUDE.md`), each traced back to the real provider behaviour it exists
//! to emulate, plus nine more ported from `feat/rfc-extract`'s
//! `crates/scim-conformance/src/templates/{status,sequence,atomicity,
//! conditional}.rs` (the `uniqueness_scimtype` family, 6 instances, and
//! `patch_sequential_application`/`patch_atomicity`/`patch_primary_demotion`,
//! 1 instance each).
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/probes.rs`
//! (the original seven) and `.../templates/*.rs` (the nine added here) --
//! the HTTP-probing logic per axis is taken over close to 1:1; what
//! changes is the *shape* of the result. That branch's probes returned a
//! schema-matrix `Outcome` (`Verdict::{Pass,Fail,Skip,Error}` against a
//! single fixed expectation, via a `Requirement`/ledger citation this
//! crate does not carry over -- see `crate::rfc`'s module docs). This
//! crate's axes instead classify the observed value against `Axis::known`
//! (see `crate::axis::Value`) and let `crate::render` decide, per axis,
//! whether a given value is a fault -- using each axis's own
//! `RfcPosition` rather than a single verdict baked into the probe.

use serde_json::{json, Value as Json};

use crate::axis::{Axis, Cost, Observation, Unobservable, Value};
use crate::capability::{Capabilities, Capability};
use crate::client::{truncate, ScimClient, ScimResponse};
use crate::fixtures::{
    body_of, cleanup, fresh_user_id, is_2xx, make_baseline, safe, short_uid, Bookkeeping,
    GROUP_URN, PATCHOP_URN, USER_URN,
};
use crate::rfc::{Keyword, RfcPosition};
use crate::schema::{decls_from_schemas, Resource};

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

/// Every combination `Returned` (`crate::schema::Returned`) crosses with
/// observed presence. Built by [`self_declared_token`]; see its doc comment
/// and `crate::rfc::self_declared_is_fault` for which combinations are
/// faults.
const USER_GROUPS_PRESENCE_KNOWN: &[&str] = &[
    "declares_default_present",
    "declares_default_absent",
    "declares_never_present",
    "declares_never_absent",
    "declares_always_present",
    "declares_always_absent",
    "declares_request_present",
    "declares_request_absent",
];

pub const USER_GROUPS_PRESENCE: Axis = Axis {
    id: "user_groups_presence",
    about: "whether User.groups appears for a User with known Group membership, judged against the target's own declared returned characteristic for User.groups",
    rfc: RfcPosition::SelfDeclared {
        basis: crate::rfc::PROBE_USER_GROUPS_PRESENCE,
        declares: "groups.returned",
    },
    knob: Some("include_user_groups"),
    cost: Cost::NeedsUserAndGroup,
    known: USER_GROUPS_PRESENCE_KNOWN,
};

/// Builds the `"declares_<value>_<present|absent>"` token
/// `crate::rfc::self_declared_is_fault` judges.
fn self_declared_token(declared: &str, present: bool) -> String {
    format!(
        "declares_{declared}_{}",
        if present { "present" } else { "absent" }
    )
}

pub const GROUP_MEMBERS_FILTER: Axis = Axis {
    id: "group_members_filter",
    about: "whether filter=members[value eq \"...\"] is processed",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_GROUP_FILTER),
    },
    knob: Some("support_group_members_filter"),
    cost: Cost::NeedsUserAndGroup,
    known: &["processed", "rejected_400"],
};

pub const GROUP_DISPLAYNAME_FILTER: Axis = Axis {
    id: "group_displayname_filter",
    about: "whether filter=displayName eq \"...\" is processed",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_GROUP_FILTER),
    },
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
    rfc: RfcPosition::Silent { basis: None },
    knob: Some("support_patch_replace_empty_value"),
    cost: Cost::NeedsUser,
    known: &["stored_as_sent", "rejected_400", "cleared"],
};

// ---------------------------------------------------- uniqueness_scimtype
//
// Ported from `feat/rfc-extract`'s
// `crates/scim-conformance/src/templates/status.rs`: create A with a
// unique value, then try to give B that same value via POST/PUT/PATCH, for
// both User (`userName`) and Group (`displayName`) -- 6 instances. That
// source branch asserted the response's `scimType` MUST be `"uniqueness"`.
// It can't be: RFC 7644 §3.12 declares `scimType` OPTIONAL with no closing
// keyword (`rfc7644.txt:3718-3719`, `crate::rfc::PROBE_UNIQUENESS_SCIMTYPE`),
// and RFC 7643 §7 already makes *rejecting* a duplicate at all a MAY, not a
// MUST (`crate::rfc::UNIQUENESS`). So this is the fingerprint axis it
// really is (`RfcPosition::Silent`, no verdict): what does the provider
// actually emit? `known` covers the values worth naming by hand --
// `"uniqueness"` (Table 9's suggested keyword), `"invalidValue"` (a
// plausible generic substitute), `"none"` (rejected with no `scimType` in
// the body at all), and `"accepted"` (not rejected -- a legitimate,
// RFC-permitted choice per `UNIQUENESS`'s MAY, but still worth recording
// since it means the uniqueness constraint isn't enforced through this
// path at all). Anything else the wire actually returns falls through to
// `Value::Unknown`, carrying full evidence -- that unnamed-value discovery
// is this axis's entire point.
const UNIQUENESS_SCIMTYPE_KNOWN: &[&str] = &["uniqueness", "invalidValue", "none", "accepted"];

pub const UNIQUENESS_SCIMTYPE_USER_POST: Axis = Axis {
    id: "uniqueness_scimtype/User/POST",
    about: "scimType (or outright acceptance) a POST of a duplicate userName produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

pub const UNIQUENESS_SCIMTYPE_USER_PUT: Axis = Axis {
    id: "uniqueness_scimtype/User/PUT",
    about: "scimType (or outright acceptance) a PUT that sets userName to another User's value produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

pub const UNIQUENESS_SCIMTYPE_USER_PATCH: Axis = Axis {
    id: "uniqueness_scimtype/User/PATCH",
    about: "scimType (or outright acceptance) a PATCH replace that sets userName to another User's value produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

pub const UNIQUENESS_SCIMTYPE_GROUP_POST: Axis = Axis {
    id: "uniqueness_scimtype/Group/POST",
    about: "scimType (or outright acceptance) a POST of a duplicate displayName produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUserAndGroup,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

pub const UNIQUENESS_SCIMTYPE_GROUP_PUT: Axis = Axis {
    id: "uniqueness_scimtype/Group/PUT",
    about: "scimType (or outright acceptance) a PUT that sets displayName to another Group's value produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUserAndGroup,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

pub const UNIQUENESS_SCIMTYPE_GROUP_PATCH: Axis = Axis {
    id: "uniqueness_scimtype/Group/PATCH",
    about: "scimType (or outright acceptance) a PATCH replace that sets displayName to another Group's value produces",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::PROBE_UNIQUENESS_SCIMTYPE),
    },
    knob: None,
    cost: Cost::NeedsUserAndGroup,
    known: UNIQUENESS_SCIMTYPE_KNOWN,
};

// ------------------------------------------ patch_sequential_application

pub const PATCH_SEQUENTIAL_APPLICATION: Axis = Axis {
    id: "patch_sequential_application",
    about: "whether two replace operations against the same PATCH path apply in array order (the later one wins)",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_PATCH_SEQUENTIAL_APPLICATION,
        keyword: Keyword::Must,
        expected: "b",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: &["b", "a", "absent"],
};

// ------------------------------------------------------- patch_atomicity

pub const PATCH_ATOMICITY: Axis = Axis {
    id: "patch_atomicity",
    about: "whether a PATCH with a valid first operation and an invalid second operation is rejected without the first operation's effect sticking",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_PATCH_ATOMICITY,
        keyword: Keyword::Must,
        expected: "rejected_and_unchanged",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: &["rejected_and_unchanged", "accepted", "rejected_but_changed"],
};

// ------------------------------------------------- patch_primary_demotion

pub const PATCH_PRIMARY_DEMOTION: Axis = Axis {
    id: "patch_primary_demotion",
    about: "whether PATCH-adding a new primary email demotes the previously primary email, leaving exactly the new one primary",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::PROBE_PATCH_PRIMARY_DEMOTION,
        keyword: Keyword::Must,
        expected: "new_primary_only",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: &[
        "new_primary_only",
        "add_dropped",
        "multiple_primary",
        "wrong_primary",
    ],
};

/// All sixteen axes, in the fixed order they're probed in ([`run_all`]) and
/// reported in (`crate::render`): the original seven `CompatibilityConfig`
/// axes, then the nine ported from `feat/rfc-extract`'s
/// `templates/{status,sequence,atomicity,conditional}.rs` (the six
/// `uniqueness_scimtype` instances, then `patch_sequential_application`,
/// `patch_atomicity`, `patch_primary_demotion`).
pub const AXES: &[Axis] = &[
    META_DATETIME_FORMAT,
    EMPTY_MULTIVALUED_RENDERING,
    USER_GROUPS_PRESENCE,
    GROUP_MEMBERS_FILTER,
    GROUP_DISPLAYNAME_FILTER,
    PATCH_REPLACE_EMPTY_ARRAY,
    PATCH_REPLACE_EMPTY_VALUE,
    UNIQUENESS_SCIMTYPE_USER_POST,
    UNIQUENESS_SCIMTYPE_USER_PUT,
    UNIQUENESS_SCIMTYPE_USER_PATCH,
    UNIQUENESS_SCIMTYPE_GROUP_POST,
    UNIQUENESS_SCIMTYPE_GROUP_PUT,
    UNIQUENESS_SCIMTYPE_GROUP_PATCH,
    PATCH_SEQUENTIAL_APPLICATION,
    PATCH_ATOMICITY,
    PATCH_PRIMARY_DEMOTION,
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
        axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
        axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "omitted"),
            evidence,
            detail: "members omitted entirely for a Group created without members".to_string(),
        },
        Some(Json::Array(a)) if a.is_empty() => Observation {
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "empty_array"),
            evidence,
            detail: "members rendered as [] for a Group created without members".to_string(),
        },
        Some(other) => Observation {
            axis: axis.id.to_string(),
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

    // The obligation this axis judges is created by the target's own
    // declaration, not by the RFC directly -- read it first. No
    // declaration for User.groups at all means there is nothing to hold
    // the target to.
    let schemas_r = safe(client.get("/Schemas")).await;
    if !is_2xx(schemas_r.status) {
        return unobservable(axis, Unobservable::NotDeclaredBySchema);
    }
    let decls = decls_from_schemas(&body_of(&schemas_r));
    let Some(declared) = decls
        .iter()
        .find(|d| d.resource == Resource::User && d.path == "groups")
        .map(|d| d.returned.as_str())
    else {
        return unobservable(axis, Unobservable::NotDeclaredBySchema);
    };

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
            axis: axis.id.to_string(),
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
    let evidence = vec![
        schemas_r.exchange.clone(),
        gr.exchange.clone(),
        getr.exchange.clone(),
    ];

    let token = self_declared_token(declared, found);
    let detail = if found {
        format!(
            "User.groups declares returned:{declared} and contains {gid} after Group membership was created"
        )
    } else {
        format!("User.groups declares returned:{declared} and does not contain {gid}: {uj}")
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence,
        detail,
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "processed"),
            evidence,
            detail: format!("filter={filter} returned {expect_group_id}"),
        }
    } else {
        Observation {
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers absent or [] after PATCH replace with []".to_string(),
        }
    } else {
        Observation {
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
            axis: axis.id.to_string(),
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
                axis: axis.id.to_string(),
                value: known_or_unknown(axis, "stored_as_sent"),
                evidence,
                detail: "phoneNumbers stored as [{\"value\":\"\"}] verbatim -- a literal replace"
                    .to_string(),
            }
        }
        None => Observation {
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers was removed entirely -- the server rewrote replace as clear"
                .to_string(),
        },
        Some(Json::Array(a)) if a.is_empty() => Observation {
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "cleared"),
            evidence,
            detail: "phoneNumbers was replaced with [] -- the server rewrote replace as clear"
                .to_string(),
        },
        other => Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "unexpected phoneNumbers shape after replace: {other:?}"
            ))),
            evidence,
            detail: String::new(),
        },
    }
}

// ---------------------------------------------- uniqueness_scimtype probes

fn unique_field(resource: Resource) -> &'static str {
    match resource {
        Resource::User | Resource::EnterpriseUser => "userName",
        Resource::Group => "displayName",
    }
}

fn schema_urn(resource: Resource) -> &'static str {
    match resource {
        Resource::User | Resource::EnterpriseUser => USER_URN,
        Resource::Group => GROUP_URN,
    }
}

fn make_with_value(resource: Resource, value: &str) -> Json {
    let mut v = json!({ "schemas": [schema_urn(resource)] });
    v[unique_field(resource)] = json!(value);
    v
}

/// Classifies `r` (the response to attempting to give B a value A already
/// holds) against `axis`'s `known` vocabulary. See `UNIQUENESS_SCIMTYPE_KNOWN`
/// for what each token means.
fn judge_uniqueness_scimtype(axis: &Axis, r: &ScimResponse) -> (Value, String) {
    if is_2xx(r.status) {
        return (
            known_or_unknown(axis, "accepted"),
            format!(
                "duplicate value accepted instead of rejected (status={})",
                r.status
            ),
        );
    }
    match r.scim_type() {
        Some(st) if st == "uniqueness" => (
            known_or_unknown(axis, "uniqueness"),
            format!(
                "rejected (status={}) with scimType=\"uniqueness\"",
                r.status
            ),
        ),
        Some(st) => (
            known_or_unknown(axis, &st),
            format!(
                "rejected (status={}) with scimType={st:?}, not \"uniqueness\"",
                r.status
            ),
        ),
        None => (
            known_or_unknown(axis, "none"),
            format!(
                "rejected (status={}) with no scimType in the error body: {}",
                r.status,
                truncate(&r.raw, 150)
            ),
        ),
    }
}

async fn probe_uniqueness_scimtype_post(
    axis: &Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    resource: Resource,
) -> Observation {
    let endpoint = resource.endpoint();
    let dup_value = format!("dup-{}", short_uid());
    let a = safe(client.post(endpoint, &make_with_value(resource, &dup_value))).await;
    if let Some(id) = a.id() {
        bk.note(endpoint, id);
    }
    if !is_2xx(a.status) {
        return unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "could not create fixture A: {} {}",
                a.status,
                truncate(&a.raw, 200)
            )),
        );
    }
    let b = safe(client.post(endpoint, &make_with_value(resource, &dup_value))).await;
    if let Some(id) = b.id() {
        bk.note(endpoint, id);
    }
    let (value, detail) = judge_uniqueness_scimtype(axis, &b);
    Observation {
        axis: axis.id.to_string(),
        value,
        evidence: vec![a.exchange.clone(), b.exchange.clone()],
        detail,
    }
}

async fn probe_uniqueness_scimtype_put(
    axis: &Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    resource: Resource,
) -> Observation {
    let endpoint = resource.endpoint();
    let field = unique_field(resource);
    let a_value = format!("dupA-{}", short_uid());
    let a = safe(client.post(endpoint, &make_with_value(resource, &a_value))).await;
    let b_created = safe(client.post(
        endpoint,
        &make_with_value(resource, &format!("dupB-{}", short_uid())),
    ))
    .await;
    match (a.id(), b_created.id()) {
        (Some(aid), Some(bid)) => {
            bk.note(endpoint, aid);
            bk.note(endpoint, bid.clone());
            let mut put_body = body_of(&b_created);
            put_body[field] = json!(a_value);
            let r = safe(client.put(&format!("{endpoint}/{bid}"), &put_body)).await;
            let (value, detail) = judge_uniqueness_scimtype(axis, &r);
            Observation {
                axis: axis.id.to_string(),
                value,
                evidence: vec![
                    a.exchange.clone(),
                    b_created.exchange.clone(),
                    r.exchange.clone(),
                ],
                detail,
            }
        }
        _ => unobservable(
            axis,
            Unobservable::ProbeFailed("could not create A/B fixtures".to_string()),
        ),
    }
}

async fn probe_uniqueness_scimtype_patch(
    axis: &Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    resource: Resource,
) -> Observation {
    let endpoint = resource.endpoint();
    let field = unique_field(resource);
    let a_value = format!("dupA-{}", short_uid());
    let a = safe(client.post(endpoint, &make_with_value(resource, &a_value))).await;
    let b_created = safe(client.post(
        endpoint,
        &make_with_value(resource, &format!("dupB-{}", short_uid())),
    ))
    .await;
    match (a.id(), b_created.id()) {
        (Some(aid), Some(bid)) => {
            bk.note(endpoint, aid);
            bk.note(endpoint, bid.clone());
            let patch_body = json!({
                "schemas": [PATCHOP_URN],
                "Operations": [{"op": "replace", "path": field, "value": a_value}],
            });
            let r = safe(client.patch(&format!("{endpoint}/{bid}"), &patch_body)).await;
            let (value, detail) = judge_uniqueness_scimtype(axis, &r);
            Observation {
                axis: axis.id.to_string(),
                value,
                evidence: vec![
                    a.exchange.clone(),
                    b_created.exchange.clone(),
                    r.exchange.clone(),
                ],
                detail,
            }
        }
        _ => unobservable(
            axis,
            Unobservable::ProbeFailed("could not create A/B fixtures".to_string()),
        ),
    }
}

pub(crate) async fn probe_uniqueness_scimtype_user_post(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    probe_uniqueness_scimtype_post(&UNIQUENESS_SCIMTYPE_USER_POST, client, bk, Resource::User).await
}

pub(crate) async fn probe_uniqueness_scimtype_user_put(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    probe_uniqueness_scimtype_put(&UNIQUENESS_SCIMTYPE_USER_PUT, client, bk, Resource::User).await
}

pub(crate) async fn probe_uniqueness_scimtype_user_patch(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &UNIQUENESS_SCIMTYPE_USER_PATCH;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    probe_uniqueness_scimtype_patch(axis, client, bk, Resource::User).await
}

pub(crate) async fn probe_uniqueness_scimtype_group_post(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    probe_uniqueness_scimtype_post(&UNIQUENESS_SCIMTYPE_GROUP_POST, client, bk, Resource::Group)
        .await
}

pub(crate) async fn probe_uniqueness_scimtype_group_put(
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Observation {
    probe_uniqueness_scimtype_put(&UNIQUENESS_SCIMTYPE_GROUP_PUT, client, bk, Resource::Group).await
}

pub(crate) async fn probe_uniqueness_scimtype_group_patch(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &UNIQUENESS_SCIMTYPE_GROUP_PATCH;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    probe_uniqueness_scimtype_patch(axis, client, bk, Resource::Group).await
}

// --------------------------------------- patch_sequential_application probe

pub(crate) async fn probe_patch_sequential_application(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &PATCH_SEQUENTIAL_APPLICATION;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    let endpoint = "/Users";

    let created = safe(client.post(
        endpoint,
        &json!({"schemas": [USER_URN], "userName": format!("u-seq-{}", short_uid())}),
    ))
    .await;
    if !is_2xx(created.status) {
        return unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "could not create fixture: {} {}",
                created.status,
                truncate(&created.raw, 200)
            )),
        );
    }
    let Some(id) = created.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture POST succeeded but returned no id".to_string()),
        );
    };
    bk.note(endpoint, id.clone());

    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "replace", "path": "nickName", "value": "a"},
            {"op": "replace", "path": "nickName", "value": "b"},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;
    let mut evidence = vec![created.exchange.clone(), r.exchange.clone()];

    if !is_2xx(r.status) {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "PATCH with 2 sequential replace operations on the same path failed: status={} \
                 body={}",
                r.status,
                truncate(&r.raw, 150)
            ))),
            evidence,
            detail: String::new(),
        };
    }

    let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
    evidence.push(got.exchange.clone());
    let gj = body_of(&got);
    let value_seen = gj.get("nickName").and_then(Json::as_str).map(String::from);
    let (token, detail) = match value_seen.as_deref() {
        Some("b") => (
            "b".to_string(),
            "the second (later) operation's value won, as RFC 7644 §3.5.2 describes".to_string(),
        ),
        Some("a") => (
            "a".to_string(),
            "the first operation's value won instead of the second -- operations are not \
             applied in array order"
                .to_string(),
        ),
        Some(other) => (
            other.to_string(),
            format!(
                "nickName={other:?} after two sequential replace operations (\"a\" then \"b\"), \
                 neither of which it is"
            ),
        ),
        None => (
            "absent".to_string(),
            "nickName absent after a PATCH that should have set it to \"b\"".to_string(),
        ),
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence,
        detail,
    }
}

// -------------------------------------------------- patch_atomicity probe

pub(crate) async fn probe_patch_atomicity(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &PATCH_ATOMICITY;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    let endpoint = "/Users";

    let created = safe(client.post(
        endpoint,
        &json!({"schemas": [USER_URN], "userName": format!("u-atomic-{}", short_uid())}),
    ))
    .await;
    if !is_2xx(created.status) {
        return unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "could not create fixture: {} {}",
                created.status,
                truncate(&created.raw, 200)
            )),
        );
    }
    let Some(id) = created.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture POST succeeded but returned no id".to_string()),
        );
    };
    bk.note(endpoint, id.clone());

    // A valid first operation, followed by a second operation this crate
    // does not expect any server to recognize (an unrecognised `op` value)
    // -- forces a failure without relying on a `readOnly` write being
    // silently ignored rather than rejected (see the source branch's note,
    // ported into `crate::rfc::PROBE_PATCH_ATOMICITY`'s sibling doc
    // comments).
    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "replace", "path": "nickName", "value": "should-not-stick"},
            {"op": "frobnicate", "path": "nickName", "value": "also-should-not-stick"},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;
    let mut evidence = vec![created.exchange.clone(), r.exchange.clone()];

    if is_2xx(r.status) {
        return Observation {
            axis: axis.id.to_string(),
            value: known_or_unknown(axis, "accepted"),
            evidence,
            detail: format!(
                "a PATCH containing an invalid operation was accepted (status={}) instead of \
                 failing atomically",
                r.status
            ),
        };
    }

    // Both halves of RFC 7644 §3.5.2's atomicity sentence must hold: the
    // request failed (checked above) AND the valid first operation's
    // effect was not partially applied (checked here). A check that stops
    // at "the request failed" would also pass a server that rejects the
    // request but still applies the first operation -- unsound, and
    // exactly the gap this axis exists to catch.
    let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
    evidence.push(got.exchange.clone());
    let gj = body_of(&got);
    let nick_name = gj.get("nickName").cloned();
    let unchanged = match &nick_name {
        None => true,
        Some(v) => v.is_null(),
    };
    let (token, detail) = if unchanged {
        (
            "rejected_and_unchanged".to_string(),
            format!(
                "the request failed (status={}) and the valid first operation's effect was not \
                 partially applied",
                r.status
            ),
        )
    } else {
        (
            "rejected_but_changed".to_string(),
            format!(
                "the request failed (status={}) but nickName={nick_name:?} -- the valid first \
                 operation was partially applied despite the second operation's error",
                r.status
            ),
        )
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence,
        detail,
    }
}

// ------------------------------------------- patch_primary_demotion probe

pub(crate) async fn probe_patch_primary_demotion(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &PATCH_PRIMARY_DEMOTION;
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    let endpoint = "/Users";

    let created = safe(client.post(
        endpoint,
        &json!({
            "schemas": [USER_URN],
            "userName": format!("u-demote-{}", short_uid()),
            "emails": [
                {"value": format!("a-{}@example.com", short_uid()), "primary": true},
                {"value": format!("b-{}@example.com", short_uid()), "primary": false},
            ],
        }),
    ))
    .await;
    if !is_2xx(created.status) {
        return unobservable(
            axis,
            Unobservable::ProbeFailed(format!(
                "could not create fixture: {} {}",
                created.status,
                truncate(&created.raw, 200)
            )),
        );
    }
    let Some(id) = created.id() else {
        return unobservable(
            axis,
            Unobservable::ProbeFailed("fixture POST succeeded but returned no id".to_string()),
        );
    };
    bk.note(endpoint, id.clone());

    let new_email = format!("c-{}@example.com", short_uid());
    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": new_email, "primary": true}]},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;
    let mut evidence = vec![created.exchange.clone(), r.exchange.clone()];

    if !is_2xx(r.status) {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "PATCH add of a new primary email failed: status={}",
                r.status
            ))),
            evidence,
            detail: String::new(),
        };
    }

    let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
    evidence.push(got.exchange.clone());
    let gj = body_of(&got);
    let emails: Vec<Json> = gj
        .get("emails")
        .and_then(Json::as_array)
        .cloned()
        .unwrap_or_default();
    // `primary_count == 1` alone is not enough: a server that silently
    // dropped the `add` operation entirely (2xx, but the new email never
    // actually appended) would leave the *original* primary (from
    // creation) as the lone primary:true value -- primary_count == 1 by
    // accident, with demotion never actually exercised. So the new email's
    // presence, and that it specifically is the lone primary:true value,
    // both have to hold.
    let primary_values: Vec<String> = emails
        .iter()
        .filter(|e| e.get("primary").and_then(Json::as_bool) == Some(true))
        .filter_map(|e| e.get("value").and_then(Json::as_str).map(String::from))
        .collect();
    let new_email_present = emails
        .iter()
        .any(|e| e.get("value").and_then(Json::as_str) == Some(new_email.as_str()));

    let (token, detail) = if !new_email_present {
        (
            "add_dropped".to_string(),
            format!(
                "the PATCH add of a new primary email returned 2xx but the new email \
                 ({new_email:?}) is not present after a follow-up GET: {emails:?}"
            ),
        )
    } else if primary_values.len() == 1 && primary_values[0] == new_email {
        (
            "new_primary_only".to_string(),
            format!(
                "exactly one email ({new_email:?}, the newly added one) is primary:true after \
                 the PATCH; the previous primary was automatically demoted"
            ),
        )
    } else if primary_values.len() == 1 {
        (
            "wrong_primary".to_string(),
            format!(
                "exactly one email is primary:true after the PATCH, but it is {:?}, not the \
                 newly added {new_email:?}",
                primary_values[0]
            ),
        )
    } else {
        (
            "multiple_primary".to_string(),
            format!(
                "expected exactly the new email ({new_email:?}) to be the lone primary:true \
                 value, found {} primary:true value(s) ({primary_values:?})",
                primary_values.len()
            ),
        )
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence,
        detail,
    }
}

/// Runs all sixteen axis probes, in the fixed [`AXES`] order, against
/// `client`. Deterministic: no probe depends on another's outcome, only on
/// the provider's own advertised capabilities (the two filter probes, the
/// two PATCH probes, and the four new PATCH-based probes below). Cleans up
/// every fixture it created afterward, best-effort, the same way
/// `crate::runner`'s caller expects.
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
        probe_uniqueness_scimtype_user_post(client, &mut bk).await,
        probe_uniqueness_scimtype_user_put(client, &mut bk).await,
        probe_uniqueness_scimtype_user_patch(client, &mut bk, &caps).await,
        probe_uniqueness_scimtype_group_post(client, &mut bk).await,
        probe_uniqueness_scimtype_group_put(client, &mut bk).await,
        probe_uniqueness_scimtype_group_patch(client, &mut bk, &caps).await,
        probe_patch_sequential_application(client, &mut bk, &caps).await,
        probe_patch_atomicity(client, &mut bk, &caps).await,
        probe_patch_primary_demotion(client, &mut bk, &caps).await,
    ];

    cleanup(client, &bk).await;
    observations
}

async fn capability_or_unknown(client: &ScimClient) -> Capabilities {
    crate::capability::fetch(client).await
}
