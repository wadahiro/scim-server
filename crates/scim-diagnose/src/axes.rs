//! The thirty-two static behavioural axes: `scim-server`'s seven
//! `CompatibilityConfig` knobs (`src/config.rs`, documented in
//! `CLAUDE.md`), each traced back to the real provider behaviour it exists
//! to emulate, plus nine more ported from `feat/rfc-extract`'s
//! `crates/scim-conformance/src/templates/{status,sequence,atomicity,
//! conditional}.rs` (the `uniqueness_scimtype` family, 6 instances, and
//! `patch_sequential_application`/`patch_atomicity`/`patch_primary_demotion`,
//! 1 instance each), plus sixteen more ported from that branch's
//! `crates/scim-conformance/src/etag.rs` (RFC 7644 §3.14 ETag/conditional-
//! request family -- see the `etag family` section below for the four
//! groups).
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/probes.rs`
//! (the original seven), `.../templates/*.rs` (the nine ported next), and
//! `.../etag.rs` (the sixteen ported last) -- the HTTP-probing logic per
//! axis is taken over close to 1:1; what changes is the *shape* of the
//! result. That branch's probes returned a schema-matrix `Outcome`
//! (`Verdict::{Pass,Fail,Skip,Error}` against a single fixed expectation,
//! via a `Requirement`/ledger citation this crate does not carry over --
//! see `crate::rfc`'s module docs). This crate's axes instead classify the
//! observed value against `Axis::known` (see `crate::axis::Value`) and let
//! `crate::render` decide, per axis, whether a given value is a fault --
//! using each axis's own `RfcPosition` rather than a single verdict baked
//! into the probe. The source branch's `etag.rs` additionally used a
//! `Keyword` (`Must`/`Should`/`May`) per row to decide `Fail` vs. `Info`;
//! this crate's `RfcPosition::Mandated { keyword, .. }` (`Must`/`Should`)
//! and `RfcPosition::Permitted`/`RfcPosition::Silent` (never a fault) carry
//! that same distinction (see `crate::rfc`'s module docs).

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

// -------------------------------------------------------------- etag family
//
// Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/etag.rs`
// (RFC 7644 §3.14, Versioning Resources -- ETags and conditional
// requests). Sixteen axes in four groups; see each group's own comment
// below for its shape. Every axis is gated on `Capability::Etag`: a
// provider that advertises `etag.supported: false` skips every one of
// these sixteen with `Unobservable::CapabilityNotAdvertised("etag")` and no
// request is sent (not even a fixture POST) -- see each probe fn below and
// `crate::runner`'s wiring. A provider that *advertises* etag support (or
// says nothing, which this crate never treats as "unsupported" -- see
// `crate::capability`'s module docs) but does not actually honor
// `If-Match`/`If-None-Match` is a different, and more interesting, case
// than "not advertised": the probe still runs, and an observed value like
// `"accepted_despite_stale"` is `Value::Known` and judged a real
// `RfcPosition::Mandated`/`Must` fault by `crate::render::is_fault` --
// never silently folded into a gated skip.

/// Group 1 (4 axes): one POST, read once. All four reuse
/// [`crate::rfc::ETAG_REPRESENTATION`] (RFC 7644 §3.14,
/// `rfc7644.txt:3963-3969`) -- one sentence carrying three different RFC
/// 2119 keywords (MAY weak-ETags, MUST header, SHOULD meta.version), the
/// same way the source branch's `etag.rs::representation` reused one `Key`
/// shape across all four rows.
const ETAG_PRESENCE_KNOWN: &[&str] = &["present", "absent"];

pub const ETAG_RESPONSE_HEADER: Axis = Axis {
    id: "etag_response_header",
    about: "whether a POST response carries an ETag HTTP header",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_REPRESENTATION,
        keyword: Keyword::Must,
        expected: "present",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_PRESENCE_KNOWN,
};

pub const ETAG_META_VERSION: Axis = Axis {
    id: "etag_meta_version",
    about: "whether a POST response body carries meta.version",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_REPRESENTATION,
        keyword: Keyword::Should,
        expected: "present",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_PRESENCE_KNOWN,
};

/// The `Must` here is not itself stated by [`crate::rfc::ETAG_REPRESENTATION`]'s
/// sentence (which only establishes that a header MUST exist and a
/// meta.version SHOULD) -- it follows from the RFC's own worked example
/// (`rfc7644.txt:4003-4037`), which shows `ETag: W/"e180ee84f0671b1"` and
/// `"version":"W\/\"e180ee84f0671b1\""` as the identical string. A provider
/// that emits both but disagrees between them cannot be relied on by a
/// client comparing one against the other, so this is still judged `Must`
/// -- but the citation reused here documents what both fields existing
/// means, not the equality requirement itself, which is why this axis is
/// not given its own `quote`.
pub const ETAG_CONSISTENCY: Axis = Axis {
    id: "etag_consistency",
    about: "whether the ETag header and meta.version, when both present, are the identical string",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_REPRESENTATION,
        keyword: Keyword::Must,
        expected: "consistent",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: &["consistent", "inconsistent"],
};

pub const ETAG_FORM: Axis = Axis {
    id: "etag_form",
    about: "weak (W/\"...\") vs strong (\"...\") ETag form",
    rfc: RfcPosition::Permitted {
        basis: crate::rfc::ETAG_REPRESENTATION,
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: &["weak", "strong"],
};

/// Group 2 (3 axes): `GET x If-None-Match` in `{current, stale, *}` ->
/// `{304 empty body, 200, 304}` per RFC 7644 §3.14
/// (`rfc7644.txt:4051-4052`, [`crate::rfc::ETAG_CONDITIONAL_READ`]). Each
/// axis is independent (its own fixture), matching this crate's
/// established per-axis-probe cost model (`uniqueness_scimtype` already
/// spends 2 POSTs per axis x 6) rather than the source branch's
/// request-chaining design.
const ETAG_CONDITIONAL_READ_KNOWN: &[&str] = &[
    "not_modified_empty_body",
    "not_modified_nonempty_body",
    "ok_200",
];

pub const ETAG_CONDITIONAL_READ_CURRENT: Axis = Axis {
    id: "etag_conditional_read/current",
    about: "GET with If-None-Match set to the resource's real current ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_READ,
        keyword: Keyword::Must,
        expected: "not_modified_empty_body",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_READ_KNOWN,
};

pub const ETAG_CONDITIONAL_READ_STALE: Axis = Axis {
    id: "etag_conditional_read/stale",
    about: "GET with If-None-Match set to a genuinely superseded ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_READ,
        keyword: Keyword::Must,
        expected: "ok_200",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_READ_KNOWN,
};

pub const ETAG_CONDITIONAL_READ_STAR: Axis = Axis {
    id: "etag_conditional_read/star",
    about: "GET with If-None-Match: * against an existing resource",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_READ,
        keyword: Keyword::Must,
        expected: "not_modified_empty_body",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_READ_KNOWN,
};

/// Group 3 (6 axes): `{PUT, PATCH} x If-Match` in `{current, stale, *}` ->
/// `{2xx (version advances), 412, 2xx}` per RFC 7644 §3.14
/// (`rfc7644.txt:4054-4058`, [`crate::rfc::ETAG_CONDITIONAL_WRITE`]), which
/// names exactly these two methods. For `current`, this crate additionally
/// requires the version to *advance* -- not just a 2xx -- because that is
/// the lost-update protection actually firing (RFC 7644 §3.14,
/// `rfc7644.txt:3966-3967`: "ensuring that clients do not inadvertently
/// overwrite each other's changes"), not merely a status code. The three
/// PATCH axes are additionally gated on `Capability::Patch`, matching every
/// other PATCH-dependent axis in this crate (`uniqueness_scimtype/*/PATCH`,
/// `patch_sequential_application`, etc).
const ETAG_CONDITIONAL_WRITE_CURRENT_KNOWN: &[&str] =
    &["accepted_version_advanced", "accepted_version_not_advanced"];
const ETAG_CONDITIONAL_WRITE_STALE_KNOWN: &[&str] =
    &["precondition_failed_412", "accepted_despite_stale"];
const ETAG_CONDITIONAL_WRITE_STAR_KNOWN: &[&str] = &["accepted", "rejected"];

pub const ETAG_CONDITIONAL_WRITE_PUT_CURRENT: Axis = Axis {
    id: "etag_conditional_write/PUT/current",
    about: "PUT with If-Match set to the resource's real current ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "accepted_version_advanced",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_CURRENT_KNOWN,
};

pub const ETAG_CONDITIONAL_WRITE_PUT_STALE: Axis = Axis {
    id: "etag_conditional_write/PUT/stale",
    about: "PUT with If-Match set to a genuinely superseded ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "precondition_failed_412",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STALE_KNOWN,
};

pub const ETAG_CONDITIONAL_WRITE_PUT_STAR: Axis = Axis {
    id: "etag_conditional_write/PUT/star",
    about: "PUT with If-Match: * against an existing resource",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "accepted",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STAR_KNOWN,
};

pub const ETAG_CONDITIONAL_WRITE_PATCH_CURRENT: Axis = Axis {
    id: "etag_conditional_write/PATCH/current",
    about: "PATCH with If-Match set to the resource's real current ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "accepted_version_advanced",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_CURRENT_KNOWN,
};

pub const ETAG_CONDITIONAL_WRITE_PATCH_STALE: Axis = Axis {
    id: "etag_conditional_write/PATCH/stale",
    about: "PATCH with If-Match set to a genuinely superseded ETag",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "precondition_failed_412",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STALE_KNOWN,
};

pub const ETAG_CONDITIONAL_WRITE_PATCH_STAR: Axis = Axis {
    id: "etag_conditional_write/PATCH/star",
    about: "PATCH with If-Match: * against an existing resource",
    rfc: RfcPosition::Mandated {
        basis: crate::rfc::ETAG_CONDITIONAL_WRITE,
        keyword: Keyword::Must,
        expected: "accepted",
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STAR_KNOWN,
};

/// Group 4 (3 axes): `DELETE x If-Match` in `{current, stale, *}`. *Not*
/// named by RFC 7644 §3.14, whose `If-Match` sentence
/// (`crate::rfc::ETAG_CONDITIONAL_WRITE`) lists only PUT and PATCH -- the
/// only place DELETE is mentioned alongside a 412 outcome at all is Table 8
/// "SCIM HTTP Status Code Usage" (`rfc7644.txt:3779-3781`,
/// [`crate::rfc::ETAG_TABLE8_PRECONDITION_FAILED`]), which only names the
/// status code a server that *does* implement DELETE preconditions should
/// use -- it does not itself require that DELETE support them. So these
/// three axes are `RfcPosition::Silent`: never a fault either way,
/// regardless of what's observed (a non-412 on a stale tag is recorded,
/// not judged) -- what this axis exists to report is what providers that
/// *do* implement DELETE preconditions actually do, not to hold every
/// provider to a rule §3.14 never states for this method. This is the one
/// axis group in the family whose authority is weaker than the rest; see
/// `crate::rfc::ETAG_TABLE8_PRECONDITION_FAILED`'s own doc comment for the
/// full reasoning behind choosing `Silent` over `Permitted` here.
pub const ETAG_DELETE_IF_MATCH_CURRENT: Axis = Axis {
    id: "etag_delete_if_match/current",
    about: "DELETE with If-Match set to the resource's real current ETag (not itself named by \
            §3.14 -- see doc comment)",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::ETAG_TABLE8_PRECONDITION_FAILED),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STAR_KNOWN,
};

pub const ETAG_DELETE_IF_MATCH_STALE: Axis = Axis {
    id: "etag_delete_if_match/stale",
    about: "DELETE with If-Match set to a genuinely superseded ETag (not itself named by §3.14 \
            -- see doc comment)",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::ETAG_TABLE8_PRECONDITION_FAILED),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STALE_KNOWN,
};

pub const ETAG_DELETE_IF_MATCH_STAR: Axis = Axis {
    id: "etag_delete_if_match/star",
    about: "DELETE with If-Match: * against an existing resource (not itself named by §3.14 -- \
            see doc comment)",
    rfc: RfcPosition::Silent {
        basis: Some(crate::rfc::ETAG_TABLE8_PRECONDITION_FAILED),
    },
    knob: None,
    cost: Cost::NeedsUser,
    known: ETAG_CONDITIONAL_WRITE_STAR_KNOWN,
};

/// All thirty-two axes, in the fixed order they're probed in
/// ([`run_all`]) and reported in (`crate::render`): the original seven
/// `CompatibilityConfig` axes, then the nine ported from
/// `feat/rfc-extract`'s `templates/{status,sequence,atomicity,
/// conditional}.rs` (the six `uniqueness_scimtype` instances, then
/// `patch_sequential_application`, `patch_atomicity`,
/// `patch_primary_demotion`), then the sixteen ported from that branch's
/// `etag.rs` (RFC 7644 §3.14 ETag/conditional-request family: 4
/// representation + 3 conditional-read + 6 conditional-write + 3
/// DELETE x If-Match).
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
    ETAG_RESPONSE_HEADER,
    ETAG_META_VERSION,
    ETAG_CONSISTENCY,
    ETAG_FORM,
    ETAG_CONDITIONAL_READ_CURRENT,
    ETAG_CONDITIONAL_READ_STALE,
    ETAG_CONDITIONAL_READ_STAR,
    ETAG_CONDITIONAL_WRITE_PUT_CURRENT,
    ETAG_CONDITIONAL_WRITE_PUT_STALE,
    ETAG_CONDITIONAL_WRITE_PUT_STAR,
    ETAG_CONDITIONAL_WRITE_PATCH_CURRENT,
    ETAG_CONDITIONAL_WRITE_PATCH_STALE,
    ETAG_CONDITIONAL_WRITE_PATCH_STAR,
    ETAG_DELETE_IF_MATCH_CURRENT,
    ETAG_DELETE_IF_MATCH_STALE,
    ETAG_DELETE_IF_MATCH_STAR,
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

// ------------------------------------------------------------- etag probes
//
// Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/etag.rs`;
// the request/assert logic is taken over close to 1:1 (`etag_header`,
// `meta_version`, `etag_form`, the unconditional-bump-to-produce-a-stale-
// tag technique), reshaped into sixteen independent, self-contained probe
// fns (one fixture apiece) to match this crate's established per-axis-probe
// pattern (`crate::runner::run`'s `match axis.id` dispatch needs one
// standalone fn per axis, unlike the source branch's single threaded
// `run_all` that chained one fixture through the whole family).

fn etag_header(r: &ScimResponse) -> Option<String> {
    r.headers
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

fn meta_version(r: &ScimResponse) -> Option<String> {
    body_of(r)
        .pointer("/meta/version")
        .and_then(Json::as_str)
        .map(String::from)
}

/// The header value, falling back to `meta.version` if the header is
/// somehow missing but the body carries a version anyway.
fn etag_of(r: &ScimResponse) -> Option<String> {
    etag_header(r).or_else(|| meta_version(r))
}

/// `W/"..."` -> weak, `"..."` (no `W/` prefix) -> strong. Per RFC 7232
/// §2.3 (incorporated by reference via RFC 7644 §3.14's opening sentence,
/// not itself vendored in `spec/rfc/` -- see `crate::rfc::ETAG_REPRESENTATION`'s
/// doc comment).
fn etag_form(etag: &str) -> &'static str {
    if etag.starts_with("W/") {
        "weak"
    } else {
        "strong"
    }
}

/// POSTs a baseline User, noting it in `bk` for cleanup if creation
/// succeeded at all (even a fixture this crate goes on to judge a failure
/// is still cleaned up: `id()` succeeding is enough to register it).
async fn create_baseline_fixture(client: &ScimClient, bk: &mut Bookkeeping) -> ScimResponse {
    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if let Some(id) = r.id() {
        bk.note("/Users", id);
    }
    r
}

/// Creates a baseline User and returns its id, its ETag/meta.version at
/// creation (whichever [`etag_of`] finds), and the creating exchange (for
/// evidence) -- the shared first step of every etag axis below. `Err`
/// carries a ready-to-return `Observation` for `axis` on any failure
/// (POST failed, no id, or no observable ETag/meta.version at all), so
/// every probe can `match ... { Ok(v) => v, Err(obs) => return obs }`.
async fn etag_fixture(
    axis: &Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
) -> Result<(String, String, crate::client::Exchange), Observation> {
    let r = create_baseline_fixture(client, bk).await;
    if !is_2xx(r.status) {
        return Err(Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "baseline POST failed: {} {}",
                r.status,
                truncate(&r.raw, 200)
            ))),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        });
    }
    let Some(id) = r.id() else {
        return Err(Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "baseline POST succeeded but returned no id".to_string(),
            )),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        });
    };
    let Some(etag) = etag_of(&r) else {
        return Err(Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "baseline POST succeeded but carried no ETag/meta.version".to_string(),
            )),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        });
    };
    Ok((id, etag, r.exchange.clone()))
}

/// Sends a real, unconditional PUT (nickName set to a fresh value) to move
/// `id`'s version on -- the only honest way to produce a genuinely *stale*
/// ETag to test against, rather than fabricating one (mirrors the source
/// branch's `conditional_read`/`conditional_write_triple` technique).
/// Falls back to a follow-up GET if the PUT response itself carried no
/// observable ETag/meta.version (a 204-shaped write, say), so a body-less
/// success is never misread as "the write produced no new tag."
async fn bump_unconditional(client: &ScimClient, id: &str) -> Option<String> {
    let path = format!("/Users/{id}");
    let got = safe(client.get(&path)).await;
    let mut body = body_of(&got);
    body["nickName"] = json!(format!("n-{}", short_uid()));
    let r = safe(client.put(&path, &body)).await;
    if let Some(e) = etag_of(&r) {
        return Some(e);
    }
    let got2 = safe(client.get(&path)).await;
    etag_of(&got2)
}

/// The ETag/meta.version a conditional write left `id` at: prefers `r`'s
/// own response, falling back to a follow-up GET if `r` carried neither
/// (the same body-less-response guard as [`bump_unconditional`]) -- so
/// "the version didn't advance" is only ever concluded from an actual
/// comparison, never from a response simply not echoing a header back.
async fn resolve_etag_after(client: &ScimClient, id: &str, r: &ScimResponse) -> Option<String> {
    if let Some(e) = etag_of(r) {
        return Some(e);
    }
    let got = safe(client.get(&format!("/Users/{id}"))).await;
    etag_of(&got)
}

/// One conditional PUT or PATCH against `id` with `If-Match: if_match`.
/// PUT resends the current full representation (needs a fresh GET each
/// time -- PUT is a full replace); PATCH needs no prior state.
async fn send_conditional_write(
    client: &ScimClient,
    id: &str,
    is_patch: bool,
    if_match: &str,
) -> ScimResponse {
    let path = format!("/Users/{id}");
    if is_patch {
        let body = json!({
            "schemas": [PATCHOP_URN],
            "Operations": [
                {"op": "replace", "path": "nickName", "value": format!("n-{}", short_uid())},
            ],
        });
        safe(client.patch_with_headers(&path, &body, &[("If-Match", if_match)])).await
    } else {
        let got = safe(client.get(&path)).await;
        let mut body = body_of(&got);
        body["nickName"] = json!(format!("n-{}", short_uid()));
        safe(client.put_with_headers(&path, &body, &[("If-Match", if_match)])).await
    }
}

fn read_case_token(status: u16, body_empty: bool) -> String {
    match status {
        304 if body_empty => "not_modified_empty_body".to_string(),
        304 => "not_modified_nonempty_body".to_string(),
        200 => "ok_200".to_string(),
        other => format!("status_{other}"),
    }
}

fn write_current_token(status: u16, advanced: bool) -> String {
    if is_2xx(status) && advanced {
        "accepted_version_advanced".to_string()
    } else if is_2xx(status) {
        "accepted_version_not_advanced".to_string()
    } else {
        format!("status_{status}")
    }
}

fn write_stale_token(status: u16) -> String {
    if status == 412 {
        "precondition_failed_412".to_string()
    } else if is_2xx(status) {
        "accepted_despite_stale".to_string()
    } else {
        format!("status_{status}")
    }
}

fn write_star_token(status: u16) -> &'static str {
    if is_2xx(status) {
        "accepted"
    } else {
        "rejected"
    }
}

// -- group 1: representation --

pub(crate) async fn probe_etag_response_header(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_RESPONSE_HEADER;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let r = create_baseline_fixture(client, bk).await;
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
    let header = etag_header(&r);
    let token = if header.is_some() {
        "present"
    } else {
        "absent"
    };
    let detail = match &header {
        Some(h) => format!(
            "ETag header present: {h:?}; RFC 7644 §3.14: \"When supported, SCIM ETags MUST be \
             specified as an HTTP header\""
        ),
        None => "ETag header absent from the POST response; RFC 7644 §3.14: \"When supported, \
                  SCIM ETags MUST be specified as an HTTP header\""
            .to_string(),
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, token),
        evidence: vec![r.exchange.clone()],
        detail,
    }
}

pub(crate) async fn probe_etag_meta_version(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_META_VERSION;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let r = create_baseline_fixture(client, bk).await;
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
    let version = meta_version(&r);
    let token = if version.is_some() {
        "present"
    } else {
        "absent"
    };
    let detail = match &version {
        Some(v) => format!(
            "meta.version present: {v:?}; RFC 7644 §3.14: \"... and SHOULD be specified within \
             the 'version' attribute\" -- a SHOULD, so absence here is recorded, never a fault"
        ),
        None => "meta.version absent from the POST response body; RFC 7644 §3.14's SHOULD, so \
                  this is recorded, never a fault"
            .to_string(),
    };
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, token),
        evidence: vec![r.exchange.clone()],
        detail,
    }
}

pub(crate) async fn probe_etag_consistency(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONSISTENCY;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let r = create_baseline_fixture(client, bk).await;
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
    let header = etag_header(&r);
    let version = meta_version(&r);
    match (&header, &version) {
        (Some(h), Some(v)) => {
            let token = if h == v { "consistent" } else { "inconsistent" };
            Observation {
                axis: axis.id.to_string(),
                value: known_or_unknown(axis, token),
                evidence: vec![r.exchange.clone()],
                detail: format!(
                    "ETag={h:?} meta.version={v:?}; the RFC's own worked example \
                     (rfc7644.txt:4003-4037) shows both as the identical string"
                ),
            }
        }
        _ => Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "cannot compare: ETag header={header:?} meta.version={version:?} (at least one \
                 absent -- see etag_response_header/etag_meta_version)"
            ))),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        },
    }
}

pub(crate) async fn probe_etag_form(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_FORM;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let r = create_baseline_fixture(client, bk).await;
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
    let Some(header) = etag_header(&r) else {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "no ETag header to classify -- see etag_response_header".to_string(),
            )),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    };
    let form = etag_form(&header);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, form),
        evidence: vec![r.exchange.clone()],
        detail: format!(
            "ETag {header:?} is a {form} ETag; RFC 7644 §3.14 permits either (\"MAY support \
             weak ETags\")"
        ),
    }
}

// -- group 2: conditional read --

pub(crate) async fn probe_etag_conditional_read_current(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_READ_CURRENT;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, _etag_at_creation, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    // `_etag_at_creation` is deliberately unused past this point: the bump
    // below immediately supersedes it, and this probe only needs the
    // resulting *current* ETag. Kept in the tuple only for symmetry with
    // the sibling probes' `etag_fixture` call.
    let Some(current_etag) = bump_unconditional(client, &id).await else {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "unconditional bump PUT failed or returned no ETag/meta.version; cannot \
                 establish a genuinely current ETag to test"
                    .to_string(),
            )),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    };
    let path = format!("/Users/{id}");
    let r = safe(client.get_with_headers(&path, &[("If-None-Match", &current_etag)])).await;
    let token = read_case_token(r.status, r.raw.is_empty());
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "If-None-Match: {current_etag:?} (the resource's real current ETag) -> status={} \
             body_len={} (rfc7644.txt:4051-4052 requires an empty body with a 304 response)",
            r.status,
            r.raw.len()
        ),
    }
}

pub(crate) async fn probe_etag_conditional_read_stale(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_READ_STALE;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, etag_at_creation, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let Some(bumped) = bump_unconditional(client, &id).await else {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "unconditional bump PUT failed or returned no ETag/meta.version; cannot \
                 establish a genuinely stale ETag to test"
                    .to_string(),
            )),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    };
    if bumped == etag_at_creation {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "version did not advance after an unconditional write ({etag_at_creation:?} == \
                 {bumped:?}); no genuinely stale ETag to test -- see \
                 etag_conditional_write/PUT/current for whether the version advances at all"
            ))),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    }
    let path = format!("/Users/{id}");
    let r = safe(client.get_with_headers(&path, &[("If-None-Match", &etag_at_creation)])).await;
    let token = read_case_token(r.status, r.raw.is_empty());
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "If-None-Match: {etag_at_creation:?} is now stale (the unconditional bump advanced \
             the version to {bumped:?}) -> status={}, expected 200",
            r.status
        ),
    }
}

pub(crate) async fn probe_etag_conditional_read_star(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_READ_STAR;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, _etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let path = format!("/Users/{id}");
    let r = safe(client.get_with_headers(&path, &[("If-None-Match", "*")])).await;
    let token = read_case_token(r.status, r.raw.is_empty());
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "If-None-Match: * matches any existing representation -> status={} body_len={}, \
             expected an empty body with a 304 response",
            r.status,
            r.raw.len()
        ),
    }
}

// -- group 3: conditional write --

async fn probe_conditional_write_current(
    axis: &'static Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    is_patch: bool,
) -> Observation {
    let (id, etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let r = send_conditional_write(client, &id, is_patch, &etag).await;
    let new_etag = resolve_etag_after(client, &id, &r).await;
    let advanced = new_etag.as_deref().is_some_and(|e| e != etag);
    let token = write_current_token(r.status, advanced);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "{} If-Match: {etag:?} (the resource's real current ETag) -> status={} \
             new_etag={new_etag:?} advanced={advanced} (rfc7644.txt:3966-3967: \"ensuring that \
             clients do not inadvertently overwrite each other's changes\")",
            if is_patch { "PATCH" } else { "PUT" },
            r.status,
        ),
    }
}

async fn probe_conditional_write_stale(
    axis: &'static Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    is_patch: bool,
) -> Observation {
    let (id, etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let Some(bumped) = bump_unconditional(client, &id).await else {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "unconditional bump PUT failed or returned no ETag/meta.version; cannot \
                 establish a genuinely stale ETag to test"
                    .to_string(),
            )),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    };
    if bumped == etag {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "version did not advance after an unconditional write ({etag:?} == {bumped:?}); \
                 no genuinely stale ETag to test"
            ))),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    }
    let r = send_conditional_write(client, &id, is_patch, &etag).await;
    let token = write_stale_token(r.status);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "{} If-Match: {etag:?} is now stale (bumped to {bumped:?}) -> status={}, expected 412",
            if is_patch { "PATCH" } else { "PUT" },
            r.status,
        ),
    }
}

async fn probe_conditional_write_star(
    axis: &'static Axis,
    client: &ScimClient,
    bk: &mut Bookkeeping,
    is_patch: bool,
) -> Observation {
    let (id, _etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let r = send_conditional_write(client, &id, is_patch, "*").await;
    let token = write_star_token(r.status);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "{} If-Match: * matches any existing representation -> status={}, expected 2xx",
            if is_patch { "PATCH" } else { "PUT" },
            r.status,
        ),
    }
}

pub(crate) async fn probe_etag_conditional_write_put_current(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PUT_CURRENT;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    probe_conditional_write_current(axis, client, bk, false).await
}

pub(crate) async fn probe_etag_conditional_write_put_stale(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PUT_STALE;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    probe_conditional_write_stale(axis, client, bk, false).await
}

pub(crate) async fn probe_etag_conditional_write_put_star(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PUT_STAR;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    probe_conditional_write_star(axis, client, bk, false).await
}

pub(crate) async fn probe_etag_conditional_write_patch_current(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PATCH_CURRENT;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    probe_conditional_write_current(axis, client, bk, true).await
}

pub(crate) async fn probe_etag_conditional_write_patch_stale(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PATCH_STALE;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    probe_conditional_write_stale(axis, client, bk, true).await
}

pub(crate) async fn probe_etag_conditional_write_patch_star(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_CONDITIONAL_WRITE_PATCH_STAR;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    if caps.get(Capability::Patch) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("patch"));
    }
    probe_conditional_write_star(axis, client, bk, true).await
}

// -- group 4: DELETE x If-Match --

pub(crate) async fn probe_etag_delete_if_match_current(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_DELETE_IF_MATCH_CURRENT;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let r = safe(client.delete_with_headers(&format!("/Users/{id}"), &[("If-Match", &etag)])).await;
    let token = write_star_token(r.status);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "DELETE If-Match: {etag:?} (real current ETag) -> status={}; not §3.14-mandated \
             (names only PUT/PATCH) -- see Table 8 (rfc7644.txt:3779-3781); recorded, never a \
             fault",
            r.status
        ),
    }
}

pub(crate) async fn probe_etag_delete_if_match_stale(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_DELETE_IF_MATCH_STALE;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let Some(bumped) = bump_unconditional(client, &id).await else {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(
                "unconditional bump PUT failed or returned no ETag/meta.version; cannot \
                 establish a genuinely stale ETag to test"
                    .to_string(),
            )),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    };
    if bumped == etag {
        return Observation {
            axis: axis.id.to_string(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "version did not advance after an unconditional write ({etag:?} == {bumped:?}); \
                 no genuinely stale ETag to test"
            ))),
            evidence: vec![create_exchange],
            detail: String::new(),
        };
    }
    let r = safe(client.delete_with_headers(&format!("/Users/{id}"), &[("If-Match", &etag)])).await;
    let token = write_stale_token(r.status);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, &token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "DELETE If-Match: {etag:?} is now stale (bumped to {bumped:?}) -> status={}; not \
             §3.14-mandated -- see Table 8 (rfc7644.txt:3779-3781); recorded, never a fault",
            r.status
        ),
    }
}

pub(crate) async fn probe_etag_delete_if_match_star(
    client: &ScimClient,
    bk: &mut Bookkeeping,
    caps: &Capabilities,
) -> Observation {
    let axis = &ETAG_DELETE_IF_MATCH_STAR;
    if caps.get(Capability::Etag) == Some(false) {
        return unobservable(axis, Unobservable::CapabilityNotAdvertised("etag"));
    }
    let (id, _etag, create_exchange) = match etag_fixture(axis, client, bk).await {
        Ok(v) => v,
        Err(obs) => return obs,
    };
    let r = safe(client.delete_with_headers(&format!("/Users/{id}"), &[("If-Match", "*")])).await;
    let token = write_star_token(r.status);
    Observation {
        axis: axis.id.to_string(),
        value: known_or_unknown(axis, token),
        evidence: vec![create_exchange, r.exchange.clone()],
        detail: format!(
            "DELETE If-Match: * matches any existing representation -> status={}; not \
             §3.14-mandated -- see Table 8 (rfc7644.txt:3779-3781); recorded, never a fault",
            r.status
        ),
    }
}

/// Runs all thirty-two axis probes, in the fixed [`AXES`] order, against
/// `client`. Deterministic: no probe depends on another's outcome, only on
/// the provider's own advertised capabilities (the two filter probes, the
/// PATCH-gated probes, and every `etag_*` probe below). Cleans up every
/// fixture it created afterward, best-effort, the same way
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
        probe_etag_response_header(client, &mut bk, &caps).await,
        probe_etag_meta_version(client, &mut bk, &caps).await,
        probe_etag_consistency(client, &mut bk, &caps).await,
        probe_etag_form(client, &mut bk, &caps).await,
        probe_etag_conditional_read_current(client, &mut bk, &caps).await,
        probe_etag_conditional_read_stale(client, &mut bk, &caps).await,
        probe_etag_conditional_read_star(client, &mut bk, &caps).await,
        probe_etag_conditional_write_put_current(client, &mut bk, &caps).await,
        probe_etag_conditional_write_put_stale(client, &mut bk, &caps).await,
        probe_etag_conditional_write_put_star(client, &mut bk, &caps).await,
        probe_etag_conditional_write_patch_current(client, &mut bk, &caps).await,
        probe_etag_conditional_write_patch_stale(client, &mut bk, &caps).await,
        probe_etag_conditional_write_patch_star(client, &mut bk, &caps).await,
        probe_etag_delete_if_match_current(client, &mut bk, &caps).await,
        probe_etag_delete_if_match_stale(client, &mut bk, &caps).await,
        probe_etag_delete_if_match_star(client, &mut bk, &caps).await,
    ];

    cleanup(client, &bk).await;
    observations
}

async fn capability_or_unknown(client: &ScimClient) -> Capabilities {
    crate::capability::fetch(client).await
}

#[cfg(test)]
mod etag_token_tests {
    use super::*;

    #[test]
    fn read_case_token_classifies_the_three_expected_shapes_and_falls_through_for_others() {
        assert_eq!(read_case_token(304, true), "not_modified_empty_body");
        assert_eq!(read_case_token(304, false), "not_modified_nonempty_body");
        assert_eq!(read_case_token(200, false), "ok_200");
        assert_eq!(read_case_token(404, true), "status_404");
    }

    #[test]
    fn write_current_token_requires_both_2xx_and_advanced() {
        assert_eq!(write_current_token(200, true), "accepted_version_advanced");
        assert_eq!(
            write_current_token(200, false),
            "accepted_version_not_advanced"
        );
        assert_eq!(write_current_token(400, false), "status_400");
    }

    /// The "advertised and not honoured" case this family exists to catch:
    /// a server that reports `etag.supported: true` but silently accepts a
    /// write against a stale `If-Match` instead of returning 412. The
    /// token this produces (`"accepted_despite_stale"`) is in
    /// `ETAG_CONDITIONAL_WRITE_STALE_KNOWN`, i.e. `Value::Known`, not
    /// `Value::Unknown` or any `Unobservable` variant -- so
    /// `crate::render::is_fault` judges it against the axis's
    /// `RfcPosition::Mandated { keyword: Must, expected:
    /// "precondition_failed_412", .. }` and reports a real violation, the
    /// same way any other Known-but-wrong value would. This is what
    /// distinguishes "advertised but not honoured" from
    /// `Unobservable::CapabilityNotAdvertised("etag")` (a provider that
    /// said `etag.supported: false` up front, and for which this whole
    /// family is skipped before a single request is sent -- see
    /// `probe_etag_conditional_write_put_stale`'s capability gate).
    #[test]
    fn write_stale_token_names_the_lost_update_case_and_it_is_known_not_unknown() {
        assert_eq!(write_stale_token(412), "precondition_failed_412");
        let lost_update_token = write_stale_token(200);
        assert_eq!(lost_update_token, "accepted_despite_stale");
        assert!(
            ETAG_CONDITIONAL_WRITE_PUT_STALE
                .known
                .contains(&lost_update_token.as_str()),
            "the lost-update token must be in `known` so it renders as Value::Known, not \
             Value::Unknown -- a provider that ignores If-Match is a named fault, not a \
             discovery"
        );
        assert_eq!(write_stale_token(500), "status_500");
    }

    #[test]
    fn write_star_token_is_a_plain_2xx_check() {
        assert_eq!(write_star_token(204), "accepted");
        assert_eq!(write_star_token(400), "rejected");
    }

    #[test]
    fn etag_form_classifies_weak_and_strong() {
        assert_eq!(etag_form("W/\"1\""), "weak");
        assert_eq!(etag_form("\"1\""), "strong");
    }

    /// The "advertised but not honoured" claim, checked through the real
    /// `crate::render::is_fault` (made `pub(crate)` specifically for this
    /// test -- see its own doc comment) rather than a reimplementation of
    /// its `match`: a production predicate copied into a test is exactly
    /// what let an earlier invariant on this branch pass while production
    /// was broken (see `CLAUDE.md`). Three observations against the same
    /// axis exercise the three-way distinction this family's gating is
    /// supposed to draw: a named, judged fault; a conforming value; and
    /// "never sent a request at all."
    #[test]
    fn advertised_but_not_honoured_is_judged_a_fault_by_the_real_render_predicate() {
        let axis = &ETAG_CONDITIONAL_WRITE_PUT_STALE;
        let obs_of = |value: Value| Observation {
            axis: axis.id.to_string(),
            value,
            evidence: Vec::new(),
            detail: String::new(),
        };

        // Advertised (etag.supported != false) but not honoured: the
        // server accepted a write against a stale If-Match instead of
        // returning 412. This is a real, named Must-violation -- not a
        // gated skip and not silently folded into "not advertised".
        assert_eq!(
            crate::render::is_fault(axis, &obs_of(Value::Known("accepted_despite_stale"))),
            Some(true),
            "a server that accepts a write against a stale If-Match instead of returning 412 \
             must be judged a Must-violation"
        );

        // Advertised and honoured: conforms.
        assert_eq!(
            crate::render::is_fault(axis, &obs_of(Value::Known("precondition_failed_412"))),
            Some(false),
        );

        // Not advertised at all (etag.supported: false): the probe never
        // ran, so there is nothing to judge -- distinct from both cases
        // above, and this is the case that must never be reported as a
        // fault just because it also isn't "conforms".
        assert_eq!(
            crate::render::is_fault(
                axis,
                &obs_of(Value::Unobservable(Unobservable::CapabilityNotAdvertised(
                    "etag"
                )))
            ),
            None,
        );
    }
}
