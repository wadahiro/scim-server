//! The seven behavioural axes: `scim-server`'s seven `CompatibilityConfig`
//! knobs (`src/config.rs`, documented in `CLAUDE.md`), each traced back to
//! the real provider behaviour it exists to emulate.
//!
//! This commit registers the seven axes -- their id, one-line description,
//! `RfcPosition` (citation into the vendored `spec/rfc/` text, verified
//! against `feat/rfc-extract`'s own citations), `CompatibilityConfig` knob,
//! write-budget `Cost`, and known values -- so `crate::runner`'s
//! cost/capability gating and `crate::render`'s three views have real data
//! to work against and can be tested end-to-end. The actual HTTP probing
//! logic per axis (ported from `feat/rfc-extract`'s
//! `crates/scim-conformance/src/probes.rs`) lands in the next commit; for
//! now each probe is a stub that reports itself as not yet implemented,
//! via the same `Unobservable::ProbeFailed` path a real probe failure
//! would use.

use crate::axis::{Axis, Cost, Observation, Unobservable, Value};
use crate::capability::Capabilities;
use crate::client::ScimClient;
use crate::fixtures::Bookkeeping;
use crate::rfc::{Keyword, RfcPosition};

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

/// All seven axes, in the fixed order they're probed in ([`crate::runner`])
/// and reported in (`crate::render`).
pub const AXES: &[Axis] = &[
    META_DATETIME_FORMAT,
    EMPTY_MULTIVALUED_RENDERING,
    USER_GROUPS_PRESENCE,
    GROUP_MEMBERS_FILTER,
    GROUP_DISPLAYNAME_FILTER,
    PATCH_REPLACE_EMPTY_ARRAY,
    PATCH_REPLACE_EMPTY_VALUE,
];

fn not_yet_implemented(axis: &Axis) -> Observation {
    Observation {
        axis: axis.id,
        value: Value::Unobservable(Unobservable::ProbeFailed(
            "axis detection lands in a later commit".to_string(),
        )),
        evidence: Vec::new(),
        detail: String::new(),
    }
}

pub(crate) async fn probe_meta_datetime_format(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
) -> Observation {
    not_yet_implemented(&META_DATETIME_FORMAT)
}

pub(crate) async fn probe_empty_multivalued_rendering(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
) -> Observation {
    not_yet_implemented(&EMPTY_MULTIVALUED_RENDERING)
}

pub(crate) async fn probe_user_groups_presence(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
) -> Observation {
    not_yet_implemented(&USER_GROUPS_PRESENCE)
}

pub(crate) async fn probe_group_members_filter(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
    _caps: &Capabilities,
) -> Observation {
    not_yet_implemented(&GROUP_MEMBERS_FILTER)
}

pub(crate) async fn probe_group_displayname_filter(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
    _caps: &Capabilities,
) -> Observation {
    not_yet_implemented(&GROUP_DISPLAYNAME_FILTER)
}

pub(crate) async fn probe_patch_replace_empty_array(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
    _caps: &Capabilities,
) -> Observation {
    not_yet_implemented(&PATCH_REPLACE_EMPTY_ARRAY)
}

pub(crate) async fn probe_patch_replace_empty_value(
    _client: &ScimClient,
    _bk: &mut Bookkeeping,
    _caps: &Capabilities,
) -> Observation {
    not_yet_implemented(&PATCH_REPLACE_EMPTY_VALUE)
}
