//! RFC citation and position types attached to every [`crate::axis::Axis`].
//!
//! Adapted from `feat/rfc-extract`'s `crates/scim-conformance/src/basis.rs`.
//! `Basis` (doc/section/line-range citation into the vendored `spec/rfc/`
//! text) is taken essentially as-is. What changes for this crate's purpose:
//! that source branch's `Basis` was always paired with a fixed
//! "deviation is a Fail" policy (a conformance suite has only one kind of
//! requirement -- checked or not). This crate's axes aren't all requirements
//! at all -- most of the seven observe RFC-*silent* behaviour on purpose
//! (see `CLAUDE.md`'s `CompatibilityConfig` and the brief this crate was
//! built from), so citation and policy are split into two things:
//!
//! - [`Basis`]: still just "where in the RFC text does this come from".
//! - [`RfcPosition`]: what the RFC actually says about the dimension --
//!   `Mandated` (one value required, [`Keyword`] sets the fault severity of
//!   a deviation), `Permitted` (the RFC names a choice, no value is a
//!   fault), or `Silent` (the RFC does not regulate this at all -- the
//!   valuable case, per the brief).

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Basis {
    #[serde(rename = "rfc")]
    pub doc: &'static str,
    pub section: &'static str,
    pub lines: &'static str,
}

impl fmt::Display for Basis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let range = self
            .lines
            .split_once(':')
            .map(|(_, r)| r)
            .unwrap_or(self.lines);
        write!(f, "{} §{} L{}", self.doc, self.section, range)
    }
}

/// RFC 2119 keyword strength behind a [`RfcPosition::Mandated`] position.
/// Sets how a deviation from `expected` is judged: a `Must` deviation is a
/// violation; a `Should` deviation is worth reporting but not a fault; a
/// `May` deviation is never a fault (in practice `May` dimensions are
/// modeled as `Permitted` instead, but the variant exists so a `Mandated`
/// position can still name one if a future axis needs it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Keyword {
    Must,
    Should,
    May,
}

impl Keyword {
    /// Whether a value other than `Mandated::expected` is a fault at all.
    pub fn is_fault(&self, matches_expected: bool) -> bool {
        if matches_expected {
            return false;
        }
        matches!(self, Keyword::Must)
    }
}

/// What the RFC says about one [`crate::axis::Axis`]'s dimension.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind")]
pub enum RfcPosition {
    /// The RFC mandates one value; a different observation is judged per
    /// `keyword` (see [`Keyword`]).
    Mandated {
        basis: Basis,
        keyword: Keyword,
        expected: &'static str,
    },
    /// The RFC explicitly permits a choice between values; no observed
    /// value here is ever a fault.
    Permitted { basis: Basis },
    /// The RFC does not regulate this dimension at all. The most valuable
    /// case: an emulation option here has no "correct" RFC value to match,
    /// only providers to match.
    Silent,
    /// The RFC does not mandate a value directly; it defines the *meaning*
    /// of a characteristic the target itself declares, and the declaration
    /// binds the target. A provider that declares `returned: default` for
    /// an attribute and then omits it contradicts its own `/Schemas`. A
    /// provider that declares `never` and omits it is self-consistent -- a
    /// variant, not a fault.
    SelfDeclared {
        basis: Basis,
        declares: &'static str,
    },
}

impl RfcPosition {
    pub fn basis(&self) -> Option<Basis> {
        match self {
            RfcPosition::Mandated { basis, .. } => Some(*basis),
            RfcPosition::Permitted { basis } => Some(*basis),
            RfcPosition::Silent => None,
            RfcPosition::SelfDeclared { basis, .. } => Some(*basis),
        }
    }
}

/// Judges a `RfcPosition::SelfDeclared` observation whose token has the
/// shape `"declares_<value>_<present|absent>"` (built by
/// `crate::axes::self_declared_token`). `never` is the only declared value
/// that requires absence -- every other declared value (`default`,
/// `always`, `request`) is read as "this attribute is meant to appear", so
/// observed absence under those is the self-contradiction. An unparseable
/// token (should not happen for a `Value::Known` produced by this crate) is
/// treated as not a fault, since there is nothing to judge it against.
pub fn self_declared_is_fault(token: &str) -> bool {
    let Some(rest) = token.strip_prefix("declares_") else {
        return false;
    };
    let Some((declared, presence)) = rest.rsplit_once('_') else {
        return false;
    };
    let present = presence == "present";
    if declared == "never" {
        present
    } else {
        !present
    }
}

#[cfg(test)]
mod self_declared_tests {
    use super::*;

    #[test]
    fn declares_default_present_is_consistent() {
        assert!(!self_declared_is_fault("declares_default_present"));
    }

    #[test]
    fn declares_never_absent_is_consistent() {
        // The knob-on case: `include_user_groups: false` rewrites the
        // schema to `returned: never` and then omits the attribute. This
        // must never be reported as a fault.
        assert!(!self_declared_is_fault("declares_never_absent"));
    }

    #[test]
    fn declares_default_absent_is_self_contradiction() {
        assert!(self_declared_is_fault("declares_default_absent"));
    }

    #[test]
    fn declares_never_present_is_self_contradiction() {
        assert!(self_declared_is_fault("declares_never_present"));
    }
}

// ------------------------------------------------------------- citations
//
// Each `Basis` below cites `spec/rfc/<doc>.txt` by verified line range --
// verify with `sed -n '<range>p' spec/rfc/<doc>.txt` before changing any of
// these constants (see `crate::axes` for which axis cites which constant,
// and the crate's top-level report for the reasoning behind each axis's
// `RfcPosition`).

/// RFC 7643 §2.3.5 (`rfc7643.txt:526-529`): "A DateTime value ... MUST be
/// encoded as a valid xsd:dateTime as specified in Section 3.3.7 of
/// [XML-Schema] and MUST include both a date and a time." An epoch integer
/// is not a valid xsd:dateTime, so `meta.created`/`meta.lastModified`
/// (themselves declared type `DateTime`, RFC 7643 §3.1) rendered as epoch
/// milliseconds is a `Must` deviation, not a stylistic choice.
pub const PROBE_META_DATETIME: Basis = Basis {
    doc: "RFC 7643",
    section: "2.3.5",
    lines: "rfc7643.txt:526-529",
};

/// RFC 7643 §2.5 (`rfc7643.txt:681-683`): "Unassigned attributes, the null
/// value, or an empty array (in the case of a multi-valued attribute)
/// SHALL be considered to be equivalent in 'state'." Names omission and an
/// empty array as equivalent representations of "no members" -- an
/// explicit choice, not a mandate of either shape.
pub const PROBE_EMPTY_MEMBERS_SHAPE: Basis = Basis {
    doc: "RFC 7643",
    section: "2.5",
    lines: "rfc7643.txt:681-683",
};

/// RFC 7643 §7's `returned` definition (`rfc7643.txt:1799-1803`): "default
/// The attribute is returned by default in all SCIM operation responses
/// where attribute values are returned... DEFAULT." Contains no RFC 2119
/// keyword -- it defines what the declaration *means*, not an imperative
/// value the RFC itself picks. `RfcPosition::SelfDeclared` reflects that:
/// the obligation comes from the target's own `/Schemas` declaration for
/// `User.groups.returned`, not from this text directly. See
/// `src/resource/schema.rs:116-153`: this server rewrites its own
/// `/Schemas` to `returned: never` when `include_user_groups` is disabled,
/// so it stays self-consistent under this model.
pub const PROBE_USER_GROUPS_PRESENCE: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1799-1803",
};

/// RFC 7644 §3.4.2.2 (`rfc7644.txt:926-932`): "Filtering is an OPTIONAL
/// parameter for SCIM service providers. Clients MAY discover service
/// provider filter capabilities by looking at the 'filter' attribute of
/// the 'ServiceProviderConfig' endpoint ... When specified, only those
/// resources matching the filter expression SHALL be returned." This only
/// mandates that *supported* filters be honored -- it says nothing about
/// which attribute paths (`members[value eq ...]`, `displayName eq ...`)
/// a provider that supports filtering at all must accept. Which specific
/// filterable attributes a provider chooses to support is unregulated:
/// `Silent`.
pub const PROBE_GROUP_FILTER: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2.2",
    lines: "rfc7644.txt:926-932",
};

/// RFC 7644 §3.5.2.3 "Replace Operation" (`rfc7644.txt:2372-2373`): "If the
/// target location is a multi-valued attribute and no filter is specified,
/// the attribute and all values are replaced." Governs
/// `patch_replace_empty_array` directly (replacing with `[]` is replacing
/// with a value, like any other -- `Must` clear the attribute). The
/// non-standard `[{"value":""}]` clearing pattern
/// (`patch_replace_empty_value`) is a different, RFC-silent question: this
/// text says what "replace" must do with the array a client sent, not
/// whether a client sending one array element with an empty string is
/// secretly asking for a clear.
pub const PROBE_PATCH_REPLACE_EMPTY_ARRAY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2.3",
    lines: "rfc7644.txt:2372-2373",
};
