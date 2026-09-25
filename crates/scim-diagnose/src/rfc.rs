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
    /// A verbatim quote from `lines`' span of the vendored RFC text,
    /// whitespace-normalized (consecutive whitespace collapsed to a single
    /// space, leading/trailing trimmed). `None` for a citation this crate
    /// does not verify word-for-word -- scoped to the eight
    /// `crate::matrix` derived-family characteristic citations (plus their
    /// PUT/PATCH/Table-9 variants), per the brief, plus the three §3.14
    /// etag citations (`ETAG_REPRESENTATION`, `ETAG_CONDITIONAL_READ`,
    /// `ETAG_CONDITIONAL_WRITE`) and the four `attribute_projection`
    /// citations (`PROJECTION_ATTRIBUTES_PARAM`, `PROJECTION_PATCH_CROSSREF`,
    /// `PROJECTION_PUT_UNLESS_OTHERWISE`, `PROJECTION_POST_BODY_SHOULD`),
    /// each of which quotes a single literal RFC 2119 sentence its
    /// `Mandated` axes rest on directly; every other static axis's citation
    /// (the original seven, `uniqueness_scimtype`/`patch_*`, and the etag
    /// family's Table 8/DELETE basis) cites `Silent`/`Permitted`/broader
    /// passages rather than a single defining sentence, and is not covered.
    /// Checked against the actual file by `tests::verify_quotes`
    /// (`crate::rfc::tests`).
    pub quote: Option<&'static str>,
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
    ///
    /// `basis` is the passage that *establishes* the silence -- the text
    /// that makes the behaviour optional or leaves the vocabulary open --
    /// so a reader can audit the classification instead of taking "the RFC
    /// says nothing" on trust. `None` only when no single passage can be
    /// pointed at, i.e. the RFC is silent by pure omission.
    Silent { basis: Option<Basis> },
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
            RfcPosition::Silent { basis } => *basis,
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
    quote: None,
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
    quote: None,
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
    quote: None,
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
    quote: None,
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
    quote: None,
};

// ------------------------------------------------------ attribute_projection family
//
// Back `crate::matrix::projection`'s `attribute_projection` family (ported
// from `feat/rfc-extract`'s `crates/scim-conformance/src/templates/
// projection.rs`, whose own citation was that branch's ledger-derived "p27"
// requirement -- this crate has no ledger, so the citation is recreated
// here as ordinary `Basis` constants, verified the same way as every other
// constant in this file). Four constants, one per HTTP method the family
// probes, because -- unlike every `DerivedFamily` in `crate::rfc`'s
// previous section, which cites one passage per *characteristic* regardless
// of method -- this family's *citation* genuinely differs by method: PATCH
// carries an explicit textual cross-reference to the general rule, PUT
// inherits it only through an implicit "unless otherwise specified"
// carve-out, and POST's citation rests on a SHOULD that only gates whether
// a representation is returned at all, not on whether §3.9's own MUST
// applies once one is. All four are nonetheless judged `Keyword::Must` --
// see `crate::matrix::projection::rfc_for_method`'s doc comment for why the
// asymmetry lives in *which passage* backs the obligation rather than in a
// softer fault threshold for POST.

/// RFC 7644 §3.9 (`rfc7644.txt:3591-3608`): the parameter's own definition
/// -- widened from the brief's `3591-3600` (the general preamble plus the
/// `attributes` clause alone) to also include `excludedAttributes`' own
/// MUST sentence at `3605-3607`, since this family judges GET control
/// instances for *both* query parameters against this one constant, and
/// citing only the `attributes` half for an `excludedAttributes` instance
/// would be citing text that never mentions the parameter under test.
/// "Clients MAY request a partial resource representation on any operation
/// that returns a resource within the response ... attributes When
/// specified ... each resource returned MUST contain the minimum set of
/// resource attributes and any attributes or sub-attributes explicitly
/// requested by the 'attributes' parameter. ... excludedAttributes When
/// specified, each resource returned MUST contain the minimum set of
/// resource attributes. Additionally, the default set of attributes minus
/// those attributes listed in 'excludedAttributes' is returned." This is
/// the family's general basis -- binding on its own for GET (RFC 7644
/// §3.4.2.5's attribute filtering already implements it there; this
/// control cell just confirms it) and the foundation every other method's
/// citation below builds on.
pub const PROJECTION_ATTRIBUTES_PARAM: Basis = Basis {
    doc: "RFC 7644",
    section: "3.9",
    lines: "rfc7644.txt:3591-3608",
    quote: Some(
        "Clients MAY request a partial resource representation on any operation that returns \
         a resource within the response by specifying either of the mutually exclusive URL \
         query parameters \"attributes\" or \"excludedAttributes\", as follows: attributes \
         When specified, the default list of attributes SHALL be overridden, and each resource \
         returned MUST contain the minimum set of resource attributes and any attributes or \
         sub-attributes explicitly requested by the \"attributes\" parameter.",
    ),
};

/// RFC 7644 §3.5.2 (`rfc7644.txt:1939-1944`): PATCH's own explicit
/// cross-reference to §3.9 -- "the server either MUST return a 200 OK
/// response code and the entire resource within the response body, subject
/// to the 'attributes' query parameter (see Section 3.9) ... The server
/// MUST return a 200 OK if the 'attributes' parameter is specified in the
/// request." The strongest of the three write-method citations: PATCH is
/// the only one of the three the RFC names by number pointing straight at
/// §3.9, rather than leaving the connection to be inferred. The final
/// sentence's own MUST (a 200, not 204, whenever `attributes` is supplied)
/// is a *status-code* requirement, not a projection requirement -- a target
/// that answers 204 with `attributes` set fails that sentence, not this
/// family's own check, so `crate::matrix::projection` records that case as
/// `Unobservable::ProbeFailed` (no representation to judge) rather than as
/// a projection fault.
pub const PROJECTION_PATCH_CROSSREF: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1939-1944",
    quote: Some(
        "On successful completion, the server either MUST return a 200 OK response code and \
         the entire resource within the response body, subject to the \"attributes\" query \
         parameter (see Section 3.9), or MAY return HTTP status code 204 (No Content) and the \
         appropriate response headers for a successful PATCH request. The server MUST return a \
         200 OK if the \"attributes\" parameter is specified in the request.",
    ),
};

/// RFC 7644 §3.5.1 (`rfc7644.txt:1687-1690`): "Unless otherwise specified,
/// a successful PUT operation returns a 200 OK response code and the
/// entire resource within the response body, enabling the client to
/// correlate the client's and the service provider's views of the updated
/// resource." Unlike PATCH's sentence, this never names §3.9 or the
/// `attributes` parameter at all -- what it supplies is the "unless
/// otherwise specified" opening that lets §3.9's own MAY/MUST language
/// override PUT's default full-representation return. The obligation PUT
/// is held to is still an unconditional MUST (§3.9's own wording carries no
/// softening for PUT specifically), so this is modeled `Keyword::Must`
/// too -- but the citation backing it is this indirect carve-out, not a
/// named cross-reference, which is the asymmetry
/// `crate::matrix::projection` keeps distinct from PATCH's.
pub const PROJECTION_PUT_UNLESS_OTHERWISE: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.1",
    lines: "rfc7644.txt:1687-1690",
    quote: Some(
        "Unless otherwise specified, a successful PUT operation returns a 200 OK response code \
         and the entire resource within the response body, enabling the client to correlate \
         the client's and the service provider's views of the updated resource.",
    ),
};

/// RFC 7644 §3.3 (`rfc7644.txt:601-604`): "When the service provider
/// successfully creates the new resource, an HTTP response SHALL be
/// returned with HTTP status code 201 (Created). The response body SHOULD
/// contain the service provider's representation of the newly created
/// resource." Unlike PUT and PATCH, POST is not even obligated to return a
/// representation at all -- only a SHOULD -- and that is the asymmetry this
/// citation carries: §3.9's own MUST only binds "any operation that
/// returns a resource within the response," and for POST that premise
/// itself rests on a SHOULD rather than a MUST.
///
/// This does *not* soften the obligation once POST *has* returned a
/// representation, though: at that point the premise is satisfied and
/// §3.9's MUST applies to POST exactly as it does to PUT/PATCH/GET, so
/// `crate::matrix::projection` still models POST as `Keyword::Must` -- a
/// leaked attribute on POST is a `VIOLATION` the same as on any other
/// method. What actually differs for POST is upstream of that: a POST that
/// returns no representation at all is not a projection fault either way
/// (nothing to judge), a case `crate::matrix::projection::judge` records as
/// `Value::Known("no_body")` rather than by discounting a body that *was*
/// returned. This constant exists to make that distinction citable, not to
/// back a different fault threshold.
pub const PROJECTION_POST_BODY_SHOULD: Basis = Basis {
    doc: "RFC 7644",
    section: "3.3",
    lines: "rfc7644.txt:601-604",
    quote: Some(
        "When the service provider successfully creates the new resource, an HTTP response \
         SHALL be returned with HTTP status code 201 (Created). The response body SHOULD \
         contain the service provider's representation of the newly created resource.",
    ),
};

// --------------------------------------------- crate::matrix derived-family citations
//
// Back the eight `DerivedFamily`s in `crate::matrix::derive` -- each cites
// the RFC text that defines the *meaning* of the schema-declared
// characteristic the family judges (`RfcPosition::SelfDeclared`), verified
// with `sed -n '<range>p' spec/rfc/<doc>.txt` the same way as every other
// constant in this file.

/// RFC 7644 §3.3 (`rfc7644.txt:583-584`): "In the request body, attributes
/// whose mutability is 'readOnly' ... SHALL be ignored." Governs POST only
/// -- PUT and PATCH have their own, differently-worded rules (see
/// `MUTABILITY_READ_ONLY_PUT`/`MUTABILITY_READ_ONLY_PATCH`).
pub const MUTABILITY_READ_ONLY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.3",
    lines: "rfc7644.txt:583-584",
    quote: Some("In the request body, attributes whose mutability is \"readOnly\" (see Sections 2.2 and 7 of [RFC7643]) SHALL be ignored."),
};

/// RFC 7644 §3.5.1 (`rfc7644.txt:1665`), the `readOnly` mutability
/// paragraph: "Any values provided SHALL be ignored." Same "ignore, don't
/// reject" predicate as POST's §3.3 rule, cited to the PUT-specific text
/// instead.
pub const MUTABILITY_READ_ONLY_PUT: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.1",
    lines: "rfc7644.txt:1665",
    quote: Some("readOnly Any values provided SHALL be ignored."),
};

/// RFC 7644 §3.5.2 (`rfc7644.txt:1886-1894`): "a client MUST NOT modify an
/// attribute that has mutability 'readOnly' or 'immutable' ... An operation
/// that is not compatible with an attribute's mutability or schema SHALL
/// return the appropriate HTTP response status code and a JSON detail error
/// response as defined in Section 3.12." Unlike POST/PUT, PATCH must
/// *reject* the operation (400, `scimType: mutability` per Table 9 --
/// `STATUS_TABLE9_MUTABILITY`), not silently ignore it.
pub const MUTABILITY_READ_ONLY_PATCH: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1886-1894",
    quote: Some("Each operation against an attribute MUST be compatible with the attribute's mutability and schema as defined in Sections 2.2 and 2.3 of [RFC7643]. For example, a client MUST NOT modify an attribute that has mutability \"readOnly\" or \"immutable\". However, a client MAY \"add\" a value to an \"immutable\" attribute if the attribute had no previous value. An operation that is not compatible with an attribute's mutability or schema SHALL return the appropriate HTTP response status code and a JSON detail error response as defined in Section 3.12."),
};

/// RFC 7644 §3.12 Table 9's `mutability` row (`rfc7644.txt:3845-3849`).
/// Names the concrete `scimType` a PATCH against a `readOnly` attribute
/// must return per §3.5.2 -- attached alongside `MUTABILITY_READ_ONLY_PATCH`.
pub const STATUS_TABLE9_MUTABILITY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.12",
    lines: "rfc7644.txt:3845-3849",
    quote: Some("| mutability | The attempted modification is | PUT (Section | | | not compatible with the target | 3.5.1), PATCH | | | attribute's mutability or | (Section 3.5.2) | | | current state (e.g., | | | | modification of an \"immutable\" | |"),
};

/// RFC 7643 §7 (`rfc7643.txt:1764-1766`): "immutable  The attribute MAY be
/// defined at resource creation ... The attribute SHALL NOT be updated."
pub const MUTABILITY_IMMUTABLE: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1764-1766",
    quote: Some("immutable The attribute MAY be defined at resource creation (e.g., POST) or at record replacement via a request (e.g., a PUT). The attribute SHALL NOT be updated."),
};

/// RFC 7643 §7 (`rfc7643.txt:1731-1732`): "required  A Boolean value that
/// specifies whether or not the attribute is required."
pub const REQUIRED: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1731-1732",
    quote: Some(
        "required A Boolean value that specifies whether or not the attribute is required.",
    ),
};

/// RFC 7643 §7 (`rfc7643.txt:1747-1753`): "caseExact ... For attributes
/// that are case exact, the server SHALL preserve case for any value
/// submitted."
pub const CASE_EXACT: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1747-1753",
    quote: Some("caseExact A Boolean value that specifies whether or not a string attribute is case sensitive. The server SHALL use case sensitivity when evaluating filters. For attributes that are case exact, the server SHALL preserve case for any value submitted. If the attribute is case insensitive, the server MAY alter case for a submitted value. Case sensitivity also impacts how attribute values MAY be compared against filter"),
};

/// RFC 7643 §7 (`rfc7643.txt:1811-1815`): "uniqueness ... A server MAY
/// reject an invalid value based on uniqueness by returning HTTP response
/// code 400 (Bad Request)."
pub const UNIQUENESS: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1811-1815",
    quote: Some("uniqueness A single keyword value that specifies how the service provider enforces uniqueness of attribute values. A server MAY reject an invalid value based on uniqueness by returning HTTP response code 400 (Bad Request). A client MAY enforce uniqueness on the client side to a greater degree than the"),
};

/// RFC 7643 §7 (`rfc7643.txt:1782-1784`): "never  The attribute is never
/// returned."
pub const RETURNED_NEVER: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1782-1784",
    quote: Some("never The attribute is never returned. This may occur because the original attribute value (e.g., a hashed value) is not retained by the service provider. A service provider MAY"),
};

/// RFC 7643 §2.3 "Attribute Data Types" (`rfc7643.txt:438`).
pub const TYPE: Basis = Basis {
    doc: "RFC 7643",
    section: "2.3",
    lines: "rfc7643.txt:438",
    quote: Some("2.3. Attribute Data Types"),
};

// -------------------------------------------------------- uniqueness_scimtype / patch family
//
// Back the `uniqueness_scimtype` (6 instances), `patch_sequential_application`,
// `patch_atomicity`, and `patch_primary_demotion` static axes in
// `crate::axes`, ported from `feat/rfc-extract`'s
// `crates/scim-conformance/src/templates/{status,sequence,atomicity,
// conditional}.rs`. Verified the same way as every other constant in this
// file: `sed -n '<range>p' spec/rfc/<doc>.txt`.

/// RFC 7644 §3.12 (`rfc7644.txt:3718-3719`): "scimType A SCIM detail error
/// keyword. See Table 9. OPTIONAL." No RFC 2119 keyword closes this to a
/// fixed vocabulary, and Table 9's own uniqueness row
/// (`rfc7644.txt:3839-3843`) only *names* "uniqueness" as the applicable
/// keyword for a uniqueness violation -- it does not itself carry a
/// keyword compelling a provider to use it, and RFC 7643 §7's `UNIQUENESS`
/// basis already established that rejecting a duplicate at all is a MAY,
/// not a MUST. `uniqueness_scimtype`'s `RfcPosition::Silent` carries no
/// `Basis` field (matching `GROUP_MEMBERS_FILTER`/`GROUP_DISPLAYNAME_FILTER`'s
/// existing convention for `Silent` axes); this constant exists purely so
/// the citation this reasoning rests on is verified against the vendored
/// text the same way every other constant here is, and so a doc comment
/// has somewhere concrete to point at.
pub const PROBE_UNIQUENESS_SCIMTYPE: Basis = Basis {
    doc: "RFC 7644",
    section: "3.12",
    lines: "rfc7644.txt:3718-3719",
    quote: None,
};

/// RFC 7644 §3.5.2 (`rfc7644.txt:1918-1924`): "Each PATCH operation
/// represents a single action to be applied to the same SCIM resource
/// specified by the request URI. Operations are applied sequentially in
/// the order they appear in the array. Each operation in the sequence is
/// applied to the target resource; the resulting resource becomes the
/// target of the next operation. Evaluation continues until all
/// operations are successfully applied or until an error condition is
/// encountered." No RFC 2119 keyword appears anywhere in this paragraph --
/// it reads as declarative description of PATCH's processing model, not an
/// imperative rule. Modeled as `Mandated`/`Must` anyway: this paragraph
/// immediately precedes, in the same subsection, the SHALL-bearing
/// primary-demotion sentence and the SHALL/MUST-bearing atomicity sentence
/// (`PROBE_PATCH_PRIMARY_DEMOTION`, `PROBE_PATCH_ATOMICITY` below) -- both
/// of which presume a well-defined, ordered sequence of per-operation
/// effects to demote/restore. A server that applies two operations against
/// the same path out of array order, or independently rather than each
/// building on the last, is not offering a different but equally valid
/// reading of PATCH -- there is no coherent PATCH semantics left once
/// "sequential" is dropped. Treated as `Must` on that basis, not as a
/// hedge; the honest alternative reading, if this is wrong, is `Silent`.
pub const PROBE_PATCH_SEQUENTIAL_APPLICATION: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1918-1924",
    quote: None,
};

/// RFC 7644 §3.5.2 (`rfc7644.txt:1926-1929`): "For multi-valued
/// attributes, a PATCH operation that sets a value's \"primary\"
/// sub-attribute to \"true\" SHALL cause the server to automatically set
/// \"primary\" to \"false\" for any other values in the array." Explicit
/// SHALL -- `Mandated`/`Must`, no judgment call needed.
pub const PROBE_PATCH_PRIMARY_DEMOTION: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1926-1929",
    quote: None,
};

/// RFC 7644 §3.5.2 (`rfc7644.txt:1931-1934`): "A PATCH request, regardless
/// of the number of operations, SHALL be treated as atomic. If a single
/// operation encounters an error condition, the original SCIM resource
/// MUST be restored, and a failure status SHALL be returned." Explicit
/// SHALL/MUST -- `Mandated`/`Must`. Note the second sentence binds *two*
/// things: the request SHALL fail, and the original resource MUST be
/// restored -- `crate::axes::probe_patch_atomicity` checks both (rejection
/// alone, with the valid first operation's effect left applied, is judged
/// `rejected_but_changed`, a fault, not a pass).
pub const PROBE_PATCH_ATOMICITY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1931-1934",
    quote: None,
};

// -------------------------------------------------------------- etag family
//
// Back the 16 `etag_*` static axes in `crate::axes`, ported from
// `feat/rfc-extract`'s `crates/scim-conformance/src/etag.rs`. Unlike the
// nine `uniqueness_scimtype`/`patch_*` axes above (none of whose bases
// carry a `quote`, matching this file's general convention that quotes are
// scoped to the eight matrix-derived-family citations), these three carry a
// verbatim `quote` and are added to `quoted_citations()` below: each cites
// a single, short, literal RFC 2119 sentence this family's `Mandated`
// positions rest on directly (unlike e.g. `PROBE_META_DATETIME`, whose
// `Must` rests on a type-encoding rule spread across a longer passage), so
// there is a natural sentence to pin and verify. Verified the same way as
// every other constant in this file: `sed -n '<range>p' spec/rfc/<doc>.txt`.

/// RFC 7644 §3.14 (`rfc7644.txt:3963-3969`). Governs all four
/// "representation" axes (`etag_response_header`, `etag_meta_version`,
/// `etag_consistency`, `etag_form`), reused verbatim the way the source
/// branch's `etag.rs::representation` reused one `Key` shape across all
/// four rows (`clone_shape()`): the ETag-header MUST, the meta.version
/// SHOULD, and the weak-ETag MAY are three different keywords in the *same*
/// sentence, so one citation legitimately backs three different
/// `RfcPosition`s (`Mandated`/`Must`, `Mandated`/`Should`, `Permitted`/MAY
/// respectively). `etag_consistency` (the header and `meta.version`
/// carrying the *same* string) rests on this sentence's shared referent,
/// not on the RFC's worked example: examples are non-normative and must
/// not be read as a MUST. The subject of both clauses is "SCIM ETags" --
/// one value, specified in a header and also within `meta.version` -- so
/// publishing two different strings means the SHOULD clause was attempted
/// and given the wrong value. That is why the axis is `Keyword::Should`
/// and not `Must`: nothing in RFC 7643/7644 states the equality as a
/// requirement in its own right, so a mismatch is reported as a deviation,
/// never as a violation.
pub const ETAG_REPRESENTATION: Basis = Basis {
    doc: "RFC 7644",
    section: "3.14",
    lines: "rfc7644.txt:3963-3969",
    quote: Some(
        "Service providers MAY support weak ETags as the preferred mechanism for performing \
         conditional retrievals and ensuring that clients do not inadvertently overwrite each \
         other's changes, respectively. When supported, SCIM ETags MUST be specified as an \
         HTTP header and SHOULD be specified within the 'version' attribute contained in the \
         resource's 'meta' attribute.",
    ),
};

/// RFC 7644 §3.14 (`rfc7644.txt:4051-4052`): "If the resource has not
/// changed, the service provider simply returns an empty body with a 304
/// (Not Modified) response code." Governs the three `etag_conditional_read`
/// axes (`GET x If-None-Match` in `{current, stale, *}`).
pub const ETAG_CONDITIONAL_READ: Basis = Basis {
    doc: "RFC 7644",
    section: "3.14",
    lines: "rfc7644.txt:4051-4052",
    quote: Some(
        "If the resource has not changed, the service provider simply returns an empty body \
         with a 304 (Not Modified) response code.",
    ),
};

/// RFC 7644 §3.14 (`rfc7644.txt:4054-4058`): "If the service provider
/// supports versioning of resources, the client MAY supply an If-Match
/// header (Section 3.1 of [RFC7232]) for PUT and PATCH operations to ensure
/// that the requested operation succeeds only if the supplied ETag matches
/// the latest service provider resource, e.g., If-Match:
/// W/"e180ee84f0671b1"." Names PUT and PATCH only -- DELETE is not named
/// here; see `ETAG_TABLE8_PRECONDITION_FAILED` for the weaker, non-fault
/// basis the DELETE axes cite instead. Governs the six
/// `etag_conditional_write` axes (`{PUT, PATCH} x If-Match` in
/// `{current, stale, *}`).
pub const ETAG_CONDITIONAL_WRITE: Basis = Basis {
    doc: "RFC 7644",
    section: "3.14",
    lines: "rfc7644.txt:4054-4058",
    quote: Some(
        "If the service provider supports versioning of resources, the client MAY supply an \
         If-Match header (Section 3.1 of [RFC7232]) for PUT and PATCH operations to ensure \
         that the requested operation succeeds only if the supplied ETag matches the latest \
         service provider resource, e.g., If-Match: W/\"e180ee84f0671b1\".",
    ),
};

/// RFC 7644 §3.12 Table 8 "SCIM HTTP Status Code Usage"
/// (`rfc7644.txt:3779-3781`): "412 (Precondition Failed) | PUT, PATCH,
/// DELETE | Failed to update. Resource has changed on the server." The one
/// place in the vendored text that mentions DELETE alongside a 412
/// precondition outcome at all -- but it only names the status code a
/// server that *does* implement DELETE preconditions should use, the same
/// way it does for PUT/PATCH; it does not itself require that DELETE
/// support preconditions, and `ETAG_CONDITIONAL_WRITE`'s own §3.14 sentence
/// (the section that actually introduces `If-Match` and says which methods
/// honor it) names only PUT and PATCH. So the three `etag_delete_if_match`
/// axes are `RfcPosition::Silent` (never a fault, either way), citing this
/// table as informational -- what a server that *chooses* to implement
/// DELETE preconditions would use -- not as a `Permitted` axis (this text
/// does not present DELETE-precondition-support-or-not as an explicit
/// named choice the way e.g. `PROBE_EMPTY_MEMBERS_SHAPE` names omission vs.
/// `[]` as two explicitly equivalent representations). No `quote` field:
/// unlike the three constants above, this is a pipe-table row rather than a
/// sentence backing a `Mandated` position, matching this file's existing
/// convention of leaving `Silent` bases unquoted.
pub const ETAG_TABLE8_PRECONDITION_FAILED: Basis = Basis {
    doc: "RFC 7644",
    section: "3.12",
    lines: "rfc7644.txt:3779-3781",
    quote: None,
};

// ------------------------------------------ discovery_presence family
//
// Backs the 38 `discovery::DISCOVERY_AXES` static axes (`crate::discovery`):
// which members a discovery endpoint's response must, may, or
// conditionally must contain, per RFC 7643 ServiceProviderConfig (§5),
// ResourceType (§6), Schema (§7), and RFC 7644 §3.4.2's ListResponse
// envelope. Ported from `feat/rfc-extract`'s `golden/attrdefs.json` (61
// scraped entries, 38 of which map to one of these four discovery
// endpoints) -- hand-written here as typed constants rather than carrying
// the JSON + scanner across, since the underlying data is small, fixed,
// and the RFCs are frozen (see the report this family's brief asked
// for). Verified the same way as every other constant in this file:
// `sed -n '<range>p' spec/rfc/<doc>.txt`.

/// RFC 7643 §5 (`rfc7643.txt:1493-1495`): "documentationUri An HTTP-addressable
/// URL pointing to the service provider's human-consumable help documentation.
/// OPTIONAL."
pub const DISCOVERY_SPC_DOCUMENTATION_URI: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1493-1495",
    quote: Some(
        "documentationUri An HTTP-addressable URL pointing to the service provider's \
         human-consumable help documentation. OPTIONAL.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1497-1499`): "patch A complex type that specifies
/// PATCH configuration options. REQUIRED. See Section 3.5.2 of [RFC7644]."
pub const DISCOVERY_SPC_PATCH: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1497-1499",
    quote: Some(
        "patch A complex type that specifies PATCH configuration options. REQUIRED. See Section \
         3.5.2 of [RFC7644].",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1501-1502`): "supported A Boolean value specifying
/// whether or not the operation is supported. REQUIRED."
pub const DISCOVERY_SPC_PATCH_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1501-1502",
    quote: Some(
        "supported A Boolean value specifying whether or not the operation is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1504-1506`): "bulk A complex type that specifies
/// bulk configuration options. See Section 3.7 of [RFC7644]. REQUIRED."
pub const DISCOVERY_SPC_BULK: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1504-1506",
    quote: Some(
        "bulk A complex type that specifies bulk configuration options. See Section 3.7 of \
         [RFC7644]. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1508-1509`): "supported A Boolean value specifying
/// whether or not the operation is supported. REQUIRED."
pub const DISCOVERY_SPC_BULK_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1508-1509",
    quote: Some(
        "supported A Boolean value specifying whether or not the operation is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1519-1520`): "maxOperations An integer value
/// specifying the maximum number of operations. REQUIRED."
pub const DISCOVERY_SPC_BULK_MAX_OPERATIONS: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1519-1520",
    quote: Some(
        "maxOperations An integer value specifying the maximum number of operations. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1522-1523`): "maxPayloadSize An integer value
/// specifying the maximum payload size in bytes. REQUIRED."
pub const DISCOVERY_SPC_BULK_MAX_PAYLOAD_SIZE: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1522-1523",
    quote: Some(
        "maxPayloadSize An integer value specifying the maximum payload size in bytes. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1525-1527`): "filter A complex type that specifies
/// FILTER options. REQUIRED. See Section 3.4.2.2 of [RFC7644]."
pub const DISCOVERY_SPC_FILTER: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1525-1527",
    quote: Some(
        "filter A complex type that specifies FILTER options. REQUIRED. See Section 3.4.2.2 of \
         [RFC7644].",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1529-1530`): "supported A Boolean value specifying
/// whether or not the operation is supported. REQUIRED."
pub const DISCOVERY_SPC_FILTER_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1529-1530",
    quote: Some(
        "supported A Boolean value specifying whether or not the operation is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1532-1533`): "maxResults An integer value
/// specifying the maximum number of resources returned in a response.
/// REQUIRED."
pub const DISCOVERY_SPC_FILTER_MAX_RESULTS: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1532-1533",
    quote: Some(
        "maxResults An integer value specifying the maximum number of resources returned in a \
         response. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1535-1537`): "changePassword A complex type that
/// specifies configuration options related to changing a password. REQUIRED."
pub const DISCOVERY_SPC_CHANGE_PASSWORD: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1535-1537",
    quote: Some(
        "changePassword A complex type that specifies configuration options related to changing a \
         password. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1539-1540`): "supported A Boolean value specifying
/// whether or not the operation is supported. REQUIRED."
pub const DISCOVERY_SPC_CHANGE_PASSWORD_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1539-1540",
    quote: Some(
        "supported A Boolean value specifying whether or not the operation is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1542-1544`): "sort A complex type that specifies
/// Sort configuration options. REQUIRED."
pub const DISCOVERY_SPC_SORT: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1542-1544",
    quote: Some("sort A complex type that specifies Sort configuration options. REQUIRED."),
};

/// RFC 7643 §5 (`rfc7643.txt:1546-1547`): "supported A Boolean value specifying
/// whether or not sorting is supported. REQUIRED."
pub const DISCOVERY_SPC_SORT_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1546-1547",
    quote: Some(
        "supported A Boolean value specifying whether or not sorting is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1549-1551`): "etag A complex type that specifies
/// ETag configuration options. REQUIRED."
pub const DISCOVERY_SPC_ETAG: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1549-1551",
    quote: Some("etag A complex type that specifies ETag configuration options. REQUIRED."),
};

/// RFC 7643 §5 (`rfc7643.txt:1553-1554`): "supported A Boolean value specifying
/// whether or not the operation is supported. REQUIRED."
pub const DISCOVERY_SPC_ETAG_SUPPORTED: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1553-1554",
    quote: Some(
        "supported A Boolean value specifying whether or not the operation is supported. REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1578-1584`): "authenticationSchemes A multi-valued
/// complex type that specifies supported authentication scheme properties. To
/// enable seamless discovery of configurations, the service provider SHOULD,
/// with the appropriate security considerations, make the authenticationSchemes
/// attribute publicly accessible without prior authentication. REQUIRED. The
/// following sub-attributes are defined:"
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1578-1584",
    quote: Some(
        "authenticationSchemes A multi-valued complex type that specifies supported authentication \
         scheme properties. To enable seamless discovery of configurations, the service provider \
         SHOULD, with the appropriate security considerations, make the authenticationSchemes \
         attribute publicly accessible without prior authentication. REQUIRED. The following \
         sub-attributes are defined:"
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1586-1588`): "type The authentication scheme. This
/// specification defines the values "oauth", "oauth2", "oauthbearertoken",
/// "httpbasic", and "httpdigest". REQUIRED."
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES_TYPE: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1586-1588",
    quote: Some(
        "type The authentication scheme. This specification defines the values \"oauth\", \
         \"oauth2\", \"oauthbearertoken\", \"httpbasic\", and \"httpdigest\". REQUIRED.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1590-1591`): "name The common authentication
/// scheme name, e.g., HTTP Basic. REQUIRED."
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES_NAME: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1590-1591",
    quote: Some("name The common authentication scheme name, e.g., HTTP Basic. REQUIRED."),
};

/// RFC 7643 §5 (`rfc7643.txt:1593-1594`): "description A description of the
/// authentication scheme. REQUIRED."
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DESCRIPTION: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1593-1594",
    quote: Some("description A description of the authentication scheme. REQUIRED."),
};

/// RFC 7643 §5 (`rfc7643.txt:1596-1597`): "specUri An HTTP-addressable URL
/// pointing to the authentication scheme's specification. OPTIONAL."
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES_SPEC_URI: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1596-1597",
    quote: Some(
        "specUri An HTTP-addressable URL pointing to the authentication scheme's specification. \
         OPTIONAL.",
    ),
};

/// RFC 7643 §5 (`rfc7643.txt:1599-1600`): "documentationUri An HTTP-addressable
/// URL pointing to the authentication scheme's usage documentation. OPTIONAL."
pub const DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DOCUMENTATION_URI: Basis = Basis {
    doc: "RFC 7643",
    section: "5",
    lines: "rfc7643.txt:1599-1600",
    quote: Some(
        "documentationUri An HTTP-addressable URL pointing to the authentication scheme's usage \
         documentation. OPTIONAL.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1614-1616`): "id The resource type's server unique
/// id. This is often the same value as the "name" attribute. OPTIONAL."
pub const DISCOVERY_RT_ID: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1614-1616",
    quote: Some(
        "id The resource type's server unique id. This is often the same value as the \"name\" \
         attribute. OPTIONAL.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1618-1622`): "name The resource type name. When
/// applicable, service providers MUST specify the name, e.g., "User" or
/// "Group". This name is referenced by the "meta.resourceType" attribute in all
/// resources. REQUIRED."
pub const DISCOVERY_RT_NAME: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1618-1622",
    quote: Some(
        "name The resource type name. When applicable, service providers MUST specify the name, \
         e.g., \"User\" or \"Group\". This name is referenced by the \"meta.resourceType\" \
         attribute in all resources. REQUIRED.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1631-1633`): "description The resource type's
/// human-readable description. When applicable, service providers MUST specify
/// the description. OPTIONAL."
pub const DISCOVERY_RT_DESCRIPTION: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1631-1633",
    quote: Some(
        "description The resource type's human-readable description. When applicable, service \
         providers MUST specify the description. OPTIONAL.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1635-1637`): "endpoint The resource type's HTTP-
/// addressable endpoint relative to the Base URL of the service provider, e.g.,
/// "Users". REQUIRED."
pub const DISCOVERY_RT_ENDPOINT: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1635-1637",
    quote: Some(
        "endpoint The resource type's HTTP-addressable endpoint relative to the Base URL of the \
         service provider, e.g., \"Users\". REQUIRED.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1639-1643`): "schema The resource type's
/// primary/base schema URI, e.g., "urn:ietf:params:scim:schemas:core:2.0:User".
/// This MUST be equal to the "id" attribute of the associated "Schema"
/// resource. REQUIRED."
pub const DISCOVERY_RT_SCHEMA: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1639-1643",
    quote: Some(
        "schema The resource type's primary/base schema URI, e.g., \
         \"urn:ietf:params:scim:schemas:core:2.0:User\". This MUST be equal to the \"id\" attribute \
         of the associated \"Schema\" resource. REQUIRED."
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1645-1647`): "schemaExtensions A list of URIs of
/// the resource type's schema extensions. OPTIONAL."
pub const DISCOVERY_RT_SCHEMA_EXTENSIONS: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1645-1647",
    quote: Some(
        "schemaExtensions A list of URIs of the resource type's schema extensions. OPTIONAL.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1649-1651`): "schema The URI of an extended
/// schema, e.g., "urn:edu:2.0:Staff". This MUST be equal to the "id" attribute
/// of a "Schema" resource. REQUIRED."
pub const DISCOVERY_RT_SCHEMA_EXTENSIONS_SCHEMA: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1649-1651",
    quote: Some(
        "schema The URI of an extended schema, e.g., \"urn:edu:2.0:Staff\". This MUST be equal to \
         the \"id\" attribute of a \"Schema\" resource. REQUIRED.",
    ),
};

/// RFC 7643 §6 (`rfc7643.txt:1653-1658`): "required A Boolean value that
/// specifies whether or not the schema extension is required for the resource
/// type. If true, a resource of this type MUST include this schema extension
/// and also include any attributes declared as required in this schema
/// extension. If false, a resource of this type MAY omit this schema extension.
/// REQUIRED."
pub const DISCOVERY_RT_SCHEMA_EXTENSIONS_REQUIRED: Basis = Basis {
    doc: "RFC 7643",
    section: "6",
    lines: "rfc7643.txt:1653-1658",
    quote: Some(
        "required A Boolean value that specifies whether or not the schema extension is required \
         for the resource type. If true, a resource of this type MUST include this schema extension \
         and also include any attributes declared as required in this schema extension. If false, a \
         resource of this type MAY omit this schema extension. REQUIRED."
    ),
};

/// RFC 7643 §7 (`rfc7643.txt:1689-1696`): "id The unique URI of the schema.
/// When applicable, service providers MUST specify the URI, e.g.,
/// "urn:ietf:params:scim:schemas:core:2.0:User". Unlike most other schemas,
/// which use some sort of Globally Unique Identifier (GUID) for the "id", the
/// schema "id" is a URI so that it can be registered and is portable between
/// different service providers and clients. REQUIRED."
pub const DISCOVERY_SCHEMA_ID: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1689-1696",
    quote: Some(
        "id The unique URI of the schema. When applicable, service providers MUST specify the URI, \
         e.g., \"urn:ietf:params:scim:schemas:core:2.0:User\". Unlike most other schemas, which use \
         some sort of Globally Unique Identifier (GUID) for the \"id\", the schema \"id\" is a URI \
         so that it can be registered and is portable between different service providers and \
         clients. REQUIRED."
    ),
};

/// RFC 7643 §7 (`rfc7643.txt:1698-1701`): "name The schema's human-readable
/// name. When applicable, service providers MUST specify the name, e.g., "User"
/// or "Group". OPTIONAL."
pub const DISCOVERY_SCHEMA_NAME: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1698-1701",
    quote: Some(
        "name The schema's human-readable name. When applicable, service providers MUST specify the \
         name, e.g., \"User\" or \"Group\". OPTIONAL."
    ),
};

/// RFC 7643 §7 (`rfc7643.txt:1703-1705`): "description The schema's human-
/// readable description. When applicable, service providers MUST specify the
/// description. OPTIONAL."
pub const DISCOVERY_SCHEMA_DESCRIPTION: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1703-1705",
    quote: Some(
        "description The schema's human-readable description. When applicable, service providers \
         MUST specify the description. OPTIONAL.",
    ),
};

/// RFC 7643 §7 (`rfc7643.txt:1743-1745`): "canonicalValues A collection of
/// suggested canonical values that MAY be used (e.g., "work" and "home"). In
/// some cases, service providers MAY choose to ignore unsupported values.
/// OPTIONAL."
pub const DISCOVERY_SCHEMA_ATTRIBUTES_CANONICAL_VALUES: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1743-1745",
    quote: Some(
        "canonicalValues A collection of suggested canonical values that MAY be used (e.g., \
         \"work\" and \"home\"). In some cases, service providers MAY choose to ignore unsupported \
         values. OPTIONAL.",
    ),
};

/// RFC 7644 §3.4.2 (`rfc7644.txt:821-825`): "totalResults The total number of
/// results returned by the list or query operation. The value may be larger
/// than the number of resources returned, such as when returning a single page
/// (see Section 3.4.2.4) of results where multiple pages are available.
/// REQUIRED."
pub const DISCOVERY_LIST_TOTAL_RESULTS: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2",
    lines: "rfc7644.txt:821-825",
    quote: Some(
        "totalResults The total number of results returned by the list or query operation. The \
         value may be larger than the number of resources returned, such as when returning a single \
         page (see Section 3.4.2.4) of results where multiple pages are available. REQUIRED."
    ),
};

/// RFC 7644 §3.4.2 (`rfc7644.txt:827-830`): "Resources A multi-valued list of
/// complex objects containing the requested resources. This MAY be a subset of
/// the full set of resources if pagination (Section 3.4.2.4) is requested.
/// REQUIRED if "totalResults" is non-zero." Conditional presence: if
/// "totalResults" is non-zero.
pub const DISCOVERY_LIST_RESOURCES: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2",
    lines: "rfc7644.txt:827-830",
    quote: Some(
        "Resources A multi-valued list of complex objects containing the requested resources. This \
         MAY be a subset of the full set of resources if pagination (Section 3.4.2.4) is requested. \
         REQUIRED if \"totalResults\" is non-zero."
    ),
};

/// RFC 7644 §3.4.2 (`rfc7644.txt:832-834`): "startIndex The 1-based index of
/// the first result in the current set of list results. REQUIRED when partial
/// results are returned due to pagination." Conditional presence: when partial
/// results are returned due to pagination.
pub const DISCOVERY_LIST_START_INDEX: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2",
    lines: "rfc7644.txt:832-834",
    quote: Some(
        "startIndex The 1-based index of the first result in the current set of list results. \
         REQUIRED when partial results are returned due to pagination.",
    ),
};

/// RFC 7644 §3.4.2 (`rfc7644.txt:836-838`): "itemsPerPage The number of
/// resources returned in a list response page. REQUIRED when partial results
/// are returned due to pagination." Conditional presence: when partial results
/// are returned due to pagination.
pub const DISCOVERY_LIST_ITEMS_PER_PAGE: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2",
    lines: "rfc7644.txt:836-838",
    quote: Some(
        "itemsPerPage The number of resources returned in a list response page. REQUIRED when \
         partial results are returned due to pagination.",
    ),
};

// -------------------------------------------------------- quote verification
//
// Part 5: every `Basis` with a `quote` attached is re-derived from the
// vendored RFC text at `lines` and checked to match word-for-word -- so a
// citation can never silently drift from the text it claims to quote.
// Scoped to the definitional citations above (the eight `crate::matrix`
// characteristics plus their PUT/PATCH/Table-9 variants, plus the three
// §3.14 etag citations, which each quote a single literal RFC 2119
// sentence); `Silent`/`Permitted` axes generally have no single defining
// sentence to quote, so they carry no `quote` and are skipped (ported
// concept from `feat/rfc-extract`'s `ledger.rs` `verify_quotes`, adapted:
// that version verified ledger-derived citations against a YAML
// requirement's own span; this one verifies a `Basis` constant's `quote`
// field against its own `lines`).

#[cfg(test)]
mod quote_tests {
    use super::*;
    use std::path::Path;

    /// Collapses consecutive whitespace (including newlines) to a single
    /// space and trims the ends -- the same normalization a citation's
    /// `quote` field is written in, so line-wrapped RFC prose compares
    /// equal regardless of exactly where the vendored `.txt` wraps a line.
    fn normalize(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Page furniture that can appear interleaved within a citation's line
    /// range in the vendored text (a page break mid-paragraph) -- stripped
    /// before normalizing, so a quote spanning a page boundary still
    /// compares equal. No citation in this file currently crosses one, but
    /// the strip is defensive rather than assumed away.
    fn is_page_furniture(line: &str) -> bool {
        let t = line.trim();
        t.is_empty()
            || t.contains("Standards Track")
            || t.contains("[Page ")
            || (t.starts_with("RFC ") && t.contains("20") && t.len() < 60)
    }

    fn extract(basis: &Basis) -> String {
        let (file, range) = basis
            .lines
            .split_once(':')
            .unwrap_or((basis.lines, basis.lines));
        let spec_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("spec/rfc");
        let text = std::fs::read_to_string(spec_dir.join(file))
            .unwrap_or_else(|e| panic!("failed to read spec/rfc/{file}: {e}"));
        let all_lines: Vec<&str> = text.lines().collect();

        let (start, end) = match range.split_once('-') {
            Some((a, b)) => (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()),
            None => {
                let n = range.parse::<usize>().unwrap();
                (n, n)
            }
        };
        let selected: Vec<&str> = all_lines
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let line_no = i + 1;
                line_no >= start && line_no <= end
            })
            .map(|(_, l)| *l)
            .filter(|l| !is_page_furniture(l))
            .collect();
        normalize(&selected.join(" "))
    }

    /// Every citation constant with a `quote` attached, gathered by name so
    /// a failure names which one broke.
    fn quoted_citations() -> Vec<(&'static str, Basis)> {
        vec![
            ("MUTABILITY_READ_ONLY", MUTABILITY_READ_ONLY),
            ("MUTABILITY_READ_ONLY_PUT", MUTABILITY_READ_ONLY_PUT),
            ("MUTABILITY_READ_ONLY_PATCH", MUTABILITY_READ_ONLY_PATCH),
            ("STATUS_TABLE9_MUTABILITY", STATUS_TABLE9_MUTABILITY),
            ("MUTABILITY_IMMUTABLE", MUTABILITY_IMMUTABLE),
            ("REQUIRED", REQUIRED),
            ("CASE_EXACT", CASE_EXACT),
            ("UNIQUENESS", UNIQUENESS),
            ("RETURNED_NEVER", RETURNED_NEVER),
            ("TYPE", TYPE),
            ("ETAG_REPRESENTATION", ETAG_REPRESENTATION),
            ("ETAG_CONDITIONAL_READ", ETAG_CONDITIONAL_READ),
            ("ETAG_CONDITIONAL_WRITE", ETAG_CONDITIONAL_WRITE),
            ("PROJECTION_ATTRIBUTES_PARAM", PROJECTION_ATTRIBUTES_PARAM),
            ("PROJECTION_PATCH_CROSSREF", PROJECTION_PATCH_CROSSREF),
            (
                "PROJECTION_PUT_UNLESS_OTHERWISE",
                PROJECTION_PUT_UNLESS_OTHERWISE,
            ),
            ("PROJECTION_POST_BODY_SHOULD", PROJECTION_POST_BODY_SHOULD),
            (
                "DISCOVERY_SPC_DOCUMENTATION_URI",
                DISCOVERY_SPC_DOCUMENTATION_URI,
            ),
            ("DISCOVERY_SPC_PATCH", DISCOVERY_SPC_PATCH),
            (
                "DISCOVERY_SPC_PATCH_SUPPORTED",
                DISCOVERY_SPC_PATCH_SUPPORTED,
            ),
            ("DISCOVERY_SPC_BULK", DISCOVERY_SPC_BULK),
            ("DISCOVERY_SPC_BULK_SUPPORTED", DISCOVERY_SPC_BULK_SUPPORTED),
            (
                "DISCOVERY_SPC_BULK_MAX_OPERATIONS",
                DISCOVERY_SPC_BULK_MAX_OPERATIONS,
            ),
            (
                "DISCOVERY_SPC_BULK_MAX_PAYLOAD_SIZE",
                DISCOVERY_SPC_BULK_MAX_PAYLOAD_SIZE,
            ),
            ("DISCOVERY_SPC_FILTER", DISCOVERY_SPC_FILTER),
            (
                "DISCOVERY_SPC_FILTER_SUPPORTED",
                DISCOVERY_SPC_FILTER_SUPPORTED,
            ),
            (
                "DISCOVERY_SPC_FILTER_MAX_RESULTS",
                DISCOVERY_SPC_FILTER_MAX_RESULTS,
            ),
            (
                "DISCOVERY_SPC_CHANGE_PASSWORD",
                DISCOVERY_SPC_CHANGE_PASSWORD,
            ),
            (
                "DISCOVERY_SPC_CHANGE_PASSWORD_SUPPORTED",
                DISCOVERY_SPC_CHANGE_PASSWORD_SUPPORTED,
            ),
            ("DISCOVERY_SPC_SORT", DISCOVERY_SPC_SORT),
            ("DISCOVERY_SPC_SORT_SUPPORTED", DISCOVERY_SPC_SORT_SUPPORTED),
            ("DISCOVERY_SPC_ETAG", DISCOVERY_SPC_ETAG),
            ("DISCOVERY_SPC_ETAG_SUPPORTED", DISCOVERY_SPC_ETAG_SUPPORTED),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES,
            ),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES_TYPE",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES_TYPE,
            ),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES_NAME",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES_NAME,
            ),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DESCRIPTION",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DESCRIPTION,
            ),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES_SPEC_URI",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES_SPEC_URI,
            ),
            (
                "DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DOCUMENTATION_URI",
                DISCOVERY_SPC_AUTHENTICATION_SCHEMES_DOCUMENTATION_URI,
            ),
            ("DISCOVERY_RT_ID", DISCOVERY_RT_ID),
            ("DISCOVERY_RT_NAME", DISCOVERY_RT_NAME),
            ("DISCOVERY_RT_DESCRIPTION", DISCOVERY_RT_DESCRIPTION),
            ("DISCOVERY_RT_ENDPOINT", DISCOVERY_RT_ENDPOINT),
            ("DISCOVERY_RT_SCHEMA", DISCOVERY_RT_SCHEMA),
            (
                "DISCOVERY_RT_SCHEMA_EXTENSIONS",
                DISCOVERY_RT_SCHEMA_EXTENSIONS,
            ),
            (
                "DISCOVERY_RT_SCHEMA_EXTENSIONS_SCHEMA",
                DISCOVERY_RT_SCHEMA_EXTENSIONS_SCHEMA,
            ),
            (
                "DISCOVERY_RT_SCHEMA_EXTENSIONS_REQUIRED",
                DISCOVERY_RT_SCHEMA_EXTENSIONS_REQUIRED,
            ),
            ("DISCOVERY_SCHEMA_ID", DISCOVERY_SCHEMA_ID),
            ("DISCOVERY_SCHEMA_NAME", DISCOVERY_SCHEMA_NAME),
            ("DISCOVERY_SCHEMA_DESCRIPTION", DISCOVERY_SCHEMA_DESCRIPTION),
            (
                "DISCOVERY_SCHEMA_ATTRIBUTES_CANONICAL_VALUES",
                DISCOVERY_SCHEMA_ATTRIBUTES_CANONICAL_VALUES,
            ),
            ("DISCOVERY_LIST_TOTAL_RESULTS", DISCOVERY_LIST_TOTAL_RESULTS),
            ("DISCOVERY_LIST_RESOURCES", DISCOVERY_LIST_RESOURCES),
            ("DISCOVERY_LIST_START_INDEX", DISCOVERY_LIST_START_INDEX),
            (
                "DISCOVERY_LIST_ITEMS_PER_PAGE",
                DISCOVERY_LIST_ITEMS_PER_PAGE,
            ),
        ]
    }

    #[test]
    fn verify_quotes() {
        let citations = quoted_citations();
        assert!(!citations.is_empty());
        for (name, basis) in citations {
            let Some(quote) = basis.quote else {
                panic!("{name} is in quoted_citations() but has no quote attached");
            };
            let extracted = extract(&basis);
            let expected = normalize(quote);
            assert!(
                extracted.contains(&expected),
                "{name}'s quote does not match spec/rfc/{}: \n  quote:     {expected:?}\n  extracted: {extracted:?}",
                basis.lines,
            );
        }
    }

    #[test]
    fn every_matrix_characteristic_basis_has_a_quote() {
        // Every Basis this file defines specifically to back a
        // crate::matrix::derive characteristic must carry a quote -- a
        // citation added later without one would silently escape
        // verification.
        for (name, basis) in quoted_citations() {
            assert!(basis.quote.is_some(), "{name} has no quote attached");
        }
    }
}
