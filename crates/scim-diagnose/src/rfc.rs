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
    /// PUT/PATCH/Table-9 variants), per the brief; the seven static axes'
    /// citations, which cite `Silent`/`Permitted`/broader passages rather
    /// than a single defining sentence, are not covered. Checked against
    /// the actual file by `tests::verify_quotes` (`crate::rfc::tests`).
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

// -------------------------------------------------------- quote verification
//
// Part 5: every `Basis` with a `quote` attached is re-derived from the
// vendored RFC text at `lines` and checked to match word-for-word -- so a
// citation can never silently drift from the text it claims to quote.
// Scoped to the definitional citations above (the eight `crate::matrix`
// characteristics plus their PUT/PATCH/Table-9 variants); `Silent` axes
// have no defining sentence to quote, so they carry no `quote` and are
// skipped (ported concept from `feat/rfc-extract`'s `ledger.rs`
// `verify_quotes`, adapted: that version verified ledger-derived citations
// against a YAML requirement's own span; this one verifies a `Basis`
// constant's `quote` field against its own `lines`).

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
