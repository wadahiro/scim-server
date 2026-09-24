//! Turns ledger entries (`crate::ledger`) into typed [`Requirement`]s that
//! `crate::templates` expands into concrete, runnable checks.
//!
//! Everything mechanical -- the quote, the raw-file span, the keywords, the
//! RFC citation -- comes straight from the ledger entry; nothing here
//! retypes a line number. What *cannot* be derived mechanically is the
//! requirement's *shape* (is this a status-code rule? an ordering
//! guarantee? a projection rule?): that is authored domain knowledge, kept
//! in exactly one place, [`crate::scim_plugin::authored_meta`]'s small
//! table keyed by entry id.

use crate::basis::Basis;
use crate::capability::Capability;
use crate::ledger::{EntryClass, Ledger, LedgerEntry};

/// What *kind* of check a requirement implies. Only a subset of these
/// (`Projection`, `Status`, `Sequence`, `Atomicity`, `Conditional`) has a
/// template in `crate::templates` today; the rest exist so the vocabulary
/// covers the ledger's other definitional-and-testable entries (p02, p04,
/// p05, p09, p21, p22) once a template is written for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// A member/value MUST simply be present (or absent) -- e.g. p04/p05's
    /// "the body MUST contain ...".
    Presence,
    /// A specific HTTP status / scimType is mandated -- p26.
    Status,
    /// A response is scoped down to a requested attribute set -- p27.
    Projection,
    /// A mutability/read-only-style constraint is enforced -- p21/p22.
    Enforcement,
    /// Multiple operations are applied in order, later ones observable
    /// over earlier ones -- p23.
    Sequence,
    /// All-or-nothing application of a multi-operation request -- p25.
    Atomicity,
    /// A side effect fires only when a stated condition holds -- p24.
    Conditional,
    /// A member/value MUST NOT be present under some condition.
    Absence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// The requirement describes what MUST/SHALL happen.
    Positive,
    /// The requirement describes what MUST NOT/SHALL NOT happen.
    Negative,
}

/// A single testable requirement, combining the ledger's mechanical data
/// (quote, span, keywords, basis) with the SCIM plugin's authored
/// classification (shape, polarity, quantifier/condition text).
#[derive(Debug, Clone)]
pub struct Requirement {
    pub id: String,
    pub doc: String,
    pub section: String,
    pub span: (u32, u32),
    pub quote: String,
    pub keywords: Vec<String>,
    pub shape: Shape,
    pub polarity: Polarity,
    /// Free-text quantifier this requirement generalizes over (e.g. p27's
    /// "any operation that returns a resource"), when the shape's
    /// template needs one to know which axes to expand across. Authored,
    /// not derived.
    pub quantifier_raw: Option<String>,
    /// Free-text condition under which the requirement's effect fires
    /// (e.g. p24's "a value's primary sub-attribute is set to true").
    /// Authored, not derived.
    pub condition_raw: Option<String>,
    pub requires_capability: Option<Capability>,
    /// This requirement's own citation -- `RFC 7644 §3.5.2 L1939-1944` for
    /// p27 -- mechanically derived from the ledger entry's `(doc, section,
    /// lines)` by [`basis_from_span`]. Never hand-typed.
    pub basis: Basis,
}

/// Maps every `class: definitional`, `testable: yes` ledger entry that also
/// appears in [`crate::scim_plugin::authored_meta`]'s table into a
/// [`Requirement`]. Entries without an authored mapping are silently
/// skipped -- as of this crate, that's p02, p04, p05, p09, p21, and p22,
/// all definitional and testable, but with no template written for their
/// shape yet. This function's contract is "requirements this crate can
/// currently turn into a runnable check", not "everything the ledger
/// marked testable".
pub fn requirements_from_ledger(ledger: &Ledger) -> Vec<Requirement> {
    ledger
        .entries
        .iter()
        .filter(|e| e.class == EntryClass::Definitional && e.testable == Some(true))
        .filter_map(|e| {
            crate::scim_plugin::authored_meta(&e.id).map(|meta| build_requirement(ledger, e, meta))
        })
        .collect()
}

fn build_requirement(
    ledger: &Ledger,
    entry: &LedgerEntry,
    meta: crate::scim_plugin::AuthoredMeta,
) -> Requirement {
    let quote = entry.quote.clone().unwrap_or_else(|| {
        panic!(
            "entry {} is mapped to a template but has no `quote` in the ledger",
            entry.id
        )
    });
    Requirement {
        id: entry.id.clone(),
        doc: ledger.doc.clone(),
        section: ledger.section.clone(),
        span: entry.lines,
        quote,
        keywords: entry.keywords.clone(),
        shape: meta.shape,
        polarity: meta.polarity,
        quantifier_raw: meta.quantifier_raw.map(String::from),
        condition_raw: meta.condition_raw.map(String::from),
        requires_capability: meta.requires_capability,
        basis: basis_from_span(&ledger.doc, &ledger.section, entry.lines),
    }
}

/// Builds a [`Basis`] from a `(doc, section, span)` triple read out of a
/// parsed ledger -- the only place a ledger-derived `Basis` is constructed,
/// so every generated check's citation is mechanically derived from the
/// entry's raw span rather than typed by hand in Rust source.
///
/// `Basis`'s fields are `&'static str` (it's a cheap `Copy` type used
/// throughout this crate as compile-time constants for the schema-driven
/// matrix and probes). Ledger data isn't known until the embedded YAML is
/// parsed at runtime, so this leaks a small one-time allocation per
/// distinct requirement to get a `'static` lifetime -- called once per
/// requirement here (five, today) and again, the same way, for every
/// `TARGETS`-matched entry in `crate::gen::attrdefs` (38, today).
pub fn basis_from_span(doc: &str, section: &str, span: (u32, u32)) -> Basis {
    // "RFC 7644" -> "rfc7644.txt", matching the vendored filename in
    // `crates/scim-conformance/spec/rfc/` and the existing `basis.rs` constants' convention
    // (`"rfc7644.txt:583-584"`).
    let filename = match doc.rsplit(' ').next() {
        Some(number) => format!("rfc{number}.txt"),
        None => format!("{doc}.txt"),
    };
    let doc_static: &'static str = Box::leak(doc.to_string().into_boxed_str());
    let section_static: &'static str = Box::leak(section.to_string().into_boxed_str());
    let lines_static: &'static str =
        Box::leak(format!("{filename}:{}-{}", span.0, span.1).into_boxed_str());
    Basis {
        doc: doc_static,
        section: section_static,
        lines: lines_static,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::load_rfc7644_3_5_2;

    #[test]
    fn requirements_from_ledger_covers_exactly_the_authored_ids() {
        let ledger = load_rfc7644_3_5_2();
        let reqs = requirements_from_ledger(&ledger);
        let mut ids: Vec<&str> = reqs.iter().map(|r| r.id.as_str()).collect();
        ids.sort();
        assert_eq!(ids, vec!["p23", "p24", "p25", "p26", "p27"]);
    }

    #[test]
    fn basis_from_span_is_not_hand_typed_and_matches_the_convention() {
        let b = basis_from_span("RFC 7644", "3.5.2", (1939, 1944));
        assert_eq!(b.doc, "RFC 7644");
        assert_eq!(b.section, "3.5.2");
        assert_eq!(b.lines, "rfc7644.txt:1939-1944");
        assert_eq!(format!("{b}"), "RFC 7644 §3.5.2 L1939-1944");
    }
}
