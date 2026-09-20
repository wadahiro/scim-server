//! The SCIM-specific "authored" layer sitting on top of the ledger
//! (`crate::ledger`) and the requirement model (`crate::requirement`).
//!
//! Reading RFC 7644 §3.5.2 and deciding "paragraph p27 describes a
//! projection rule, generalized over every operation that returns a
//! resource" is not something a mechanical extractor can do from the raw
//! text alone -- it takes a human who understands what SCIM operations,
//! resources, and query parameters are. This module is that one place: a
//! flat table, keyed by ledger entry id, naming each requirement's
//! [`Shape`](crate::requirement::Shape) and any free-text
//! quantifier/condition its template needs. Everything else about a
//! [`Requirement`](crate::requirement::Requirement) -- its quote, span, and
//! RFC citation -- is derived mechanically from the ledger
//! (`crate::requirement::requirements_from_ledger`), never authored here.
//!
//! If this crate is ever split so a generic `rfc-extract` layer owns
//! `ledger`/`requirement` and only the SCIM-specific classification lives
//! downstream (plan §0 decision 1/2), this module is the one that would
//! move with the SCIM side.

use crate::capability::Capability;
use crate::requirement::{Polarity, Shape};

/// One entry's authored classification. See the module docs for why this
/// can't be derived from the ledger text alone.
pub struct AuthoredMeta {
    pub shape: Shape,
    pub polarity: Polarity,
    pub quantifier_raw: Option<&'static str>,
    pub condition_raw: Option<&'static str>,
    pub requires_capability: Option<Capability>,
}

/// Looks up the authored classification for a ledger entry id.
///
/// Only 5 of `spec/ledger/rfc7644-3.5.2.yaml`'s 11 `class: definitional,
/// testable: yes` entries are mapped here today -- p23 (sequence), p24
/// (conditional), p25 (atomicity), p26 (status), p27 (projection), each
/// with a template in `crate::templates`. The other 6
/// (p02/p04/p05/p09/p21/p22) are real, testable requirements with no
/// template yet; `crate::requirement::requirements_from_ledger` skips
/// whatever isn't listed here rather than guessing a shape.
pub fn authored_meta(entry_id: &str) -> Option<AuthoredMeta> {
    match entry_id {
        // p23: "Operations are applied sequentially in the order they
        // appear in the array. Each operation in the sequence is applied
        // to the target resource; the resulting resource becomes the
        // target of the next operation." No RFC-2119 keyword at all (the
        // ledger's own `keywords: []` note) -- classified from the
        // paragraph's plain "are applied ... becomes the target of the
        // next" ordering language, not from a keyword.
        "p23" => Some(AuthoredMeta {
            shape: Shape::Sequence,
            polarity: Polarity::Positive,
            quantifier_raw: None,
            condition_raw: None,
            requires_capability: Some(Capability::Patch),
        }),
        // p24: "... a PATCH operation that sets a value's "primary"
        // sub-attribute to "true" SHALL cause the server to automatically
        // set "primary" to "false" for any other values in the array."
        "p24" => Some(AuthoredMeta {
            shape: Shape::Conditional,
            polarity: Polarity::Positive,
            quantifier_raw: None,
            condition_raw: Some(
                r#"a PATCH operation sets a value's "primary" sub-attribute to "true""#,
            ),
            requires_capability: Some(Capability::Patch),
        }),
        // p25: "A PATCH request, regardless of the number of operations,
        // SHALL be treated as atomic. If a single operation encounters an
        // error condition, the original SCIM resource MUST be restored,
        // and a failure status SHALL be returned."
        "p25" => Some(AuthoredMeta {
            shape: Shape::Atomicity,
            polarity: Polarity::Positive,
            quantifier_raw: None,
            condition_raw: Some("a single operation encounters an error condition"),
            requires_capability: Some(Capability::Patch),
        }),
        // p26: "If a request fails, the server SHALL return an HTTP
        // response status code and a JSON detail error response as
        // defined in Section 3.12." Combined with Table 9's `uniqueness`
        // row (§3.12) for the concrete status/scimType this template
        // checks.
        // Note: p26 expands to a mix of POST/PUT/PATCH cells (not every
        // cell needs PATCH), and `requires_capability` isn't actually
        // consumed anywhere for ledger cells today (`capability::gate`
        // only sees `matrix::Cell`, never `templates::Cell`) -- `None`
        // here, matching p27 below, rather than a capability requirement
        // that would only be half-true and isn't enforced regardless.
        "p26" => Some(AuthoredMeta {
            shape: Shape::Status,
            polarity: Polarity::Positive,
            quantifier_raw: Some("uniqueness"),
            condition_raw: Some("if a request fails"),
            requires_capability: None,
        }),
        // p27: "On successful completion, the server either MUST return a
        // 200 OK response code and the entire resource within the response
        // body, subject to the "attributes" query parameter (see Section
        // 3.9), or MAY return HTTP status code 204 ... The server MUST
        // return a 200 OK if the "attributes" parameter is specified..."
        // The quantifier generalizes this PATCH-specific sentence to
        // "any operation that returns a resource" (RFC 7644 §3.9,
        // `basis::PROJECTION_SEC_3_9` -- the secondary basis the
        // projection template attaches to its POST/PUT cells).
        "p27" => Some(AuthoredMeta {
            shape: Shape::Projection,
            polarity: Polarity::Positive,
            quantifier_raw: Some("any operation that returns a resource"),
            condition_raw: Some(r#"the "attributes" parameter is specified in the request"#),
            requires_capability: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_five_entries_are_authored() {
        let mapped: Vec<&str> = [
            "p01", "p02", "p03", "p04", "p05", "p06", "p07", "p08", "p09", "p10", "p11", "p12",
            "p13", "p14", "p15", "p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23", "p24",
            "p25", "p26", "p27",
        ]
        .into_iter()
        .filter(|id| authored_meta(id).is_some())
        .collect();
        assert_eq!(mapped, vec!["p23", "p24", "p25", "p26", "p27"]);
    }
}
