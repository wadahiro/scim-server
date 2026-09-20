//! RFC citation attached to every generated check: which document, which
//! section, and which raw-file line range the requirement being tested
//! comes from. `lines` always points into the vendored, unmodified text in
//! `spec/rfc/` (e.g. `"rfc7643.txt:1731-1732"`), never into a reflowed copy.

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

/// RFC 7644 §3.3: "In the request body, attributes whose mutability is
/// 'readOnly' ... SHALL be ignored." Governs POST only -- PUT and PATCH
/// have their own, differently-worded rules (see
/// `MUTABILITY_READ_ONLY_PUT`/`MUTABILITY_READ_ONLY_PATCH`).
pub const MUTABILITY_READ_ONLY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.3",
    lines: "rfc7644.txt:583-584",
};

/// RFC 7644 §3.5.1 "Replacing with PUT", the `readOnly` mutability
/// paragraph: "Any values provided SHALL be ignored." Same "ignore, don't
/// reject" predicate as POST's §3.3 rule, cited to the PUT-specific text
/// instead.
pub const MUTABILITY_READ_ONLY_PUT: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.1",
    lines: "rfc7644.txt:1665",
};

/// RFC 7644 §3.5.2 "Modifying with PATCH": "a client MUST NOT modify an
/// attribute that has mutability "readOnly" or "immutable" ... An
/// operation that is not compatible with an attribute's mutability or
/// schema SHALL return the appropriate HTTP response status code and a
/// JSON detail error response as defined in Section 3.12." Unlike POST/PUT,
/// PATCH must *reject* the operation (400, `scimType: mutability` per
/// Table 9 -- see `STATUS_TABLE9_MUTABILITY`), not silently ignore it.
pub const MUTABILITY_READ_ONLY_PATCH: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2",
    lines: "rfc7644.txt:1886-1894",
};

/// RFC 7643 §7: "immutable  The attribute MAY be defined at resource
/// creation ... The attribute SHALL NOT be updated."
pub const MUTABILITY_IMMUTABLE: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1764-1766",
};

/// RFC 7643 §7: "required  A Boolean value that specifies whether or not
/// the attribute is required."
pub const REQUIRED: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1731-1732",
};

/// RFC 7643 §7: "caseExact ... the server SHALL preserve case for any value
/// submitted."
pub const CASE_EXACT: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1747-1753",
};

/// RFC 7643 §7: "uniqueness ... A server MAY reject an invalid value based
/// on uniqueness by returning HTTP response code 400 (Bad Request)."
pub const UNIQUENESS: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1811-1815",
};

/// RFC 7643 §7: "never  The attribute is never returned."
pub const RETURNED_NEVER: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1782-1784",
};

/// RFC 7643 §2.3 "Attribute Data Types".
pub const TYPE: Basis = Basis {
    doc: "RFC 7643",
    section: "2.3",
    lines: "rfc7643.txt:438",
};

/// RFC 7644 §3.12 Table 9's `mutability` row (`rfc7644.txt:3845`): "The
/// attempted modification is not compatible with the target attribute's
/// mutability or current state ... | PUT (Section 3.5.1), PATCH (Section
/// 3.5.2)". Names the concrete `scimType` a PATCH against a `readOnly`
/// attribute must return per §3.5.2's "SHALL return ... a JSON detail
/// error response as defined in Section 3.12" -- attached as a secondary
/// basis alongside `MUTABILITY_READ_ONLY_PATCH`.
pub const STATUS_TABLE9_MUTABILITY: Basis = Basis {
    doc: "RFC 7644",
    section: "3.12",
    lines: "rfc7644.txt:3845-3849",
};

/// Method-aware basis lookup. Every characteristic's citation is fixed
/// regardless of method (`for_characteristic` below) except
/// `MutabilityReadOnly`: POST is governed by §3.3, PUT by §3.5.1, and PATCH
/// by the stricter §3.5.2 "MUST NOT modify" / Table 9 `mutability` rule
/// (see the three `MUTABILITY_READ_ONLY*` constants' doc comments). The
/// `Method::NA` container-skip cell keeps the §3.3 citation, matching the
/// golden fixture's N/A rows.
pub fn basis_for(c: crate::matrix::Characteristic, m: crate::matrix::Method) -> Basis {
    use crate::matrix::{Characteristic::MutabilityReadOnly, Method};
    if c == MutabilityReadOnly {
        match m {
            Method::Put => MUTABILITY_READ_ONLY_PUT,
            Method::Patch => MUTABILITY_READ_ONLY_PATCH,
            _ => MUTABILITY_READ_ONLY,
        }
    } else {
        for_characteristic(c)
    }
}

pub fn for_characteristic(c: crate::matrix::Characteristic) -> Basis {
    use crate::matrix::Characteristic::*;
    match c {
        MutabilityReadOnly => MUTABILITY_READ_ONLY,
        MutabilityImmutable => MUTABILITY_IMMUTABLE,
        Required => REQUIRED,
        CaseExact => CASE_EXACT,
        Uniqueness => UNIQUENESS,
        ReturnedNever => RETURNED_NEVER,
        TypeWrong | TypeValid => TYPE,
    }
}
