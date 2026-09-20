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

// ------------------------------------------------------- T10c protocol probes
//
// These back `crate::probes`, not the schema-driven matrix above: each cites
// the RFC text a single non-schema-driven probe checks compliance with.

/// RFC 7643 §2.3.5: "A DateTime value ... MUST be encoded as a valid
/// xsd:dateTime ... and MUST include both a date and a time." Also see
/// §3.1's `meta.created`/`lastModified` definitions (`rfc7643.txt:919-925`),
/// which require those two fields to be a `DateTime`.
pub const PROBE_META_DATETIME: Basis = Basis {
    doc: "RFC 7643",
    section: "2.3.5",
    lines: "rfc7643.txt:526-529",
};

/// RFC 7643 §2.5: "Unassigned attributes, the null value, or an empty array
/// (in the case of a multi-valued attribute) SHALL be considered to be
/// equivalent in 'state'."
pub const PROBE_EMPTY_MEMBERS_SHAPE: Basis = Basis {
    doc: "RFC 7643",
    section: "2.5",
    lines: "rfc7643.txt:681-683",
};

/// RFC 7643 §4.1.2: "groups ... A list of groups to which the user
/// belongs...". Combined with §7's `returned: default` definition
/// (`rfc7643.txt:1799-1803`): a `default`-returned attribute with a real
/// value is expected in the response, not omitted.
pub const PROBE_USER_GROUPS_PRESENCE: Basis = Basis {
    doc: "RFC 7643",
    section: "4.1.2",
    lines: "rfc7643.txt:1325-1327",
};

/// RFC 7644 §3.4.2.2: "Clients MAY request a subset of resources by
/// specifying the 'filter' query parameter ... When specified, only those
/// resources matching the filter expression SHALL be returned." A
/// well-formed filter (Table 9's `invalidFilter`, `rfc7644.txt:3821-3826`,
/// is for syntax the server can't parse) must be processed, not rejected.
pub const PROBE_GROUP_FILTER: Basis = Basis {
    doc: "RFC 7644",
    section: "3.4.2.2",
    lines: "rfc7644.txt:931-932",
};

/// RFC 7644 §3.5.2.3 "Replace Operation": "If the target location is a
/// multi-valued attribute and no filter is specified, the attribute and all
/// values are replaced."
pub const PROBE_PATCH_REPLACE: Basis = Basis {
    doc: "RFC 7644",
    section: "3.5.2.3",
    lines: "rfc7644.txt:2372-2373",
};

// ---------------------------------------------------------- T10 ledger checks
//
// Secondary citations attached by `crate::templates` alongside a
// requirement's own (ledger-derived) basis. Unlike the ledger-derived
// primary basis (`crate::requirement::basis_from_span`), these cite RFC
// text with no corresponding ledger entry, so their line numbers are
// hand-verified against `spec/rfc/rfc7644.txt` the same way every other
// constant in this file is.

/// RFC 7644 §3.9 "Additional Operation Response Parameters"
/// (`rfc7644.txt:3571`): "Clients MAY request a partial resource
/// representation on any operation that returns a resource within the
/// response by specifying either of the mutually exclusive URL query
/// parameters "attributes" or "excludedAttributes" ... attributes  When
/// specified ... each resource returned MUST contain the minimum set of
/// resource attributes and any attributes or sub-attributes explicitly
/// requested by the "attributes" parameter." The general rule p27's PATCH-
/// specific sentence ("subject to the 'attributes' query parameter (see
/// Section 3.9)") generalizes to every operation that returns a resource,
/// including POST and PUT -- attached as a secondary basis on the
/// projection template's POST/PUT cells.
pub const PROJECTION_SEC_3_9: Basis = Basis {
    doc: "RFC 7644",
    section: "3.9",
    lines: "rfc7644.txt:3591-3600",
};

/// RFC 7644 §3.12 Table 9's `uniqueness` row (`rfc7644.txt:3911`, "Table 9:
/// SCIM Detail Error Keyword Values"): "uniqueness | One or more of the
/// attribute values are already in use or are reserved. | POST (Create -
/// Section 3.3), PUT (Section 3.5.1), PATCH (Section 3.5.2)". Names the
/// concrete `scimType` and the {POST, PUT, PATCH} applicability p26's
/// "return ... a JSON detail error response as defined in Section 3.12"
/// defers to -- attached as a secondary basis by the status template.
pub const STATUS_TABLE9_UNIQUENESS: Basis = Basis {
    doc: "RFC 7644",
    section: "3.12",
    lines: "rfc7644.txt:3839-3844",
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

// --------------------------------------------------------- T11 diagnose CLI
//
// Used by `crate::diagnose` only, for the one path a schema-driven finding
// can't otherwise reach: `GET /Schemas` itself failing before the matrix
// can even be generated. Cites the same section T9's `TARGETS` table
// points `(7643, "7")` at ("/Schemas").

/// RFC 7643 §7 "Schema Definition" (`rfc7643.txt:1660`): "This section
/// defines a way to specify the schema in use by resources available and
/// accepted by a SCIM service provider" -- the attribute characteristics
/// this crate reads back from a live `GET /Schemas` response to derive the
/// whole schema-driven matrix (`schema_matrix`).
pub const DISCOVERY_SCHEMAS_UNREACHABLE: Basis = Basis {
    doc: "RFC 7643",
    section: "7",
    lines: "rfc7643.txt:1660",
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
        ProbeMetaDatetime => PROBE_META_DATETIME,
        ProbeEmptyMembersShape => PROBE_EMPTY_MEMBERS_SHAPE,
        ProbeUserGroupsPresence => PROBE_USER_GROUPS_PRESENCE,
        ProbeGroupMembersFilter | ProbeGroupDisplaynameFilter => PROBE_GROUP_FILTER,
        ProbePatchReplaceEmptyArray | ProbePatchReplaceEmptyValue => PROBE_PATCH_REPLACE,
        LedgerP27Projection | LedgerP26Status | LedgerP23Sequence | LedgerP24Conditional
        | LedgerP25Atomicity => unreachable!(
            "ledger characteristics carry their own per-instance basis (crate::requirement) \
             and are never resolved through this fixed table"
        ),
    }
}
