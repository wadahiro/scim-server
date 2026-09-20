//! Expands a [`crate::requirement::Requirement`] into concrete [`Cell`]s
//! and executes them against a live server, producing the same
//! [`crate::matrix::Outcome`] shape the schema-driven matrix
//! (`crate::matrix`) and protocol probes (`crate::probes`) produce.
//!
//! This is T10's "generated checks from a requirement ledger" path: unlike
//! the schema-driven matrix (which derives cells from a provider's own
//! `GET /Schemas`), a ledger cell is keyed off one hand-curated
//! [`crate::requirement::Requirement`] and an axis combination (method /
//! resource / query parameter) the owning template expands it across. Each
//! shape gets its own file (`projection`, `status`, `sequence`,
//! `atomicity`, `conditional`); [`crate::ledger_suite`] runs all five.

pub mod atomicity;
pub mod conditional;
pub mod projection;
pub mod sequence;
pub mod status;

use crate::basis::Basis;
pub(crate) use crate::matrix::exec::{
    body_of, cleanup, is_2xx, safe, short_uid, Bookkeeping, GROUP_URN, PATCHOP_URN, USER_URN,
};
use crate::matrix::{Characteristic, Method, Outcome, Verdict};
use crate::schema::Resource;

/// One concrete, not-yet-executed check derived from a `Requirement`.
/// Distinct from `crate::matrix::cells::Cell` (keyed off an `AttrDecl` from
/// `/Schemas`): a ledger cell is keyed off a `Requirement` and whatever
/// axis combination its template expands across.
#[derive(Debug, Clone)]
pub struct Cell {
    pub req_id: &'static str,
    pub resource: Resource,
    pub method: Method,
    /// The query parameter this cell exercises (`"attributes"` /
    /// `"excludedAttributes"`), for shapes that have one. `None` for
    /// shapes with no query-parameter axis.
    pub param: Option<&'static str>,
    pub characteristic: Characteristic,
    pub basis: Basis,
    /// Additional citations beyond `basis` -- e.g. projection's PUT/POST
    /// cells also cite RFC 7644 §3.9's general "attributes" rule
    /// (`basis::PROJECTION_SEC_3_9`), not just §3.5.2's PATCH-specific
    /// sentence.
    pub secondary: Vec<Basis>,
}

/// A cell's fixed identity in the output row, factored out the same way
/// `crate::probes::ProbeKey` does it for protocol probes: `resource` and
/// `characteristic`/`method` are the cell's own, `attribute` is a
/// human-readable label (there is no single declared attribute backing a
/// ledger cell, so this is e.g. `"userName"` for a projection param cell,
/// not an `AttrDecl` path).
pub(crate) fn row(
    cell: &Cell,
    attribute: impl Into<String>,
    schema: &str,
    verdict: Verdict,
    observed: Option<String>,
    detail: impl Into<String>,
) -> Outcome {
    Outcome {
        attribute: attribute.into(),
        schema: schema.to_string(),
        resource: cell.resource,
        characteristic: cell.characteristic,
        method: cell.method,
        verdict,
        basis: cell.basis,
        detail: detail.into(),
        observed,
        secondary: cell.secondary.clone(),
    }
}

pub(crate) fn pass(
    cell: &Cell,
    attribute: impl Into<String>,
    schema: &str,
    observed: impl Into<String>,
    detail: impl Into<String>,
) -> Outcome {
    row(
        cell,
        attribute,
        schema,
        Verdict::Pass,
        Some(observed.into()),
        detail,
    )
}

pub(crate) fn fail(
    cell: &Cell,
    attribute: impl Into<String>,
    schema: &str,
    observed: impl Into<String>,
    detail: impl Into<String>,
) -> Outcome {
    row(
        cell,
        attribute,
        schema,
        Verdict::Fail,
        Some(observed.into()),
        detail,
    )
}

pub(crate) fn error(
    cell: &Cell,
    attribute: impl Into<String>,
    schema: &str,
    detail: impl Into<String>,
) -> Outcome {
    row(cell, attribute, schema, Verdict::Error, None, detail)
}
