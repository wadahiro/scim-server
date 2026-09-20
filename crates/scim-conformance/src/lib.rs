//! RFC 7643/7644 conformance checks generated from a provider's own
//! `GET /Schemas` response, rather than hand-written per attribute.
//!
//! Given a base URL, [`schema_matrix`] reads `/Schemas`, derives one
//! [`schema::AttrDecl`] per attribute/sub-attribute
//! ([`schema::decls_from_schemas`]), expands that into a matrix of checks
//! ([`matrix::cells_from_decls`]) crossing each attribute's declared
//! characteristics (mutability, required, caseExact, uniqueness, returned,
//! type) with the HTTP methods that can exercise them, executes every cell
//! against the server ([`matrix::run_cells`]), and returns one
//! [`matrix::Outcome`] per cell with a verdict and an RFC citation
//! ([`basis::Basis`]).

pub mod basis;
pub mod capability;
pub mod client;
pub mod matrix;
pub mod probes;
pub mod schema;

pub use basis::Basis;
pub use capability::{Capabilities, Capability, Gated};
pub use client::{Auth, ClientConfig, ScimClient};
pub use matrix::{Cell, Characteristic, Method, Outcome, Verdict};
pub use schema::{decls_from_schemas, AttrDecl};

/// Convenience entry point: reads `GET /Schemas`, derives and runs the full
/// check matrix, and returns the outcomes. Equivalent to calling
/// `decls_from_schemas` -> `cells_from_decls` -> `run_cells` by hand.
pub async fn schema_matrix(client: &mut ScimClient) -> Result<Vec<Outcome>, client::Error> {
    let schemas_resp = client.get("/Schemas").await?;
    let schemas = schemas_resp.body.unwrap_or(serde_json::Value::Null);
    let decls = decls_from_schemas(&schemas);
    let cells = matrix::cells_from_decls(&decls);
    Ok(matrix::run_cells(client, &cells).await)
}

/// Everything this crate can check against a live provider: the
/// schema-driven matrix ([`schema_matrix`]) plus the protocol probes
/// ([`probes::run_all`]) that catch what a schema alone can't see (T10c).
/// Deterministic order: the matrix first (in `decls_from_schemas` order),
/// then the probes (in the fixed order `probes::run_all` runs them).
pub async fn full_suite(client: &mut ScimClient) -> Result<Vec<Outcome>, client::Error> {
    let mut outcomes = schema_matrix(client).await?;
    outcomes.extend(probes::run_all(client).await);
    Ok(outcomes)
}
