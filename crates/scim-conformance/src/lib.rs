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
//!
//! [`checks_from_attrdefs`] ([`gen::attrdefs`]) is a separate, smaller
//! family: presence checks for RFC 7643's required-member tables
//! (`ServiceProviderConfig`, `ResourceType`, `Schema`) and RFC 7644
//! §3.4.2's list-response envelope, against four fixed discovery
//! endpoints. It doesn't fit the attribute x method matrix shape, so it
//! returns its own [`gen::attrdefs::AttrdefCheck`] rather than
//! [`matrix::Outcome`], and isn't part of [`full_suite`].

pub mod basis;
pub mod capability;
pub mod client;
pub mod diag;
pub mod etag;
pub mod findings;
pub mod gen;
pub mod ledger;
pub mod matrix;
pub mod probes;
pub mod render;
pub mod report;
pub mod requirement;
pub mod schema;
pub mod scim_plugin;
pub mod scoreboard;
pub mod spec_extract;
pub mod templates;

pub use basis::Basis;
pub use capability::{Capabilities, Capability, Gated};
pub use client::{Auth, ClientConfig, ScimClient};
pub use diag::{run, run_scoreboard, DiagError, DiagOptions};
pub use gen::attrdefs::{checks_from_attrdefs, AttrdefCheck};
pub use matrix::{Cell, Characteristic, Method, Outcome, Verdict};
pub use render::render_text;
pub use report::{Counts, DiagnosticReport, Finding};
pub use schema::{decls_from_schemas, AttrDecl};
pub use scoreboard::Scoreboard;

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

/// Generates and runs every check this crate can derive from the RFC 7644
/// §3.5.2 requirement ledger (T10): loads `spec/ledger/rfc7644-3.5.2.yaml`
/// ([`ledger::load_rfc7644_3_5_2`]), maps it to [`requirement::Requirement`]s
/// ([`requirement::requirements_from_ledger`]), and dispatches each one to
/// its shape's template (`templates::{projection,status,sequence,atomicity,
/// conditional}`) to expand into cells and execute them. Deterministic
/// order: the same order `requirements_from_ledger` returns requirements in
/// (ledger entry order -- p23, p24, p25, p26, p27).
pub async fn ledger_suite(client: &mut ScimClient) -> Vec<Outcome> {
    let ledger = ledger::load_rfc7644_3_5_2();
    let reqs = requirement::requirements_from_ledger(&ledger);
    let mut outcomes = Vec::new();
    for req in &reqs {
        let rows = match req.id.as_str() {
            "p23" => templates::sequence::run(&templates::sequence::expand(req), client).await,
            "p24" => {
                templates::conditional::run(&templates::conditional::expand(req), client).await
            }
            "p25" => templates::atomicity::run(&templates::atomicity::expand(req), client).await,
            "p26" => templates::status::run(&templates::status::expand(req), client).await,
            "p27" => templates::projection::run(&templates::projection::expand(req), client).await,
            other => unreachable!(
                "requirements_from_ledger produced a requirement ({other}) with no template \
                 dispatch here -- scim_plugin::authored_meta and this match have drifted apart"
            ),
        };
        outcomes.extend(rows);
    }
    outcomes
}

/// Everything this crate can check against a live provider: the
/// schema-driven matrix ([`schema_matrix`]) plus the protocol probes
/// ([`probes::run_all`]) that catch what a schema alone can't see (T10c),
/// plus the RFC 7644 §3.14 ETag/versioning checks ([`etag::run_all`],
/// T13), plus the ledger-generated checks ([`ledger_suite`], T10).
/// Deterministic order: the matrix first (in `decls_from_schemas` order),
/// then the probes (in the fixed order `probes::run_all` runs them), then
/// the ETag family (in the fixed order `etag::run_all` runs it), then the
/// ledger-generated checks (in ledger entry order).
pub async fn full_suite(client: &mut ScimClient) -> Result<Vec<Outcome>, client::Error> {
    let mut outcomes = schema_matrix(client).await?;
    outcomes.extend(probes::run_all(client).await);
    outcomes.extend(etag::run_all(client).await);
    outcomes.extend(ledger_suite(client).await);
    Ok(outcomes)
}

/// T11: everything [`full_suite`] can generate (schema matrix + probes +
/// ledger), plus [`checks_from_attrdefs`] (T9's discovery presence
/// checks, which don't fit `full_suite`'s attribute x method shape --
/// see that function's own doc comment), folded into one
/// [`report::DiagnosticReport`].
///
/// If `full_suite` itself fails (its only fallible step is the initial
/// `GET /Schemas`), that failure becomes a single `Verdict::Error` finding
/// rather than aborting the whole report -- `checks_from_attrdefs` still
/// runs and is still reported, since it doesn't depend on `/Schemas`.
pub async fn diagnose(client: &mut ScimClient) -> report::DiagnosticReport {
    use matrix::Verdict;
    use report::{Counts, DiagnosticReport, Finding};

    let mut findings: Vec<Finding> = Vec::new();

    match full_suite(client).await {
        Ok(outcomes) => findings.extend(outcomes.into_iter().map(Finding::from)),
        Err(e) => findings.push(Finding {
            family: "schema",
            key: "schema_matrix/GET /Schemas".to_string(),
            verdict: Verdict::Error,
            basis: basis::DISCOVERY_SCHEMAS_UNREACHABLE,
            secondary: Vec::new(),
            detail: format!("could not generate the schema-driven matrix: {e}"),
            observed: None,
            keyword: None,
        }),
    }

    findings.extend(
        checks_from_attrdefs(client)
            .await
            .into_iter()
            .map(Finding::from),
    );

    let counts = Counts::tally(&findings);
    DiagnosticReport {
        target: client.base_url().to_string(),
        findings,
        counts,
    }
}
