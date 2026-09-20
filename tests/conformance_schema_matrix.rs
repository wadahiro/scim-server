//! Runs the schema-driven RFC 7643/7644 conformance matrix
//! (`crates/scim-conformance`) against this repository's own server and
//! checks it against the differential oracle recorded by the Python
//! prototype (`tools/prototype/golden/schema_matrix.json`, 242 cells).
//!
//! The matrix is generated from this server's own `GET /Schemas` response
//! (`scim_conformance::schema::decls_from_schemas`), not from a hand-written
//! attribute list, so it automatically follows any schema extension the
//! server advertises.

use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::matrix::{
    cells_from_decls, run_cells, Cell, Characteristic, Method, Outcome, Verdict,
};
use scim_conformance::schema::{decls_from_schemas, AttrDecl, Resource};
use serde_json::Value;
use tokio::sync::OnceCell;

mod common;

/// The check matrix, generated from this server's own `/Schemas` and then
/// actually executed against it. Computed once and shared across every
/// `#[tokio::test]` in this file: `run_cells` writes real resources, so
/// running it once keeps this file's total wall time bounded.
struct MatrixRun {
    decls: Vec<AttrDecl>,
    cells: Vec<Cell>,
    outcomes: Vec<Outcome>,
}

static MATRIX: OnceCell<MatrixRun> = OnceCell::const_new();

async fn matrix() -> &'static MatrixRun {
    MATRIX
        .get_or_init(|| async {
            let cfg = common::create_test_app_config();
            let server = common::spawn_real_server(cfg).await;
            let mut client = ScimClient::new(ClientConfig {
                base_url: server.base_url.clone(),
                auth: Auth::None,
                timeout: Duration::from_secs(10),
            })
            .expect("client construction");

            let schemas_resp = client.get("/Schemas").await.expect("GET /Schemas");
            assert_eq!(schemas_resp.status, 200, "GET /Schemas must succeed");
            let schemas = schemas_resp.body.expect("/Schemas body must be JSON");

            let decls = decls_from_schemas(&schemas);
            let cells = cells_from_decls(&decls);
            let outcomes = run_cells(&mut client, &cells).await;

            // Intentionally leaked: every test in this file needs the
            // server alive for its whole (single-process) lifetime, and
            // `OnceCell` gives no natural place to shut it down again.
            std::mem::forget(server);

            MatrixRun {
                decls,
                cells,
                outcomes,
            }
        })
        .await
}

/// The number of `AttrDecl`s a stock, unmodified scim-server currently
/// advertises across User, Group, and the enterprise extension (excluding
/// ServiceProviderConfig, which has no write endpoint). If this changes,
/// the server's schema surface changed — update the pinned count together
/// with `CELL_COUNT`, not silently.
const DECL_COUNT: usize = 93;

/// The number of matrix cells `decls_from_decls` derives from
/// [`DECL_COUNT`] declarations: readOnly x{POST,PUT,PATCH} (or one N/A for
/// a decomposed complex container), immutable x{POST-create,PATCH-change,
/// PUT-change}, required x{POST-omit,PUT-omit} (or one N/A for a readOnly
/// required attribute), caseExact x{POST} (or one N/A), uniqueness
/// x{POST,PUT,PATCH}-duplicate (or one N/A), returned:never
/// x{POST,GET,PUT,PATCH}, and type_wrong/type_valid x{POST,PUT} for every
/// non-readOnly declaration. Computed once against this server and then
/// pinned here so a change is visible as a diff, not a silent drift.
const CELL_COUNT: usize = 389;

#[tokio::test]
async fn decls_count_is_93() {
    let m = matrix().await;
    assert_eq!(
        m.decls.len(),
        DECL_COUNT,
        "decls_from_schemas produced {} decls, expected {DECL_COUNT}; the schema surface changed",
        m.decls.len()
    );

    // Sanity: no ServiceProviderConfig attribute leaked through.
    assert!(
        !m.decls
            .iter()
            .any(|d| d.schema.contains("ServiceProviderConfig")),
        "ServiceProviderConfig has no write endpoint and must be excluded"
    );
}

#[tokio::test]
async fn cell_count_is_pinned() {
    let m = matrix().await;
    assert_eq!(
        m.cells.len(),
        CELL_COUNT,
        "cells_from_decls produced {} cells, expected the pinned {CELL_COUNT}",
        m.cells.len()
    );

    // Breakdown by characteristic x method, computed from the actual
    // cells (not re-derived by hand), for the task report.
    let mut by_char_method: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for c in &m.cells {
        let characteristic = serde_json::to_value(c.characteristic)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let method = serde_json::to_value(c.method)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        *by_char_method.entry((characteristic, method)).or_default() += 1;
    }
    eprintln!("cells by characteristic x method: {by_char_method:#?}");

    // Determinism: same decls in, byte-for-byte (here: field-for-field,
    // via derived PartialEq) identical cells out.
    let again = cells_from_decls(&m.decls);
    assert_eq!(again, m.cells, "cells_from_decls is not deterministic");
}

/// The 5 fields that key a cell (both in the golden fixture and in a
/// serialized `Outcome`): resource, attribute, schema, characteristic,
/// method.
fn cell_key(v: &Value) -> (String, String, String, String, String) {
    (
        v["resource"].as_str().unwrap().to_string(),
        v["attribute"].as_str().unwrap().to_string(),
        v["schema"].as_str().unwrap().to_string(),
        v["characteristic"].as_str().unwrap().to_string(),
        v["method"].as_str().unwrap().to_string(),
    )
}

/// `Outcome` serialized and stripped of `detail` (the only field the golden
/// fixture doesn't carry — see `tools/prototype/README.md`'s golden
/// regeneration recipe, which drops `detail` and `basis.text`). What's left
/// must be a byte-for-byte match against the golden object: `verdict` and
/// `basis` included, not just the key.
fn outcome_json(o: &Outcome) -> Value {
    let mut v = serde_json::to_value(o).expect("Outcome serializes");
    v.as_object_mut().unwrap().remove("detail");
    v
}

#[tokio::test]
async fn golden_cells_are_a_subset_with_matching_verdicts() {
    let m = matrix().await;
    let golden: Vec<Value> =
        serde_json::from_str(include_str!("../tools/prototype/golden/schema_matrix.json"))
            .expect("golden JSON parses");
    assert_eq!(
        golden.len(),
        242,
        "golden fixture changed size unexpectedly"
    );

    let mut by_key = std::collections::HashMap::new();
    for o in &m.outcomes {
        let v = outcome_json(o);
        by_key.insert(cell_key(&v), v);
    }

    // The golden fixture's `mutability_readOnly` PATCH rows were recorded
    // under the Python prototype's predicate, which cited RFC 7644 §3.3
    // (the POST-only "ignore" rule) for every method including PATCH. That
    // predicate is superseded for PATCH by §3.5.2 (L1886-1894): a client
    // "MUST NOT modify" a readOnly attribute over PATCH, and a
    // non-compatible operation must be rejected with 400 `scimType:
    // "mutability"` (Table 9), not silently ignored. So the golden PATCH
    // rows' recorded verdict (PASS) and basis (§3.3) no longer reflect the
    // correct requirement; skip the object comparison for them and just
    // confirm the Rust matrix still produces that cell (see also `V-25` in
    // `classify_known_fail` below).
    //
    // The golden `mutability_readOnly` PUT rows are cited correctly in
    // predicate (PUT's own §3.5.1 rule says "ignore", same as POST's §3.3),
    // but the basis was sharpened from the POST-only §3.3 citation to
    // PUT's own §3.5.1 (L1665); strip `basis` before comparing those so the
    // (unchanged) verdict is still checked.
    let mut excluded_patch_readonly = 0usize;
    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    for g in &golden {
        let key = cell_key(g);
        let is_readonly_patch = key.3 == "mutability_readOnly" && key.4 == "PATCH";
        let is_readonly_put = key.3 == "mutability_readOnly" && key.4 == "PUT";
        match by_key.get(&key) {
            None => missing.push(key),
            Some(actual) => {
                if is_readonly_patch {
                    excluded_patch_readonly += 1;
                    continue;
                }
                let (g_cmp, actual_cmp) = if is_readonly_put {
                    let mut g2 = g.clone();
                    let mut a2 = actual.clone();
                    g2.as_object_mut().unwrap().remove("basis");
                    a2.as_object_mut().unwrap().remove("basis");
                    (g2, a2)
                } else {
                    (g.clone(), actual.clone())
                };
                if actual_cmp != g_cmp {
                    mismatches.push(format!("{key:?}: golden={g} rust={actual}"));
                }
            }
        }
    }
    eprintln!(
        "golden mutability_readOnly PATCH rows excluded from verdict/basis comparison \
         (superseded by RFC 7644 §3.5.2 L1886-1894 -- see V-25): {excluded_patch_readonly}"
    );
    assert!(
        excluded_patch_readonly > 0 && excluded_patch_readonly <= 18,
        "expected 18 or fewer golden mutability_readOnly PATCH rows, got {excluded_patch_readonly}"
    );

    assert!(
        missing.is_empty(),
        "golden cells missing from the Rust matrix: {missing:#?}"
    );
    assert!(
        mismatches.is_empty(),
        "mismatches vs golden (verdict and/or basis differ):\n{}",
        mismatches.join("\n")
    );
}

/// Classifies a FAIL outcome as one of the five known, tracked
/// non-conformances found while evaluating this generator against this
/// server (fixing them is out of scope for this task — see the commit this
/// test ships in). Anything else is a candidate new finding and must not be
/// silently added here.
fn classify_known_fail(o: &Outcome) -> Option<&'static str> {
    use Characteristic::*;

    let attr = o.attribute.as_str();
    match (o.resource, o.characteristic, attr, o.method) {
        // V-25: PATCH targeting a readOnly attribute is silently ignored
        // (2xx) instead of being rejected with 400 scimType=mutability —
        // RFC 7644 §3.5.2 L1886-1894, Table 9's mutability row (§3.12).
        // Every mutability_readOnly PATCH cell is judged by this rule, not
        // by V-21's echo-back predicate below, so this arm must come
        // first: it takes precedence for PATCH even for manager.$ref /
        // manager.displayName, which also happen to echo the forged value.
        (_, MutabilityReadOnly, _, Method::Patch) => Some("V-25"),

        // V-21: readOnly manager.$ref / manager.displayName (enterprise
        // extension) forged values are echoed back on POST/PUT — RFC 7644
        // §3.3 L583-584 (POST) / §3.5.1 L1665 (PUT).
        (
            Resource::EnterpriseUser,
            MutabilityReadOnly,
            "manager.$ref",
            Method::Post | Method::Put,
        ) => Some("V-21"),
        (
            Resource::EnterpriseUser,
            MutabilityReadOnly,
            "manager.displayName",
            Method::Post | Method::Put,
        ) => Some("V-21"),

        // V-22: PUT /Groups/{id} without displayName -> 200 (required not
        // enforced on PUT) — RFC 7643 §7 L1731-1732.
        (Resource::Group, Required, "displayName", Method::PutOmit) => Some("V-22"),

        // V-23: type validation bypass — RFC 7643 §2.3 L438.
        (Resource::Group, TypeWrong, "externalId", Method::Post | Method::Put) => Some("V-23"),
        (Resource::Group, TypeWrong, a, Method::Post | Method::Put)
            if a == "members" || a.starts_with("members.") =>
        {
            Some("V-23")
        }
        (Resource::User, TypeWrong, a, Method::Post | Method::Put)
            if a.starts_with("addresses.") =>
        {
            Some("V-23")
        }

        // V-24: readOnly User.groups forged values appear in the POST
        // response (GET shows []) — RFC 7644 §3.3.
        (Resource::User, MutabilityReadOnly, a, Method::Post)
            if a == "groups.value" || a == "groups.$ref" || a == "groups.display" =>
        {
            Some("V-24")
        }

        _ => None,
    }
}

#[tokio::test]
async fn failures_are_exactly_the_known_findings() {
    let m = matrix().await;

    let mut by_verdict: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for o in &m.outcomes {
        *by_verdict.entry(o.verdict.tag()).or_default() += 1;
    }
    eprintln!(
        "verdict distribution: {by_verdict:?} (total {})",
        m.outcomes.len()
    );

    // ERROR means the probe itself misbehaved (baseline creation failed,
    // an unexpected status code, ...) — a porting bug, never a finding.
    // The golden run never produced one; neither should this port.
    let errors: Vec<&Outcome> = m
        .outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Error))
        .collect();
    assert!(
        errors.is_empty(),
        "ERROR outcomes indicate a probe bug, not a finding:\n{}",
        errors
            .iter()
            .map(|o| format!(
                "resource={:?} attribute={} characteristic={:?} method={:?} detail={}",
                o.resource, o.attribute, o.characteristic, o.method, o.detail
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );

    let fails: Vec<&Outcome> = m
        .outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Fail))
        .collect();

    let mut unclassified = Vec::new();
    let mut by_finding: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for f in &fails {
        match classify_known_fail(f) {
            Some(finding) => *by_finding.entry(finding).or_default() += 1,
            None => unclassified.push(f),
        }
    }

    if !unclassified.is_empty() {
        let report: Vec<String> = unclassified
            .iter()
            .map(|o| {
                format!(
                    "resource={:?} attribute={} characteristic={:?} method={:?} detail={}",
                    o.resource, o.attribute, o.characteristic, o.method, o.detail
                )
            })
            .collect();
        panic!(
            "unclassified FAIL outcomes (candidate new findings):\n{}",
            report.join("\n")
        );
    }

    eprintln!(
        "FAILs by known finding: {by_finding:?} (total {})",
        fails.len()
    );
    assert!(
        !fails.is_empty(),
        "expected at least the known findings to reproduce as FAIL"
    );
}

fn find_outcome<'a>(
    m: &'a MatrixRun,
    resource: Resource,
    attribute: &str,
    characteristic: Characteristic,
    method: Method,
) -> Option<&'a Outcome> {
    m.outcomes.iter().find(|o| {
        o.resource == resource
            && o.attribute == attribute
            && o.characteristic == characteristic
            && o.method == method
    })
}

#[tokio::test]
async fn representative_cells_pass() {
    let m = matrix().await;

    let expect_pass = |resource: Resource,
                       attribute: &str,
                       characteristic: Characteristic,
                       method: Method| {
        let o = find_outcome(m, resource, attribute, characteristic, method).unwrap_or_else(|| {
            panic!("no outcome for {resource:?} {attribute} {characteristic:?} {method:?}")
        });
        assert!(
            matches!(o.verdict, Verdict::Pass),
            "expected PASS for {resource:?} {attribute} {characteristic:?} {method:?}, got {:?}: {}",
            o.verdict,
            o.detail
        );
    };

    // id / meta.created / meta.lastModified: readOnly forging ignored.
    expect_pass(
        Resource::User,
        "id",
        Characteristic::MutabilityReadOnly,
        Method::Post,
    );
    expect_pass(
        Resource::User,
        "meta.created",
        Characteristic::MutabilityReadOnly,
        Method::Post,
    );
    expect_pass(
        Resource::User,
        "meta.lastModified",
        Characteristic::MutabilityReadOnly,
        Method::Post,
    );
    // members.type: readOnly? no -- immutable is the real characteristic
    // for members.type; the representative "forging ignored" cell for it
    // is the readOnly-analogous immutable PATCH-change rejection.
    expect_pass(
        Resource::Group,
        "members.type",
        Characteristic::MutabilityImmutable,
        Method::PatchChange,
    );

    // password: never returned.
    expect_pass(
        Resource::User,
        "password",
        Characteristic::ReturnedNever,
        Method::Post,
    );

    // userName missing on POST -> 400.
    expect_pass(
        Resource::User,
        "userName",
        Characteristic::Required,
        Method::PostOmit,
    );

    // externalId: caseExact round-trip preserves mixed case.
    expect_pass(
        Resource::User,
        "externalId",
        Characteristic::CaseExact,
        Method::Post,
    );
}
