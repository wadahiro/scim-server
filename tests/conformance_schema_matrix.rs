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
    build_patch_request, cells_from_decls, container_is_readonly, first_writable_subattr,
    forged_value_for, get_attr, immutable_post_payload, is_group_member_subattr, make_baseline,
    patch_targets_decl_precisely, path_segments, run_cells, set_attr, set_attr_with_companion,
    valid_value_for, wrong_value_for, Cell, Characteristic, Method, Outcome, PatchRequestPlan,
    Verdict, ENTERPRISE_URN,
};
use scim_conformance::schema::{decls_from_schemas, AttrDecl, AttrType, Resource};
use serde_json::{json, Value};
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

/// Golden-comparison strategy, decided after PR #72 fixed the five findings
/// this matrix was built to reproduce (V-21..V-25 -- V-18/V-19 are
/// ledger-matrix cells, not schema-matrix ones, and are not part of this
/// golden fixture):
///
/// The golden fixture (`tools/prototype/golden/schema_matrix.json`) was
/// recorded against the *pre-fix* server, so a chunk of its recorded
/// verdicts no longer match by design -- that's the fix working, not a
/// regression. Its original purpose was to prove the Rust port generates
/// the same 242 cells, with the same judgements, as the Python prototype
/// (a differential-oracle property). Three options were on the table:
/// (a) compare cell *keys* only and assert the verdict divergence is
/// confined to exactly the cells the fixes touched, (b) regenerate the
/// golden against the fixed server (loses the port-vs-prototype property
/// entirely), (c) drop the comparison.
///
/// This test takes (a). Measured against this rebase (golden 242 cells,
/// 18 of them `mutability_readOnly` PATCH rows excluded up front for the
/// reason below): every golden key is still present in the Rust matrix
/// (the port-equivalence property on cell *generation* survives), and of
/// the 224 remaining rows exactly 21 diverge in verdict, every one of them
/// golden=FAIL -> rust=PASS, and every one classifies under
/// `classify_known_fail` as V-21 (4: manager.$ref/manager.displayName x
/// POST/PUT), V-22 (1: Group displayName required on PUT-omit), V-23 (13:
/// Group type-validation bypass on externalId/members/members.*, User
/// addresses.* on POST), or V-24 (3: User groups.value/$ref/display on
/// POST). Two of the V-21 PUT rows (`manager.$ref`, `manager.displayName`)
/// also sharpen their `basis` citation from the POST-only §3.3 the
/// prototype cited to PUT's own §3.5.1 (L1665) -- the readOnly-PUT check
/// cites the rule for the method it's actually exercising, which the
/// prototype's single shared citation didn't distinguish; `basis` is
/// dropped before comparing those two so the (unchanged) verdict is still
/// checked. This keeps a real, falsifiable property (cell generation still
/// matches the prototype; verdict divergence is fully accounted for) and
/// records the fix's effect in the same place the pre-fix behavior used to
/// live, rather than silently deleting that history.
#[tokio::test]
async fn golden_cells_are_a_subset_and_divergence_is_confined_to_fixed_findings() {
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
    let mut outcome_by_key = std::collections::HashMap::new();
    for o in &m.outcomes {
        let v = outcome_json(o);
        let key = cell_key(&v);
        by_key.insert(key.clone(), v);
        outcome_by_key.insert(key, o);
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
    // confirm the Rust matrix still produces that cell. All 18 of these
    // cells are PASS (see `patch_mutability_readonly_fails_are_zero` below
    // for the measurement, including `Group.members.display` -- the one
    // cell that used to look like a residual before the PATCH-readOnly
    // probe's own unsoundness for that cell was corrected); this exclusion
    // is purely about the golden's stale *predicate* (§3.3 instead of
    // §3.5.2), not about hiding a failure.
    let mut excluded_patch_readonly = 0usize;
    let mut mismatches = Vec::new();
    let mut missing = Vec::new();
    let mut divergent = 0usize;
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
                    let g_verdict = g["verdict"].as_str().unwrap_or("");
                    let a_verdict = actual["verdict"].as_str().unwrap_or("");
                    if g_verdict == "FAIL" && a_verdict == "PASS" {
                        let label = outcome_by_key
                            .get(&key)
                            .and_then(|o| classify_known_fail_ignoring_verdict(o));
                        match label {
                            Some(l) if l != "V-25" => {
                                divergent += 1;
                            }
                            other => mismatches.push(format!(
                                "{key:?}: golden={g} rust={actual} (unexplained divergence, \
                                 classify_known_fail={other:?})"
                            )),
                        }
                    } else {
                        mismatches.push(format!("{key:?}: golden={g} rust={actual}"));
                    }
                }
            }
        }
    }
    eprintln!(
        "golden mutability_readOnly PATCH rows excluded from verdict/basis comparison \
         (golden's predicate, §3.3, superseded for PATCH by RFC 7644 §3.5.2 L1886-1894): \
         {excluded_patch_readonly}"
    );
    eprintln!(
        "golden->rust divergence confined to fixed findings (V-21/V-22/V-23/V-24): {divergent}"
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
        "mismatches vs golden (verdict and/or basis differ, and not attributable to a known \
         fixed finding):\n{}",
        mismatches.join("\n")
    );
    assert_eq!(
        divergent, 21,
        "expected exactly 21 cells to diverge from golden (all FAIL->PASS, all classified as \
         V-21/V-22/V-23/V-24); got {divergent} -- if this moved, a fix's effect on the matrix \
         changed and this pinned count must be re-measured, not silently updated"
    );
}

/// Like `classify_known_fail`, but usable on a PASS outcome too (the golden
/// comparison above needs to label a cell that *used* to FAIL and now
/// PASSes, and `classify_known_fail`'s PATCH arm matches on
/// resource/attribute/characteristic/method only -- it never actually
/// looks at `o.verdict` -- so this is exactly that function, not a
/// reimplementation).
fn classify_known_fail_ignoring_verdict(o: &Outcome) -> Option<&'static str> {
    classify_known_fail(o)
}

/// Classifies a FAIL outcome by the finding it used to be part of, before
/// PR #72 fixed all eight (V-18, V-19, V-21..V-25) this generator was built
/// to reproduce. Retained purely as a regression-diagnosis label now: every
/// arm matches zero FAIL outcomes against a fixed server (see below), and
/// exists so that *if* one of them regresses, the FAIL it reappears as is
/// immediately attributed to the finding it used to be, not reported as an
/// unexplained new one.
use scim_conformance::findings::classify_known_fail;

/// Regression guard, not a detection demonstration: against a server with
/// PR #72's fixes, this matrix should FAIL nowhere -- and it does, measured
/// (verdict distribution printed below; 0 FAIL, 0 ERROR). This wasn't
/// always so: `Group.members.display` / `mutability_readOnly` / `PATCH`
/// used to be pinned here as a "known V-25 residual" with the *server*
/// blamed for it. That conclusion was wrong -- the probe was unsound, not
/// the server.
///
/// `Group.members.display` is the one cell where a ReadWrite, top-level
/// multi-valued complex attribute (`members`) holds a readOnly
/// sub-attribute (`display`). The generic PATCH-readOnly probe has no
/// per-element filter target for a sub-attribute of a multi-valued
/// complex, so it fell back to `path: "members"`, sending
/// `{"op":"replace","path":"members","value":[{"display":"FORGED-..."}]}`
/// -- a `replace` of the *whole*, ReadWrite `members` array with a
/// structurally invalid element (no `value`). The server accepted that
/// (200, forged `display` dropped because member display names are always
/// resolved live via join, never stored -- see this repo's own "never
/// store member data in Group JSON" rule) and the probe judged that 200 a
/// FAIL, when it never actually exercised `display`'s mutability: it
/// exercised `members`'s (ReadWrite, correctly accepted). Verified by hand
/// against this branch's own server: `path: "members"`,
/// `value: [{"display":"FORGED"}]` (what the old probe sent) -> 200, no
/// error; `path: "members[value eq \"<member-id>\"].display"`,
/// `value: "FORGED"` -> 400, `scimType: mutability`. So the server *does*
/// enforce RFC 7644 §3.5.2 for this sub-attribute when the operation
/// actually targets it.
///
/// Fixed in `crates/scim-conformance/src/matrix/exec.rs`: the PATCH-readOnly
/// probe (`exec_readonly`) now targets a readOnly sub-attribute of a
/// ReadWrite, top-level multi-valued complex attribute with a value filter
/// (`members[value eq "<id>"].display`) instead of the coarse container
/// path, reusing the member id (`companion`) this probe's own baseline POST
/// already created (`container_is_readonly` distinguishes this case from
/// `User.groups.*`, whose *container* is itself readOnly, so the coarse
/// `path: "groups"` was already a sound probe of the container's own
/// mutability). If no element value is available to filter on for some
/// future cell in this class, the probe SKIPs it with an explicit reason
/// instead of falling back to the unsound coarse probe.
#[tokio::test]
async fn patch_mutability_readonly_fails_are_zero() {
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

    // Diagnose every FAIL (key, verdict, detail, and its
    // classify_known_fail label) so a regression is immediately
    // attributable, not just detected.
    let report: Vec<String> = fails
        .iter()
        .map(|o| {
            format!(
                "resource={:?} attribute={} schema={} characteristic={:?} method={:?} \
                 verdict={:?} label={:?} detail={}",
                o.resource,
                o.attribute,
                o.schema,
                o.characteristic,
                o.method,
                o.verdict,
                classify_known_fail(o),
                o.detail
            )
        })
        .collect();
    eprintln!(
        "FAILs (key, verdict, detail, label):\n{}",
        report.join("\n")
    );

    assert_eq!(
        fails.len(),
        0,
        "expected 0 FAILs (PR #72 fixed every server-side non-conformance this matrix was built \
         to find, and the apparent Group.members.display/mutability_readOnly/PATCH residual was \
         a false positive in the probe itself, since corrected -- see this test's doc comment); \
         got {}:\n{}",
        fails.len(),
        report.join("\n")
    );

    // Show the actual request/response for the cell that used to be the
    // false-positive FAIL, so it's visible in test output that the probe
    // now carries a valuePath and the server answers 400 mutability.
    let members_display_patch = find_outcome(
        m,
        Resource::Group,
        "members.display",
        Characteristic::MutabilityReadOnly,
        Method::Patch,
    )
    .expect("Group.members.display readOnly PATCH cell must exist in the matrix");
    eprintln!(
        "Group.members.display / mutability_readOnly / PATCH: verdict={:?} detail={}",
        members_display_patch.verdict, members_display_patch.detail
    );
    assert!(
        matches!(members_display_patch.verdict, Verdict::Pass),
        "Group.members.display readOnly PATCH must PASS now that the probe targets it with a \
         value filter instead of the coarse container path: {}",
        members_display_patch.detail
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

// =====================================================================
// Deliverable 1: the targeting invariant.
//
// Every check above judges a *verdict*. None of them can tell you whether
// the request that produced it actually exercised the rule it claims to.
// `Group.members.display`/`mutability_readOnly`/PATCH passed silently for
// months while sending `{"path":"members","value":[{"display":"FORGED"}]}`
// -- a legitimate write to the ReadWrite `members` container, judged as if
// it were a write to the readOnly `display` sub-attribute. It happened to
// FAIL here (giving it away); against a server that simply ignores
// malformed member elements, the exact same unsound probe would have
// silently PASSed, and a FAIL from it against a *third* server could never
// be trusted to mean what it claims.
//
// This section is the automated invariant that removes the luck: for
// every cell the schema matrix generates, it rebuilds the request via the
// *same* pure builders `matrix::exec`'s executors call (imported above,
// never reimplemented here) and checks that request's path/body location
// actually resolves to the cell's own `decl.path` -- not a coarser
// ancestor. See `targeting_invariant_every_cell_isolates_its_declared_attribute`'s doc
// comment below for the full accounting of what's checked, what's
// excluded and why, and what a placeholder runtime value does and does
// not prove.
// =====================================================================

/// Composes the dotted attribute path a PATCH `Operations[0].path` targets,
/// for comparison against `decl.path`. Handles every form
/// `build_patch_request` can produce: a bare dotted path
/// (`"name.givenName"`, or its enterprise-prefixed form
/// `"urn:...:enterprise:2.0:User:manager.$ref"`), a container-only path
/// (`"members"`, `"groups"`), and a valuePath filter
/// (`members[value eq "x"].display`). The schema-URN extension prefix is
/// stripped first if present.
fn composed_attr_path(raw: &str) -> String {
    let stripped = raw
        .strip_prefix(&format!("{ENTERPRISE_URN}:"))
        .unwrap_or(raw);
    if let Some(bracket) = stripped.find('[') {
        let top = &stripped[..bracket];
        let close = stripped[bracket..]
            .find(']')
            .map(|i| bracket + i)
            .expect("valuePath must have a closing ]");
        let rest = stripped[close + 1..].strip_prefix('.').unwrap_or("");
        if rest.is_empty() {
            top.to_string()
        } else {
            format!("{top}.{rest}")
        }
    } else {
        stripped.to_string()
    }
}

/// The targeting invariant's core assertion for one PATCH-family request:
/// `raw_path` must resolve (via [`composed_attr_path`]) to `decl.path`
/// itself, or to the one documented exception -- a bare container path
/// when the container itself is `readOnly` (see `container_is_readonly`'s
/// doc comment in `matrix::exec`: there is no way to write to a readOnly
/// container's sub-attributes at all, so probing the container's own
/// mutability *is* probing all of them). Anything else -- in particular a
/// bare container path when the container is ReadWrite/Immutable -- is
/// exactly the bug class this invariant exists to catch, and panics with
/// enough detail to identify the cell.
fn assert_patch_targets_decl(decl: &AttrDecl, universe: &[&AttrDecl], raw_path: &str) {
    let composed = composed_attr_path(raw_path);
    if composed == decl.path {
        return;
    }
    if composed == decl.top() && container_is_readonly(decl, universe) {
        return;
    }
    panic!(
        "UNSOUND TARGETING for {:?} (resource {:?}): PATCH path={raw_path:?} resolves to \
         {composed:?}, a proper ancestor of the declared attribute, not the attribute itself. A \
         verdict built from this request cannot be trusted to judge {:?}'s own characteristic \
         -- this is exactly the bug class this invariant exists to catch \
         (see Group.members.display's history in patch_mutability_readonly_fails_are_zero).",
        decl.path, decl.resource, decl.path
    );
}

/// Deliverable 1's targeting invariant: for every `(AttrDecl,
/// Characteristic, Method)` cell the schema matrix generates, the request
/// the probe would actually send must isolate the rule the cell's verdict
/// claims to judge -- not some coarser ancestor attribute or container.
/// This is the automated form of the manual audit that caught
/// `Group.members.display`'s `mutability_readOnly`/PATCH false FAIL: a
/// probe sending `path: "members"` while judging `members.display` can
/// never be trusted, no matter what verdict it happens to produce.
///
/// Two request families are checked, using the exact same pure builders
/// `matrix::exec`'s executors call (imported at the top of this file, not
/// reimplemented, so this test cannot silently drift from what actually
/// gets sent over the wire):
///
/// - **PATCH-family cells** (`mutability_readOnly`/PATCH,
///   `mutability_immutable`/PATCH-change, `uniqueness`/PATCH-duplicate,
///   `returned_never`/PATCH): built via `build_patch_request`, whose
///   `Operations[0].path` is checked by `assert_patch_targets_decl`
///   (dotted, valuePath-composed, and the one documented
///   readOnly-container exception all accepted; a bare ancestor path
///   otherwise fails the test). `build_patch_request` needs a
///   `filter_value` identifying an existing element (a real
///   `members.value`) that only a live POST can mint; this test supplies
///   a fixed placeholder UUID instead. **What that does and does not
///   prove**: it proves the request *shape* is sound whenever a filter
///   value is available -- the same shape a live run sends once its own
///   baseline POST succeeds. It does not prove the live run's companion
///   creation always succeeds; when it doesn't, `matrix::exec` degrades
///   that cell to `Verdict::Skip` with an explicit reason
///   (`build_patch_request`'s `Unavailable` arm) rather than falling back
///   to the unsound coarse path -- a property `capability_gate`-style unit
///   tests on `exec.rs` already cover directly, not re-proven here.
///
/// - **POST/PUT-family cells** (`mutability_readOnly`/POST+PUT,
///   `mutability_immutable`/POST-create, `caseExact`/POST,
///   `uniqueness`/POST+PUT-duplicate, `returned_never`/POST+PUT,
///   `type_wrong`/POST+PUT, `type_valid`/POST+PUT, `required`/POST-omit
///   +PUT-omit): built via `set_attr`/`set_attr_with_companion`/
///   `immutable_post_payload` (the same helpers the executors call), then
///   read back with `get_attr` and checked to equal the value placed (or,
///   for `required`'s omission legs, checked to be *absent*).
///
/// Cells this invariant does not reach, with the reason, are the single
/// documented allowlist below:
///
/// - `Method::NA` / `Method::Get`: no request body or PATCH path exists to
///   target (`NA`: a container-decomposed or otherwise-inapplicable
///   characteristic; `Get`: `returned_never`'s read-only leg, judged by
///   the attribute's *absence* from a GET response, not by any request
///   this probe itself sends).
/// - `type_valid` on a top-level `Complex` attribute with no bare scalar
///   value of its own (`name`, `manager`, `emails`, ...): the executor
///   necessarily probes a representative writable sub-attribute instead
///   (`first_writable_subattr`) -- there is no scalar `decl.path` location
///   to place a value at, so strict path-targeting doesn't apply. Checked
///   instead for the weaker but real property that the substitute is
///   actually a declared child of `decl`, never an unrelated attribute.
#[tokio::test]
async fn targeting_invariant_every_cell_isolates_its_declared_attribute() {
    let m = matrix().await;
    let universe: Vec<&AttrDecl> = m.decls.iter().collect();

    // Stands in for a real element's identifying `members.value`, which
    // only a live POST can mint. See this test's doc comment for exactly
    // what using a placeholder here does and does not prove.
    let placeholder_filter: Value = json!("11111111-1111-1111-1111-111111111111");

    let mut checked_patch = 0usize;
    let mut checked_post_put = 0usize;
    let mut excluded_no_request = 0usize;
    let mut excluded_decomposition = 0usize;

    for cell in &m.cells {
        let decl = &cell.decl;
        match (cell.characteristic, cell.method) {
            (_, Method::NA) | (Characteristic::ReturnedNever, Method::Get) => {
                excluded_no_request += 1;
            }

            (Characteristic::TypeValid, Method::Post | Method::Put)
                if decl.r#type == AttrType::Complex && decl.depth() == 1 =>
            {
                let temp = first_writable_subattr(&universe, decl);
                assert!(
                    temp.is_some_and(|t| t.parent.as_deref() == Some(decl.path.as_str())),
                    "type_valid decomposition for {:?} must substitute a genuine child \
                     attribute, got {:?}",
                    decl.path,
                    temp.map(|t| &t.path)
                );
                excluded_decomposition += 1;
            }

            (Characteristic::MutabilityReadOnly, Method::Patch) => {
                let forged = forged_value_for(decl);
                let precise = patch_targets_decl_precisely(decl, &universe);
                let (filter_value, new_value) = if precise {
                    (None, forged.clone())
                } else {
                    let segs = path_segments(decl);
                    let fv = if segs[1] == "value" {
                        forged.clone()
                    } else {
                        placeholder_filter.clone()
                    };
                    (Some(fv), forged_value_for(decl))
                };
                match build_patch_request(decl, &universe, filter_value.as_ref(), new_value) {
                    PatchRequestPlan::Body(req) => {
                        let path = req["Operations"][0]["path"].as_str().unwrap();
                        assert_patch_targets_decl(decl, &universe, path);
                        checked_patch += 1;
                    }
                    PatchRequestPlan::Unavailable(reason) => {
                        panic!(
                            "unexpected Unavailable for {:?} with a placeholder filter \
                             supplied: {reason}",
                            decl.path
                        );
                    }
                }
            }

            (Characteristic::MutabilityImmutable, Method::PatchChange) => {
                let changed = forged_value_for(decl);
                match build_patch_request(decl, &universe, Some(&placeholder_filter), changed) {
                    PatchRequestPlan::Body(req) => {
                        let path = req["Operations"][0]["path"].as_str().unwrap();
                        assert_patch_targets_decl(decl, &universe, path);
                        checked_patch += 1;
                    }
                    PatchRequestPlan::Unavailable(reason) => {
                        panic!("unexpected Unavailable for {:?}: {reason}", decl.path);
                    }
                }
            }

            (Characteristic::Uniqueness, Method::PatchDuplicate)
            | (Characteristic::ReturnedNever, Method::Patch) => {
                // No declaration in this server's current schema drives
                // either of these into the imprecise-container case (see
                // the module doc on `build_patch_request` in
                // `matrix::exec`), but route through the exact same
                // builder anyway: if a future schema change ever does
                // trigger it, this invariant must catch it here rather
                // than shipping an unsound probe silently.
                let value = forged_value_for(decl);
                match build_patch_request(decl, &universe, Some(&placeholder_filter), value) {
                    PatchRequestPlan::Body(req) => {
                        let path = req["Operations"][0]["path"].as_str().unwrap();
                        assert_patch_targets_decl(decl, &universe, path);
                        checked_patch += 1;
                    }
                    PatchRequestPlan::Unavailable(reason) => {
                        panic!("unexpected Unavailable for {:?}: {reason}", decl.path);
                    }
                }
            }

            (Characteristic::MutabilityReadOnly, Method::Post | Method::Put) => {
                let forged = forged_value_for(decl);
                let companion = if decl.depth() > 1 && decl.last() != "value" {
                    Some(placeholder_filter.clone())
                } else {
                    None
                };
                let mut payload = make_baseline(decl.resource);
                set_attr_with_companion(&mut payload, decl, forged.clone(), companion);
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == forged,
                    "POST/PUT payload for {:?} does not place the forged value at its own \
                     JSON location: got present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::MutabilityImmutable, Method::PostCreate) => {
                let valid = valid_value_for(decl);
                let (payload, expected, _filter) = immutable_post_payload(
                    decl,
                    valid,
                    Some("11111111-1111-1111-1111-111111111111"),
                );
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == expected,
                    "PostCreate payload for {:?} does not place the value at its own JSON \
                     location: got present={ok} value={got:?}, expected {expected:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::MutabilityImmutable, Method::PutChange) => {
                // PUT-change is a full-resource replace, not a PATCH: the
                // client always sends the whole `decl.path` location
                // afresh (`set_attr`), so this is structurally identical
                // to the ReadOnly POST/PUT case, not to PATCH-change's
                // valuePath concern.
                let changed = forged_value_for(decl);
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, changed.clone());
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == changed,
                    "PutChange payload for {:?} does not place the value at its own JSON \
                     location: got present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::CaseExact, Method::Post) => {
                let mixed = json!("MiXeD-CaSe");
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, mixed.clone());
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == mixed,
                    "caseExact payload for {:?} mistargeted: present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::Uniqueness, Method::PostDuplicate | Method::PutDuplicate) => {
                let dup = json!("dup-value");
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, dup.clone());
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == dup,
                    "uniqueness payload for {:?} mistargeted: present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::ReturnedNever, Method::Post | Method::Put) => {
                let val = json!("S3cr3t!");
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, val.clone());
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == val,
                    "returned_never payload for {:?} mistargeted: present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::TypeWrong, Method::Post | Method::Put) => {
                let wrong = wrong_value_for(decl);
                let companion = if is_group_member_subattr(decl) && decl.last() != "value" {
                    Some(placeholder_filter.clone())
                } else {
                    None
                };
                let mut payload = make_baseline(decl.resource);
                set_attr_with_companion(&mut payload, decl, wrong.clone(), companion);
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == wrong,
                    "type_wrong payload for {:?} mistargeted: present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::TypeValid, Method::Post | Method::Put) => {
                // Top-level Complex attributes were routed to the
                // decomposition-exclusion arm above; everything reaching
                // here has a genuine scalar `decl.path` location.
                let valid = valid_value_for(decl);
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, valid.clone());
                let (ok, got) = get_attr(&payload, decl);
                assert!(
                    ok && got == valid,
                    "type_valid payload for {:?} mistargeted: present={ok} value={got:?}",
                    decl.path
                );
                checked_post_put += 1;
            }

            (Characteristic::Required, Method::PostOmit | Method::PutOmit) => {
                // Not a forged value but an omission: the invariant here
                // is that removing `decl.path` from the payload actually
                // makes `get_attr(decl)` report it absent -- proving the
                // omission targeted the declared attribute's own key, not
                // some other one. `cells_from_decls` only ever generates
                // this cell for depth==1 attributes (required sub-attribute
                // omission isn't separately probed), which is exactly what
                // `exec_required` removes via `payload.remove(&decl.path)`.
                assert_eq!(
                    decl.depth(),
                    1,
                    "required POST/PUT-omit cell for a depth>1 attribute would need its own \
                     omission targeting check -- none exists in this server's schema today"
                );
                let mut payload = make_baseline(decl.resource);
                set_attr(&mut payload, decl, json!("placeholder"));
                payload.as_object_mut().unwrap().remove(decl.path.as_str());
                let (ok, _) = get_attr(&payload, decl);
                assert!(
                    !ok,
                    "required omission for {:?} did not remove the declared attribute's own key",
                    decl.path
                );
                checked_post_put += 1;
            }

            other => panic!(
                "targeting invariant has no coverage for cell {other:?} on {:?} -- add it to a \
                 checked branch or the documented allowlist",
                decl.path
            ),
        }
    }

    eprintln!(
        "targeting invariant: {checked_patch} PATCH-family cells checked, {checked_post_put} \
         POST/PUT-family cells checked, {excluded_no_request} excluded (no request: NA/GET), \
         {excluded_decomposition} excluded (type_valid complex-container decomposition)"
    );
    assert_eq!(
        checked_patch + checked_post_put + excluded_no_request + excluded_decomposition,
        m.cells.len(),
        "every cell must be either checked or explicitly, documentedly excluded"
    );
}
