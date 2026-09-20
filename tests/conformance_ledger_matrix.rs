//! T10: runs the checks `crates/scim-conformance` generates from the RFC
//! 7644 §3.5.2 requirement ledger (`spec/ledger/rfc7644-3.5.2.yaml`,
//! `scim_conformance::ledger_suite`) against this repository's own server.
//!
//! This is the "does a ledger entry mechanically produce a runnable check"
//! experiment (plan §0 decision 6): p27 (projection) and p26 (status) used
//! to reproduce this server's own known non-conformances (V-18, V-19);
//! both were fixed in PR #72 and both are now regression guards asserting
//! PASS everywhere instead. p23 (sequence), p24 (conditional), and p25
//! (atomicity) are single cells this server was not previously known to
//! fail or pass, and are unaffected by #72.
//!
//! The ledger's own quote-verification test
//! (`crates/scim-conformance/src/ledger.rs`'s
//! `rfc7644_3_5_2_ledger_has_27_entries_and_verified_quotes`) is kept as a
//! crate unit test rather than duplicated here -- it needs no live server,
//! just the vendored RFC text and the ledger YAML, both baked in at compile
//! time via `include_str!`.

use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::ledger::load_rfc7644_3_5_2;
use scim_conformance::ledger_suite;
use scim_conformance::matrix::{Method, Outcome, Verdict};
use tokio::sync::OnceCell;

mod common;

/// The ledger-generated suite, run once against a real server and shared
/// across every `#[tokio::test]` in this file (each template creates its
/// own fixtures; running the whole suite 4 times would quadruple this
/// file's wall time for no reason).
struct LedgerRun {
    outcomes: Vec<Outcome>,
}

static LEDGER_RUN: OnceCell<LedgerRun> = OnceCell::const_new();

async fn ledger_run() -> &'static LedgerRun {
    LEDGER_RUN
        .get_or_init(|| async {
            let cfg = common::create_test_app_config();
            let server = common::spawn_real_server(cfg).await;
            let mut client = ScimClient::new(ClientConfig {
                base_url: server.base_url.clone(),
                auth: Auth::None,
                timeout: Duration::from_secs(10),
            })
            .expect("client construction");

            let outcomes = ledger_suite(&mut client).await;

            // Intentionally leaked -- see the identical comment in
            // tests/conformance_schema_matrix.rs: every test in this file
            // needs the server alive for the process's whole lifetime, and
            // `OnceCell` has no natural place to shut it down again.
            std::mem::forget(server);

            LedgerRun { outcomes }
        })
        .await
}

/// The `characteristic` enum's serialized name (`"ledger_p27_projection"`,
/// ...), the same way `tests/conformance_knob_mutation.rs` reads it.
fn characteristic_str(o: &Outcome) -> String {
    serde_json::to_value(o.characteristic)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string()
}

fn rows_for<'a>(outcomes: &'a [Outcome], characteristic: &str) -> Vec<&'a Outcome> {
    outcomes
        .iter()
        .filter(|o| characteristic_str(o) == characteristic)
        .collect()
}

/// Every ledger-generated outcome must cite its basis as
/// `RFC 7644 §3.5.2 L<a>-<b>`, with `[a, b]` inside the ledger's own
/// section span (`spec/ledger/rfc7644-3.5.2.yaml`'s top-level `lines`) --
/// the mechanical guarantee that a generated check's citation traces back
/// to the ledger entry it came from, not to a hand-typed line number.
#[tokio::test]
async fn every_ledger_outcome_cites_its_basis_within_the_section_span() {
    let run = ledger_run().await;
    let ledger = load_rfc7644_3_5_2();
    let (section_start, section_end) = ledger.lines;
    assert!(
        !run.outcomes.is_empty(),
        "ledger_suite produced no outcomes at all"
    );

    for o in &run.outcomes {
        let basis = o.basis.to_string();
        let prefix = "RFC 7644 §3.5.2 L";
        assert!(
            basis.starts_with(prefix),
            "basis {basis:?} does not start with {prefix:?} ({:?} {:?} {:?})",
            o.resource,
            o.characteristic,
            o.method
        );
        let range = &basis[prefix.len()..];
        let (a, b) = range
            .split_once('-')
            .unwrap_or_else(|| panic!("basis {basis:?} has no 'L<a>-<b>' range"));
        let a: u32 = a
            .parse()
            .unwrap_or_else(|_| panic!("bad start in {basis:?}"));
        let b: u32 = b.parse().unwrap_or_else(|_| panic!("bad end in {basis:?}"));
        assert!(
            a >= section_start && b <= section_end,
            "basis {basis:?} span [{a}, {b}] escapes the ledger's own section span [{section_start}, {section_end}]"
        );
    }
}

/// p27 (projection): 16 cells -- 12 POST/PUT/PATCH x {User, Group} x
/// {attributes, excludedAttributes}, plus 4 GET control cells. This *used*
/// to reproduce V-18 (every non-GET cell FAILed because POST/PUT/PATCH
/// ignored `attributes`/`excludedAttributes` entirely); PR #72 fixed it,
/// and against this rebase all 16 cells -- non-GET and the GET controls
/// alike -- measure PASS. Renamed from `projection_cells_reproduce_v18` to
/// reflect what it now asserts: projection is honoured on every
/// resource-returning method, not just GET.
#[tokio::test]
async fn projection_is_honoured_on_every_resource_returning_method() {
    let run = ledger_run().await;
    let cells = rows_for(&run.outcomes, "ledger_p27_projection");
    assert_eq!(
        cells.len(),
        16,
        "expected 16 projection cells, got {}",
        cells.len()
    );

    let non_get: Vec<&&Outcome> = cells.iter().filter(|o| o.method != Method::Get).collect();
    let get: Vec<&&Outcome> = cells.iter().filter(|o| o.method == Method::Get).collect();
    assert_eq!(non_get.len(), 12, "expected 12 non-GET cells");
    assert_eq!(get.len(), 4, "expected 4 GET control cells");

    for o in &non_get {
        assert_eq!(
            o.verdict,
            Verdict::Pass,
            "expected PASS for {:?} {:?} attribute={:?} (V-18 was fixed in #72 -- a FAIL here \
             is a regression): {}",
            o.resource,
            o.method,
            o.attribute,
            o.detail
        );
    }
    for o in &get {
        assert_eq!(
            o.verdict,
            Verdict::Pass,
            "expected PASS (GET control) for {:?} attribute={:?}: {}",
            o.resource,
            o.attribute,
            o.detail
        );
    }
}

/// p26 (status): 6 cells -- {POST, PUT, PATCH} x {User, Group} duplicate
/// creation/update. *Used* to reproduce V-19 (POST correctly rejected a
/// duplicate with `scimType: "uniqueness"`, while PUT and PATCH rejected
/// the same duplicate with `scimType: "invalidValue"` instead); PR #72
/// fixed it, and against this rebase all 6 cells reject the duplicate with
/// `scimType: "uniqueness"` regardless of method. Renamed from
/// `uniqueness_cells_reproduce_v19` to reflect that.
#[tokio::test]
async fn uniqueness_scim_type_is_uniform_across_methods() {
    let run = ledger_run().await;
    let cells = rows_for(&run.outcomes, "ledger_p26_status");
    assert_eq!(
        cells.len(),
        6,
        "expected 6 status/uniqueness cells, got {}",
        cells.len()
    );

    for o in &cells {
        match o.method {
            Method::PostDuplicate | Method::PutDuplicate | Method::PatchDuplicate => {
                assert_eq!(
                    o.verdict,
                    Verdict::Pass,
                    "expected {:?} duplicate ({:?}) to PASS (V-19 was fixed in #72 -- a FAIL \
                     here is a regression): {}",
                    o.method,
                    o.resource,
                    o.detail
                );
                let observed = o.observed.clone().unwrap_or_default();
                assert!(
                    observed.contains("scimType=uniqueness"),
                    "expected observed to contain \"scimType=uniqueness\" for {:?} {:?}, got {observed:?}",
                    o.resource,
                    o.method
                );
            }
            other => panic!("unexpected method {other:?} in status/uniqueness cells"),
        }
    }
}

/// p23 (sequence), p24 (conditional), p25 (atomicity): one cell each.
/// Every cell must produce a real verdict (PASS or FAIL, never ERROR/SKIP
/// -- an ERROR here is a bug in the check itself, not a finding about the
/// server). The ledger recorded p23/p24 as `verified-ok` and p25 as
/// `unverified`; manual probing during development (see each template's
/// module docs) found this server PASSes all three, so that is what's
/// asserted here. A FAIL on any of them would be a genuine new finding
/// about this server, not a check-authoring bug -- if this test starts
/// failing, treat the FAIL as data, not as something to loosen the
/// assertion around.
#[tokio::test]
async fn sequence_atomicity_conditional_run() {
    let run = ledger_run().await;
    let ids = [
        "ledger_p23_sequence",
        "ledger_p24_conditional",
        "ledger_p25_atomicity",
    ];

    let mut by_id = std::collections::HashMap::new();
    for id in ids {
        let matches = rows_for(&run.outcomes, id);
        assert_eq!(
            matches.len(),
            1,
            "expected exactly 1 cell for {id}, got {}",
            matches.len()
        );
        let o = matches[0];
        println!(
            "{id}: verdict={:?} observed={:?} detail={}",
            o.verdict, o.observed, o.detail
        );
        assert!(
            matches!(o.verdict, Verdict::Pass | Verdict::Fail),
            "{id} produced {:?} (expected PASS or FAIL, never ERROR/SKIP): {}",
            o.verdict,
            o.detail
        );
        by_id.insert(id, o);
    }

    assert_eq!(
        by_id["ledger_p23_sequence"].verdict,
        Verdict::Pass,
        "p23 (sequence): {}",
        by_id["ledger_p23_sequence"].detail
    );
    assert_eq!(
        by_id["ledger_p24_conditional"].verdict,
        Verdict::Pass,
        "p24 (conditional): {}",
        by_id["ledger_p24_conditional"].detail
    );
    assert_eq!(
        by_id["ledger_p25_atomicity"].verdict,
        Verdict::Pass,
        "p25 (atomicity): {}",
        by_id["ledger_p25_atomicity"].detail
    );
}
