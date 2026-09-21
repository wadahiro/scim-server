//! T12: the scoreboard's three honesty-about-scope numbers, computed
//! against this repository's own server.
//!
//! `req_coverage`'s denominator is pinned at 147 -- see
//! `crate::scoreboard`'s module doc comment for the exact filter (RFC 7644
//! §3.x paragraphs classified `definitional`/`definitional_prose` by
//! `crate::spec_extract`, a Rust port of `tools/prototype/extract.py`'s
//! classification) and the command that produced it by hand this session.
//! Running `extract.py` is deterministic, so pinning the exact number here
//! (rather than just asserting "some positive number") is safe.

use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::matrix::cells_from_decls;
use scim_conformance::schema::decls_from_schemas;
use scim_conformance::scoreboard;

mod common;

async fn spawned_client() -> (common::TestServerHandle, ScimClient) {
    let cfg = common::create_test_app_config();
    let server = common::spawn_real_server(cfg).await;
    let client = ScimClient::new(ClientConfig {
        base_url: server.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("client construction");
    (server, client)
}

#[tokio::test]
async fn req_coverage_denominator_is_the_documented_147() {
    // Pure, no server needed -- exercises the same function `compute` uses.
    assert_eq!(
        scoreboard::requirement_inventory().len(),
        147,
        "RFC 7644 §3.x definitional/definitional_prose paragraph count per \
         crate::spec_extract; see scoreboard.rs's module doc comment for the \
         extract.py command that produced this by hand"
    );
}

#[tokio::test]
async fn scoreboard_numbers_are_internally_consistent_and_guards_hold() {
    let (server, mut client) = spawned_client().await;

    let sb = scoreboard::compute(&mut client).await;

    // Transparency check (see scoreboard.rs's module doc comment,
    // "req_coverage"): most citations across the whole generated-check
    // suite are RFC 7643 (schema characteristics) or outside §3, so most of
    // them fall outside this specific RFC-7644-§3 denominator's scope.
    // Printed, not asserted on a specific number, since it isn't part of
    // the `Scoreboard` struct's contract -- just documented here so the
    // fraction is visible.
    {
        let outcomes = scim_conformance::full_suite(&mut client)
            .await
            .expect("full_suite");
        let attrdef_checks = scim_conformance::checks_from_attrdefs(&mut client).await;
        let rc = scoreboard::req_coverage(&outcomes, &attrdef_checks);
        println!(
            "req_coverage citation scope: {}/{} citations were RFC 7644 §3.x (in scope); \
             {} fell outside scope (RFC 7643, or RFC 7644 outside §3)",
            rc.in_scope_citations,
            rc.total_citations,
            rc.total_citations - rc.in_scope_citations
        );
    }

    // req_coverage
    assert_eq!(
        sb.req_coverage.1, 147,
        "denominator must match crate::scoreboard::requirement_inventory()"
    );
    assert!(
        sb.req_coverage.0 <= sb.req_coverage.1,
        "covered ({}) must not exceed total ({})",
        sb.req_coverage.0,
        sb.req_coverage.1
    );
    println!(
        "req_coverage: {}/{} (RFC 7644 §3, definitional|definitional_prose)",
        sb.req_coverage.0, sb.req_coverage.1
    );

    // cell_completeness
    assert!(
        sb.cell_completeness.0 <= sb.cell_completeness.1,
        "generated ({}) must not exceed derivable ({})",
        sb.cell_completeness.0,
        sb.cell_completeness.1
    );
    // Cross-check against the live server's own /Schemas, independent of
    // whatever `compute` fetched internally -- this is `tests/
    // conformance_schema_matrix.rs`'s own pinned CELL_COUNT (389).
    let schemas_resp = client.get("/Schemas").await.expect("GET /Schemas");
    let decls = decls_from_schemas(&schemas_resp.body.expect("body"));
    let expected_actual = cells_from_decls(&decls).len();
    assert_eq!(
        sb.cell_completeness.0, expected_actual,
        "cell_completeness.0 must equal cells_from_decls(decls).len()"
    );
    println!(
        "cell_completeness: {}/{}",
        sb.cell_completeness.0, sb.cell_completeness.1
    );

    // knob_detection: live-measured -- the 7 compatibility knobs, every one
    // must appear and (per tests/conformance_knob_mutation.rs) must be
    // caught. A `false` here is a regression signal.
    let expected_knob_labels = [
        "knob:meta_datetime_format",
        "knob:show_empty_groups_members",
        "knob:include_user_groups",
        "knob:support_patch_replace_empty_array",
        "knob:support_patch_replace_empty_value",
        "knob:support_group_members_filter",
        "knob:support_group_displayname_filter",
    ];
    assert_eq!(
        sb.knob_detection.len(),
        expected_knob_labels.len(),
        "unexpected number of knob_detection rows: {:#?}",
        sb.knob_detection
    );
    for label in expected_knob_labels {
        let row = sb
            .knob_detection
            .iter()
            .find(|(l, _)| l == label)
            .unwrap_or_else(|| {
                panic!(
                    "knob_detection row {label:?} missing: {:#?}",
                    sb.knob_detection
                )
            });
        assert!(
            row.1,
            "knob_detection row {label:?} expected caught=true, got false -- this is a \
             regression against a known-present, live-detectable behavior"
        );
    }
    println!("knob_detection: {:#?}", sb.knob_detection);

    // regression_guards: V-18, V-19, V-21..V-25 were all fixed in PR #72.
    // Every one must appear and every one must measure 0 fails (the fix
    // holding). V-25 used to be reported here with a known "residual" of
    // 1/18 (Group.members.display/mutability_readOnly/PATCH) -- that was a
    // false positive in the PATCH-readOnly probe itself (it sent a coarse
    // container-level request that never actually exercised that
    // sub-attribute's mutability), corrected in PR #73; see
    // tests/conformance_schema_matrix.rs's
    // patch_mutability_readonly_fails_are_zero for the measurement. A
    // `fails != 0` on any guard, including V-25, is now a regression to
    // investigate, not a literal to update blindly.
    let expected_guard_labels = ["V-18", "V-19", "V-21", "V-22", "V-23", "V-24", "V-25"];
    assert_eq!(
        sb.regression_guards.len(),
        expected_guard_labels.len(),
        "unexpected number of regression_guards rows: {:#?}",
        sb.regression_guards
    );
    for label in expected_guard_labels {
        let g = sb
            .regression_guards
            .iter()
            .find(|g| g.label == label)
            .unwrap_or_else(|| {
                panic!(
                    "regression_guards row {label:?} missing: {:#?}",
                    sb.regression_guards
                )
            });
        assert!(
            g.relevant > 0,
            "regression_guards row {label:?} has no relevant cells at all -- the finding is no \
             longer measurable, which is itself worth investigating: {g:?}"
        );
        assert_eq!(
            g.fails, 0,
            "regression_guards row {label:?} expected 0 fails (fixed in #72), got {} of \
             {} -- this is a regression",
            g.fails, g.relevant
        );
    }
    println!("regression_guards: {:#?}", sb.regression_guards);

    server.shutdown().await;
}
