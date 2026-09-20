//! T9: runs `scim_conformance::checks_from_attrdefs` (generated from
//! `tools/prototype/golden/attrdefs.json`, the required-member table
//! extracted from RFC 7643 §5/§6/§7 and RFC 7644 §3.4.2) against this
//! repository's own server.
//!
//! `crates/scim-conformance/src/gen/attrdefs.rs`'s own unit tests (basis
//! resolution for all 61 entries, the tri-state presence classifier on
//! hand-built fixtures) need no live server and stay there; this file only
//! covers what genuinely requires one: the verdict distribution this
//! server actually produces.

use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::{checks_from_attrdefs, AttrdefCheck, Verdict};
use tokio::sync::OnceCell;

mod common;

static CHECKS: OnceCell<Vec<AttrdefCheck>> = OnceCell::const_new();

async fn checks() -> &'static Vec<AttrdefCheck> {
    CHECKS
        .get_or_init(|| async {
            let cfg = common::create_test_app_config();
            let server = common::spawn_real_server(cfg).await;
            let mut client = ScimClient::new(ClientConfig {
                base_url: server.base_url.clone(),
                auth: Auth::None,
                timeout: Duration::from_secs(10),
            })
            .expect("client construction");

            let checks = checks_from_attrdefs(&mut client).await;

            // Intentionally leaked -- see the identical comment in
            // tests/conformance_ledger_matrix.rs: this test needs the
            // server alive for the process's whole lifetime.
            std::mem::forget(server);

            checks
        })
        .await
}

/// 38 of the golden fixture's 61 entries name a `(rfc, section)` this
/// module has a `TARGETS` mapping for; the other 23 describe attributes of
/// resources this module doesn't check (RFC 7643 §2.2's general
/// characteristics text and §4.*'s User-schema entries) and produce no
/// check at all.
#[tokio::test]
async fn produces_exactly_the_targets_matched_checks() {
    let checks = checks().await;
    assert_eq!(
        checks.len(),
        38,
        "expected 38 checks (one per TARGETS-matched golden entry), got {}: {:#?}",
        checks.len(),
        checks.iter().map(|c| &c.attribute).collect::<Vec<_>>()
    );
}

/// Every check must cite a basis whose document/section matches its own
/// `rfc_section` label -- the mechanical guarantee that a generated
/// check's citation traces back to a real definition site in the vendored
/// RFC text, not a hand-typed line number.
#[tokio::test]
async fn every_check_cites_a_basis_matching_its_own_rfc_section() {
    let checks = checks().await;
    assert!(!checks.is_empty());
    for c in checks {
        let expected_doc = if c.rfc_section.starts_with("RFC 7643") {
            "RFC 7643"
        } else if c.rfc_section.starts_with("RFC 7644") {
            "RFC 7644"
        } else {
            panic!("unexpected rfc_section {:?}", c.rfc_section)
        };
        assert_eq!(
            c.basis.doc, expected_doc,
            "attribute {:?}: rfc_section {:?} but basis.doc {:?}",
            c.attribute, c.rfc_section, c.basis.doc
        );
    }
}

/// The verdict distribution this server actually produces. The plan this
/// task implements records an earlier prototype run's distribution as
/// PASS 26 / SKIP 3 / INFO 9 / FAIL 0; this test asserts whatever this
/// server's current behavior actually is and documents any difference
/// in the comment below rather than silently forcing a match.
#[tokio::test]
async fn verdict_distribution() {
    let checks = checks().await;

    let mut pass = 0usize;
    let mut skip = 0usize;
    let mut info = 0usize;
    let mut fail = 0usize;
    let mut error = 0usize;
    for c in checks {
        match c.verdict {
            Verdict::Pass => pass += 1,
            Verdict::Skip => skip += 1,
            Verdict::Info => info += 1,
            Verdict::Fail => fail += 1,
            Verdict::Error => error += 1,
        }
    }
    println!("PASS {pass} / SKIP {skip} / INFO {info} / FAIL {fail} / ERROR {error}");
    for c in checks {
        println!(
            "{:<6} {:<40} {:<26} {}",
            c.verdict.tag(),
            c.attribute,
            c.rfc_section,
            c.detail
        );
    }

    assert_eq!(error, 0, "no check should ERROR against this server");
    // Matches the plan's expected distribution (PASS 26 / SKIP 3 / INFO 9
    // / FAIL 0) exactly: the 3 SKIPs are RFC 7644 §3.4.2's 3 conditional
    // envelope fields (Resources/startIndex/itemsPerPage, "REQUIRED if ..."
    // -- always SKIP regardless of server state), the 9 INFOs are the
    // fixture's 9 OPTIONAL (non-conditional) entries (never judged), and
    // the remaining 26 REQUIRED, non-conditional entries all PASS on this
    // server today.
    assert_eq!(pass, 26, "PASS count changed");
    assert_eq!(skip, 3, "SKIP count changed");
    assert_eq!(info, 9, "INFO count changed");
    assert_eq!(fail, 0, "FAIL count changed");
}
