//! T11: exercises `scim_conformance::run` (the same entry point
//! `scim-server diagnose` calls) directly against this repository's own
//! server -- no subprocess, no CLI binary involved -- and checks the
//! result has the shape the plan's acceptance line promises: a non-empty
//! report where every finding carries a real RFC 7643/7644 citation,
//! `--read-only` only ever reaches the server through GET, and (post PR
//! #72, and post the PATCH-readOnly probe fix in PR #73) the FAIL set is
//! empty.

use scim_conformance::{Auth, DiagOptions, Verdict};
use tokio::sync::OnceCell;

mod common;

/// A `DiagOptions` pointed at `base_url` with every optional knob at its
/// default (no auth, 10s timeout, not read-only).
fn opts(base_url: &str, read_only: bool) -> DiagOptions {
    DiagOptions {
        base_url: base_url.to_string(),
        auth: Auth::None,
        headers: Vec::new(),
        insecure: false,
        ca_certs: Vec::new(),
        native_roots: false,
        timeout_secs: 10,
        read_only,
    }
}

/// The full (non-read-only) report, run once and shared across every test
/// in this file -- `scim_conformance::run` writes real resources via the
/// schema matrix/probes/ledger suite, so running it once keeps this file's
/// wall time bounded (same rationale as `conformance_schema_matrix.rs`'s
/// `MatrixRun`).
static REPORT: OnceCell<(String, scim_conformance::DiagnosticReport)> = OnceCell::const_new();

async fn report() -> &'static scim_conformance::DiagnosticReport {
    &REPORT
        .get_or_init(|| async {
            let cfg = common::create_test_app_config();
            let server = common::spawn_real_server(cfg).await;
            let base_url = server.base_url.clone();

            let report = scim_conformance::run(&opts(&base_url, false))
                .await
                .expect("diagnose must succeed against this server");

            // Intentionally leaked -- see the identical comment in
            // tests/conformance_schema_matrix.rs: every test in this file
            // needs the server alive for the process's whole lifetime.
            std::mem::forget(server);

            (base_url, report)
        })
        .await
        .1
}

#[tokio::test]
async fn report_is_non_empty() {
    let r = report().await;
    assert!(
        !r.findings.is_empty(),
        "diagnose against a live server produced no findings at all"
    );
    assert_eq!(r.counts.total(), r.findings.len());
}

#[tokio::test]
async fn every_finding_cites_rfc_7643_or_7644() {
    let r = report().await;
    let mut bad = Vec::new();
    for f in &r.findings {
        let rendered = f.basis.to_string();
        if !(rendered.starts_with("RFC 7643") || rendered.starts_with("RFC 7644")) {
            bad.push(format!("{} -> {rendered:?}", f.key));
        }
        for sec in &f.secondary {
            let rendered = sec.to_string();
            if !(rendered.starts_with("RFC 7643") || rendered.starts_with("RFC 7644")) {
                bad.push(format!("{} (secondary) -> {rendered:?}", f.key));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "findings whose basis does not cite RFC 7643/7644:\n{}",
        bad.join("\n")
    );
}

/// Classifies a FAIL finding's `key` (`"{Resource}.{attribute}/
/// {characteristic}/{method}"`, see `scim_conformance::report::Finding`)
/// as one of the five known non-conformances this generator already found
/// in this server (`tests/conformance_schema_matrix.rs`'s
/// `classify_known_fail`, adapted here to work off `Finding::key` instead
/// of `Outcome`'s separate fields -- `Finding` is deliberately flatter
/// than `Outcome` and doesn't keep them apart, see
/// `crates/scim-conformance/src/report.rs`).
fn classify_known_fail(key: &str) -> Option<&'static str> {
    let (resource_attr, rest) = key.split_once('/')?;
    let (characteristic, method) = rest.split_once('/')?;
    let (resource, attr) = resource_attr.split_once('.')?;

    // V-25: PATCH targeting a readOnly attribute is silently ignored
    // instead of rejected -- takes precedence over V-21 for PATCH cells
    // that also happen to echo the forged value.
    if characteristic == "mutability_readOnly" && method == "PATCH" {
        return Some("V-25");
    }
    match (resource, characteristic, attr, method) {
        ("EnterpriseUser", "mutability_readOnly", "manager.$ref", "POST" | "PUT") => Some("V-21"),
        ("EnterpriseUser", "mutability_readOnly", "manager.displayName", "POST" | "PUT") => {
            Some("V-21")
        }
        ("Group", "required", "displayName", "PUT-omit") => Some("V-22"),
        ("Group", "type_wrong", "externalId", "POST" | "PUT") => Some("V-23"),
        ("Group", "type_wrong", a, "POST" | "PUT")
            if a == "members" || a.starts_with("members.") =>
        {
            Some("V-23")
        }
        ("User", "type_wrong", a, "POST" | "PUT") if a.starts_with("addresses.") => Some("V-23"),
        ("User", "mutability_readOnly", a, "POST")
            if a == "groups.value" || a == "groups.$ref" || a == "groups.display" =>
        {
            Some("V-24")
        }
        _ => None,
    }
}

/// PR #72 fixed all five of V-21..V-25, so against this rebase the report
/// should have no FAILs at all. It used to be reported here with a
/// "genuine, narrow residual" on `Group.members.display`: PATCH against
/// that readOnly sub-attribute of the top-level multi-valued `members`
/// complex appeared to be silently ignored instead of rejected. That was a
/// false positive in the *probe*, not a server gap -- the coarse,
/// container-level `path: "members"` request the old probe sent for this
/// cell shape (no per-element filter target during a forge) replaced the
/// whole (ReadWrite) `members` array with a structurally invalid element,
/// which is not a probe of `display`'s mutability at all. PR #73 fixed the
/// probe to target the sub-attribute precisely with a value filter
/// (`members[value eq "<id>"].display`); the server correctly rejects that
/// with 400 `scimType: mutability` (see
/// `tests/conformance_schema_matrix.rs`'s
/// `patch_mutability_readonly_fails_are_zero` for the measurement).
/// Renamed from `fail_set_is_confined_to_the_known_v25_residual` to
/// reflect what's now asserted: the FAIL set is empty.
#[tokio::test]
async fn fail_set_is_empty() {
    let r = report().await;
    let fails: Vec<&scim_conformance::Finding> = r
        .findings
        .iter()
        .filter(|f| matches!(f.verdict, Verdict::Fail))
        .collect();

    let report_lines: Vec<String> = fails
        .iter()
        .map(|f| {
            format!(
                "{} verdict={:?} label={:?} detail={}",
                f.key,
                f.verdict,
                classify_known_fail(&f.key),
                f.detail
            )
        })
        .collect();
    eprintln!(
        "FAILs (key, verdict, label, detail):\n{}",
        report_lines.join("\n")
    );

    assert_eq!(
        fails.len(),
        0,
        "expected 0 FAILs (PR #72 fixed every server-side non-conformance V-21..V-25 covered, \
         and the apparent Group.members.display/mutability_readOnly/PATCH residual was a false \
         positive in the probe itself, since corrected in PR #73 -- see this test's doc \
         comment); got {}:\n{}",
        fails.len(),
        report_lines.join("\n")
    );
}

#[tokio::test]
async fn read_only_runs_only_the_get_only_discovery_family() {
    let cfg = common::create_test_app_config();
    let server = common::spawn_real_server(cfg).await;
    let base_url = server.base_url.clone();

    let ro_report = scim_conformance::run(&opts(&base_url, true))
        .await
        .expect("read-only diagnose must succeed");

    server.shutdown().await;

    assert!(
        !ro_report.findings.is_empty(),
        "read-only report must still contain the discovery family's findings"
    );

    // Coarse, family-level read-only (see `DiagOptions::read_only`'s doc
    // comment): the schema-driven matrix, the protocol probes, and the
    // ledger-generated checks -- the only families that ever send a
    // POST/PUT/PATCH/DELETE -- must be entirely absent. Only "discovery"
    // (`checks_from_attrdefs`, GET-only end to end) may appear.
    let non_discovery: Vec<&str> = ro_report
        .findings
        .iter()
        .map(|f| f.family)
        .filter(|f| *f != "discovery")
        .collect();
    assert!(
        non_discovery.is_empty(),
        "read-only report must contain only \"discovery\" findings, got families: {non_discovery:?}"
    );

    // Pinned to `conformance_attrdefs.rs`'s own verdict distribution
    // (PASS 26 / SKIP 3 / INFO 9 / FAIL 0, 38 checks total) -- makes this
    // test bite if `checks_from_attrdefs`'s output ever changes shape,
    // not just if a write-family finding leaks in.
    assert_eq!(ro_report.findings.len(), 38);
    assert_eq!(ro_report.counts.fail, 0);
    assert_eq!(ro_report.counts.error, 0);
}
