//! T13: runs `scim_conformance::etag::run_all` (RFC 7644 §3.14
//! Versioning Resources -- ETags/conditional requests) against this
//! repository's own server (`spawn_real_server(create_test_app_config())`).
//!
//! This server implements ETags end to end (`src/resource/user.rs`'s
//! `if_match_satisfied`/`if_none_match_satisfied` helpers, `meta.version`,
//! `ServiceProviderConfig`'s `etag.supported: true`), so most rows are
//! expected to PASS -- but every expectation below is a *measured* value
//! from this run, not an assumption; if a row measures anything other than
//! what's asserted, that's a new finding to report, not something to
//! quietly loosen the assertion to match.

use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::etag::run_all;
use scim_conformance::matrix::{Characteristic, Keyword, Method, Outcome, Verdict};
use tokio::sync::OnceCell;

mod common;

struct EtagRun {
    outcomes: Vec<Outcome>,
}

static ETAG_RUN: OnceCell<EtagRun> = OnceCell::const_new();

async fn etag_run() -> &'static EtagRun {
    ETAG_RUN
        .get_or_init(|| async {
            let cfg = common::create_test_app_config();
            let server = common::spawn_real_server(cfg).await;
            let mut client = ScimClient::new(ClientConfig {
                base_url: server.base_url.clone(),
                auth: Auth::None,
                timeout: Duration::from_secs(10),
            })
            .expect("client construction");

            let outcomes = run_all(&mut client).await;

            // Intentionally leaked -- same pattern as
            // tests/conformance_ledger_matrix.rs: every test in this file
            // needs the server alive for the process's whole lifetime.
            std::mem::forget(server);

            EtagRun { outcomes }
        })
        .await
}

/// Matches rows by (characteristic, method) plus an `attribute` *prefix* --
/// the three `{current,stale,*}` cases of one axis share a prefix
/// (`"If-Match"`/`"If-None-Match"`) but carry a distinct suffix
/// (`"=current"`/`"=stale"`/`"=*"`) so each case gets its own
/// `Finding::key` (see `crate::etag::Key::with_attribute`'s doc comment).
fn rows<'a>(
    outcomes: &'a [Outcome],
    characteristic: Characteristic,
    method: Method,
    attribute_prefix: &str,
) -> Vec<&'a Outcome> {
    outcomes
        .iter()
        .filter(|o| {
            o.characteristic == characteristic
                && o.method == method
                && o.attribute.starts_with(attribute_prefix)
        })
        .collect()
}

/// Exact-match version of `rows`, for the representation family's four
/// distinctly-named rows (`"ETag"`, `"meta.version"`, `"ETag==meta.version"`,
/// `"ETag.form"`) -- `rows`'s prefix match would wrongly fold
/// `"ETag==meta.version"`/`"ETag.form"` into a lookup for `"ETag"`.
fn one<'a>(
    outcomes: &'a [Outcome],
    characteristic: Characteristic,
    method: Method,
    attribute: &str,
) -> &'a Outcome {
    let mut found: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| {
            o.characteristic == characteristic && o.method == method && o.attribute == attribute
        })
        .collect();
    assert_eq!(
        found.len(),
        1,
        "expected exactly one {attribute:?}/{characteristic:?}/{method:?} row, found {}: {:#?}",
        found.len(),
        found
    );
    found.remove(0)
}

#[tokio::test]
async fn etag_family_produces_16_rows() {
    let run = etag_run().await;
    assert_eq!(
        run.outcomes.len(),
        16,
        "expected 16 generated rows (4 representation + 3 conditional-read + 3 PUT + 3 PATCH \
         + 3 DELETE), got: {:#?}",
        run.outcomes
    );
}

#[tokio::test]
async fn representation_header_must_be_present() {
    let run = etag_run().await;
    let o = one(
        &run.outcomes,
        Characteristic::EtagRepresentation,
        Method::Post,
        "ETag",
    );
    assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
    assert_eq!(o.keyword, Some(Keyword::Must));
}

#[tokio::test]
async fn representation_meta_version_is_should_and_present() {
    let run = etag_run().await;
    let o = one(
        &run.outcomes,
        Characteristic::EtagRepresentation,
        Method::Post,
        "meta.version",
    );
    assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
    assert_eq!(o.keyword, Some(Keyword::Should));
}

#[tokio::test]
async fn representation_etag_equals_meta_version() {
    let run = etag_run().await;
    let o = one(
        &run.outcomes,
        Characteristic::EtagRepresentation,
        Method::Post,
        "ETag==meta.version",
    );
    assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
    assert_eq!(o.keyword, Some(Keyword::Must));
}

#[tokio::test]
async fn representation_form_is_recorded_never_failed() {
    let run = etag_run().await;
    let o = one(
        &run.outcomes,
        Characteristic::EtagRepresentation,
        Method::Post,
        "ETag.form",
    );
    assert_ne!(o.verdict, Verdict::Fail, "{o:#?}");
    assert_eq!(o.keyword, Some(Keyword::May));
    // This server's version column is a plain integer rendered as
    // `W/"<n>"` (CLAUDE.md's ETag/versioning section) -- weak.
    assert_eq!(o.observed.as_deref(), Some("weak"), "{o:#?}");
}

#[tokio::test]
async fn conditional_read_current_stale_star() {
    let run = etag_run().await;
    let found = rows(
        &run.outcomes,
        Characteristic::EtagConditionalRead,
        Method::Get,
        "If-None-Match",
    );
    assert_eq!(found.len(), 3, "{found:#?}");
    for o in &found {
        assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
        assert_eq!(o.keyword, Some(Keyword::Must));
    }
}

#[tokio::test]
async fn conditional_write_put_current_stale_star() {
    let run = etag_run().await;
    let found = rows(
        &run.outcomes,
        Characteristic::EtagConditionalWrite,
        Method::Put,
        "If-Match",
    );
    assert_eq!(found.len(), 3, "{found:#?}");
    for o in &found {
        assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
        assert_eq!(o.keyword, Some(Keyword::Must));
    }
}

#[tokio::test]
async fn conditional_write_patch_current_stale_star() {
    let run = etag_run().await;
    let found = rows(
        &run.outcomes,
        Characteristic::EtagConditionalWrite,
        Method::Patch,
        "If-Match",
    );
    assert_eq!(found.len(), 3, "{found:#?}");
    for o in &found {
        assert_eq!(o.verdict, Verdict::Pass, "{o:#?}");
        assert_eq!(o.keyword, Some(Keyword::Must));
    }
}

#[tokio::test]
async fn conditional_delete_is_info_only_never_fail() {
    let run = etag_run().await;
    let found = rows(
        &run.outcomes,
        Characteristic::EtagConditionalWrite,
        Method::Delete,
        "If-Match",
    );
    assert_eq!(found.len(), 3, "{found:#?}");
    for o in &found {
        assert_ne!(
            o.verdict,
            Verdict::Fail,
            "DELETE x If-Match must never FAIL: {o:#?}"
        );
        assert_eq!(o.verdict, Verdict::Info, "{o:#?}");
        assert_eq!(o.keyword, Some(Keyword::May));
    }
}

#[tokio::test]
async fn every_row_cites_section_3_14_or_table_8() {
    let run = etag_run().await;
    for o in &run.outcomes {
        let cite = o.basis.to_string();
        let ok = cite.starts_with("RFC 7644 §3.14") || cite.starts_with("RFC 7644 §3.12");
        assert!(ok, "unexpected basis for {o:#?}: {cite}");
    }
}
