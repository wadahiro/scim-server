mod common;

use clap::Parser;
use common::{create_test_app_config, spawn_real_server};
use scim_server::cli::{Cli, Command};
use scim_server::config::{AppConfig, CompatibilityConfig};
use scim_server::diag::cli::{into_options, AuthKind, DiagOptions, Format, ProbeAttr};
use scim_server::diag::model::{KnobValue, Report, Verdict};

/// Read-only opts (no `--probe-email`) — used by the tier2-readonly test,
/// which is specifically about nothing being written.
fn test_opts(base_url: &str) -> DiagOptions {
    DiagOptions {
        base_url: base_url.to_string(),
        auth: AuthKind::None,
        token: None,
        username: None,
        password: None,
        headers: vec![],
        ca_certs: vec![],
        native_roots: false,
        insecure: false,
        read_only: true,
        dry_run: false,
        prefix: "scimdiag-test".to_string(),
        probe_email: None,
        allow_consumer_email: false,
        probe_attribute: ProbeAttr::PhoneNumbers,
        cleanup_only: false,
        only: vec![],
        skip: vec![],
        format: Format::Text,
        output: None,
        emit_config_snippet: false,
        verbose: 0,
        quiet: true,
        timeout: 30,
        deadline: 60,
    }
}

/// Write-mode opts with a valid, RFC-6761-reserved (`example.test`)
/// `--probe-email` template — used by every test that exercises the
/// fixture-provisioning / write-check paths.
fn write_opts(base_url: &str, prefix: &str) -> DiagOptions {
    DiagOptions {
        base_url: base_url.to_string(),
        auth: AuthKind::None,
        token: None,
        username: None,
        password: None,
        headers: vec![],
        ca_certs: vec![],
        native_roots: false,
        insecure: false,
        read_only: false,
        dry_run: false,
        prefix: prefix.to_string(),
        probe_email: Some("{prefix}+{n}@example.test".to_string()),
        allow_consumer_email: false,
        probe_attribute: ProbeAttr::PhoneNumbers,
        cleanup_only: false,
        only: vec![],
        skip: vec![],
        format: Format::Text,
        output: None,
        emit_config_snippet: false,
        verbose: 0,
        quiet: true,
        timeout: 30,
        deadline: 120,
    }
}

/// Sets `compatibility` on *both* the global config and every tenant — the
/// only way to reliably control the effective compatibility this server's
/// oracle-mode diagnose run observes, because `get_effective_compatibility`
/// (`config.rs:732`) replaces the whole struct rather than merging fields:
/// a tenant block with only one field set would silently reset the other
/// six to their defaults (bug (d), tracked separately) and this test would
/// then be asserting a config it doesn't actually have.
fn config_with_compat(c: CompatibilityConfig) -> AppConfig {
    let mut cfg = create_test_app_config();
    cfg.compatibility = c.clone();
    for t in &mut cfg.tenants {
        t.compatibility = Some(c.clone());
    }
    cfg
}

/// Asserts all 7 `CompatibilityConfig` knobs the report detected match
/// `expect`. Every assertion names its knob in the failure message so a
/// failure doesn't require cross-referencing `detected_knobs()`'s order.
fn assert_knobs_match(report: &Report, expect: &CompatibilityConfig) {
    let got: std::collections::HashMap<&'static str, KnobValue> =
        report.detected_knobs().into_iter().collect();

    assert_eq!(
        got.get("meta_datetime_format"),
        Some(&KnobValue::Str(expect.meta_datetime_format.clone())),
        "meta_datetime_format: got {:?}",
        got.get("meta_datetime_format")
    );
    assert_eq!(
        got.get("show_empty_groups_members"),
        Some(&KnobValue::Bool(expect.show_empty_groups_members)),
        "show_empty_groups_members: got {:?}",
        got.get("show_empty_groups_members")
    );
    assert_eq!(
        got.get("include_user_groups"),
        Some(&KnobValue::Bool(expect.include_user_groups)),
        "include_user_groups: got {:?}",
        got.get("include_user_groups")
    );
    assert_eq!(
        got.get("support_group_members_filter"),
        Some(&KnobValue::Bool(expect.support_group_members_filter)),
        "support_group_members_filter: got {:?}",
        got.get("support_group_members_filter")
    );
    assert_eq!(
        got.get("support_group_displayname_filter"),
        Some(&KnobValue::Bool(expect.support_group_displayname_filter)),
        "support_group_displayname_filter: got {:?}",
        got.get("support_group_displayname_filter")
    );
    assert_eq!(
        got.get("support_patch_replace_empty_array"),
        Some(&KnobValue::Bool(expect.support_patch_replace_empty_array)),
        "support_patch_replace_empty_array: got {:?}",
        got.get("support_patch_replace_empty_array")
    );
    assert_eq!(
        got.get("support_patch_replace_empty_value"),
        Some(&KnobValue::Bool(expect.support_patch_replace_empty_value)),
        "support_patch_replace_empty_value: got {:?}",
        got.get("support_patch_replace_empty_value")
    );
}

fn verdict_tag(v: &Verdict) -> &'static str {
    v.tag()
}

/// Container-contract regression guard: the Dockerfile `CMD` and
/// docker-compose `command` arrays must keep parsing as bare `serve`
/// invocations (`command: None`), never as an attempt to invoke the
/// `diagnose` subcommand. Pure clap assertions, no I/O.
#[test]
fn cli_backward_compat() {
    let cli = Cli::try_parse_from([
        "scim-server",
        "-c",
        "x.yaml",
        "--port",
        "8080",
        "--host",
        "0.0.0.0",
    ])
    .unwrap();
    assert!(cli.command.is_none());
    assert_eq!(cli.serve.config.as_deref(), Some("x.yaml"));
    assert_eq!(cli.serve.port, Some(8080));
    assert_eq!(cli.serve.host.as_deref(), Some("0.0.0.0"));

    // Dockerfile:40 CMD ["--host", "0.0.0.0"]
    let cli = Cli::try_parse_from(["scim-server", "--host", "0.0.0.0"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(cli.serve.host.as_deref(), Some("0.0.0.0"));

    // docker-compose.yml:8 command: ["--config", "/data/config.yaml"]
    let cli = Cli::try_parse_from(["scim-server", "--config", "/data/config.yaml"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(cli.serve.config.as_deref(), Some("/data/config.yaml"));

    // The `diagnose` subcommand still parses on its own.
    let cli = Cli::try_parse_from([
        "scim-server",
        "diagnose",
        "https://api.example.com/scim/v2",
        "--read-only",
    ])
    .unwrap();
    assert!(matches!(cli.command, Some(Command::Diagnose(_))));

    // The explicit `serve` subcommand form also still works.
    let cli = Cli::try_parse_from(["scim-server", "serve", "--port", "9000"]).unwrap();
    match cli.command {
        Some(Command::Serve(a)) => assert_eq!(a.port, Some(9000)),
        other => panic!("expected Some(Command::Serve(_)), got {other:?}"),
    }
}

/// Runs the read-only Tier 2 checks PR2 implements against this server
/// itself (via a real HTTP listener, `--read-only`, no auth) and asserts
/// on the actual, verified outcome of each — not a blanket "everything
/// passes".
///
/// This server used to have three genuine, self-diagnosed RFC 7644
/// non-conformances here — `rfc.response_content_type` and `rfc.404_shape`
/// FAILed, and `rfc.error_status_is_string` SKIPped as a consequence (its
/// `status` field didn't exist because the 404 body wasn't Error-shaped at
/// all). All three are now fixed:
///
///   * `rfc.response_content_type`: SCIM routes now serve
///     `Content-Type: application/scim+json; charset=utf-8` via
///     `scim_content_type_middleware` (`src/extractors.rs`), layered onto
///     the SCIM router only in `app::build_router` — custom endpoints keep
///     their configured `content_type` untouched.
///   * `rfc.404_shape` / `rfc.error_status_is_string`: every ad hoc
///     `{"message": ...}` error body in `src/resource/user.rs`,
///     `src/resource/group.rs`, and `src/auth.rs` now goes through
///     `scim_error_response` (`src/error.rs`), which emits the SCIM Error
///     resource shape with `status` as a JSON string.
///
/// PR4 (Tier 3/4) surfaced one more genuine non-conformance, now fixed too:
///
///   * `spc.wellformed`: `service_provider.rs::service_provider_config` used
///     to never set a `schemas` member on `ServiceProviderConfig` at all
///     (`scim_v2::ServiceProviderConfig` has no `schemas` field). It now
///     serializes to a `serde_json::Value` and injects the
///     `ServiceProviderConfig` URN, the same way `rfc.404_shape`'s Error
///     shape is produced.
#[tokio::test]
async fn diagnose_self_tier2_readonly() {
    let cfg = create_test_app_config();
    let srv = spawn_real_server(cfg).await;

    let report = scim_server::diag::run(&test_opts(&srv.base_url))
        .await
        .expect("diagnose run should complete");

    let by_id: std::collections::HashMap<&str, &Verdict> =
        report.outcomes.iter().map(|o| (o.id, &o.verdict)).collect();

    // preflight
    assert_eq!(
        verdict_tag(by_id["rfc.connect"]),
        "OK",
        "rfc.connect: {:?}",
        by_id["rfc.connect"]
    );
    assert_eq!(
        verdict_tag(by_id["rfc.auth"]),
        "OK",
        "rfc.auth: {:?}",
        by_id["rfc.auth"]
    );

    // genuinely RFC-conformant on this server
    for id in [
        "rfc.schemas_endpoint",
        "rfc.resource_types",
        "rfc.list_envelope",
    ] {
        assert_eq!(verdict_tag(by_id[id]), "OK", "{id}: {:?}", by_id[id]);
    }

    // Previously genuine non-conformances (see the doc comment above) —
    // now fixed, and asserted OK rather than silently dropped, so a
    // regression shows up here.
    assert_eq!(
        verdict_tag(by_id["rfc.response_content_type"]),
        "OK",
        "rfc.response_content_type: {:?}",
        by_id["rfc.response_content_type"]
    );
    assert_eq!(
        verdict_tag(by_id["rfc.404_shape"]),
        "OK",
        "rfc.404_shape: {:?}",
        by_id["rfc.404_shape"]
    );
    assert_eq!(
        verdict_tag(by_id["rfc.error_status_is_string"]),
        "OK",
        "rfc.error_status_is_string: {:?}",
        by_id["rfc.error_status_is_string"]
    );

    // `compat.meta_datetime_format` has `needs: &[]` (it must keep working
    // read-only), so it actually runs here — but there is no fixture and
    // no other data in this fresh in-memory DB to fall back to, so it
    // Skips rather than Fails.
    assert_eq!(
        verdict_tag(by_id["compat.meta_datetime_format"]),
        "SKIP",
        "compat.meta_datetime_format: {:?}",
        by_id["compat.meta_datetime_format"]
    );

    // Three Tier 3 checks also have `needs: &[]` (they only read
    // `ctx.spc`/`ctx.opts`, no fixtures) and so actually run read-only too.
    //
    // `spc.wellformed` is now genuinely OK (see the doc comment above):
    // ServiceProviderConfig carries its `schemas` member.
    assert_eq!(
        verdict_tag(by_id["spc.wellformed"]),
        "OK",
        "spc.wellformed: {:?}",
        by_id["spc.wellformed"]
    );
    // filter.maxResults=1000 and there are no probe fixtures in this fresh
    // DB, so `GET /Users?count=1001` trivially clamps (there's nothing to
    // clamp) and this Passes.
    assert_eq!(
        verdict_tag(by_id["spc.filter_max_results"]),
        "OK",
        "spc.filter_max_results: {:?}",
        by_id["spc.filter_max_results"]
    );
    // `--auth none` against the `unauthenticated` tenant, whose advertised
    // authenticationSchemes[0].type is "none".
    assert_eq!(
        verdict_tag(by_id["spc.auth_schemes_match"]),
        "OK",
        "spc.auth_schemes_match: {:?}",
        by_id["spc.auth_schemes_match"]
    );

    // Every other catalog entry needs write mode (or an upstream observation
    // write mode would have produced) and is Skipped under `--read-only`.
    for (id, verdict) in &by_id {
        if [
            "rfc.connect",
            "rfc.auth",
            "rfc.schemas_endpoint",
            "rfc.resource_types",
            "rfc.list_envelope",
            "rfc.404_shape",
            "rfc.error_status_is_string",
            "rfc.response_content_type",
            "compat.meta_datetime_format",
            "spc.wellformed",
            "spc.filter_max_results",
            "spc.auth_schemes_match",
        ]
        .contains(id)
        {
            continue;
        }
        assert_eq!(
            verdict_tag(verdict),
            "SKIP",
            "{id} should Skip under --read-only: {verdict:?}"
        );
    }

    // every catalog entry appears exactly once, nothing silently dropped:
    // 2 preflight (rfc.connect/rfc.auth) + 52 catalog entries (6 PR2
    // read-only + 8 Tier1 + 16 Tier2-write + 9 Tier3 + 1
    // rfc.password_never_returned + 12 Tier4, per the design note's §5.9
    // ordering table for the complete catalog).
    assert_eq!(report.outcomes.len(), 54, "outcomes: {:?}", by_id.keys());

    // Nothing in this run Fails anymore (SKIP/QUIRK never drive exit_code()
    // non-zero either).
    assert_eq!(report.counts().fail, 0, "counts: {:?}", report.counts());
    assert_eq!(report.exit_code(), 0);

    srv.shutdown().await;
}

/// Oracle test #1: every knob at scim-server's own default should be
/// detected as such (`OK`, not `QUIRK`) when diagnose is pointed at this
/// server configured with `CompatibilityConfig::default()`.
///
/// Only the 7 Tier 1 knobs are asserted — Tier 2/3/4 verdicts are covered by
/// `diagnose_self_tier2_readonly` and the ETag/`*`-precondition tests in
/// `tests/etag_version_test.rs` instead.
#[tokio::test]
async fn diagnose_detects_all_defaults() {
    let cfg = config_with_compat(CompatibilityConfig::default());
    let srv = spawn_real_server(cfg.clone()).await;

    let report = scim_server::diag::run(&write_opts(&srv.base_url, "scimdiag-defaults"))
        .await
        .expect("diagnose run should complete");

    assert_knobs_match(&report, &cfg.compatibility);

    srv.shutdown().await;
}

/// Oracle test #2: the mirror image — every knob flipped away from its
/// default should be detected as a `QUIRK` with the flipped value.
#[tokio::test]
async fn diagnose_detects_all_quirks_on() {
    let quirks = CompatibilityConfig {
        meta_datetime_format: "epoch".to_string(),
        show_empty_groups_members: false,
        include_user_groups: false,
        support_group_members_filter: false,
        support_group_displayname_filter: false,
        support_patch_replace_empty_array: false,
        support_patch_replace_empty_value: true,
    };
    let cfg = config_with_compat(quirks.clone());
    let srv = spawn_real_server(cfg).await;

    let report = scim_server::diag::run(&write_opts(&srv.base_url, "scimdiag-quirks"))
        .await
        .expect("diagnose run should complete");

    assert_knobs_match(&report, &quirks);

    srv.shutdown().await;
}

/// `--read-only` skips every write-mode check (`Need::Writes`), regardless
/// of `--probe-email` being present.
#[tokio::test]
async fn diagnose_read_only_skips_writes() {
    let cfg = create_test_app_config();
    let srv = spawn_real_server(cfg).await;

    let mut opts = write_opts(&srv.base_url, "scimdiag-ro");
    opts.read_only = true;

    let report = scim_server::diag::run(&opts)
        .await
        .expect("diagnose run should complete");
    let by_id: std::collections::HashMap<&str, &Verdict> =
        report.outcomes.iter().map(|o| (o.id, &o.verdict)).collect();

    let write_needing_ids = [
        "rfc.content_type",
        "rfc.create_user",
        "rfc.location_roundtrip",
        "compat.show_empty_groups_members",
        "compat.include_user_groups",
        "compat.groups_consistency",
        "compat.support_group_members_filter",
        "compat.support_group_displayname_filter",
        "compat.support_patch_replace_empty_array",
        "compat.support_patch_replace_empty_value",
        "rfc.duplicate_username",
        "rfc.put_replace",
        "rfc.patch_add_remove",
        "rfc.patch_204_or_200",
        "rfc.filter_eq_username",
        "rfc.filter_case_insensitive",
        "rfc.filter_sw",
        "rfc.pagination",
        "rfc.pagination_count_zero",
        "rfc.sort",
        "rfc.attributes_param",
        "rfc.excluded_attributes",
        "rfc.delete_then_get",
        "etag.response_header",
        "etag.matches_meta_version",
        "etag.weak_form",
        "etag.if_none_match_304",
        "etag.if_none_match_weak_compare",
        "etag.if_none_match_star",
        "etag.if_none_match_stale",
        "etag.if_match_412",
        "etag.if_match_current",
        "etag.if_match_star",
        "etag.patch_if_match",
        "etag.delete_if_match",
        "spc.bulk_supported",
        "spc.change_password_supported",
        "rfc.password_never_returned",
    ];
    for id in write_needing_ids {
        match by_id[id] {
            Verdict::Skip { reason } => {
                assert!(
                    reason.contains("read-only"),
                    "{id} skip reason should mention --read-only: {reason}"
                );
            }
            other => panic!("{id} expected Skip under --read-only, got {other:?}"),
        }
    }

    // No fixture was ever created.
    let cleanup = report
        .cleanup
        .expect("cleanup should still have run (as a no-op)");
    assert_eq!(cleanup.attempted, 0, "cleanup: {cleanup:?}");

    srv.shutdown().await;
}

/// After a normal write-mode run, every fixture this tool created is gone
/// — verified both through the report's `CleanupReport` and by directly
/// re-querying the live server for anything matching the run's prefix.
#[tokio::test]
async fn diagnose_cleans_up() {
    let cfg = create_test_app_config();
    let srv = spawn_real_server(cfg).await;
    let prefix = "scimdiag-cleanup";

    let report = scim_server::diag::run(&write_opts(&srv.base_url, prefix))
        .await
        .expect("diagnose run should complete");

    let cleanup = report.cleanup.expect("cleanup should have run");
    assert!(
        cleanup.failures.is_empty(),
        "cleanup failures: {:?}",
        cleanup.failures
    );
    assert!(
        cleanup.attempted > 0,
        "expected fixtures to have been created and cleaned up: {cleanup:?}"
    );
    assert_eq!(
        cleanup.deleted, cleanup.attempted,
        "not everything was deleted: {cleanup:?}"
    );

    let client = reqwest::Client::new();
    let users: serde_json::Value = client
        .get(format!("{}/Users", srv.base_url))
        .query(&[("filter", format!("userName sw \"{prefix}\""))])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        users["totalResults"].as_i64(),
        Some(0),
        "leftover users after cleanup: {users}"
    );

    let groups: serde_json::Value = client
        .get(format!("{}/Groups", srv.base_url))
        .query(&[("filter", format!("displayName sw \"{prefix}\""))])
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        groups["totalResults"].as_i64(),
        Some(0),
        "leftover groups after cleanup: {groups}"
    );

    srv.shutdown().await;
}

/// Write mode without `--probe-email` degrades to Skip instead of hard-
/// erroring or inventing an address (§5.8).
#[tokio::test]
async fn diagnose_degrades_without_probe_email() {
    let cfg = create_test_app_config();
    let srv = spawn_real_server(cfg).await;

    let mut opts = write_opts(&srv.base_url, "scimdiag-noemail");
    opts.probe_email = None;

    let report = scim_server::diag::run(&opts)
        .await
        .expect("diagnose run should complete");
    let by_id: std::collections::HashMap<&str, &Verdict> =
        report.outcomes.iter().map(|o| (o.id, &o.verdict)).collect();

    for id in [
        "rfc.create_user",
        "compat.show_empty_groups_members",
        "rfc.delete_then_get",
    ] {
        match by_id[id] {
            Verdict::Skip { reason } => {
                assert!(
                    reason.contains("probe-email"),
                    "{id} skip reason should mention probe-email: {reason}"
                );
            }
            other => panic!("{id} expected Skip, got {other:?}"),
        }
    }

    // `spc.wellformed` has `needs: &[]` (§5.9) and so runs regardless of
    // write mode, but it's genuinely OK now (see
    // `diagnose_self_tier2_readonly`'s doc comment) — nothing here drives
    // exit_code() non-zero.
    assert_eq!(report.counts().fail, 0, "counts: {:?}", report.counts());
    assert_eq!(report.exit_code(), 0, "counts: {:?}", report.counts());

    srv.shutdown().await;
}

/// `--probe-email` on a consumer domain is a hard `BadArgs` at parse time
/// unless `--allow-consumer-email` is also passed.
#[test]
fn diagnose_rejects_consumer_email() {
    let cli = Cli::try_parse_from([
        "scim-server",
        "diagnose",
        "https://api.example.com/scim/v2",
        "--auth",
        "none",
        "--probe-email",
        "{prefix}+{n}@gmail.com",
    ])
    .unwrap();
    let Some(Command::Diagnose(args)) = cli.command else {
        panic!("expected the diagnose subcommand to parse");
    };
    let err = into_options(*args)
        .expect_err("gmail.com should be rejected without --allow-consumer-email");
    assert!(err.to_string().contains("gmail.com"), "{err}");

    let cli = Cli::try_parse_from([
        "scim-server",
        "diagnose",
        "https://api.example.com/scim/v2",
        "--auth",
        "none",
        "--probe-email",
        "{prefix}+{n}@gmail.com",
        "--allow-consumer-email",
    ])
    .unwrap();
    let Some(Command::Diagnose(args)) = cli.command else {
        panic!("expected the diagnose subcommand to parse");
    };
    let opts =
        into_options(*args).expect("--allow-consumer-email should permit the consumer domain");
    assert!(opts.allow_consumer_email);
    assert_eq!(opts.probe_email.as_deref(), Some("{prefix}+{n}@gmail.com"));
}
