//! Integration tests for `scim-diagnose`'s thirty-two static behavioural
//! axes (the original seven `CompatibilityConfig` axes, the nine ported
//! from `feat/rfc-extract`'s uniqueness/sequence/atomicity/conditional
//! templates, and the sixteen ported from that branch's `etag.rs`), run
//! against this repo's own server (`common::spawn_real_server`, a real
//! HTTP listener -- `scim_diagnose::ScimClient` speaks real HTTP, not
//! `axum_test`'s in-process transport).
//!
//! Four things are asserted:
//!
//! 1. Against a default-`CompatibilityConfig` server, every one of the
//!    thirty-two axes observes a `Value::Known` value (not `Unobservable`)
//!    -- the tool can actually see `scim-server`'s own behaviour end to
//!    end.
//! 2. The tool's core claim: start the server with a **non-default**
//!    `CompatibilityConfig`, assert the profile changes to match it, and
//!    that `compatibility_config()` round-trips -- the YAML it emits names
//!    the same knob values the server was actually started with.
//! 3. The nine `uniqueness_scimtype`/`patch_*` axes' actual observed values
//!    against this repo's own server -- what `scim-server` really does for
//!    uniqueness scimType, PATCH sequencing, atomicity, and primary
//!    demotion.
//! 4. The sixteen `etag_*` axes' actual observed values against this
//!    repo's own server -- what `scim-server` really does for the RFC 7644
//!    §3.14 ETag/conditional-request family.

mod common;

use common::spawn_real_server;
use scim_diagnose::axis::{Cost, Unobservable, Value};
use scim_diagnose::{Auth, DiagOptions};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};

fn base_app_config(compatibility: CompatibilityConfig) -> AppConfig {
    AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
        },
        backend: BackendConfig {
            backend_type: "database".to_string(),
            database: Some(DatabaseConfig {
                db_type: "sqlite".to_string(),
                url: ":memory:".to_string(),
                max_connections: 1,
            }),
        },
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            host: None,
            host_resolution: None,
            auth: AuthConfig {
                auth_type: "unauthenticated".to_string(),
                token: None,
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: Vec::new(),
            compatibility: None,
        }],
        compatibility,
    }
}

fn non_default_compatibility() -> CompatibilityConfig {
    // Flips every one of the seven knobs away from `CompatibilityConfig`'s
    // default, so a test that only checked "the profile changed" couldn't
    // pass by accident on a single lucky field.
    CompatibilityConfig {
        meta_datetime_format: "epoch".to_string(),
        show_empty_groups_members: false,
        include_user_groups: false,
        support_group_members_filter: false,
        support_group_displayname_filter: false,
        support_patch_replace_empty_array: false,
        support_patch_replace_empty_value: true,
    }
}

async fn run_profile(base_url: &str, allow_writes: bool) -> scim_diagnose::Profile {
    let opts = DiagOptions {
        base_url: base_url.to_string(),
        auth: Auth::None,
        headers: Vec::new(),
        insecure: false,
        ca_certs: Vec::new(),
        native_roots: false,
        timeout_secs: 30,
        allow_writes,
    };
    scim_diagnose::run(&opts)
        .await
        .expect("diagnose run against the in-process test server should not fail transport-wise")
}

#[tokio::test]
async fn all_thirty_two_axes_are_known_against_the_default_server() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;

    let profile = run_profile(&handle.base_url, true).await;

    // The profile carries the thirty-two static axes plus the
    // schema-derived matrix's 389 instances (crate::matrix) -- assert on
    // the former by id, not on the collection's total length.
    let static_ids: std::collections::HashSet<&str> =
        scim_diagnose::axes::AXES.iter().map(|a| a.id).collect();
    let static_observed: Vec<_> = profile
        .observations
        .iter()
        .filter(|o| static_ids.contains(o.axis.as_str()))
        .collect();
    assert_eq!(
        static_observed.len(),
        32,
        "all thirty-two static axes must report"
    );
    for obs in &static_observed {
        match &obs.value {
            Value::Known(_) => {}
            other => panic!(
                "axis {} expected a Known value against scim-server's own default \
                 server, got {other:?} (detail: {})",
                obs.axis, obs.detail
            ),
        }
    }

    handle.shutdown().await;
}

/// The nine new axes' actual observed values against this repo's own
/// reference server -- printed to stdout (visible with `cargo test --
/// --nocapture`) so a run of this test doubles as the "observed value for
/// each of the 9 against this server" evidence the diagnose crate exists
/// to produce.
#[tokio::test]
async fn new_nine_axes_observed_values_against_this_server() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;

    let profile = run_profile(&handle.base_url, true).await;

    let new_axis_ids = [
        "uniqueness_scimtype/User/POST",
        "uniqueness_scimtype/User/PUT",
        "uniqueness_scimtype/User/PATCH",
        "uniqueness_scimtype/Group/POST",
        "uniqueness_scimtype/Group/PUT",
        "uniqueness_scimtype/Group/PATCH",
        "patch_sequential_application",
        "patch_atomicity",
        "patch_primary_demotion",
    ];
    for axis_id in new_axis_ids {
        let obs = profile
            .get(axis_id)
            .unwrap_or_else(|| panic!("axis {axis_id} missing from profile"));
        println!("{axis_id}: {:?} ({})", obs.value, obs.detail);
        assert!(
            matches!(obs.value, Value::Known(_)),
            "axis {axis_id} expected a Known value against scim-server's own default server, \
             got {:?} (detail: {})",
            obs.value,
            obs.detail
        );
    }

    // scim-server's PATCH implementation actually treats operations
    // sequentially and demotes correctly, so this repo's own server should
    // report the RFC-preferred token for each Mandated axis.
    let expect_known = |axis_id: &str, expected: &str| {
        let obs = profile.get(axis_id).unwrap();
        match &obs.value {
            Value::Known(v) => assert_eq!(*v, expected, "axis {axis_id}: detail: {}", obs.detail),
            other => panic!("axis {axis_id}: expected Known({expected:?}), got {other:?}"),
        }
    };
    expect_known("patch_sequential_application", "b");
    expect_known("patch_atomicity", "rejected_and_unchanged");
    expect_known("patch_primary_demotion", "new_primary_only");

    handle.shutdown().await;
}

/// The sixteen `etag_*` axes' actual observed values against this repo's
/// own reference server -- printed to stdout (visible with `cargo test --
/// --nocapture`), the "observed value for each of the 16 against this
/// server" evidence for the ETag/conditional-request family. `scim-server`
/// implements RFC 7644 §3.14 fully (weak ETags, `meta.version`,
/// conditional GET/PUT/PATCH/DELETE -- see `tests/etag_version_test.rs`),
/// so every `Mandated` axis here is expected to report the RFC-preferred
/// token, and the two non-`Mandated` axes (`etag_form`, `etag_delete_if_match/*`)
/// their actual, non-judged observations.
#[tokio::test]
async fn etag_family_observed_values_against_this_server() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;

    let profile = run_profile(&handle.base_url, true).await;

    let etag_axis_ids = [
        "etag_response_header",
        "etag_meta_version",
        "etag_consistency",
        "etag_form",
        "etag_conditional_read/current",
        "etag_conditional_read/stale",
        "etag_conditional_read/star",
        "etag_conditional_write/PUT/current",
        "etag_conditional_write/PUT/stale",
        "etag_conditional_write/PUT/star",
        "etag_conditional_write/PATCH/current",
        "etag_conditional_write/PATCH/stale",
        "etag_conditional_write/PATCH/star",
        "etag_delete_if_match/current",
        "etag_delete_if_match/stale",
        "etag_delete_if_match/star",
    ];
    for axis_id in etag_axis_ids {
        let obs = profile
            .get(axis_id)
            .unwrap_or_else(|| panic!("axis {axis_id} missing from profile"));
        println!("{axis_id}: {:?} ({})", obs.value, obs.detail);
        assert!(
            matches!(obs.value, Value::Known(_)),
            "axis {axis_id} expected a Known value against scim-server's own default server, \
             got {:?} (detail: {})",
            obs.value,
            obs.detail
        );
    }

    let expect_known = |axis_id: &str, expected: &str| {
        let obs = profile.get(axis_id).unwrap();
        match &obs.value {
            Value::Known(v) => assert_eq!(*v, expected, "axis {axis_id}: detail: {}", obs.detail),
            other => panic!("axis {axis_id}: expected Known({expected:?}), got {other:?}"),
        }
    };
    expect_known("etag_response_header", "present");
    expect_known("etag_meta_version", "present");
    expect_known("etag_consistency", "consistent");
    expect_known("etag_form", "weak");
    expect_known("etag_conditional_read/current", "not_modified_empty_body");
    expect_known("etag_conditional_read/stale", "ok_200");
    expect_known("etag_conditional_read/star", "not_modified_empty_body");
    expect_known(
        "etag_conditional_write/PUT/current",
        "accepted_version_advanced",
    );
    expect_known(
        "etag_conditional_write/PUT/stale",
        "precondition_failed_412",
    );
    expect_known("etag_conditional_write/PUT/star", "accepted");
    expect_known(
        "etag_conditional_write/PATCH/current",
        "accepted_version_advanced",
    );
    expect_known(
        "etag_conditional_write/PATCH/stale",
        "precondition_failed_412",
    );
    expect_known("etag_conditional_write/PATCH/star", "accepted");
    expect_known("etag_delete_if_match/current", "accepted");
    expect_known("etag_delete_if_match/stale", "precondition_failed_412");
    expect_known("etag_delete_if_match/star", "accepted");

    handle.shutdown().await;
}

#[tokio::test]
async fn without_allow_writes_write_axes_report_needs_write() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;

    let profile = run_profile(&handle.base_url, false).await;

    for axis in scim_diagnose::axes::AXES {
        let obs = profile
            .get(axis.id)
            .unwrap_or_else(|| panic!("axis {} missing from profile", axis.id));
        if axis.cost == Cost::DiscoveryOnly {
            continue;
        }
        assert!(
            matches!(obs.value, Value::Unobservable(Unobservable::NeedsWrite)),
            "axis {} has cost {:?} and --allow-writes was not passed, expected \
             Unobservable::NeedsWrite, got {:?}",
            axis.id,
            axis.cost,
            obs.value
        );
    }

    handle.shutdown().await;
}

/// The tool's core claim: a profile taken against a server started with a
/// non-default `CompatibilityConfig` reflects that config, and
/// `compatibility_config()` emits YAML naming the same knob values the
/// server was actually started with.
#[tokio::test]
async fn profile_matches_non_default_compatibility_and_round_trips() {
    let compat = non_default_compatibility();
    let handle = spawn_real_server(base_app_config(compat.clone())).await;

    let profile = run_profile(&handle.base_url, true).await;

    let expect = |axis_id: &str, expected: &str| {
        let obs = profile
            .get(axis_id)
            .unwrap_or_else(|| panic!("axis {axis_id} missing from profile"));
        match &obs.value {
            Value::Known(v) => assert_eq!(
                *v, expected,
                "axis {axis_id}: expected {expected:?}, observed {v:?} (detail: {})",
                obs.detail
            ),
            other => panic!("axis {axis_id}: expected Known({expected:?}), got {other:?}"),
        }
    };

    expect("meta_datetime_format", "epoch");
    expect("empty_multivalued_rendering", "omitted");
    // The server rewrites its own /Schemas to `returned: never` for
    // User.groups when include_user_groups is disabled (see
    // src/resource/schema.rs), so this is the self-consistent case, not a
    // fault -- see `RfcPosition::SelfDeclared`.
    expect("user_groups_presence", "declares_never_absent");
    expect("group_members_filter", "rejected_400");
    expect("group_displayname_filter", "rejected_400");
    expect("patch_replace_empty_array", "rejected_400");
    expect("patch_replace_empty_value", "cleared");

    // Round-trip: the emitted compatibility.yaml must name the very same
    // knob values `compat` was constructed with.
    let yaml = scim_diagnose::compatibility_config(&profile);
    let parsed: serde_yaml::Value =
        serde_yaml::from_str(&yaml).expect("compatibility_config output must be valid YAML");
    let block = &parsed["compatibility"];

    assert_eq!(
        block["meta_datetime_format"].as_str(),
        Some(compat.meta_datetime_format.as_str())
    );
    assert_eq!(
        block["show_empty_groups_members"].as_bool(),
        Some(compat.show_empty_groups_members)
    );
    assert_eq!(
        block["include_user_groups"].as_bool(),
        Some(compat.include_user_groups)
    );
    assert_eq!(
        block["support_group_members_filter"].as_bool(),
        Some(compat.support_group_members_filter)
    );
    assert_eq!(
        block["support_group_displayname_filter"].as_bool(),
        Some(compat.support_group_displayname_filter)
    );
    assert_eq!(
        block["support_patch_replace_empty_array"].as_bool(),
        Some(compat.support_patch_replace_empty_array)
    );
    assert_eq!(
        block["support_patch_replace_empty_value"].as_bool(),
        Some(compat.support_patch_replace_empty_value)
    );

    handle.shutdown().await;
}
