//! Per-knob emulation-fidelity check: the third step of the loop this
//! crate exists to close (see `CLAUDE.md`'s "What this is for" section) --
//! observe an unnamed behaviour, implement it as a `CompatibilityConfig`
//! option, *prove the emulation is faithful*. This is the "prove" step,
//! generalised from `tests/diagnose_axes_test.rs`'s
//! `profile_matches_non_default_compatibility_and_round_trips` (which only
//! checks that the seven knob axes themselves reflect a non-default
//! config) into a per-knob blast-radius check over the *entire* profile
//! (475 axes, not just the seven knob axes).
//!
//! For each of the seven `CompatibilityConfig` fields, independently: spin
//! up this server twice (once at default, once with that one field
//! flipped -- every other field stays default), take a full profile of
//! both, and compute the set of axis ids whose observed value token
//! (`scim_diagnose::render::value_token`, made `pub` for exactly this --
//! see its doc comment) differs between the two runs. That set must equal
//! `EXPECTED` below *exactly* -- "no more" proves the option's blast
//! radius is what it claims to be; "no fewer" proves this tool can
//! actually see the option working (a knob whose flip changes nothing
//! would be a silent failure of either the option or the tool, not a
//! pass -- see the loop below, which panics loudly rather than treating an
//! empty change set as success).
//!
//! `EXPECTED`'s values were established empirically (run this test with
//! `-- --nocapture` and read the per-knob diff it always prints, win or
//! lose) rather than assumed; `render.rs`'s `KNOB_FIDELITY` table -- the
//! static claim the `diagnose` report and `--format json` output surface
//! to a human -- is kept in sync with this table by hand. If you change
//! `EXPECTED` here, update `crates/scim-diagnose/src/render.rs`'s
//! `KNOB_FIDELITY` to match.
//!
//! Cost: one baseline profile (`spawn_real_server` + a full 475-axis
//! `--allow-writes` run) reused across all seven knobs, plus one more
//! profile per knob -- eight server spawns and eight full profiles total,
//! all in-process HTTP against this repo's own binary. Measured wall time
//! for the `#[tokio::test]` body itself (excluding compilation): printed
//! by the test as `fidelity test body wall time: ...`.

mod common;

use common::spawn_real_server;
use scim_diagnose::render::value_token;
use scim_diagnose::{Auth, DiagOptions};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};
use std::collections::{BTreeMap, BTreeSet};

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

async fn run_profile(base_url: &str) -> scim_diagnose::Profile {
    let opts = DiagOptions {
        base_url: base_url.to_string(),
        auth: Auth::None,
        headers: Vec::new(),
        insecure: false,
        ca_certs: Vec::new(),
        native_roots: false,
        timeout_secs: 30,
        allow_writes: true,
    };
    scim_diagnose::run(&opts)
        .await
        .expect("diagnose run against the in-process test server should not fail transport-wise")
}

/// axis id -> `value_token(observed)`, for diffing two profiles.
fn tokens(profile: &scim_diagnose::Profile) -> BTreeMap<String, String> {
    profile
        .observations
        .iter()
        .map(|o| (o.axis.clone(), value_token(&o.value)))
        .collect()
}

/// The set of axis ids whose token differs between `baseline` and
/// `flipped` -- an id present in only one of the two counts as changed
/// too (a derived-family instance can exist under one config and not the
/// other, e.g. `include_user_groups`'s `returned_never/User.groups/*`).
fn changed_axes(
    baseline: &BTreeMap<String, String>,
    flipped: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut ids: BTreeSet<&String> = baseline.keys().collect();
    ids.extend(flipped.keys());
    ids.into_iter()
        .filter(|id| baseline.get(*id) != flipped.get(*id))
        .cloned()
        .collect()
}

/// One knob's expected, empirically-measured change set -- see this
/// module's doc comment for how these were established. Kept in sync by
/// hand with `crates/scim-diagnose/src/render.rs`'s `KNOB_FIDELITY`.
struct Expectation {
    knob: &'static str,
    flip: fn(CompatibilityConfig) -> CompatibilityConfig,
    expected: &'static [&'static str],
}

const EXPECTED: &[Expectation] = &[
    Expectation {
        knob: "meta_datetime_format",
        flip: |c| CompatibilityConfig {
            meta_datetime_format: "epoch".to_string(),
            ..c
        },
        expected: &["meta_datetime_format"],
    },
    Expectation {
        knob: "show_empty_groups_members",
        flip: |c| CompatibilityConfig {
            show_empty_groups_members: false,
            ..c
        },
        expected: &["empty_multivalued_rendering"],
    },
    Expectation {
        knob: "include_user_groups",
        flip: |c| CompatibilityConfig {
            include_user_groups: false,
            ..c
        },
        // Wider than its own axis: disabling this also makes scim-server
        // rewrite its own GET /Schemas declaration of User.groups's
        // `returned` characteristic to `never` (src/resource/schema.rs).
        // The schema-derived matrix (crate::matrix::derive) regenerates
        // against that new declaration, so four new
        // returned_never/User.groups/{GET,PATCH,POST,PUT} instances
        // appear that simply don't exist against the default server
        // (which declares `returned: default` for that attribute, a
        // characteristic the derived matrix does not probe at all -- so
        // these are *new* ids, not changed values on existing ones).
        expected: &[
            "returned_never/User.groups/GET",
            "returned_never/User.groups/PATCH",
            "returned_never/User.groups/POST",
            "returned_never/User.groups/PUT",
            "user_groups_presence",
        ],
    },
    Expectation {
        knob: "support_group_members_filter",
        flip: |c| CompatibilityConfig {
            support_group_members_filter: false,
            ..c
        },
        expected: &["group_members_filter"],
    },
    Expectation {
        knob: "support_group_displayname_filter",
        flip: |c| CompatibilityConfig {
            support_group_displayname_filter: false,
            ..c
        },
        expected: &["group_displayname_filter"],
    },
    Expectation {
        knob: "support_patch_replace_empty_array",
        flip: |c| CompatibilityConfig {
            support_patch_replace_empty_array: false,
            ..c
        },
        expected: &["patch_replace_empty_array"],
    },
    Expectation {
        knob: "support_patch_replace_empty_value",
        flip: |c| CompatibilityConfig {
            support_patch_replace_empty_value: true,
            ..c
        },
        expected: &["patch_replace_empty_value"],
    },
];

#[tokio::test]
async fn per_knob_fidelity_matches_documented_change_set_exactly() {
    let started = std::time::Instant::now();

    // One baseline profile, reused across all seven knobs (see this
    // module's doc comment's "Cost" paragraph) -- avoids re-taking the
    // same default-config profile seven times over.
    let baseline_handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let baseline_profile = run_profile(&baseline_handle.base_url).await;
    let baseline = tokens(&baseline_profile);
    baseline_handle.shutdown().await;

    let mut failures: Vec<String> = Vec::new();

    for exp in EXPECTED {
        let flipped_config = (exp.flip)(CompatibilityConfig::default());
        let handle = spawn_real_server(base_app_config(flipped_config)).await;
        let flipped_profile = run_profile(&handle.base_url).await;
        let flipped = tokens(&flipped_profile);
        handle.shutdown().await;

        let changed = changed_axes(&baseline, &flipped);
        let expected: BTreeSet<String> = exp.expected.iter().map(|s| s.to_string()).collect();

        println!(
            "knob {}: changed = {:?} (expected {:?})",
            exp.knob, changed, expected
        );

        // A knob whose flip changes nothing is a failure, not a vacuous
        // pass -- either the option does nothing observable or the tool
        // is blind to it. Fail loudly rather than let an empty `expected`
        // (there is none in this table) or an empty `changed` slip past
        // silently.
        if changed.is_empty() {
            failures.push(format!(
                "knob {}: flipping it changed NO axis at all -- the emulation is either a \
                 no-op or invisible to this tool; this is a failure, not a pass",
                exp.knob
            ));
            continue;
        }

        if changed != expected {
            let missing: Vec<&String> = expected.difference(&changed).collect();
            let extra: Vec<&String> = changed.difference(&expected).collect();
            failures.push(format!(
                "knob {}: changed set does not match expected exactly. missing (expected but \
                 did not change): {missing:?}; extra (changed but not expected): {extra:?}",
                exp.knob
            ));
        }
    }

    let elapsed = started.elapsed();
    println!("fidelity test body wall time: {elapsed:?}");

    assert!(
        failures.is_empty(),
        "per-knob fidelity check failed:\n{}",
        failures.join("\n")
    );
}
