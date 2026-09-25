//! Integration tests for `scim-diagnose`'s `discovery_presence` family
//! (`scim_diagnose::discovery`) -- 38 static checks against RFC 7643's
//! `ServiceProviderConfig` (§5), `ResourceType` (§6), and `Schema` (§7)
//! required-member tables, plus RFC 7644 §3.4.2's `ListResponse` envelope,
//! run against this repo's own server (`common::spawn_real_server`).
//!
//! Three things are asserted:
//!
//! 1. Every one of the 38 axes reports (present in the profile at all),
//!    both with and without `--allow-writes` -- the point of this family
//!    being `Cost::DiscoveryOnly` is that it never needs the flag, unlike
//!    every write-costed family in this crate.
//! 2. This repo's own reference server actually satisfies the 26
//!    non-conditional `REQUIRED` checks (`Value::Known("present")`) --
//!    `scim-server` implements `ServiceProviderConfig`/`ResourceTypes`/
//!    `Schemas` fully, so this is the "observed value against this server"
//!    evidence the family exists to produce.
//! 3. The three conditionally-`REQUIRED` `ListResponse` entries
//!    (`Resources`, `startIndex`, `itemsPerPage`) are `Unobservable`, not
//!    judged either way -- this family's deliberate policy of not
//!    evaluating the RFC's own gating condition (see
//!    `scim_diagnose::discovery`'s module doc comment).

mod common;

use common::spawn_real_server;
use scim_diagnose::axis::{Unobservable, Value};
use scim_diagnose::discovery::DISCOVERY_AXES;
use scim_diagnose::rfc::RfcPosition;
use scim_diagnose::{Auth, DiagOptions};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};

fn base_app_config() -> AppConfig {
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
        compatibility: CompatibilityConfig::default(),
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

const CONDITIONAL_IDS: [&str; 3] = [
    "discovery_presence/ListResponse.Resources",
    "discovery_presence/ListResponse.startIndex",
    "discovery_presence/ListResponse.itemsPerPage",
];

#[tokio::test]
async fn all_thirty_eight_discovery_axes_report_without_allow_writes() {
    let handle = spawn_real_server(base_app_config()).await;

    let profile = run_profile(&handle.base_url, false).await;

    assert_eq!(DISCOVERY_AXES.len(), 38);
    for axis in DISCOVERY_AXES {
        let obs = profile
            .get(axis.id)
            .unwrap_or_else(|| panic!("discovery axis {} missing from profile", axis.id));
        // The one property this family exists to guarantee: it never
        // reports `Unobservable::NeedsWrite`, regardless of
        // `--allow-writes` -- every instance is `Cost::DiscoveryOnly`.
        assert!(
            !matches!(obs.value, Value::Unobservable(Unobservable::NeedsWrite)),
            "axis {} is Cost::DiscoveryOnly and must never report NeedsWrite, got {:?}",
            axis.id,
            obs.value
        );
    }

    handle.shutdown().await;
}

#[tokio::test]
async fn required_entries_are_known_present_against_this_server() {
    let handle = spawn_real_server(base_app_config()).await;

    let profile = run_profile(&handle.base_url, false).await;

    let mut mandated_checked = 0;
    let mut permitted_checked = 0;
    for axis in DISCOVERY_AXES {
        if CONDITIONAL_IDS.contains(&axis.id) {
            continue;
        }
        let obs = profile.get(axis.id).unwrap();
        println!("{}: {:?} ({})", axis.id, obs.value, obs.detail);
        let Value::Known(v) = &obs.value else {
            panic!(
                "axis {}: expected a Known value against scim-server's own reference \
                 implementation, got {:?} (detail: {})",
                axis.id, obs.value, obs.detail
            );
        };
        match axis.rfc {
            // scim-server implements ServiceProviderConfig/ResourceTypes/
            // Schemas fully, so every non-conditional REQUIRED entry is
            // actually present -- the "observed value against this
            // server" evidence for the 26 Mandated/Must checks.
            RfcPosition::Mandated { .. } => {
                assert_eq!(
                    *v, "present",
                    "axis {}: RFC-mandated member missing (detail: {})",
                    axis.id, obs.detail
                );
                mandated_checked += 1;
            }
            // OPTIONAL entries: either value conforms -- just observe it.
            RfcPosition::Permitted { .. } => permitted_checked += 1,
            other => panic!("axis {}: unexpected RfcPosition {other:?}", axis.id),
        }
    }
    assert_eq!(mandated_checked, 26, "26 non-conditional REQUIRED entries");
    assert_eq!(permitted_checked, 9, "9 OPTIONAL entries");

    handle.shutdown().await;
}

#[tokio::test]
async fn conditional_list_response_entries_are_unobservable_not_judged() {
    let handle = spawn_real_server(base_app_config()).await;

    let profile = run_profile(&handle.base_url, false).await;

    for id in CONDITIONAL_IDS {
        let obs = profile.get(id).unwrap();
        println!("{id}: {:?} ({})", obs.value, obs.detail);
        assert!(
            matches!(obs.value, Value::Unobservable(Unobservable::ProbeFailed(_))),
            "conditional axis {id} must be Unobservable (this family does not evaluate RFC \
             7644 §3.4.2's gating condition), got {:?}",
            obs.value
        );
    }

    handle.shutdown().await;
}
