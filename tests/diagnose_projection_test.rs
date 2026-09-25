//! Integration tests for `scim-diagnose`'s `attribute_projection` family
//! (`scim_diagnose::matrix::projection`) -- `attributes`/`excludedAttributes`
//! honoured on every operation that returns a resource, expanded over this
//! repo's own `GET /ResourceTypes` (not a hardcoded User/Group pair) and
//! run against this repo's own server (`common::spawn_real_server`, a real
//! HTTP listener), mirroring `diagnose_derived_matrix_test.rs`'s approach
//! for the schema-derived matrix.
//!
//! Three things are asserted:
//!
//! 1. The instance count is *derived* from the target's declared resource
//!    types, not hardcoded: `targets.len() * 8` (`{POST, PUT, PATCH} x
//!    {attributes, excludedAttributes}` = 6 writes + a GET control per
//!    param = 2), and the target names come from `/ResourceTypes`' own
//!    `name` fields.
//! 2. `pick_pair` (the production attribute-selection rule, not a copy of
//!    it) picks `(userName, externalId)` for User and `(displayName,
//!    externalId)` for Group against this server's actual schema.
//! 3. Running the family end to end against this server's own reference
//!    implementation resolves every instance to `Value::Known("absent")`
//!    -- `scim-server` honours attribute projection everywhere this family
//!    checks.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::spawn_real_server;
use scim_diagnose::axis::Value as ObservedValue;
use scim_diagnose::client::{Auth, ClientConfig, ScimClient};
use scim_diagnose::matrix::{
    expand_projection, projection_pick_pair, projection_targets_from, run_projection,
};
use scim_diagnose::schema::decls_from_schemas;
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

async fn client_for(base_url: &str) -> ScimClient {
    ScimClient::new(ClientConfig {
        base_url: base_url.to_string(),
        auth: Auth::None,
        timeout: Duration::from_secs(30),
    })
    .expect("client construction")
}

/// This server's declared resource types: exactly User and Group today
/// (`src/resource/resource_type.rs`). If this repo ever adds a third
/// resource type, this constant -- and only this constant -- needs
/// updating; `INSTANCES_PER_TARGET` stays fixed by the family's own shape.
const RESOURCE_TYPE_COUNT: usize = 2;
const INSTANCES_PER_TARGET: usize = 8; // {POST,PUT,PATCH} x {attributes,excludedAttributes} + GET x 2
const INSTANCE_COUNT: usize = RESOURCE_TYPE_COUNT * INSTANCES_PER_TARGET;

#[tokio::test]
async fn instance_count_is_derived_from_declared_resource_types() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let client = client_for(&handle.base_url).await;

    let schemas_r = client.get("/Schemas").await.expect("GET /Schemas");
    assert_eq!(schemas_r.status, 200);
    let decls = decls_from_schemas(&schemas_r.body.expect("/Schemas body must be JSON"));

    let rt_r = client
        .get("/ResourceTypes")
        .await
        .expect("GET /ResourceTypes");
    assert_eq!(rt_r.status, 200);
    let resource_types = rt_r.body.expect("/ResourceTypes body must be JSON");

    let declared_names: HashSet<String> = resource_types
        .get("Resources")
        .and_then(|v| v.as_array())
        .expect("Resources array")
        .iter()
        .filter_map(|r| r.get("name").and_then(|n| n.as_str()).map(str::to_string))
        .collect();
    assert_eq!(
        declared_names,
        HashSet::from(["User".to_string(), "Group".to_string()]),
        "this test's RESOURCE_TYPE_COUNT assumes exactly User and Group are declared"
    );

    let targets = projection_targets_from(&resource_types, &decls);
    assert_eq!(
        targets.len(),
        RESOURCE_TYPE_COUNT,
        "every declared resource type must produce a target (pick_pair must find a usable pair \
         for both User and Group)"
    );
    let target_names: HashSet<String> = targets.iter().map(|t| t.name.clone()).collect();
    assert_eq!(
        target_names, declared_names,
        "target names must come from /ResourceTypes' own declarations, not a hardcoded pair"
    );

    let axes = expand_projection(&targets);
    assert_eq!(
        axes.len(),
        targets.len() * INSTANCES_PER_TARGET,
        "instance count must be derived from the target list, not hardcoded"
    );
    assert_eq!(
        axes.len(),
        INSTANCE_COUNT,
        "for this server (User + Group declared) the derived count is pinned at 16"
    );
    let ids: HashSet<&str> = axes.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids.len(), axes.len(), "every generated id must be unique");

    handle.shutdown().await;
}

/// `pick_pair` is the production attribute-selection rule
/// (`scim_diagnose::matrix::projection::pick_pair`, exported as
/// `projection_pick_pair`) -- this asserts it picks the pair described in
/// the report against this server's *actual* schema, not a hand-built
/// fixture, so a change to `src/schema/definitions.rs` that breaks the
/// rule's assumptions is caught here.
#[tokio::test]
async fn pick_pair_selects_the_expected_attributes_for_user_and_group() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let client = client_for(&handle.base_url).await;
    let schemas_r = client.get("/Schemas").await.expect("GET /Schemas");
    let decls = decls_from_schemas(&schemas_r.body.expect("/Schemas body must be JSON"));

    let user_top_level: Vec<_> = decls
        .iter()
        .filter(|d| d.schema == "urn:ietf:params:scim:schemas:core:2.0:User" && d.depth() == 1)
        .cloned()
        .collect();
    let (user_request, user_absent) =
        projection_pick_pair(&user_top_level).expect("User must yield a pair");
    assert_eq!(user_request.path, "userName");
    assert_eq!(user_absent.path, "externalId");

    let group_top_level: Vec<_> = decls
        .iter()
        .filter(|d| d.schema == "urn:ietf:params:scim:schemas:core:2.0:Group" && d.depth() == 1)
        .cloned()
        .collect();
    let (group_request, group_absent) =
        projection_pick_pair(&group_top_level).expect("Group must yield a pair");
    assert_eq!(group_request.path, "displayName");
    assert_eq!(group_absent.path, "externalId");

    handle.shutdown().await;
}

/// Runs the full family end to end against this repo's own reference
/// server. `scim-server` implements RFC 7644 §3.9 attribute filtering
/// everywhere this family checks, so every instance is expected to resolve
/// to `Value::Known("absent")` -- a regression here means a real
/// projection defect, not merely an unnamed discovery.
#[tokio::test]
async fn run_projection_against_a_live_server_resolves_every_instance_to_absent() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let client = client_for(&handle.base_url).await;

    let schemas_r = client.get("/Schemas").await.expect("GET /Schemas");
    let decls = decls_from_schemas(&schemas_r.body.expect("/Schemas body must be JSON"));
    let rt_r = client
        .get("/ResourceTypes")
        .await
        .expect("GET /ResourceTypes");
    let resource_types = rt_r.body.expect("/ResourceTypes body must be JSON");
    let targets = projection_targets_from(&resource_types, &decls);
    let axes = expand_projection(&targets);
    assert_eq!(axes.len(), INSTANCE_COUNT);

    let mut client = client_for(&handle.base_url).await;
    let observations = run_projection(&mut client, &axes).await;
    assert_eq!(
        observations.len(),
        axes.len(),
        "run_projection must return exactly one Observation per instance"
    );
    for (axis, obs) in axes.iter().zip(&observations) {
        assert_eq!(
            &obs.axis, &axis.id,
            "observations must stay in the same order as the instances they came from"
        );
    }

    for obs in &observations {
        assert!(
            matches!(&obs.value, ObservedValue::Known("absent")),
            "{}: expected Known(\"absent\") against this server's own reference \
             implementation, got {:?} ({})",
            obs.axis,
            obs.value,
            obs.detail
        );
    }

    handle.shutdown().await;
}
