//! Integration tests for `scim-diagnose`'s schema-derived matrix
//! (`crate::matrix`) -- the 389 (attribute x characteristic x method)
//! instances generated from this repo's own `GET /Schemas`, run against
//! this repo's own server (`common::spawn_real_server`, a real HTTP
//! listener).
//!
//! Two things are asserted:
//!
//! 1. `expand_all` produces a deterministic, pinned instance count for this
//!    server's current schema surface.
//! 2. The targeting invariant: for every PATCH-family instance, the request
//!    the executor would actually send names exactly the instance's own
//!    declared attribute -- never a coarser ancestor. This is the ported
//!    form of `feat/rfc-extract`'s
//!    `targeting_invariant_every_cell_isolates_its_declared_attribute`.

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::spawn_real_server;
use scim_diagnose::axis::Value as ObservedValue;
use scim_diagnose::client::{Auth, ClientConfig, ScimClient};
use scim_diagnose::matrix::{
    build_patch_request, expand_all, run_derived_family, DerivedAxis, Method, PatchRequestPlan,
};
use scim_diagnose::schema::{decls_from_schemas, AttrDecl, AttrType, Resource};
use scim_server::config::{
    AppConfig, AuthConfig, BackendConfig, CompatibilityConfig, DatabaseConfig, ServerConfig,
    TenantConfig,
};
use serde_json::{json, Value};

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

async fn fetch_decls(base_url: &str) -> Vec<AttrDecl> {
    let client = ScimClient::new(ClientConfig {
        base_url: base_url.to_string(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("client construction");
    let r = client.get("/Schemas").await.expect("GET /Schemas");
    assert_eq!(r.status, 200, "GET /Schemas must succeed");
    decls_from_schemas(&r.body.expect("/Schemas body must be JSON"))
}

/// The number of `AttrDecl`s this server currently advertises across User,
/// Group, and the enterprise extension (excluding ServiceProviderConfig,
/// which has no write endpoint). Matches the source branch's pinned
/// `DECL_COUNT` (93) for an equivalent, unmodified scim-server.
const DECL_COUNT: usize = 93;

/// The number of derived instances `expand_all` derives from
/// [`DECL_COUNT`] declarations -- pinned per the brief's expectation of
/// 389. If this ever changes, the server's schema surface changed; update
/// deliberately, not silently.
const INSTANCE_COUNT: usize = 389;

#[tokio::test]
async fn decl_and_instance_counts_are_pinned() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let decls = fetch_decls(&handle.base_url).await;
    assert_eq!(
        decls.len(),
        DECL_COUNT,
        "decls_from_schemas produced {} decls, expected {DECL_COUNT}; the schema surface changed",
        decls.len()
    );
    assert!(
        !decls
            .iter()
            .any(|d| d.schema.contains("ServiceProviderConfig")),
        "ServiceProviderConfig has no write endpoint and must be excluded"
    );

    let axes = expand_all(&decls);
    assert_eq!(
        axes.len(),
        INSTANCE_COUNT,
        "expand_all produced {} instances, expected the pinned {INSTANCE_COUNT}",
        axes.len()
    );

    let ids: HashSet<&str> = axes.iter().map(|a| a.id.as_str()).collect();
    assert_eq!(ids.len(), axes.len(), "every generated id must be unique");

    // Total axes = the 32 static axes (crate::axes::AXES: the original 7
    // CompatibilityConfig axes, plus the 9 ported from feat/rfc-extract's
    // uniqueness/sequence/atomicity/conditional templates, plus the 16
    // ported from feat/rfc-extract's etag.rs -- RFC 7644 §3.14
    // ETag/conditional-request family) + the 389 schema-derived instances
    // = 421.
    assert_eq!(
        scim_diagnose::axes::AXES.len() + INSTANCE_COUNT,
        421,
        "total axes (static + schema-derived) must be pinned at 421"
    );

    handle.shutdown().await;
}

/// Actually runs the full 389-instance derived matrix against a live
/// server end to end (`run_derived_family`, not just the pure request
/// builders the targeting invariant exercises below). Asserts every
/// instance produces exactly one `Observation`, in the same order, and
/// that the overwhelming majority resolve to `Value::Known` against this
/// repo's own reference server -- `Unobservable`/`Unknown` are expected for
/// a handful of edge cases (e.g. a companion fixture creation failing) but
/// must not be the common case.
#[tokio::test]
async fn run_derived_family_against_a_live_server_produces_one_observation_per_instance() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let decls = fetch_decls(&handle.base_url).await;
    let axes = expand_all(&decls);
    assert_eq!(axes.len(), INSTANCE_COUNT);

    let mut client = ScimClient::new(ClientConfig {
        base_url: handle.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(30),
    })
    .expect("client construction");

    let observations = run_derived_family(&mut client, &axes).await;
    assert_eq!(
        observations.len(),
        axes.len(),
        "run_derived_family must return exactly one Observation per instance"
    );
    for (axis, obs) in axes.iter().zip(&observations) {
        assert_eq!(
            &obs.axis, &axis.id,
            "observations must stay in the same order as the instances they came from"
        );
    }

    let known = observations
        .iter()
        .filter(|o| matches!(o.value, ObservedValue::Known(_)))
        .count();
    eprintln!(
        "run_derived_family: {known}/{} instances resolved to Value::Known against this \
         server's own reference implementation",
        observations.len()
    );
    assert!(
        known * 10 >= observations.len() * 9,
        "expected at least 90% of instances to resolve Known against this repo's own server, \
         got {known}/{}",
        observations.len()
    );

    handle.shutdown().await;
}

// =====================================================================
// Targeting invariant: every PATCH-family instance's request must isolate
// its own declared attribute, never a coarser ancestor. Ported from
// `feat/rfc-extract`'s `tests/conformance_schema_matrix.rs`
// `targeting_invariant_every_cell_isolates_its_declared_attribute`, adapted
// to this crate's `DerivedAxis`/`expand_all` shape. See `matrix::exec`'s
// module doc comment for why this matters: a probe that PATCHes
// `Group.members` while judging `Group.members.display`'s mutability can
// never be trusted, no matter what verdict it happens to produce.
// =====================================================================

const ENTERPRISE_URN: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

fn composed_attr_path(raw: &str) -> String {
    let stripped = raw
        .strip_prefix(&format!("{ENTERPRISE_URN}:"))
        .unwrap_or(raw);
    if let Some(bracket) = stripped.find('[') {
        let top = &stripped[..bracket];
        let close = stripped[bracket..]
            .find(']')
            .map(|i| bracket + i)
            .expect("valuePath must have a closing ]");
        let rest = stripped[close + 1..].strip_prefix('.').unwrap_or("");
        if rest.is_empty() {
            top.to_string()
        } else {
            format!("{top}.{rest}")
        }
    } else {
        stripped.to_string()
    }
}

fn container_is_readonly(decl: &AttrDecl, universe: &[&AttrDecl]) -> bool {
    let top = decl.top();
    universe.iter().any(|d| {
        d.resource == decl.resource
            && d.depth() == 1
            && d.path == top
            && d.mutability == scim_diagnose::schema::Mutability::ReadOnly
    })
}

fn assert_patch_targets_decl(decl: &AttrDecl, universe: &[&AttrDecl], raw_path: &str) {
    let composed = composed_attr_path(raw_path);
    if composed == decl.path {
        return;
    }
    if composed == decl.top() && container_is_readonly(decl, universe) {
        return;
    }
    panic!(
        "UNSOUND TARGETING for {:?} (resource {:?}): PATCH path={raw_path:?} resolves to \
         {composed:?}, a proper ancestor of the declared attribute, not the attribute itself.",
        decl.path, decl.resource
    );
}

/// Builds the exact PATCH request `matrix::exec`'s readOnly/immutable/
/// uniqueness/returned_never executors would send for `instance`, mirroring
/// their own request-construction logic closely enough to prove the
/// *shape* is sound -- see this file's module doc comment for what a
/// placeholder filter value does and does not prove.
/// Asks the **production** request builder what it would send for this
/// instance, then extracts the `path` it chose. Calling
/// `matrix::build_patch_request` rather than re-deriving the rule here is
/// the whole point: a copy of the logic in the test would keep passing
/// while production drifted away from it, which is precisely the failure
/// this invariant exists to catch.
///
/// `None` means production reported `Unavailable` -- it refuses to compose a
/// request that cannot isolate the attribute, and the executor turns that
/// into `Unobservable`. There is nothing to check in that case.
fn build_patch_path_for(instance: &DerivedAxis, universe: &[&AttrDecl]) -> Option<String> {
    let decl = &instance.decl;
    let placeholder: Value = json!("11111111-1111-1111-1111-111111111111");
    let new_value: Value = json!("forged-by-the-targeting-invariant");

    // Try with a filter value available first; fall back to none so the
    // `Unavailable` branch is exercised for instances that have no
    // identifying sibling to filter on.
    let plan = match build_patch_request(decl, universe, Some(&placeholder), new_value.clone()) {
        PatchRequestPlan::Unavailable(_) => build_patch_request(decl, universe, None, new_value),
        plan => plan,
    };

    match plan {
        PatchRequestPlan::Body(body) => Some(
            body["Operations"][0]["path"]
                .as_str()
                .expect("production build_patch_request must always set Operations[0].path")
                .to_string(),
        ),
        PatchRequestPlan::Unavailable(_) => None,
    }
}

#[tokio::test]
async fn targeting_invariant_every_patch_instance_isolates_its_declared_attribute() {
    let handle = spawn_real_server(base_app_config(CompatibilityConfig::default())).await;
    let decls = fetch_decls(&handle.base_url).await;
    let axes = expand_all(&decls);
    let universe: Vec<&AttrDecl> = decls.iter().collect();

    let mut checked = 0usize;
    let mut skipped_non_patch = 0usize;

    for instance in &axes {
        let is_patch_family = matches!(
            instance.method,
            Method::Patch | Method::PatchChange | Method::PatchDuplicate
        );
        if !is_patch_family {
            skipped_non_patch += 1;
            continue;
        }
        let Some(path) = build_patch_path_for(instance, &universe) else {
            // No filter value could be composed (depth-1 path with no
            // second segment) -- matrix::exec would report this instance
            // Unobservable, never guess a value; nothing to check.
            continue;
        };
        assert_patch_targets_decl(&instance.decl, &universe, &path);
        checked += 1;
    }

    eprintln!(
        "targeting invariant: {checked} PATCH-family instances checked, \
         {skipped_non_patch} non-PATCH instances skipped"
    );
    assert!(
        checked > 0,
        "the invariant must actually exercise at least one PATCH instance"
    );

    handle.shutdown().await;
}

#[test]
fn container_is_readonly_distinguishes_readwrite_and_readonly_containers() {
    fn decl(
        path: &str,
        resource: Resource,
        mutability: scim_diagnose::schema::Mutability,
    ) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource,
            path: path.to_string(),
            parent: None,
            r#type: AttrType::Complex,
            mutability,
            returned: scim_diagnose::schema::Returned::Default,
            uniqueness: scim_diagnose::schema::Uniqueness::None,
            case_exact: false,
            required: false,
            multi_valued: true,
            top_multi_valued: true,
            canonical_values: None,
            has_sub_attributes: true,
        }
    }
    use scim_diagnose::schema::Mutability;

    let members = decl("members", Resource::Group, Mutability::ReadWrite);
    let mut display = members.clone();
    display.path = "members.display".to_string();
    display.parent = Some("members".to_string());
    display.mutability = Mutability::ReadOnly;
    display.r#type = AttrType::String;

    let universe = vec![&members, &display];
    assert!(
        !container_is_readonly(&display, &universe),
        "Group.members is ReadWrite, so members.display cannot rely on a coarse container PATCH"
    );
}
