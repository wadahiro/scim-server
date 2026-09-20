//! T9c: proves that `scim_conformance::capability::gate` decides which
//! PATCH-method cells to skip *without sending any request other than the
//! two `GET`s needed to build its inputs* (`GET /Schemas` to derive the
//! cells, `GET /ServiceProviderConfig` to read the provider's advertised
//! capabilities).
//!
//! The stub server here answers exactly those two `GET`s -- `/Schemas` with
//! a snapshot captured once from this repository's own real server (via
//! `spawn_real_server`), `/ServiceProviderConfig` with a hand-written body
//! advertising `patch.supported: false` -- and 500s on anything else, so an
//! un-gated PATCH request would be visible immediately (either as a
//! `request_count` above 2, or as an ERROR outcome if it were ever actually
//! executed).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use scim_conformance::capability::{self, Gated};
use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::matrix::{cells_from_decls, Method};
use scim_conformance::schema::decls_from_schemas;
use scim_conformance::Verdict;
use serde_json::{json, Value};

mod common;

#[derive(Clone)]
struct StubState {
    schemas: Arc<Value>,
    request_count: Arc<AtomicUsize>,
}

async fn get_schemas(State(state): State<StubState>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    Json((*state.schemas).clone())
}

async fn get_service_provider_config(State(state): State<StubState>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": false},
        "filter": {"supported": true, "maxResults": 200},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "sort": {"supported": true},
        "etag": {"supported": true},
        "changePassword": {"supported": true},
        "authenticationSchemes": [],
    }))
}

/// Anything besides the two `GET`s above. If capability gating ever failed
/// to skip a PATCH-method cell before sending its request, the request
/// would land here.
async fn catch_all(State(state): State<StubState>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "unexpected request reached the capability-gate stub",
    )
}

struct Stub {
    base_url: String,
    request_count: Arc<AtomicUsize>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl Stub {
    async fn shutdown(mut self) {
        let _ = self.shutdown.take().unwrap().send(());
        let _ = self.join.await;
    }
}

async fn spawn_stub(schemas: Value) -> Stub {
    let request_count = Arc::new(AtomicUsize::new(0));
    let state = StubState {
        schemas: Arc::new(schemas),
        request_count: request_count.clone(),
    };
    let router = Router::new()
        .route("/scim/v2/Schemas", get(get_schemas))
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(get_service_provider_config),
        )
        .fallback(catch_all)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    let join = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .with_graceful_shutdown(async {
                rx.await.ok();
            })
            .await
            .unwrap();
    });

    Stub {
        base_url: format!("http://{addr}/scim/v2"),
        request_count,
        shutdown: Some(tx),
        join,
    }
}

#[tokio::test]
async fn patch_method_cells_are_gated_without_touching_the_stub() {
    // Capture a real server's own `/Schemas` response once, to serve as the
    // stub's fixture -- the stub itself never runs scim-server.
    let real_server = common::spawn_real_server(common::create_test_app_config()).await;
    let real_client = ScimClient::new(ClientConfig {
        base_url: real_server.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("real client construction");
    let schemas_resp = real_client
        .get("/Schemas")
        .await
        .expect("GET /Schemas from the real server");
    assert_eq!(schemas_resp.status, 200);
    let schemas = schemas_resp.body.expect("/Schemas body must be JSON");
    real_server.shutdown().await;

    let stub = spawn_stub(schemas).await;
    let stub_client = ScimClient::new(ClientConfig {
        base_url: stub.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("stub client construction");

    // Build the cell matrix purely from the stub's /Schemas.
    let schemas_resp = stub_client
        .get("/Schemas")
        .await
        .expect("GET /Schemas from the stub");
    assert_eq!(schemas_resp.status, 200);
    let decls = decls_from_schemas(&schemas_resp.body.expect("JSON body"));
    let cells = cells_from_decls(&decls);

    // Build capabilities purely from the stub's /ServiceProviderConfig.
    let caps = capability::fetch(&stub_client).await;
    assert_eq!(
        caps.patch,
        Some(false),
        "the stub's ServiceProviderConfig must have been read correctly"
    );

    // The gate decision itself is pure (no I/O): this is the point of the
    // test -- an un-gated PATCH cell would be executed by `run_cells`, not
    // by `gate`, so if gating works, nothing further ever needs to touch
    // the stub to know these cells will be skipped.
    let gated = capability::gate(&cells, &caps);
    assert_eq!(gated.len(), cells.len());

    let mut patch_method_cells = 0usize;
    for (cell, g) in cells.iter().zip(&gated) {
        let is_patch_method = matches!(
            cell.method,
            Method::Patch | Method::PatchChange | Method::PatchDuplicate
        );
        if is_patch_method {
            patch_method_cells += 1;
            match g {
                Gated::Skip(o) => {
                    assert_eq!(
                        o.verdict,
                        Verdict::Skip,
                        "PATCH-method cell {} {:?} must gate to Skip",
                        cell.decl.path,
                        cell.method
                    );
                    assert_eq!(
                        o.detail, "patch.supported=false",
                        "skip reason for {} {:?}",
                        cell.decl.path, cell.method
                    );
                }
                Gated::Run => panic!(
                    "PATCH-method cell {} {:?} was not gated even though patch.supported=false",
                    cell.decl.path, cell.method
                ),
            }
        } else {
            assert!(
                matches!(g, Gated::Run),
                "non-PATCH-method cell {} {:?} was unexpectedly gated",
                cell.decl.path,
                cell.method
            );
        }
    }
    assert!(
        patch_method_cells > 0,
        "expected at least one PATCH-method cell in the captured schema \
         (readOnly/immutable/uniqueness/returned:never all contribute one)"
    );

    // Exactly the two GETs above reached the stub: computing every gating
    // decision touched nothing else, in particular no PATCH request.
    assert_eq!(
        stub.request_count.load(Ordering::SeqCst),
        2,
        "only GET /Schemas and GET /ServiceProviderConfig should have reached the stub"
    );

    stub.shutdown().await;
}
