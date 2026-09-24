//! T13: proves `scim_conformance::etag::run_all` skips its entire family
//! without sending a single conditional request when the provider's own
//! `/ServiceProviderConfig` reports `etag.supported: false` -- not even the
//! fixture `POST` the representation checks would otherwise need.
//!
//! Mirrors `tests/conformance_capability_gate.rs`'s counting approach: a
//! stub server answers exactly `GET /ServiceProviderConfig` and 500s on
//! anything else, so an un-gated request would be visible immediately
//! (either as `request_count` above 1, or as an ERROR outcome).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::etag::run_all;
use scim_conformance::matrix::Verdict;
use serde_json::json;

#[derive(Clone)]
struct StubState {
    request_count: Arc<AtomicUsize>,
}

async fn get_service_provider_config(State(state): State<StubState>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": true},
        "filter": {"supported": true, "maxResults": 200},
        "bulk": {"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
        "sort": {"supported": true},
        "etag": {"supported": false},
        "changePassword": {"supported": true},
        "authenticationSchemes": [],
    }))
}

/// Anything besides `GET /ServiceProviderConfig`. If the ETag capability
/// gate ever failed to skip the whole family before sending a request, the
/// request would land here.
async fn catch_all(State(state): State<StubState>) -> impl IntoResponse {
    state.request_count.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "unexpected request reached the etag capability-gate stub",
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

async fn spawn_stub() -> Stub {
    let request_count = Arc::new(AtomicUsize::new(0));
    let state = StubState {
        request_count: request_count.clone(),
    };
    let router = Router::new()
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
async fn etag_unsupported_skips_every_row_without_touching_anything_else() {
    let stub = spawn_stub().await;
    let mut client = ScimClient::new(ClientConfig {
        base_url: stub.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("stub client construction");

    let outcomes = run_all(&mut client).await;

    assert_eq!(outcomes.len(), 16, "{outcomes:#?}");
    for o in &outcomes {
        assert_eq!(o.verdict, Verdict::Skip, "{o:#?}");
        assert_eq!(o.detail, "etag.supported=false", "{o:#?}");
    }

    // Exactly the one GET above reached the stub: no fixture POST, no
    // conditional GET/PUT/PATCH/DELETE was ever sent.
    assert_eq!(
        stub.request_count.load(Ordering::SeqCst),
        1,
        "only GET /ServiceProviderConfig should have reached the stub"
    );

    stub.shutdown().await;
}
