//! Fixture creation, id/short-uid generation, and best-effort cleanup
//! shared by every axis probe in `crate::axes`.
//!
//! Ported from `feat/rfc-extract`'s
//! `crates/scim-conformance/src/matrix/exec.rs` -- only the subset the
//! seven axis probes actually use (`Bookkeeping`, `short_uid`,
//! `make_baseline`, `fresh_user_id`, `cleanup`, `safe`, `body_of`,
//! `is_2xx`, and the three schema URN constants). The much larger
//! schema-matrix-driven parts of that file (`set_attr`, `patch_body`,
//! `run_cells`, forged-value helpers, ...) are not ported: they exist to
//! drive `Cell`s generated from `GET /Schemas`, which this crate does not
//! do (see `crate::schema::decl`, ported but not yet wired to a matrix
//! runner -- future work per the brief this crate was built from).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Value};

use crate::client::{ScimClient, ScimResponse};
use crate::schema::Resource;

pub const USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const GROUP_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const PATCHOP_URN: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn short_uid() -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}{:04x}", t as u32, n as u16)
}

/// Every id a run created, so it can best-effort delete them all when it's
/// done (a 404 on delete counts as success).
pub struct Bookkeeping {
    created: Vec<(&'static str, String)>,
}

impl Bookkeeping {
    pub fn new() -> Self {
        Bookkeeping {
            created: Vec::new(),
        }
    }

    pub fn note(&mut self, endpoint: &'static str, id: String) {
        self.created.push((endpoint, id));
    }
}

impl Default for Bookkeeping {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs a client call, turning a transport error into a synthetic response
/// (status 0) instead of panicking: a socket-level failure still produces
/// a response the caller can classify as a probe failure.
pub async fn safe(
    fut: impl std::future::Future<Output = Result<ScimResponse, crate::client::Error>>,
) -> ScimResponse {
    match fut.await {
        Ok(r) => r,
        Err(e) => ScimResponse {
            status: 0,
            headers: reqwest::header::HeaderMap::new(),
            body: None,
            raw: e.to_string(),
            exchange: crate::client::Exchange {
                method: String::new(),
                url: String::new(),
                status: None,
                elapsed_ms: 0,
                request_body: None,
                response_body: None,
            },
        },
    }
}

pub fn body_of(r: &ScimResponse) -> Value {
    r.body.clone().unwrap_or(Value::Null)
}

pub fn is_2xx(status: u16) -> bool {
    (200..300).contains(&status)
}

pub fn make_baseline(resource: Resource) -> Value {
    match resource {
        Resource::User | Resource::EnterpriseUser => json!({
            "schemas": [USER_URN],
            "userName": format!("u-{}", short_uid()),
        }),
        Resource::Group => json!({
            "schemas": [GROUP_URN],
            "displayName": format!("g-{}", short_uid()),
        }),
    }
}

pub async fn fresh_user_id(client: &ScimClient, bk: &mut Bookkeeping) -> Option<String> {
    let r = safe(client.post("/Users", &make_baseline(Resource::User))).await;
    if is_2xx(r.status) {
        let id = r.id()?;
        bk.note("/Users", id.clone());
        Some(id)
    } else {
        None
    }
}

pub async fn cleanup(client: &ScimClient, bk: &Bookkeeping) {
    let mut done: HashMap<(&'static str, &str), ()> = HashMap::new();
    for (endpoint, id) in &bk.created {
        if done.insert((*endpoint, id.as_str()), ()).is_some() {
            continue;
        }
        let r = safe(client.delete(&format!("{endpoint}/{id}"))).await;
        // 404 counts as success (already gone, or never really created).
        let _ = r.status;
    }
}
