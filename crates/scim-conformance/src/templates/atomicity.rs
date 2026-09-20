//! p25 -- RFC 7644 §3.5.2: "A PATCH request, regardless of the number of
//! operations, SHALL be treated as atomic. If a single operation
//! encounters an error condition, the original SCIM resource MUST be
//! restored, and a failure status SHALL be returned."
//!
//! One cell (User): a single PATCH request with a valid first operation
//! (`replace nickName "<value>"`) followed by a second operation this
//! server rejects -- an unrecognized `op` value (`"frobnicate"`, confirmed
//! by manual probe to 400 with `scimType: "invalidValue"`; a `replace` on
//! the readOnly `id` path was tried first and found to be silently
//! ignored rather than rejected, so it can't stand in for "an operation
//! encounters an error condition" here). The request must fail (4xx), and
//! a follow-up GET must show `nickName` unchanged from before the request
//! -- the first operation's effect rolled back, not partially applied.

use serde_json::json;

use super::{cleanup, error, fail, is_2xx, pass, safe, Bookkeeping, Cell, PATCHOP_URN, USER_URN};
use crate::client::ScimClient;
use crate::matrix::{Characteristic, Method, Outcome};
use crate::requirement::Requirement;
use crate::schema::Resource;

pub fn expand(req: &Requirement) -> Vec<Cell> {
    vec![Cell {
        req_id: "p25",
        resource: Resource::User,
        method: Method::Patch,
        param: None,
        characteristic: Characteristic::LedgerP25Atomicity,
        basis: req.basis,
        secondary: Vec::new(),
    }]
}

pub async fn run(cells: &[Cell], client: &mut ScimClient) -> Vec<Outcome> {
    let cell = &cells[0];
    let endpoint = Resource::User.endpoint();
    let mut bk = Bookkeeping::new();

    let created = safe(client.post(
        endpoint,
        &json!({"schemas": [USER_URN], "userName": format!("u-atomic-{}", super::short_uid())}),
    ))
    .await;
    if !is_2xx(created.status) {
        return vec![error(
            cell,
            "nickName",
            USER_URN,
            "could not create fixture",
        )];
    }
    let id = created.id().unwrap_or_default();
    bk.note(endpoint, id.clone());

    // Baseline: nickName is absent before the atomic request.
    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "replace", "path": "nickName", "value": "should-not-stick"},
            {"op": "frobnicate", "path": "nickName", "value": "also-should-not-stick"},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;

    let outcome = if is_2xx(r.status) {
        fail(
            cell,
            "nickName",
            USER_URN,
            format!("status={}", r.status),
            "a PATCH containing an invalid operation was accepted (2xx) instead of failing atomically",
        )
    } else {
        let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
        let nick_name = got.body.as_ref().and_then(|b| b.get("nickName"));
        let unchanged = matches!(nick_name, None | Some(serde_json::Value::Null));
        if unchanged {
            pass(
                cell,
                "nickName",
                USER_URN,
                format!("status={} nickName=<absent>", r.status),
                "the request failed and the valid first operation's effect was not partially applied",
            )
        } else {
            fail(
                cell,
                "nickName",
                USER_URN,
                format!("status={} nickName={:?}", r.status, nick_name),
                format!(
                    "the request failed (status={}) but nickName={:?} -- the valid first \
                     operation was partially applied despite the second operation's error",
                    r.status, nick_name
                ),
            )
        }
    };

    cleanup(client, &bk).await;
    vec![outcome]
}
