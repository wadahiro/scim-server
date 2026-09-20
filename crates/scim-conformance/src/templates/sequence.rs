//! p23 -- RFC 7644 §3.5.2: "Operations are applied sequentially in the
//! order they appear in the array. Each operation in the sequence is
//! applied to the target resource; the resulting resource becomes the
//! target of the next operation." No RFC 2119 keyword at all -- the
//! ledger's own note on this entry records that a mechanical, keyword-based
//! extractor would never surface it as a requirement; it was recognized as
//! testable from the paragraph's plain "are applied ... becomes the target
//! of the next" ordering language.
//!
//! One cell (User): a single PATCH request with two `replace` operations
//! on the same path (`nickName` "a" then "b"); a follow-up GET must show
//! "b" -- the later operation observing (and overriding) the earlier one's
//! result, not both being applied independently or the first one winning.

use serde_json::json;

use super::{cleanup, error, fail, is_2xx, pass, safe, Bookkeeping, Cell, PATCHOP_URN, USER_URN};
use crate::client::{truncate, ScimClient};
use crate::matrix::{Characteristic, Method, Outcome};
use crate::requirement::Requirement;
use crate::schema::Resource;

pub fn expand(req: &Requirement) -> Vec<Cell> {
    vec![Cell {
        req_id: "p23",
        resource: Resource::User,
        method: Method::Patch,
        param: None,
        characteristic: Characteristic::LedgerP23Sequence,
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
        &json!({"schemas": [USER_URN], "userName": format!("u-seq-{}", super::short_uid())}),
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

    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "replace", "path": "nickName", "value": "a"},
            {"op": "replace", "path": "nickName", "value": "b"},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;

    let outcome = if !is_2xx(r.status) {
        error(
            cell,
            "nickName",
            USER_URN,
            format!(
                "PATCH with 2 sequential replace operations failed: status={} body={}",
                r.status,
                truncate(&r.raw, 150)
            ),
        )
    } else {
        let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
        let value = got
            .body
            .as_ref()
            .and_then(|b| b.get("nickName"))
            .and_then(|v| v.as_str())
            .map(String::from);
        match value.as_deref() {
            Some("b") => pass(
                cell,
                "nickName",
                USER_URN,
                "b",
                "the second (later) operation's value won, as RFC 7644 §3.5.2 requires",
            ),
            Some(other) => fail(
                cell,
                "nickName",
                USER_URN,
                other.to_string(),
                format!("expected the later operation's value \"b\" to win, got {other:?}"),
            ),
            None => fail(
                cell,
                "nickName",
                USER_URN,
                "<absent>",
                "nickName absent after a PATCH that should have set it to \"b\"",
            ),
        }
    };

    cleanup(client, &bk).await;
    vec![outcome]
}
