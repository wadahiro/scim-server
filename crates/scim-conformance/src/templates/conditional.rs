//! p24 -- RFC 7644 §3.5.2: "For multi-valued attributes, a PATCH operation
//! that sets a value's "primary" sub-attribute to "true" SHALL cause the
//! server to automatically set "primary" to "false" for any other values
//! in the array." The SHALL-when clause: the side effect (demoting every
//! other value's `primary`) fires only conditionally, when some value's
//! `primary` is set to `true`.
//!
//! One cell (User): create a user with two emails, the first `primary:
//! true`; PATCH `add` a third email with `primary: true`; a follow-up GET
//! must show exactly one `primary: true` value, and it must be the newly
//! added email specifically -- not merely "exactly one", which a server
//! that silently dropped the `add` altogether (leaving the original
//! `primary: true` untouched) would also produce by accident. See `run`'s
//! `new_email_present` check.

use serde_json::json;

use super::{cleanup, error, fail, is_2xx, pass, safe, Bookkeeping, Cell, PATCHOP_URN, USER_URN};
use crate::client::ScimClient;
use crate::matrix::{Characteristic, Method, Outcome};
use crate::requirement::Requirement;
use crate::schema::Resource;

pub fn expand(req: &Requirement) -> Vec<Cell> {
    vec![Cell {
        req_id: "p24",
        resource: Resource::User,
        method: Method::Patch,
        param: None,
        characteristic: Characteristic::LedgerP24Conditional,
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
        &json!({
            "schemas": [USER_URN],
            "userName": format!("u-cond-{}", super::short_uid()),
            "emails": [
                {"value": format!("a-{}@example.com", super::short_uid()), "primary": true},
                {"value": format!("b-{}@example.com", super::short_uid()), "primary": false},
            ],
        }),
    ))
    .await;
    if !is_2xx(created.status) {
        return vec![error(
            cell,
            "emails[].primary",
            USER_URN,
            "could not create fixture",
        )];
    }
    let id = created.id().unwrap_or_default();
    bk.note(endpoint, id.clone());

    let new_email = format!("c-{}@example.com", super::short_uid());
    let patch_body = json!({
        "schemas": [PATCHOP_URN],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": new_email, "primary": true}]},
        ],
    });
    let r = safe(client.patch(&format!("{endpoint}/{id}"), &patch_body)).await;

    let outcome = if !is_2xx(r.status) {
        error(
            cell,
            "emails[].primary",
            USER_URN,
            format!(
                "PATCH add of a new primary email failed: status={}",
                r.status
            ),
        )
    } else {
        let got = safe(client.get(&format!("{endpoint}/{id}"))).await;
        let emails = got
            .body
            .as_ref()
            .and_then(|b| b.get("emails"))
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let primary_count = emails
            .iter()
            .filter(|e| e.get("primary").and_then(|p| p.as_bool()) == Some(true))
            .count();
        let primary_values: Vec<String> = emails
            .iter()
            .filter(|e| e.get("primary").and_then(|p| p.as_bool()) == Some(true))
            .filter_map(|e| e.get("value").and_then(|v| v.as_str()).map(String::from))
            .collect();
        // `primary_count == 1` alone is not enough: a server that silently
        // dropped the `add` operation entirely (2xx, but the new email
        // never actually appended) would leave the *original* primary
        // (the first email, `primary: true` from creation) as the lone
        // `primary: true` value -- `primary_count == 1` by accident, with
        // nothing about demotion ever exercised. The requirement is
        // specifically that the *new* value's `primary: true` caused the
        // *other* values to be demoted, so the probe must also confirm
        // the new email is present at all, and that it -- not some
        // leftover -- is the one left `primary: true`.
        let new_email_present = emails
            .iter()
            .any(|e| e.get("value").and_then(|v| v.as_str()) == Some(new_email.as_str()));
        if !new_email_present {
            fail(
                cell,
                "emails[].primary",
                USER_URN,
                "new_email_absent",
                format!(
                    "the PATCH add of a new primary email returned 2xx but the new email \
                     ({new_email:?}) is not present in emails after a follow-up GET: {emails:?}"
                ),
            )
        } else if primary_count == 1
            && primary_values.first().map(String::as_str) == Some(new_email.as_str())
        {
            pass(
                cell,
                "emails[].primary",
                USER_URN,
                "primary_count=1",
                format!(
                    "exactly one email ({new_email:?}, the newly added one) is primary:true \
                     after the PATCH; the previous primary was automatically demoted"
                ),
            )
        } else {
            fail(
                cell,
                "emails[].primary",
                USER_URN,
                format!("primary_count={primary_count}"),
                format!(
                    "expected exactly the new email ({new_email:?}) to be the lone primary:true \
                     value after the PATCH, found {primary_count} primary:true value(s) \
                     ({primary_values:?})"
                ),
            )
        }
    };

    cleanup(client, &bk).await;
    vec![outcome]
}
