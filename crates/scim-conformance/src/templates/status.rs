//! p26 -- RFC 7644 §3.5.2: "If a request fails, the server SHALL return an
//! HTTP response status code and a JSON detail error response as defined in
//! Section 3.12." Section 3.12's Table 9 names the concrete `scimType` for
//! a uniqueness violation (`uniqueness`, applicable to POST/PUT/PATCH --
//! `basis::STATUS_TABLE9_UNIQUENESS`), so this template checks that
//! specific mapping rather than "some 4xx", which is all
//! `crate::matrix`'s schema-driven `Uniqueness` characteristic checks
//! (RFC 7643 §7 permits any 400/409 for a uniqueness rejection --
//! `basis::UNIQUENESS`). The two checks disagree exactly where a server
//! rejects a duplicate with the wrong `scimType`.
//!
//! Axes: `{POST, PUT, PATCH} x {User, Group}` = 6 cells, all citing p26's
//! own span plus Table 9's `uniqueness` row as a secondary basis.

use serde_json::{json, Value};

use super::{
    body_of, cleanup, error, fail, is_2xx, pass, safe, short_uid, Bookkeeping, Cell, GROUP_URN,
    PATCHOP_URN, USER_URN,
};
use crate::basis;
use crate::client::ScimClient;
use crate::matrix::{Characteristic, Method, Outcome};
use crate::requirement::Requirement;
use crate::schema::Resource;

const METHODS: [Method; 3] = [
    Method::PostDuplicate,
    Method::PutDuplicate,
    Method::PatchDuplicate,
];
const RESOURCES: [Resource; 2] = [Resource::User, Resource::Group];

fn schema_urn(resource: Resource) -> &'static str {
    match resource {
        Resource::User | Resource::EnterpriseUser => USER_URN,
        Resource::Group => GROUP_URN,
    }
}

/// The resource's server-enforced-unique attribute: `userName` for User,
/// `displayName` for Group (RFC 7643 §4.1.1 / §4.2 -- both declared
/// `uniqueness: server` in this provider's own `/Schemas`, per T9b).
fn unique_field(resource: Resource) -> &'static str {
    match resource {
        Resource::User | Resource::EnterpriseUser => "userName",
        Resource::Group => "displayName",
    }
}

fn make_with_value(resource: Resource, value: &str) -> Value {
    match resource {
        Resource::User | Resource::EnterpriseUser => json!({
            "schemas": [USER_URN],
            "userName": value,
        }),
        Resource::Group => json!({
            "schemas": [GROUP_URN],
            "displayName": value,
        }),
    }
}

pub fn expand(req: &Requirement) -> Vec<Cell> {
    let mut cells = Vec::with_capacity(RESOURCES.len() * METHODS.len());
    for &resource in &RESOURCES {
        for &method in &METHODS {
            cells.push(Cell {
                req_id: "p26",
                resource,
                method,
                param: None,
                characteristic: Characteristic::LedgerP26Status,
                basis: req.basis,
                secondary: vec![basis::STATUS_TABLE9_UNIQUENESS],
            });
        }
    }
    cells
}

fn find_cell(cells: &[Cell], resource: Resource, method: Method) -> &Cell {
    cells
        .iter()
        .find(|c| c.resource == resource && c.method == method)
        .expect("expand() emits one cell per (resource, method)")
}

/// RFC 7644 §3.12 Table 9's verdict: `scimType == "uniqueness"` passes
/// regardless of the exact 4xx status (RFC 7643 §7, `rfc7643.txt:1811-1814`,
/// permits either 400 or 409 for a uniqueness rejection); any other
/// `scimType`, or an outright 2xx accept, fails.
fn judge(cell: &Cell, field: &str, r: &crate::client::ScimResponse) -> Outcome {
    let schema = schema_urn(cell.resource);
    if is_2xx(r.status) {
        return fail(
            cell,
            field,
            schema,
            "accepted",
            format!("duplicate {field} was accepted (status={})", r.status),
        );
    }
    match r.scim_type() {
        Some(st) if st == "uniqueness" => pass(
            cell,
            field,
            schema,
            format!("scimType=uniqueness status={}", r.status),
            "duplicate rejected with scimType=\"uniqueness\" as RFC 7644 §3.12 Table 9 requires",
        ),
        Some(st) => fail(
            cell,
            field,
            schema,
            format!("scimType={st} status={}", r.status),
            format!(
                "duplicate rejected (status={}) but scimType={st:?}, not \"uniqueness\" as \
                 RFC 7644 §3.12 Table 9 requires",
                r.status
            ),
        ),
        None => fail(
            cell,
            field,
            schema,
            format!("scimType=<none> status={}", r.status),
            format!(
                "duplicate rejected (status={}) but the error body carries no scimType at all",
                r.status
            ),
        ),
    }
}

pub async fn run(cells: &[Cell], client: &mut ScimClient) -> Vec<Outcome> {
    let mut bk = Bookkeeping::new();
    let mut outcomes = Vec::with_capacity(cells.len());

    for &resource in &RESOURCES {
        let endpoint = resource.endpoint();
        let schema = schema_urn(resource);
        let field = unique_field(resource);

        // POST: A exists; POST a duplicate of A's unique value as B.
        {
            let cell = find_cell(cells, resource, Method::PostDuplicate);
            let dup_value = format!("dup-{}", short_uid());
            let a = safe(client.post(endpoint, &make_with_value(resource, &dup_value))).await;
            if let Some(id) = a.id() {
                bk.note(endpoint, id);
            }
            let b = safe(client.post(endpoint, &make_with_value(resource, &dup_value))).await;
            if let Some(id) = b.id() {
                bk.note(endpoint, id);
            }
            outcomes.push(judge(cell, field, &b));
        }

        // PUT: A and B exist with distinct values; PUT B with A's value.
        {
            let cell = find_cell(cells, resource, Method::PutDuplicate);
            let a_value = format!("dupA-{}", short_uid());
            let a = safe(client.post(endpoint, &make_with_value(resource, &a_value))).await;
            let b_created = safe(client.post(
                endpoint,
                &make_with_value(resource, &format!("dupB-{}", short_uid())),
            ))
            .await;
            match (a.id(), b_created.id()) {
                (Some(aid), Some(bid)) => {
                    bk.note(endpoint, aid);
                    bk.note(endpoint, bid.clone());
                    let mut put_body = body_of(&b_created);
                    put_body[field] = json!(a_value);
                    let r = safe(client.put(&format!("{endpoint}/{bid}"), &put_body)).await;
                    outcomes.push(judge(cell, field, &r));
                }
                _ => outcomes.push(error(cell, field, schema, "could not create A/B fixtures")),
            }
        }

        // PATCH: A and B exist with distinct values; PATCH B replacing its
        // value with A's.
        {
            let cell = find_cell(cells, resource, Method::PatchDuplicate);
            let a_value = format!("dupA-{}", short_uid());
            let a = safe(client.post(endpoint, &make_with_value(resource, &a_value))).await;
            let b_created = safe(client.post(
                endpoint,
                &make_with_value(resource, &format!("dupB-{}", short_uid())),
            ))
            .await;
            match (a.id(), b_created.id()) {
                (Some(aid), Some(bid)) => {
                    bk.note(endpoint, aid);
                    bk.note(endpoint, bid.clone());
                    let patch_body = json!({
                        "schemas": [PATCHOP_URN],
                        "Operations": [{"op": "replace", "path": field, "value": a_value}],
                    });
                    let r = safe(client.patch(&format!("{endpoint}/{bid}"), &patch_body)).await;
                    outcomes.push(judge(cell, field, &r));
                }
                _ => outcomes.push(error(cell, field, schema, "could not create A/B fixtures")),
            }
        }
    }

    cleanup(client, &bk).await;
    outcomes
}
