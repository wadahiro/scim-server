//! p27 -- RFC 7644 §3.5.2: "On successful completion, the server either
//! MUST return a 200 OK response code and the entire resource within the
//! response body, subject to the "attributes" query parameter (see Section
//! 3.9) ... The server MUST return a 200 OK if the "attributes" parameter
//! is specified in the request." The requirement's authored
//! `quantifier_raw` ("any operation that returns a resource",
//! `crate::scim_plugin`) generalizes this PATCH-specific sentence to every
//! operation that returns a resource body.
//!
//! Axes: `Method{POST, PUT, PATCH} x Resource{User, Group} x
//! Param{attributes, excludedAttributes}` = 12 cells, basis = the
//! requirement's own span; POST/PUT additionally cite RFC 7644 §3.9 as a
//! secondary basis (`basis::PROJECTION_SEC_3_9`) since p27 itself only
//! states the PATCH case. Plus 4 `Method::Get x Resource x Param` control
//! cells, expected to already pass (RFC 7644 §3.4.2.5 attribute filtering
//! is implemented for GET) -- their presence turns a bare "12/12 FAIL"
//! into "the parameter is honored on GET but nowhere else".

use serde_json::{json, Value};

use super::{
    body_of, cleanup, error, fail, is_2xx, pass, safe, short_uid, Bookkeeping, Cell, GROUP_URN,
    PATCHOP_URN, USER_URN,
};
use crate::basis;
use crate::client::{truncate, ScimClient, ScimResponse};
use crate::matrix::{Characteristic, Method, Outcome};
use crate::requirement::Requirement;
use crate::schema::Resource;

/// One (resource, query param) combination under test: the value to send
/// and the attribute expected to be absent from the response because of
/// it.
struct Combo {
    resource: Resource,
    param: &'static str,
    value: &'static str,
    check_absent: &'static str,
}

const COMBOS: [Combo; 4] = [
    Combo {
        resource: Resource::User,
        param: "attributes",
        value: "userName",
        check_absent: "name",
    },
    Combo {
        resource: Resource::User,
        param: "excludedAttributes",
        value: "name",
        check_absent: "name",
    },
    Combo {
        resource: Resource::Group,
        param: "attributes",
        value: "displayName",
        check_absent: "externalId",
    },
    Combo {
        resource: Resource::Group,
        param: "excludedAttributes",
        value: "externalId",
        check_absent: "externalId",
    },
];

const METHODS: [Method; 4] = [Method::Post, Method::Put, Method::Patch, Method::Get];

fn schema_urn(resource: Resource) -> &'static str {
    match resource {
        Resource::User | Resource::EnterpriseUser => USER_URN,
        Resource::Group => GROUP_URN,
    }
}

/// Pure, deterministic: 12 non-GET cells (basis + secondary per the module
/// docs) plus 4 GET control cells (no secondary).
pub fn expand(req: &Requirement) -> Vec<Cell> {
    let mut cells = Vec::with_capacity(COMBOS.len() * METHODS.len());
    for combo in &COMBOS {
        for &method in &METHODS {
            let secondary = if matches!(method, Method::Post | Method::Put) {
                vec![basis::PROJECTION_SEC_3_9]
            } else {
                Vec::new()
            };
            cells.push(Cell {
                req_id: "p27",
                resource: combo.resource,
                method,
                param: Some(combo.param),
                characteristic: Characteristic::LedgerP27Projection,
                basis: req.basis,
                secondary,
            });
        }
    }
    cells
}

fn fixture_body(resource: Resource) -> Value {
    match resource {
        Resource::User | Resource::EnterpriseUser => json!({
            "schemas": [USER_URN],
            "userName": format!("u-proj-{}", short_uid()),
            "name": {"givenName": "Proj", "familyName": "Test"},
        }),
        Resource::Group => json!({
            "schemas": [GROUP_URN],
            "displayName": format!("g-proj-{}", short_uid()),
            "externalId": format!("ext-{}", short_uid()),
        }),
    }
}

/// The PATCH target used for the PATCH-method cells: directly replaces the
/// very field each combo checks for absence, so a PASS here is a strong
/// signal (the field was both just-written and still correctly hidden),
/// not just "happened to not be echoed".
fn patch_target(resource: Resource) -> (&'static str, Value) {
    match resource {
        Resource::User | Resource::EnterpriseUser => {
            ("name.givenName", json!(format!("Patched-{}", short_uid())))
        }
        Resource::Group => ("externalId", json!(format!("ext-patched-{}", short_uid()))),
    }
}

fn field_present(body: &Value, field: &str) -> bool {
    match body.get(field) {
        None | Some(Value::Null) => false,
        Some(Value::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

fn judge(cell: &Cell, attribute: &str, r: &ScimResponse, check_field: &str) -> Outcome {
    let schema = schema_urn(cell.resource);
    if !is_2xx(r.status) {
        return error(
            cell,
            attribute,
            schema,
            format!(
                "request failed: status={} body={}",
                r.status,
                truncate(&r.raw, 150)
            ),
        );
    }
    let body = body_of(r);
    if field_present(&body, check_field) {
        fail(
            cell,
            attribute,
            schema,
            "present",
            format!("\"{check_field}\" still present in the response despite the query parameter"),
        )
    } else {
        pass(
            cell,
            attribute,
            schema,
            "absent",
            format!("\"{check_field}\" correctly absent from the response"),
        )
    }
}

fn find_cell<'a>(cells: &'a [Cell], resource: Resource, method: Method, param: &str) -> &'a Cell {
    cells
        .iter()
        .find(|c| c.resource == resource && c.method == method && c.param == Some(param))
        .expect("expand() emits one cell per (combo, method)")
}

/// Executes every cell `expand` produced. Creates its own fixtures (one per
/// (combo, method) -- GET/PUT/PATCH each need a baseline resource to
/// operate on) and cleans them up afterward.
pub async fn run(cells: &[Cell], client: &mut ScimClient) -> Vec<Outcome> {
    let mut bk = Bookkeeping::new();
    let mut outcomes = Vec::with_capacity(cells.len());

    for combo in &COMBOS {
        let endpoint = combo.resource.endpoint();
        let attribute = format!("{} (?{}={})", combo.check_absent, combo.param, combo.value);

        for &method in &METHODS {
            let cell = find_cell(cells, combo.resource, method, combo.param);
            let query: [(&str, &str); 1] = [(combo.param, combo.value)];

            let outcome = match method {
                Method::Post => {
                    let r = safe(client.request(
                        reqwest::Method::POST,
                        endpoint,
                        &query,
                        Some(&fixture_body(combo.resource)),
                    ))
                    .await;
                    if let Some(id) = r.id() {
                        bk.note(endpoint, id);
                    }
                    judge(cell, &attribute, &r, combo.check_absent)
                }
                Method::Put => {
                    let created = safe(client.post(endpoint, &fixture_body(combo.resource))).await;
                    if !is_2xx(created.status) {
                        error(
                            cell,
                            &attribute,
                            schema_urn(combo.resource),
                            "could not create PUT fixture",
                        )
                    } else {
                        let id = created.id().unwrap_or_default();
                        bk.note(endpoint, id.clone());
                        let put_body = body_of(&created);
                        let r = safe(client.request(
                            reqwest::Method::PUT,
                            &format!("{endpoint}/{id}"),
                            &query,
                            Some(&put_body),
                        ))
                        .await;
                        judge(cell, &attribute, &r, combo.check_absent)
                    }
                }
                Method::Patch => {
                    let created = safe(client.post(endpoint, &fixture_body(combo.resource))).await;
                    if !is_2xx(created.status) {
                        error(
                            cell,
                            &attribute,
                            schema_urn(combo.resource),
                            "could not create PATCH fixture",
                        )
                    } else {
                        let id = created.id().unwrap_or_default();
                        bk.note(endpoint, id.clone());
                        let (path, value) = patch_target(combo.resource);
                        let patch_body = json!({
                            "schemas": [PATCHOP_URN],
                            "Operations": [{"op": "replace", "path": path, "value": value}],
                        });
                        let r = safe(client.request(
                            reqwest::Method::PATCH,
                            &format!("{endpoint}/{id}"),
                            &query,
                            Some(&patch_body),
                        ))
                        .await;
                        judge(cell, &attribute, &r, combo.check_absent)
                    }
                }
                Method::Get => {
                    let created = safe(client.post(endpoint, &fixture_body(combo.resource))).await;
                    if !is_2xx(created.status) {
                        error(
                            cell,
                            &attribute,
                            schema_urn(combo.resource),
                            "could not create GET fixture",
                        )
                    } else {
                        let id = created.id().unwrap_or_default();
                        bk.note(endpoint, id.clone());
                        let r = safe(client.request(
                            reqwest::Method::GET,
                            &format!("{endpoint}/{id}"),
                            &query,
                            None,
                        ))
                        .await;
                        judge(cell, &attribute, &r, combo.check_absent)
                    }
                }
                _ => unreachable!("expand() only ever emits POST/PUT/PATCH/GET cells"),
            };
            outcomes.push(outcome);
        }
    }

    cleanup(client, &bk).await;
    outcomes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::load_rfc7644_3_5_2;
    use crate::requirement::requirements_from_ledger;

    fn p27() -> Requirement {
        let ledger = load_rfc7644_3_5_2();
        requirements_from_ledger(&ledger)
            .into_iter()
            .find(|r| r.id == "p27")
            .expect("p27 must be a generated requirement")
    }

    #[test]
    fn expand_produces_16_cells_with_the_documented_secondary_pattern() {
        let req = p27();
        let cells = expand(&req);
        assert_eq!(cells.len(), 16);

        let non_get = cells.iter().filter(|c| c.method != Method::Get).count();
        let get = cells.iter().filter(|c| c.method == Method::Get).count();
        assert_eq!(non_get, 12);
        assert_eq!(get, 4);

        for c in &cells {
            assert!(c.basis.to_string().starts_with("RFC 7644 §3.5.2 L"));
            match c.method {
                Method::Post | Method::Put => assert_eq!(c.secondary.len(), 1),
                Method::Patch | Method::Get => assert!(c.secondary.is_empty()),
                _ => unreachable!(),
            }
        }
    }
}
