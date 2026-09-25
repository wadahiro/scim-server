//! The `attribute_projection` family: `attributes` / `excludedAttributes`
//! (RFC 7644 §3.9), honoured or not on every operation that returns a
//! resource. Ported from `feat/rfc-extract`'s
//! `crates/scim-conformance/src/templates/projection.rs` -- the
//! request/assert logic (fixture creation, per-method probing, "does the
//! field the query parameter should have hidden actually stay hidden"
//! judgement) is taken over close to 1:1. What changes: that branch's
//! citation was its own ledger-derived "p27" `Requirement`; this crate has
//! no ledger, so the citation moves to `crate::rfc`'s four
//! `PROJECTION_*` constants (see their doc comments for the reasoning
//! behind each one, including why the citation is genuinely different per
//! method here, unlike every `crate::matrix::derive` family).
//!
//! The bigger change from the source branch: that branch hardcoded `Method
//! x Resource{User, Group} x Param` = 16 cells. This module instead expands
//! over the target's own declared resource types (`GET /ResourceTypes`),
//! the same way `crate::matrix::derive`'s eight families expand over the
//! target's own declared attributes (`GET /Schemas`) rather than a fixed
//! list -- that is the property that lets this family work against a
//! provider with custom resource types and no cooperation from us. Against
//! this server, whose `/ResourceTypes` declares exactly User and Group,
//! the instance count still comes out to the source branch's 16: `{POST,
//! PUT, PATCH} x {attributes, excludedAttributes}` = 6 writes plus a GET
//! control per param = 2, times 2 resource types = 16 -- but the count is
//! *derived*, not hardcoded, so a target with three resource types
//! produces 24, not a hardcoded-16 test failure.
//!
//! Deviation from `crate::matrix::derive::DerivedFamily`'s exact shape:
//! that type's `expand: fn(&[AttrDecl]) -> Vec<DerivedAxis>` and
//! `DerivedAxis::decl: AttrDecl` both assume one instance judges a single,
//! already-known attribute declaration. This family's instances are keyed
//! by *resource type*, not by one attribute -- each instance's fixture
//! touches two attributes (the one requested/excluded, and the different
//! one that must then be absent) -- so it cannot be plugged into that
//! generic type without either faking a second attribute into a single
//! `AttrDecl` field or maintaining a side-table the generic id-driven
//! dispatch (`crate::render`'s `parse_derived_id` + `known_and_fault_for`)
//! was never built to carry. [`ProjectionAxis`] is a parallel, smaller type
//! instead, following the same *pattern* `derive.rs`/`exec.rs` establish
//! (a pure, deterministic `expand`, a fixed `known` vocabulary and
//! `is_fault` predicate, `Cost`-gated execution) without literally being a
//! `DerivedFamily`.
//!
//! `Cost`: every instance (GET included -- it still needs a fixture to GET)
//! is `Cost::NeedsUser`. `crate::axis::Cost` has no variant for "creates one
//! resource of the target's declared type", only "creates a User" /
//! "creates a User and a Group" -- both written for the seven original,
//! fixed-resource axes. `NeedsUser` is reused here as the closest existing
//! fit (a single write-budgeted resource, gated by `--allow-writes`, mail
//! risk aside) even for a Group instance, which creates a Group, not a
//! User; no dedicated `Cost` variant exists for "one resource of an
//! arbitrary declared type" and adding one is out of scope for this
//! family.

use serde_json::{json, Value as Json};

use super::derive::Method;
use super::exec::{set_attr, valid_value_for};
use crate::axis::{Cost, Observation, Unobservable, Value};
use crate::client::{truncate, ScimClient, ScimResponse};
use crate::fixtures::{body_of, cleanup, is_2xx, safe, Bookkeeping, PATCHOP_URN};
use crate::rfc::{self, Keyword, RfcPosition};
use crate::schema::{AttrDecl, Returned};

pub const FAMILY_ID: &str = "attribute_projection";

/// `present` is the only fault value: the field the query parameter should
/// have hidden leaked through anyway. `absent` is the expected, conforming
/// value. `no_body` names a response that carried no resource body at all
/// to judge either way (see [`judge`]) -- also never a fault, but recorded
/// distinctly from `absent` since it is not itself evidence the parameter
/// was honoured, only that there was nothing to check.
const KNOWN: &[&str] = &["absent", "present", "no_body"];

/// `pub`: `crate::render`'s aggregated text view needs this same predicate
/// to flag a majority-non-conforming value, and must not reimplement it.
pub fn is_fault_token(v: &str) -> bool {
    v == "present"
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Param {
    Attributes,
    ExcludedAttributes,
}

impl Param {
    pub fn as_str(&self) -> &'static str {
        match self {
            Param::Attributes => "attributes",
            Param::ExcludedAttributes => "excludedAttributes",
        }
    }
}

const PARAMS: [Param; 2] = [Param::Attributes, Param::ExcludedAttributes];
const METHODS: [Method; 4] = [Method::Post, Method::Put, Method::Patch, Method::Get];

/// One resource type this family probes, with the request/absent attribute
/// pair already picked from its own schema (see [`pick_pair`]).
#[derive(Clone)]
pub struct ProjectionTarget {
    /// `/ResourceTypes`' `name`, e.g. `"User"`.
    pub name: String,
    /// `/ResourceTypes`' `endpoint`, e.g. `"/Users"`.
    pub endpoint: String,
    /// `/ResourceTypes`' `schema` URN.
    pub schema_urn: String,
    /// Every top-level (depth-1) attribute `GET /Schemas` declared for this
    /// resource type's own schema -- used to populate every other required
    /// field a fixture needs beyond `request`/`absent` themselves.
    pub top_level: Vec<AttrDecl>,
    /// The attribute requested via `?attributes=` -- a declared `required`
    /// attribute that is not `returned: always` (so requesting it is a
    /// meaningful exercise of the parameter, not a no-op: an
    /// always-returned attribute like `id` appears with or without it).
    pub request: AttrDecl,
    /// The attribute whose absence is checked -- a different declared
    /// attribute, `returned: default` (so it is present unless suppressed;
    /// checking absence of a `returned: never` attribute would prove
    /// nothing about the query parameter at all).
    pub absent: AttrDecl,
}

/// Picks `(request, absent)` from one resource type's own top-level
/// declarations, per the rule documented on [`ProjectionTarget::request`]
/// and [`ProjectionTarget::absent`]: `request` is the first declared
/// `required` attribute that isn't `returned: always`, in schema
/// declaration order; `absent` is the first *other* attribute, in the same
/// order, declared `returned: default`. `None` when no such pair exists
/// (no required-and-meaningfully-requestable attribute, or nothing else
/// declared `returned: default`) -- the resource type is skipped entirely
/// rather than guessed at (see [`targets_from`]).
pub fn pick_pair(top_level: &[AttrDecl]) -> Option<(AttrDecl, AttrDecl)> {
    let request = top_level
        .iter()
        .find(|d| d.required && d.returned != Returned::Always)?;
    let absent = top_level
        .iter()
        .find(|d| d.path != request.path && d.returned == Returned::Default)?;
    Some((request.clone(), absent.clone()))
}

/// Builds one [`ProjectionTarget`] per resource type named in a `GET
/// /ResourceTypes` `ListResponse` (`resource_types`), using `all_decls`
/// (flattened `GET /Schemas`, `crate::schema::decls_from_schemas`) to find
/// that resource type's own top-level declarations by matching its
/// declared `schema` URN -- not by name against a fixed enum, which is what
/// lets an arbitrary target's custom resource type participate. A resource
/// type whose `schema`/`endpoint`/`name` fields are missing, or for which
/// [`pick_pair`] finds no usable pair, is skipped (not an error for the
/// whole run).
pub fn targets_from(resource_types: &Json, all_decls: &[AttrDecl]) -> Vec<ProjectionTarget> {
    let mut out = Vec::new();
    let Some(resources) = resource_types.get("Resources").and_then(|v| v.as_array()) else {
        return out;
    };
    for r in resources {
        let (Some(name), Some(endpoint), Some(schema_urn)) = (
            r.get("name").and_then(|v| v.as_str()),
            r.get("endpoint").and_then(|v| v.as_str()),
            r.get("schema").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        let top_level: Vec<AttrDecl> = all_decls
            .iter()
            .filter(|d| d.schema == schema_urn && d.depth() == 1)
            .cloned()
            .collect();
        let Some((request, absent)) = pick_pair(&top_level) else {
            continue;
        };
        out.push(ProjectionTarget {
            name: name.to_string(),
            endpoint: endpoint.to_string(),
            schema_urn: schema_urn.to_string(),
            top_level,
            request,
            absent,
        });
    }
    out
}

/// One (resource type, method, query param) instance.
pub struct ProjectionAxis {
    pub id: String,
    pub target_name: String,
    pub endpoint: String,
    pub schema_urn: String,
    pub method: Method,
    pub param: Param,
    /// The value sent for `param`.
    pub query_value: String,
    /// The attribute path expected absent from the response.
    pub check_absent: String,
    pub request: AttrDecl,
    pub absent: AttrDecl,
    pub top_level: Vec<AttrDecl>,
    pub rfc: RfcPosition,
    pub cost: Cost,
    pub known: &'static [&'static str],
}

/// The per-method `RfcPosition` -- see `crate::rfc`'s four `PROJECTION_*`
/// constants for the full reasoning behind each one, and this module's own
/// doc comment for why the *citation* genuinely differs by method here
/// (PATCH's direct cross-reference vs. PUT's implicit "unless otherwise
/// specified" carve-out vs. POST's citation resting on a SHOULD), unlike
/// every citation in `crate::matrix::derive`.
///
/// All four are nonetheless `Keyword::Must`, not just PUT/PATCH/GET: §3.9's
/// own MUST binds "any operation that returns a resource within the
/// response" (`crate::rfc::PROJECTION_ATTRIBUTES_PARAM`) unconditionally --
/// once POST *has* returned a representation, that MUST applies to it the
/// same as to PUT/PATCH/GET. §3.3's SHOULD (`PROJECTION_POST_BODY_SHOULD`)
/// only gates whether POST returns a representation *at all*; that case is
/// already handled separately in [`judge`] (`Value::Known("no_body")`,
/// never a fault) rather than by softening the keyword for every POST
/// instance that *did* return a body. POST therefore cites §3.9 like the
/// others -- the passage that actually carries the MUST -- and §3.3's
/// SHOULD is named on the `no_body` observation, the one branch it
/// governs. So the asymmetry this family models lives in which passage
/// backs each method's obligation (PATCH's direct cross-reference, PUT's
/// "unless otherwise specified" carve-out), not in a per-method fault
/// threshold -- see [`known_and_fault_for`], which every
/// instance's fault judgement actually goes through, for where `keyword`
/// and `expected` turn into the boolean `crate::render` renders.
fn rfc_for_method(method: Method) -> RfcPosition {
    match method {
        Method::Patch => RfcPosition::Mandated {
            basis: rfc::PROJECTION_PATCH_CROSSREF,
            keyword: Keyword::Must,
            expected: "absent",
        },
        Method::Put => RfcPosition::Mandated {
            basis: rfc::PROJECTION_PUT_UNLESS_OTHERWISE,
            keyword: Keyword::Must,
            expected: "absent",
        },
        // §3.9's MUST is what binds POST here, so that is what the report
        // cites. §3.3's SHOULD (`PROJECTION_POST_BODY_SHOULD`) governs only
        // whether a body comes back at all; citing it for the projection
        // obligation would send a reader to a passage containing no MUST.
        // It is attached to the `no_body` observation instead, where it is
        // the operative text.
        Method::Post => RfcPosition::Mandated {
            basis: rfc::PROJECTION_ATTRIBUTES_PARAM,
            keyword: Keyword::Must,
            expected: "absent",
        },
        Method::Get => RfcPosition::Mandated {
            basis: rfc::PROJECTION_ATTRIBUTES_PARAM,
            keyword: Keyword::Must,
            expected: "absent",
        },
        other => unreachable!("attribute_projection never expands {other:?}"),
    }
}

/// The `known` vocabulary and `is_fault` predicate for one method, derived
/// from [`rfc_for_method`]'s `RfcPosition` -- the single place a
/// `(method, observed token)` pair actually turns into a fault/no-fault
/// verdict, so `crate::render`'s aggregated text view judges through this
/// function rather than a flat, method-blind predicate (mirrors
/// `crate::matrix::derive::known_and_fault_for`'s role for the eight
/// schema-derived families).
pub fn known_and_fault_for(method: Method) -> (&'static [&'static str], fn(&str) -> bool) {
    let RfcPosition::Mandated {
        keyword, expected, ..
    } = rfc_for_method(method)
    else {
        unreachable!("attribute_projection's RfcPosition is always Mandated");
    };
    debug_assert_eq!(expected, "absent");
    fn never_fault(_: &str) -> bool {
        false
    }
    match keyword {
        Keyword::Must => (KNOWN, is_fault_token as fn(&str) -> bool),
        Keyword::Should | Keyword::May => (KNOWN, never_fault as fn(&str) -> bool),
    }
}

/// Pure and deterministic: `targets.len() * PARAMS.len() * METHODS.len()`
/// instances, in target/param/method order -- so `expand` alone is what the
/// instance-count invariant in `tests/diagnose_projection_test.rs` checks
/// against, not a hand-counted expectation.
pub fn expand(targets: &[ProjectionTarget]) -> Vec<ProjectionAxis> {
    let mut out = Vec::with_capacity(targets.len() * PARAMS.len() * METHODS.len());
    for t in targets {
        for &param in &PARAMS {
            let (query_value, check_absent) = match param {
                Param::Attributes => (t.request.path.clone(), t.absent.path.clone()),
                Param::ExcludedAttributes => (t.absent.path.clone(), t.absent.path.clone()),
            };
            for &method in &METHODS {
                out.push(ProjectionAxis {
                    id: format!(
                        "{FAMILY_ID}/{}.{}/{}",
                        t.name,
                        param.as_str(),
                        method.as_str()
                    ),
                    target_name: t.name.clone(),
                    endpoint: t.endpoint.clone(),
                    schema_urn: t.schema_urn.clone(),
                    method,
                    param,
                    query_value: query_value.clone(),
                    check_absent: check_absent.clone(),
                    request: t.request.clone(),
                    absent: t.absent.clone(),
                    top_level: t.top_level.clone(),
                    rfc: rfc_for_method(method),
                    cost: Cost::NeedsUser,
                    known: KNOWN,
                });
            }
        }
    }
    out
}

// ---------------------------------------------------------------- execution

/// Every declared-required attribute gets a value (so the fixture is
/// accepted), plus `request`/`absent` explicitly (harmless overwrite when
/// one of them is already required) -- so `absent` is genuinely present
/// pre-filter, making its absence after filtering a real signal, not an
/// accident of an otherwise-empty fixture.
fn fixture_body(target: &ProjectionAxis) -> Json {
    let mut body = json!({ "schemas": [target.schema_urn.clone()] });
    for decl in &target.top_level {
        if decl.required {
            set_attr(&mut body, decl, valid_value_for(decl));
        }
    }
    set_attr(&mut body, &target.request, valid_value_for(&target.request));
    set_attr(&mut body, &target.absent, valid_value_for(&target.absent));
    body
}

fn field_present(body: &Json, field: &str) -> bool {
    match body.get(field) {
        None | Some(Json::Null) => false,
        Some(Json::Array(a)) => !a.is_empty(),
        Some(_) => true,
    }
}

/// A bodyless success (most notably a PATCH answering 204 while
/// `attributes` was supplied -- RFC 7644 §3.5.2 L1943-1944 requires 200 in
/// that case, a status-code requirement this family does not itself check,
/// see `crate::rfc::PROJECTION_PATCH_CROSSREF`) proves nothing about
/// attribute projection either way: there is no representation to judge
/// present or absent. It is recorded as its own named, `Known` value
/// (`"no_body"`, in [`KNOWN`]) rather than `Unobservable` -- the brief's own
/// language for this case is "its own observable value, not a projection
/// failure", and `Unobservable` would both contradict that (nothing
/// "unobservable" happened; the absence of a body *is* the observation) and
/// embed the endpoint/status into `profile_json`'s `observed` field via
/// `Unobservable::ProbeFailed`'s token, which is not diff-stable across
/// runs the way every other `Known` token is.
fn judge(axis: &ProjectionAxis, r: &ScimResponse) -> Observation {
    if !is_2xx(r.status) {
        return Observation {
            axis: axis.id.clone(),
            value: Value::Unobservable(Unobservable::ProbeFailed(format!(
                "request failed: status={} body={}",
                r.status,
                truncate(&r.raw, 150)
            ))),
            evidence: vec![r.exchange.clone()],
            detail: String::new(),
        };
    }
    let body = body_of(r);
    if body.is_null() || body.as_object().is_none_or(|o| o.is_empty()) {
        let detail = format!(
            "{} {} returned status {} with no resource body; nothing to judge attribute \
             projection against either way",
            axis.method.as_str(),
            axis.endpoint,
            r.status
        );
        return Observation {
            axis: axis.id.clone(),
            value: Value::Known("no_body"),
            evidence: vec![r.exchange.clone()],
            // Returning a representation at all is a SHOULD, not a MUST --
            // name the passage that says so, since this is the one branch
            // it actually governs.
            detail: format!(
                "{detail} (returning a representation is a SHOULD: {})",
                rfc::PROJECTION_POST_BODY_SHOULD
            ),
        };
    }
    let present = field_present(&body, &axis.check_absent);
    let token = if present { "present" } else { "absent" };
    let detail = if present {
        format!(
            "\"{}\" still present in the response despite ?{}={}",
            axis.check_absent,
            axis.param.as_str(),
            axis.query_value
        )
    } else {
        format!(
            "\"{}\" correctly absent from the response (?{}={})",
            axis.check_absent,
            axis.param.as_str(),
            axis.query_value
        )
    };
    Observation {
        axis: axis.id.clone(),
        value: if KNOWN.contains(&token) {
            Value::Known(token)
        } else {
            Value::Unknown(token.to_string())
        },
        evidence: vec![r.exchange.clone()],
        detail,
    }
}

fn error_observation(axis: &ProjectionAxis, r: &ScimResponse, what: &str) -> Observation {
    Observation {
        axis: axis.id.clone(),
        value: Value::Unobservable(Unobservable::ProbeFailed(format!(
            "{what}: status={} body={}",
            r.status,
            truncate(&r.raw, 150)
        ))),
        evidence: vec![r.exchange.clone()],
        detail: String::new(),
    }
}

/// PUT/PATCH/GET's fixture step creates a baseline resource *before*
/// sending the query-parameter'd request under test, and that unfiltered
/// creation response is what makes "absent" a real signal rather than an
/// accident: `axis.check_absent` must actually have been stored (and
/// echoed back) pre-filter, or its absence from the *filtered* response
/// proves nothing about the query parameter at all -- this is "the only
/// reliable signal" the brief calls for, and it depends on this check
/// holding. `fixture_body` always sets `check_absent` explicitly (see its
/// own doc comment), so this should hold whenever the server stores and
/// returns what it was asked to create; when it does not (a
/// `returned: never`-in-practice defect, or the create response omitting
/// the field for some other reason), this is recorded as
/// `Unobservable::ProbeFailed` rather than silently proceeding to judge a
/// check that was never meaningful. POST has no separate unfiltered
/// baseline to check against -- POST *is* the operation under test, and a
/// second fixture POST to self-verify would double the write budget for a
/// consistency check every other write-method instance gets for free from
/// its own baseline step; see this family's module doc comment and the
/// final report for this caveat spelled out.
fn verify_fixture_retained_check_field(
    axis: &ProjectionAxis,
    created: &ScimResponse,
) -> Option<Observation> {
    let created_body = body_of(created);
    if field_present(&created_body, &axis.check_absent) {
        return None;
    }
    Some(Observation {
        axis: axis.id.clone(),
        value: Value::Unobservable(Unobservable::ProbeFailed(format!(
            "fixture creation did not retain \"{}\" pre-filter (absent from the unfiltered \
             create response); its absence from a filtered response cannot be judged a \
             projection signal",
            axis.check_absent
        ))),
        evidence: vec![created.exchange.clone()],
        detail: String::new(),
    })
}

/// Executes every instance `expand` produced. One fixture per instance
/// (GET/PUT/PATCH each need a baseline resource to operate on, same as the
/// source branch); cleans up afterward.
pub async fn run(client: &mut ScimClient, axes: &[ProjectionAxis]) -> Vec<Observation> {
    let mut bk = Bookkeeping::new();
    let mut out = Vec::with_capacity(axes.len());

    for axis in axes {
        let endpoint: &'static str = intern_endpoint(&axis.endpoint);
        let query: [(&str, &str); 1] = [(axis.param.as_str(), axis.query_value.as_str())];

        let obs = match axis.method {
            Method::Post => {
                let r = safe(client.request(
                    reqwest::Method::POST,
                    endpoint,
                    &query,
                    Some(&fixture_body(axis)),
                ))
                .await;
                if let Some(id) = r.id() {
                    bk.note(endpoint, id);
                }
                judge(axis, &r)
            }
            Method::Put => {
                let created = safe(client.post(endpoint, &fixture_body(axis))).await;
                if !is_2xx(created.status) {
                    error_observation(axis, &created, "could not create PUT fixture")
                } else {
                    let id = created.id().unwrap_or_default();
                    bk.note(endpoint, id.clone());
                    if let Some(obs) = verify_fixture_retained_check_field(axis, &created) {
                        obs
                    } else {
                        let put_body = body_of(&created);
                        let r = safe(client.request(
                            reqwest::Method::PUT,
                            &format!("{endpoint}/{id}"),
                            &query,
                            Some(&put_body),
                        ))
                        .await;
                        judge(axis, &r)
                    }
                }
            }
            Method::Patch => {
                let created = safe(client.post(endpoint, &fixture_body(axis))).await;
                if !is_2xx(created.status) {
                    error_observation(axis, &created, "could not create PATCH fixture")
                } else {
                    let id = created.id().unwrap_or_default();
                    bk.note(endpoint, id.clone());
                    if let Some(obs) = verify_fixture_retained_check_field(axis, &created) {
                        obs
                    } else {
                        let patch_body = json!({
                            "schemas": [PATCHOP_URN],
                            "Operations": [{
                                "op": "replace",
                                "path": axis.absent.path.clone(),
                                "value": valid_value_for(&axis.absent),
                            }],
                        });
                        let r = safe(client.request(
                            reqwest::Method::PATCH,
                            &format!("{endpoint}/{id}"),
                            &query,
                            Some(&patch_body),
                        ))
                        .await;
                        judge(axis, &r)
                    }
                }
            }
            Method::Get => {
                let created = safe(client.post(endpoint, &fixture_body(axis))).await;
                if !is_2xx(created.status) {
                    error_observation(axis, &created, "could not create GET fixture")
                } else {
                    let id = created.id().unwrap_or_default();
                    bk.note(endpoint, id.clone());
                    if let Some(obs) = verify_fixture_retained_check_field(axis, &created) {
                        obs
                    } else {
                        let r = safe(client.request(
                            reqwest::Method::GET,
                            &format!("{endpoint}/{id}"),
                            &query,
                            None,
                        ))
                        .await;
                        judge(axis, &r)
                    }
                }
            }
            other => unreachable!("attribute_projection never expands {other:?}"),
        };
        out.push(obs);
    }

    cleanup(client, &bk).await;
    out
}

/// `Bookkeeping::note` takes `endpoint: &'static str` -- every other caller
/// in this crate passes a literal (`"/Users"`, `"/Groups"`), since every
/// other family's resources are fixed at compile time. This family's
/// `endpoint` comes from the target's own `GET /ResourceTypes` response, so
/// it is not `'static` in general. The two endpoints this server actually
/// declares intern to the existing literals (no leak); a genuinely novel
/// endpoint from a target with custom resource types leaks one short string
/// per distinct endpoint for the life of the process -- an acceptable cost
/// for a short-lived diagnostic CLI run, and the only way to satisfy
/// `Bookkeeping`'s existing signature without changing it for every other
/// caller.
fn intern_endpoint(endpoint: &str) -> &'static str {
    match endpoint {
        "/Users" => "/Users",
        "/Groups" => "/Groups",
        other => Box::leak(other.to_string().into_boxed_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrType, Mutability, Resource};

    fn decl(path: &str, required: bool, returned: Returned) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: path.to_string(),
            parent: None,
            r#type: AttrType::String,
            mutability: Mutability::ReadWrite,
            returned,
            uniqueness: crate::schema::Uniqueness::None,
            case_exact: false,
            required,
            multi_valued: false,
            top_multi_valued: false,
            canonical_values: None,
            has_sub_attributes: false,
        }
    }

    #[test]
    fn pick_pair_skips_always_returned_required_attribute() {
        let mut id = decl("id", true, Returned::Always);
        id.mutability = Mutability::ReadOnly;
        let user_name = decl("userName", true, Returned::Default);
        let name = decl("name", false, Returned::Default);
        let (request, absent) = pick_pair(&[id, user_name, name]).unwrap();
        assert_eq!(request.path, "userName");
        assert_eq!(absent.path, "name");
    }

    #[test]
    fn pick_pair_none_without_a_usable_pair() {
        let only_required_and_always = decl("id", true, Returned::Always);
        assert!(pick_pair(&[only_required_and_always]).is_none());
    }

    fn user_target() -> ProjectionTarget {
        let mut id = decl("id", true, Returned::Always);
        id.mutability = Mutability::ReadOnly;
        let external_id = decl("externalId", false, Returned::Default);
        let user_name = decl("userName", true, Returned::Default);
        let top_level = vec![id, external_id.clone(), user_name.clone()];
        ProjectionTarget {
            name: "User".to_string(),
            endpoint: "/Users".to_string(),
            schema_urn: "urn:ietf:params:scim:schemas:core:2.0:User".to_string(),
            top_level,
            request: user_name,
            absent: external_id,
        }
    }

    #[test]
    fn expand_is_deterministic_and_sized_by_targets_params_methods() {
        let targets = vec![user_target()];
        let a: Vec<String> = expand(&targets).into_iter().map(|x| x.id).collect();
        let b: Vec<String> = expand(&targets).into_iter().map(|x| x.id).collect();
        assert_eq!(a, b);
        // targets.len() (== 1 here) x params x methods -- the count is a
        // function of the target's own declared resource types, never a
        // hardcoded 16.
        assert_eq!(a.len(), targets.len() * PARAMS.len() * METHODS.len());
        assert!(a.contains(&"attribute_projection/User.attributes/POST".to_string()));
        assert!(a.contains(&"attribute_projection/User.excludedAttributes/GET".to_string()));
    }

    #[test]
    fn excluded_attributes_combo_requests_and_checks_the_same_field() {
        let targets = vec![user_target()];
        let axes = expand(&targets);
        let combo = axes
            .iter()
            .find(|a| a.param == Param::ExcludedAttributes && a.method == Method::Post)
            .unwrap();
        assert_eq!(combo.query_value, combo.check_absent);
        assert_eq!(combo.query_value, "externalId");
    }

    #[test]
    fn attributes_combo_requests_the_required_field_and_checks_a_different_one() {
        let targets = vec![user_target()];
        let axes = expand(&targets);
        let combo = axes
            .iter()
            .find(|a| a.param == Param::Attributes && a.method == Method::Post)
            .unwrap();
        assert_eq!(combo.query_value, "userName");
        assert_eq!(combo.check_absent, "externalId");
        assert_ne!(combo.query_value, combo.check_absent);
    }

    #[test]
    fn rfc_position_asymmetry_is_modeled_not_flattened() {
        // All four methods are judged `Keyword::Must` -- the asymmetry
        // lives in *which passage* backs the obligation, not in a softer
        // fault threshold for any one method (see `rfc_for_method`'s doc
        // comment).
        for method in [Method::Patch, Method::Put, Method::Post, Method::Get] {
            assert!(
                matches!(
                    rfc_for_method(method),
                    RfcPosition::Mandated {
                        keyword: Keyword::Must,
                        expected: "absent",
                        ..
                    }
                ),
                "{method:?} must be Mandated/Must/absent"
            );
        }
        // Three distinct bases (PATCH's direct cross-reference, PUT's
        // "unless otherwise specified" carve-out, POST's SHOULD-gated
        // premise) -- not flattened onto one shared citation the way every
        // `crate::matrix::derive` family's *keyword* is.
        let bases: Vec<&'static str> = [Method::Patch, Method::Put, Method::Post]
            .into_iter()
            .map(|m| {
                let RfcPosition::Mandated { basis, .. } = rfc_for_method(m) else {
                    unreachable!()
                };
                basis.lines
            })
            .collect();
        assert_eq!(
            bases.iter().collect::<std::collections::HashSet<_>>().len(),
            3,
            "PATCH/PUT/POST must each cite a distinct passage: {bases:?}"
        );
    }

    #[test]
    fn known_and_fault_for_matches_is_fault_token_for_every_method() {
        for method in [Method::Patch, Method::Put, Method::Post, Method::Get] {
            let (known, is_fault) = known_and_fault_for(method);
            assert_eq!(known, KNOWN);
            assert!(is_fault("present"));
            assert!(!is_fault("absent"));
            assert!(!is_fault("no_body"));
        }
    }

    #[test]
    fn is_fault_token_only_flags_present() {
        assert!(is_fault_token("present"));
        assert!(!is_fault_token("absent"));
        assert!(!is_fault_token("no_body"));
    }
}
