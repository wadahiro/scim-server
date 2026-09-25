//! The pure part of the schema-derived matrix: turning a target's own
//! flattened `GET /Schemas` declarations ([`AttrDecl`]) into a list of
//! [`DerivedAxis`] instances, with no I/O. `expand_all` must be
//! deterministic (same input -> byte-identical output), since the 389-count
//! test and the targeting invariant (`tests/diagnose_derived_matrix_test.rs`)
//! both depend on that.
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/matrix/
//! cells.rs` (`cells_from_decls`'s eight characteristic rules, taken
//! essentially as-is -- same predicates, same fixed emission order per
//! characteristic) -- adapted from that branch's `Cell` (which names a
//! characteristic/method pair generically and defers pass/fail policy to a
//! separately-computed `Outcome`) to this crate's [`DerivedAxis`], which
//! instead carries its own fixed `known` vocabulary and `is_fault`
//! predicate the way `crate::axes`'s seven static axes do.

use crate::axis::Cost;
use crate::rfc::RfcPosition;
use crate::schema::{AttrDecl, AttrType, Mutability, Resource, Returned};

/// The "method" column. Most values are literal HTTP methods, but several
/// characteristics use a compound step label (matching the source branch's
/// naming) because the check exercises more than one request per instance
/// (e.g. `required`'s `POST-omit` creates with the attribute missing,
/// distinct from a plain `POST`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Post,
    Put,
    Patch,
    Get,
    #[allow(dead_code)]
    Delete,
    NA,
    PostCreate,
    PatchChange,
    PutChange,
    PostOmit,
    PutOmit,
    PostDuplicate,
    PutDuplicate,
    PatchDuplicate,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Get => "GET",
            Method::Delete => "DELETE",
            Method::NA => "N/A",
            Method::PostCreate => "POST-create",
            Method::PatchChange => "PATCH-change",
            Method::PutChange => "PUT-change",
            Method::PostOmit => "POST-omit",
            Method::PutOmit => "PUT-omit",
            Method::PostDuplicate => "POST-duplicate",
            Method::PutDuplicate => "PUT-duplicate",
            Method::PatchDuplicate => "PATCH-duplicate",
        }
    }

    /// Inverse of [`Method::as_str`]. Used by `crate::render`'s aggregated
    /// text view to parse a `DerivedAxis::id`'s trailing method component
    /// back into a `Method`, so it can look up the right `known`/`is_fault`
    /// pair via [`known_and_fault_for`] without needing the original
    /// `DerivedAxis` (which `Observation` -- the durable, serializable
    /// record -- does not carry forward; see that struct's doc comment).
    pub fn parse(s: &str) -> Option<Method> {
        Some(match s {
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "GET" => Method::Get,
            "DELETE" => Method::Delete,
            "N/A" => Method::NA,
            "POST-create" => Method::PostCreate,
            "PATCH-change" => Method::PatchChange,
            "PUT-change" => Method::PutChange,
            "POST-omit" => Method::PostOmit,
            "PUT-omit" => Method::PutOmit,
            "POST-duplicate" => Method::PostDuplicate,
            "PUT-duplicate" => Method::PutDuplicate,
            "PATCH-duplicate" => Method::PatchDuplicate,
            _ => return None,
        })
    }
}

/// A family of axes whose instances come from the target's own
/// declarations -- one `DerivedAxis` per (attribute x characteristic x
/// method), generated at run time from `GET /Schemas` rather than known at
/// compile time the way `crate::axes::AXES`'s seven static axes are.
///
/// Deviation from the brief's suggested shape: `rfc` here is the family's
/// *representative* citation (used in the aggregated text report's header
/// for the family), not the one every instance is judged under.
/// `mutability_readonly` in particular judges POST/PUT under RFC 7644 §3.3 /
/// §3.5.1 (silently ignoring a forged value is correct) but PATCH under the
/// stricter §3.5.2 / Table 9 (silently ignoring is *not* conformant on
/// PATCH -- it must be rejected with 400 `scimType: mutability`) -- three
/// different citations for one family. Per-instance fault judgement lives
/// in each `DerivedAxis`'s own `is_fault` predicate, not in a single
/// family-wide `RfcPosition`; see `crate::matrix::exec` for where the
/// method-specific citation actually gets attached to a probe's evidence.
pub struct DerivedFamily {
    pub id_prefix: &'static str,
    pub about: &'static str,
    pub rfc: RfcPosition,
    pub cost: Cost,
    pub expand: fn(&[AttrDecl]) -> Vec<DerivedAxis>,
}

/// One generated instance: one (attribute, characteristic, method) triple.
#[derive(Clone)]
pub struct DerivedAxis {
    /// Stable, sortable id: `"<family_id_prefix>/<Resource>.<decl.path>/<method>"`,
    /// e.g. `"mutability_readonly/User.manager.$ref/PATCH"`. Built once at
    /// generation time so `profile_json` stays diffable across runs and
    /// across providers without needing to re-derive it from `decl`+`method`.
    pub id: String,
    pub family_id: &'static str,
    pub decl: AttrDecl,
    pub method: Method,
    /// Values this instance's probe can name; an observation outside this
    /// set is `Value::Unknown` (see `crate::axis::Value`), same convention
    /// as the seven static axes.
    pub known: &'static [&'static str],
    /// Whether a given `known` token is a fault, given this instance's
    /// method (and, for `mutability_readonly`/PATCH, RFC 7644 §3.5.2's
    /// stricter rule vs. POST/PUT's "ignore is correct" rule -- see
    /// `DerivedFamily`'s doc comment).
    pub is_fault: fn(&str) -> bool,
    pub cost: Cost,
}

/// Whether a top-level complex attribute with declared sub-attributes
/// decomposes into per-subattribute readOnly checks instead of being probed
/// as a whole (ported from `cells.rs`'s `is_container_skip`).
pub fn is_container_skip(decl: &AttrDecl) -> bool {
    decl.depth() == 1 && decl.r#type == AttrType::Complex && decl.has_sub_attributes
}

pub fn is_group_member_ref(decl: &AttrDecl) -> bool {
    decl.resource == Resource::Group
        && decl.top() == "members"
        && (decl.last() == "value" || decl.last() == "$ref")
}

pub fn is_group_member_subattr(decl: &AttrDecl) -> bool {
    decl.resource == Resource::Group && decl.depth() > 1 && decl.top() == "members"
}

pub fn resource_label(resource: Resource) -> &'static str {
    match resource {
        Resource::User => "User",
        Resource::Group => "Group",
        Resource::EnterpriseUser => "EnterpriseUser",
    }
}

fn instance_id(family_id: &'static str, decl: &AttrDecl, method: Method) -> String {
    format!(
        "{family_id}/{}.{}/{}",
        resource_label(decl.resource),
        decl.path,
        method.as_str()
    )
}

fn axis(
    family_id: &'static str,
    decl: &AttrDecl,
    method: Method,
    known: &'static [&'static str],
    is_fault: fn(&str) -> bool,
    cost: Cost,
) -> DerivedAxis {
    DerivedAxis {
        id: instance_id(family_id, decl, method),
        family_id,
        decl: decl.clone(),
        method,
        known,
        is_fault,
        cost,
    }
}

// -------------------------------------------------------- mutability_readonly

const RO_POST_PUT_KNOWN: &[&str] = &["ignored", "leaked"];
fn ro_post_put_is_fault(v: &str) -> bool {
    v == "leaked"
}
const RO_PATCH_KNOWN: &[&str] = &[
    "rejected_mutability",
    "rejected_wrong_scimtype",
    "applied",
    "ignored",
];
fn ro_patch_is_fault(v: &str) -> bool {
    v != "rejected_mutability"
}
const NA_KNOWN: &[&str] = &["not_applicable"];
fn never_fault(_: &str) -> bool {
    false
}

fn expand_mutability_readonly(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "mutability_readonly";
    let mut out = Vec::new();
    for decl in decls {
        if decl.mutability != Mutability::ReadOnly {
            continue;
        }
        if is_container_skip(decl) {
            out.push(axis(
                id,
                decl,
                Method::NA,
                NA_KNOWN,
                never_fault,
                Cost::DiscoveryOnly,
            ));
        } else {
            out.push(axis(
                id,
                decl,
                Method::Post,
                RO_POST_PUT_KNOWN,
                ro_post_put_is_fault,
                Cost::NeedsUser,
            ));
            out.push(axis(
                id,
                decl,
                Method::Put,
                RO_POST_PUT_KNOWN,
                ro_post_put_is_fault,
                Cost::NeedsUser,
            ));
            out.push(axis(
                id,
                decl,
                Method::Patch,
                RO_PATCH_KNOWN,
                ro_patch_is_fault,
                Cost::NeedsUser,
            ));
        }
    }
    out
}

// ------------------------------------------------------ mutability_immutable

const IM_CREATE_KNOWN: &[&str] = &["accepted", "rejected_or_dropped"];
fn im_create_is_fault(v: &str) -> bool {
    v == "rejected_or_dropped"
}
const IM_CHANGE_KNOWN: &[&str] = &["rejected", "ignored", "changed"];
fn im_change_is_fault(v: &str) -> bool {
    v == "changed"
}

fn expand_mutability_immutable(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "mutability_immutable";
    let mut out = Vec::new();
    for decl in decls {
        if decl.mutability != Mutability::Immutable {
            continue;
        }
        out.push(axis(
            id,
            decl,
            Method::PostCreate,
            IM_CREATE_KNOWN,
            im_create_is_fault,
            Cost::NeedsUser,
        ));
        out.push(axis(
            id,
            decl,
            Method::PatchChange,
            IM_CHANGE_KNOWN,
            im_change_is_fault,
            Cost::NeedsUser,
        ));
        out.push(axis(
            id,
            decl,
            Method::PutChange,
            IM_CHANGE_KNOWN,
            im_change_is_fault,
            Cost::NeedsUser,
        ));
    }
    out
}

// -------------------------------------------------------------------- required

const REQ_KNOWN: &[&str] = &["rejected_400", "accepted"];
fn req_is_fault(v: &str) -> bool {
    v == "accepted"
}

fn expand_required(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "required";
    let mut out = Vec::new();
    for decl in decls {
        if !decl.required {
            continue;
        }
        if decl.mutability == Mutability::ReadOnly {
            out.push(axis(
                id,
                decl,
                Method::NA,
                NA_KNOWN,
                never_fault,
                Cost::DiscoveryOnly,
            ));
        } else {
            out.push(axis(
                id,
                decl,
                Method::PostOmit,
                REQ_KNOWN,
                req_is_fault,
                Cost::NeedsUser,
            ));
            out.push(axis(
                id,
                decl,
                Method::PutOmit,
                REQ_KNOWN,
                req_is_fault,
                Cost::NeedsUser,
            ));
        }
    }
    out
}

// ------------------------------------------------------------------- caseExact

const CASE_KNOWN: &[&str] = &["preserved", "not_preserved"];
fn case_is_fault(v: &str) -> bool {
    v == "not_preserved"
}

fn expand_case_exact(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "case_exact";
    let mut out = Vec::new();
    for decl in decls {
        if !decl.case_exact {
            continue;
        }
        let skip = decl.mutability == Mutability::ReadOnly
            || decl.returned == Returned::Never
            || is_group_member_ref(decl);
        if skip {
            out.push(axis(
                id,
                decl,
                Method::NA,
                NA_KNOWN,
                never_fault,
                Cost::DiscoveryOnly,
            ));
        } else {
            out.push(axis(
                id,
                decl,
                Method::Post,
                CASE_KNOWN,
                case_is_fault,
                Cost::NeedsUser,
            ));
        }
    }
    out
}

// ------------------------------------------------------------------ uniqueness

const UNIQ_KNOWN: &[&str] = &["rejected_duplicate", "accepted_duplicate"];
fn uniq_is_fault(v: &str) -> bool {
    v == "accepted_duplicate"
}

fn expand_uniqueness(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    use crate::schema::Uniqueness as U;
    let id = "uniqueness";
    let mut out = Vec::new();
    for decl in decls {
        if !matches!(decl.uniqueness, U::Server | U::Global) {
            continue;
        }
        if decl.mutability == Mutability::ReadOnly {
            out.push(axis(
                id,
                decl,
                Method::NA,
                NA_KNOWN,
                never_fault,
                Cost::DiscoveryOnly,
            ));
        } else {
            out.push(axis(
                id,
                decl,
                Method::PostDuplicate,
                UNIQ_KNOWN,
                uniq_is_fault,
                Cost::NeedsUser,
            ));
            out.push(axis(
                id,
                decl,
                Method::PutDuplicate,
                UNIQ_KNOWN,
                uniq_is_fault,
                Cost::NeedsUser,
            ));
            out.push(axis(
                id,
                decl,
                Method::PatchDuplicate,
                UNIQ_KNOWN,
                uniq_is_fault,
                Cost::NeedsUser,
            ));
        }
    }
    out
}

// -------------------------------------------------------------- returned_never

const RN_KNOWN: &[&str] = &["absent_from_response", "leaked"];
fn rn_is_fault(v: &str) -> bool {
    v == "leaked"
}

fn expand_returned_never(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "returned_never";
    let mut out = Vec::new();
    for decl in decls {
        if decl.returned != Returned::Never {
            continue;
        }
        for method in [Method::Post, Method::Get, Method::Put, Method::Patch] {
            out.push(axis(
                id,
                decl,
                method,
                RN_KNOWN,
                rn_is_fault,
                Cost::NeedsUser,
            ));
        }
    }
    out
}

// ------------------------------------------------------------------ type_wrong

const TW_KNOWN: &[&str] = &["rejected_400", "accepted"];
fn tw_is_fault(v: &str) -> bool {
    v == "accepted"
}

fn expand_type_wrong(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "type_wrong";
    let mut out = Vec::new();
    for decl in decls {
        if decl.mutability == Mutability::ReadOnly {
            continue;
        }
        out.push(axis(
            id,
            decl,
            Method::Post,
            TW_KNOWN,
            tw_is_fault,
            Cost::NeedsUser,
        ));
        out.push(axis(
            id,
            decl,
            Method::Put,
            TW_KNOWN,
            tw_is_fault,
            Cost::NeedsUser,
        ));
    }
    out
}

// ------------------------------------------------------------------ type_valid

const TV_KNOWN: &[&str] = &["round_tripped", "mismatch"];
fn tv_is_fault(v: &str) -> bool {
    v == "mismatch"
}

fn expand_type_valid(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let id = "type_valid";
    let mut out = Vec::new();
    for decl in decls {
        if decl.mutability == Mutability::ReadOnly {
            continue;
        }
        out.push(axis(
            id,
            decl,
            Method::Post,
            TV_KNOWN,
            tv_is_fault,
            Cost::NeedsUser,
        ));
        out.push(axis(
            id,
            decl,
            Method::Put,
            TV_KNOWN,
            tv_is_fault,
            Cost::NeedsUser,
        ));
    }
    out
}

// --------------------------------------------------------------------- registry

pub const DERIVED_FAMILIES: &[DerivedFamily] = &[
    DerivedFamily {
        id_prefix: "mutability_readonly",
        about: "whether a readOnly attribute's client-supplied value is ignored (POST/PUT) or rejected (PATCH)",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::MUTABILITY_READ_ONLY,
            declares: "mutability",
        },
        cost: Cost::NeedsUser,
        expand: expand_mutability_readonly,
    },
    DerivedFamily {
        id_prefix: "mutability_immutable",
        about: "whether an immutable attribute's value can be changed after creation",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::MUTABILITY_IMMUTABLE,
            declares: "mutability",
        },
        cost: Cost::NeedsUser,
        expand: expand_mutability_immutable,
    },
    DerivedFamily {
        id_prefix: "required",
        about: "whether omitting a required attribute is rejected",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::REQUIRED,
            declares: "required",
        },
        cost: Cost::NeedsUser,
        expand: expand_required,
    },
    DerivedFamily {
        id_prefix: "case_exact",
        about: "whether a caseExact attribute's case is preserved",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::CASE_EXACT,
            declares: "caseExact",
        },
        cost: Cost::NeedsUser,
        expand: expand_case_exact,
    },
    DerivedFamily {
        id_prefix: "uniqueness",
        about: "whether a server/global-unique attribute rejects a duplicate value",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::UNIQUENESS,
            declares: "uniqueness",
        },
        cost: Cost::NeedsUser,
        expand: expand_uniqueness,
    },
    DerivedFamily {
        id_prefix: "returned_never",
        about: "whether a returned:never attribute ever appears in a response",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::RETURNED_NEVER,
            declares: "returned",
        },
        cost: Cost::NeedsUser,
        expand: expand_returned_never,
    },
    DerivedFamily {
        id_prefix: "type_wrong",
        about: "whether a wrong-typed value is rejected",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::TYPE,
            declares: "type",
        },
        cost: Cost::NeedsUser,
        expand: expand_type_wrong,
    },
    DerivedFamily {
        id_prefix: "type_valid",
        about: "whether a valid, correctly-typed value round-trips",
        rfc: RfcPosition::SelfDeclared {
            basis: crate::rfc::TYPE,
            declares: "type",
        },
        cost: Cost::NeedsUser,
        expand: expand_type_valid,
    },
];

/// Runs every family's `expand` against `decls`, in `DERIVED_FAMILIES`
/// order, and concatenates the results. Pure and deterministic: same
/// `decls` in the same order always produces the same 389-instance (for
/// this server's current schema surface) output in the same order.
pub fn expand_all(decls: &[AttrDecl]) -> Vec<DerivedAxis> {
    let mut out = Vec::new();
    for family in DERIVED_FAMILIES {
        out.extend((family.expand)(decls));
    }
    out
}

/// Looks up a family by the prefix of a `DerivedAxis::id`/`Observation::axis`
/// string (everything before the first `/`).
pub fn family_for(axis_id: &str) -> Option<&'static DerivedFamily> {
    let prefix = axis_id.split('/').next().unwrap_or(axis_id);
    DERIVED_FAMILIES.iter().find(|f| f.id_prefix == prefix)
}

/// The `known` vocabulary and `is_fault` predicate a `(family_prefix,
/// method)` pair uses -- every `DerivedAxis` this family's `expand`
/// produces for that method shares both, regardless of which specific
/// attribute it judges (`is_fault` is a function of family and method only,
/// never of the attribute's own declaration). Used by `crate::render`'s
/// aggregated text view to judge fault-ness for a persisted `Observation`,
/// which does not carry a `DerivedAxis`'s function pointers forward. `None`
/// for a `(family_prefix, method)` combination this family never emits.
/// A `(family_prefix, method)` pair's `known` vocabulary and `is_fault`
/// predicate -- see [`known_and_fault_for`].
pub type KnownAndFault = (&'static [&'static str], fn(&str) -> bool);

pub fn known_and_fault_for(family_prefix: &str, method: Method) -> Option<KnownAndFault> {
    use Method::*;
    Some(match (family_prefix, method) {
        ("mutability_readonly", NA) => (NA_KNOWN, never_fault as fn(&str) -> bool),
        ("mutability_readonly", Post) | ("mutability_readonly", Put) => {
            (RO_POST_PUT_KNOWN, ro_post_put_is_fault as fn(&str) -> bool)
        }
        ("mutability_readonly", Patch) => (RO_PATCH_KNOWN, ro_patch_is_fault as fn(&str) -> bool),
        ("mutability_immutable", PostCreate) => {
            (IM_CREATE_KNOWN, im_create_is_fault as fn(&str) -> bool)
        }
        ("mutability_immutable", PatchChange) | ("mutability_immutable", PutChange) => {
            (IM_CHANGE_KNOWN, im_change_is_fault as fn(&str) -> bool)
        }
        ("required", NA) => (NA_KNOWN, never_fault as fn(&str) -> bool),
        ("required", PostOmit) | ("required", PutOmit) => {
            (REQ_KNOWN, req_is_fault as fn(&str) -> bool)
        }
        ("case_exact", NA) => (NA_KNOWN, never_fault as fn(&str) -> bool),
        ("case_exact", Post) => (CASE_KNOWN, case_is_fault as fn(&str) -> bool),
        ("uniqueness", NA) => (NA_KNOWN, never_fault as fn(&str) -> bool),
        ("uniqueness", PostDuplicate)
        | ("uniqueness", PutDuplicate)
        | ("uniqueness", PatchDuplicate) => (UNIQ_KNOWN, uniq_is_fault as fn(&str) -> bool),
        ("returned_never", Post)
        | ("returned_never", Get)
        | ("returned_never", Put)
        | ("returned_never", Patch) => (RN_KNOWN, rn_is_fault as fn(&str) -> bool),
        ("type_wrong", Post) | ("type_wrong", Put) => (TW_KNOWN, tw_is_fault as fn(&str) -> bool),
        ("type_valid", Post) | ("type_valid", Put) => (TV_KNOWN, tv_is_fault as fn(&str) -> bool),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrType, Returned, Uniqueness as U};

    fn decl(path: &str, mutability: Mutability) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: path.to_string(),
            parent: None,
            r#type: AttrType::String,
            mutability,
            returned: Returned::Default,
            uniqueness: U::None,
            case_exact: false,
            required: false,
            multi_valued: false,
            top_multi_valued: false,
            canonical_values: None,
            has_sub_attributes: false,
        }
    }

    #[test]
    fn expand_all_is_deterministic() {
        let decls = vec![decl("userName", Mutability::ReadWrite)];
        let a: Vec<String> = expand_all(&decls).into_iter().map(|d| d.id).collect();
        let b: Vec<String> = expand_all(&decls).into_iter().map(|d| d.id).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn read_only_container_with_sub_attributes_is_na_only() {
        let mut meta = decl("meta", Mutability::ReadOnly);
        meta.r#type = AttrType::Complex;
        meta.has_sub_attributes = true;
        let axes = expand_mutability_readonly(&[meta]);
        assert_eq!(axes.len(), 1);
        assert_eq!(axes[0].method, Method::NA);
    }

    #[test]
    fn read_only_leaf_gets_post_put_patch() {
        let id = decl("id", Mutability::ReadOnly);
        let axes = expand_mutability_readonly(&[id]);
        assert_eq!(axes.len(), 3);
        assert_eq!(
            axes.iter().map(|a| a.method).collect::<Vec<_>>(),
            vec![Method::Post, Method::Put, Method::Patch]
        );
        assert_eq!(axes[0].id, "mutability_readonly/User.id/POST");
    }

    #[test]
    fn ids_are_stable_and_sortable() {
        // "Sortable" means: sorting ids groups every attribute's methods
        // together and orders attributes lexicographically -- not that
        // generation order already equals sort order (it doesn't: methods
        // are emitted POST, PUT, PATCH, which is not their alphabetical
        // order, e.g. "PATCH" < "POST" < "PUT").
        let d1 = decl("aName", Mutability::ReadOnly);
        let d2 = decl("zName", Mutability::ReadOnly);
        let axes = expand_mutability_readonly(&[d1, d2]);
        let ids: Vec<&str> = axes.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids.len(), 6, "2 decls x 3 methods");
        assert_eq!(
            ids.iter().collect::<std::collections::HashSet<_>>().len(),
            ids.len(),
            "every generated id must be unique"
        );
        let mut sorted = ids.clone();
        sorted.sort();
        assert!(
            sorted[0].starts_with("mutability_readonly/User.aName/")
                && sorted[1].starts_with("mutability_readonly/User.aName/")
                && sorted[2].starts_with("mutability_readonly/User.aName/"),
            "sorting groups every attribute's methods together: {sorted:?}"
        );
        assert!(
            sorted[0] < sorted[3],
            "attributes sort lexicographically ahead of one another: {sorted:?}"
        );
    }

    #[test]
    fn writable_attribute_gets_type_wrong_and_type_valid_on_post_and_put() {
        let username = decl("userName", Mutability::ReadWrite);
        let tw = expand_type_wrong(std::slice::from_ref(&username));
        let tv = expand_type_valid(&[username]);
        assert_eq!(
            tw.iter().map(|a| a.method).collect::<Vec<_>>(),
            vec![Method::Post, Method::Put]
        );
        assert_eq!(
            tv.iter().map(|a| a.method).collect::<Vec<_>>(),
            vec![Method::Post, Method::Put]
        );
    }

    #[test]
    fn is_group_member_ref_matches_value_and_ref_only() {
        let mut value = decl("members.value", Mutability::Immutable);
        value.resource = Resource::Group;
        assert!(is_group_member_ref(&value));

        let mut display = decl("members.display", Mutability::ReadOnly);
        display.resource = Resource::Group;
        assert!(!is_group_member_ref(&display));
    }
}
