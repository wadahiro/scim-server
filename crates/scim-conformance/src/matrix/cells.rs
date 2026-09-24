//! The pure part of the matrix: turning a list of [`AttrDecl`] into a list
//! of [`Cell`], with no I/O. `cells_from_decls` must be deterministic (same
//! input -> byte-identical output) since `run_cells` and the tests both
//! depend on that.

use serde::Serialize;

use crate::basis::{self, Basis};
use crate::capability::Capability;
use crate::schema::{AttrDecl, Mutability, Resource};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Characteristic {
    #[serde(rename = "mutability_readOnly")]
    MutabilityReadOnly,
    #[serde(rename = "mutability_immutable")]
    MutabilityImmutable,
    #[serde(rename = "required")]
    Required,
    #[serde(rename = "caseExact")]
    CaseExact,
    #[serde(rename = "uniqueness")]
    Uniqueness,
    #[serde(rename = "returned_never")]
    ReturnedNever,
    #[serde(rename = "type_wrong")]
    TypeWrong,
    #[serde(rename = "type_valid")]
    TypeValid,
    // -- T10c protocol probes (`crate::probes`), not schema-matrix cells --
    // these never appear in `cells_from_decls`'s output, only in `Outcome`s
    // produced directly by a probe function.
    #[serde(rename = "probe_meta_datetime")]
    ProbeMetaDatetime,
    #[serde(rename = "probe_empty_members_shape")]
    ProbeEmptyMembersShape,
    #[serde(rename = "probe_user_groups_presence")]
    ProbeUserGroupsPresence,
    #[serde(rename = "probe_group_members_filter")]
    ProbeGroupMembersFilter,
    #[serde(rename = "probe_group_displayname_filter")]
    ProbeGroupDisplaynameFilter,
    #[serde(rename = "probe_patch_replace_empty_array")]
    ProbePatchReplaceEmptyArray,
    #[serde(rename = "probe_patch_replace_empty_value")]
    ProbePatchReplaceEmptyValue,
    // -- T10 ledger-generated checks (`crate::templates`), produced
    // directly from a `Requirement` -- like the probes above, these never
    // appear in `cells_from_decls`'s output. Named `ledger_<id>_<shape>`
    // per entry id in `crates/scim-conformance/spec/ledger/rfc7644-3.5.2.yaml`.
    #[serde(rename = "ledger_p27_projection")]
    LedgerP27Projection,
    #[serde(rename = "ledger_p26_status")]
    LedgerP26Status,
    #[serde(rename = "ledger_p23_sequence")]
    LedgerP23Sequence,
    #[serde(rename = "ledger_p24_conditional")]
    LedgerP24Conditional,
    #[serde(rename = "ledger_p25_atomicity")]
    LedgerP25Atomicity,
    // -- RFC 7644 §3.14 ETag/versioning checks (`crate::etag`) -- like the
    // probes above, gated on `Capability::Etag` and produced directly by
    // that module rather than `cells_from_decls`.
    #[serde(rename = "etag_representation")]
    EtagRepresentation,
    #[serde(rename = "etag_conditional_read")]
    EtagConditionalRead,
    #[serde(rename = "etag_conditional_write")]
    EtagConditionalWrite,
}

/// The "method" column. Most values are literal HTTP methods, but several
/// characteristics use a compound step label (matching the prototype's
/// output) because the check exercises more than one request per cell
/// (e.g. `required`'s `POST-omit` creates with the attribute missing,
/// distinct from a plain `POST`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Method {
    #[serde(rename = "POST")]
    Post,
    #[serde(rename = "PUT")]
    Put,
    #[serde(rename = "PATCH")]
    Patch,
    #[serde(rename = "GET")]
    Get,
    #[serde(rename = "DELETE")]
    Delete,
    #[serde(rename = "N/A")]
    NA,
    #[serde(rename = "POST-create")]
    PostCreate,
    #[serde(rename = "PATCH-change")]
    PatchChange,
    #[serde(rename = "PUT-change")]
    PutChange,
    #[serde(rename = "POST-omit")]
    PostOmit,
    #[serde(rename = "PUT-omit")]
    PutOmit,
    #[serde(rename = "POST-duplicate")]
    PostDuplicate,
    #[serde(rename = "PUT-duplicate")]
    PutDuplicate,
    #[serde(rename = "PATCH-duplicate")]
    PatchDuplicate,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Cell {
    pub decl: AttrDecl,
    pub resource: Resource,
    pub characteristic: Characteristic,
    pub method: Method,
    pub basis: Basis,
    /// `Some(cap)` when this cell can only be exercised if the provider
    /// advertises `cap` as supported (see `crate::capability::gate`). Set
    /// for every PATCH-method cell (`Patch`, `PatchChange`,
    /// `PatchDuplicate` all require `Capability::Patch`); nothing else in
    /// the matrix needs one yet.
    pub requires_capability: Option<Capability>,
}

/// The capability (if any) needed to exercise a cell with this `method`.
fn requires_capability_for(method: Method) -> Option<Capability> {
    match method {
        Method::Patch | Method::PatchChange | Method::PatchDuplicate => Some(Capability::Patch),
        _ => None,
    }
}

/// Whether a top-level complex attribute with declared sub-attributes
/// decomposes into per-subattribute readOnly checks instead of being probed
/// as a whole (ported from `checks.py`'s `is_container_skip`).
pub fn is_container_skip(decl: &AttrDecl) -> bool {
    decl.depth() == 1 && decl.r#type == crate::schema::AttrType::Complex && decl.has_sub_attributes
}

fn cell(decl: &AttrDecl, characteristic: Characteristic, method: Method) -> Cell {
    Cell {
        decl: decl.clone(),
        resource: decl.resource,
        characteristic,
        method,
        basis: basis::basis_for(characteristic, method),
        requires_capability: requires_capability_for(method),
    }
}

/// Generates the full check matrix from a flattened attribute list. Pure
/// and deterministic: iterates `decls` in order, and for each declared
/// characteristic emits its methods in a fixed order.
pub fn cells_from_decls(decls: &[AttrDecl]) -> Vec<Cell> {
    use Characteristic::*;
    use Method::*;

    let mut out = Vec::new();
    for decl in decls {
        if decl.mutability == Mutability::ReadOnly {
            if is_container_skip(decl) {
                out.push(cell(decl, MutabilityReadOnly, NA));
            } else {
                out.push(cell(decl, MutabilityReadOnly, Post));
                out.push(cell(decl, MutabilityReadOnly, Put));
                out.push(cell(decl, MutabilityReadOnly, Patch));
            }
        }
        if decl.mutability == Mutability::Immutable {
            out.push(cell(decl, MutabilityImmutable, PostCreate));
            out.push(cell(decl, MutabilityImmutable, PatchChange));
            out.push(cell(decl, MutabilityImmutable, PutChange));
        }
        if decl.required {
            if decl.mutability == Mutability::ReadOnly {
                out.push(cell(decl, Required, NA));
            } else {
                out.push(cell(decl, Required, PostOmit));
                out.push(cell(decl, Required, PutOmit));
            }
        }
        if decl.case_exact {
            let skip = decl.mutability == Mutability::ReadOnly
                || decl.returned == crate::schema::Returned::Never
                || is_group_member_ref(decl);
            if skip {
                out.push(cell(decl, CaseExact, NA));
            } else {
                out.push(cell(decl, CaseExact, Post));
            }
        }
        if matches!(
            decl.uniqueness,
            crate::schema::Uniqueness::Server | crate::schema::Uniqueness::Global
        ) {
            if decl.mutability == Mutability::ReadOnly {
                out.push(cell(decl, Uniqueness, NA));
            } else {
                out.push(cell(decl, Uniqueness, PostDuplicate));
                out.push(cell(decl, Uniqueness, PutDuplicate));
                out.push(cell(decl, Uniqueness, PatchDuplicate));
            }
        }
        if decl.returned == crate::schema::Returned::Never {
            out.push(cell(decl, ReturnedNever, Post));
            out.push(cell(decl, ReturnedNever, Get));
            out.push(cell(decl, ReturnedNever, Put));
            out.push(cell(decl, ReturnedNever, Patch));
        }
        if decl.mutability != Mutability::ReadOnly {
            out.push(cell(decl, TypeWrong, Post));
            out.push(cell(decl, TypeWrong, Put));
            // Emitted unconditionally even when `returned: never` — the
            // check itself degrades to SKIP in that case (a round trip
            // can't be observed in any response), but the cell still
            // exists so the matrix stays a pure function of the decls.
            out.push(cell(decl, TypeValid, Post));
            out.push(cell(decl, TypeValid, Put));
        }
    }
    out
}

pub fn is_group_member_ref(decl: &AttrDecl) -> bool {
    decl.resource == Resource::Group
        && decl.top() == "members"
        && (decl.last() == "value" || decl.last() == "$ref")
}

pub fn is_group_member_subattr(decl: &AttrDecl) -> bool {
    decl.resource == Resource::Group && decl.depth() > 1 && decl.top() == "members"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrType, Returned, Uniqueness as U};

    fn decl(path: &str, parent: Option<&str>, mutability: Mutability) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: path.to_string(),
            parent: parent.map(String::from),
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
    fn cells_from_decls_is_deterministic() {
        let decls = vec![decl("userName", None, Mutability::ReadWrite)];
        assert_eq!(cells_from_decls(&decls), cells_from_decls(&decls));
    }

    #[test]
    fn read_only_container_with_sub_attributes_is_skipped_not_probed() {
        let mut meta = decl("meta", None, Mutability::ReadOnly);
        meta.r#type = AttrType::Complex;
        meta.has_sub_attributes = true;
        let cells = cells_from_decls(&[meta]);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0].method, Method::NA);
        assert_eq!(cells[0].characteristic, Characteristic::MutabilityReadOnly);
    }

    #[test]
    fn read_only_leaf_gets_post_put_patch() {
        let id = decl("id", None, Mutability::ReadOnly);
        let cells = cells_from_decls(&[id]);
        assert_eq!(cells.len(), 3);
        assert_eq!(
            cells.iter().map(|c| c.method).collect::<Vec<_>>(),
            vec![Method::Post, Method::Put, Method::Patch]
        );
    }

    #[test]
    fn writable_attribute_gets_type_wrong_and_type_valid_on_post_and_put() {
        let username = decl("userName", None, Mutability::ReadWrite);
        let cells = cells_from_decls(&[username]);
        let type_cells: Vec<_> = cells.iter().map(|c| (c.characteristic, c.method)).collect();
        assert_eq!(
            type_cells,
            vec![
                (Characteristic::TypeWrong, Method::Post),
                (Characteristic::TypeWrong, Method::Put),
                (Characteristic::TypeValid, Method::Post),
                (Characteristic::TypeValid, Method::Put),
            ]
        );
    }

    #[test]
    fn is_group_member_ref_matches_value_and_ref_only() {
        let value = decl("members.value", Some("members"), Mutability::Immutable);
        let mut value = value;
        value.resource = Resource::Group;
        assert!(is_group_member_ref(&value));

        let mut display = decl("members.display", Some("members"), Mutability::ReadOnly);
        display.resource = Resource::Group;
        assert!(!is_group_member_ref(&display));
    }
}
