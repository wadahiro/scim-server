//! Schema-derived axis families: axes whose instances are not known at
//! compile time (unlike `crate::axes::AXES`'s seven fixed axes) but are
//! generated at run time, one per (attribute x characteristic x method),
//! from the target's own `GET /Schemas` response.
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/matrix/`
//! (`cells.rs`'s generator, `exec.rs`'s executors) -- adapted from that
//! crate's fixed pass/fail `Outcome`/`Verdict` shape to this crate's
//! `Observation`/`Value` model. The generator (`derive::expand_all`,
//! `derive.rs`) is close to a 1:1 port of `cells_from_decls`: same
//! predicates, same fixed emission order per characteristic, so that this
//! crate's instance count matches what the source branch's schema matrix
//! would generate for the same declarations. The executors (`exec.rs`) are
//! a port of the *logic*, not the code: this crate's executors produce a
//! `DerivedAxis`'s `Value`, not an `Outcome`.

pub mod derive;
pub mod exec;

pub use derive::{
    expand_all, family_for, is_container_skip, is_group_member_ref, is_group_member_subattr,
    known_and_fault_for, resource_label, DerivedAxis, DerivedFamily, Method, DERIVED_FAMILIES,
};
pub use exec::{
    build_patch_request, patch_targets_decl_precisely, run_derived_family, PatchRequestPlan,
};
