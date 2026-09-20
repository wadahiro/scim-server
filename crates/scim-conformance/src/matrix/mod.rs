pub mod cells;
pub mod exec;

pub use cells::{
    cells_from_decls, is_container_skip, is_group_member_ref, is_group_member_subattr, Cell,
    Characteristic, Method,
};
pub use exec::run_cells;
// Pure request-construction helpers, exposed so
// `tests/conformance_schema_matrix.rs`'s targeting invariant can build
// exactly the same requests the executors above send, rather than
// reimplementing (and risking drifting from) that logic. See
// `exec`'s "precise PATCH targeting" section for the soundness contract
// these are part of.
pub use exec::{
    build_patch_request, container_is_readonly, dotted_path, first_writable_subattr,
    forged_value_for, get_attr, immutable_post_payload, make_baseline, patch_body, patch_path,
    patch_targets_decl_precisely, patch_value_for, path_segments, set_attr,
    set_attr_with_companion, valid_value_for, value_filtered_patch_request, values_match,
    wrong_value_for, PatchRequestPlan, ENTERPRISE_URN,
};

use serde::Serialize;

use crate::basis::Basis;
use crate::schema::Resource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Verdict {
    Pass,
    Fail,
    Skip,
    /// The probe itself failed (transport error, unexpected precondition
    /// failure, ...). The golden run never produced one of these; a Rust
    /// port that does should be treated as a bug, not a finding.
    Error,
    /// Not judged at all -- e.g. `crate::gen::attrdefs`'s checks for an
    /// `OPTIONAL` (not `REQUIRED`) attribute, which the Python prototype
    /// (`tools/prototype/run_attrdef_checks.py`) reports for information
    /// only and never counts as pass or fail.
    Info,
}

impl Verdict {
    pub fn tag(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
            Verdict::Error => "ERROR",
            Verdict::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    pub attribute: String,
    pub schema: String,
    pub resource: Resource,
    pub characteristic: Characteristic,
    pub method: Method,
    pub verdict: Verdict,
    pub basis: Basis,
    pub detail: String,
    /// A short canonical description of what was actually observed (e.g.
    /// `"rfc3339"`, `"epoch"`, `"status=400"`), set by the protocol probes
    /// in [`crate::probes`]. `None` for almost every schema-matrix cell
    /// (see `crate::matrix::exec`), which describe everything in `detail`
    /// instead; skipped so the schema-matrix golden fixture (which predates
    /// this field) still compares equal. The one schema-matrix exception is
    /// `mutability_readOnly`'s PATCH judgement (RFC 7644 §3.5.2), which
    /// also sets this -- the golden fixture excludes those rows from its
    /// comparison entirely (see `tests/conformance_schema_matrix.rs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
    /// Additional RFC citations beyond `basis` (T10's ledger-generated
    /// checks: e.g. a projection cell exercised through POST/PUT cites its
    /// own requirement's basis (§3.5.2) plus a secondary citation to
    /// §3.9's general rule). Empty for almost every schema-matrix cell and
    /// probe, which cite exactly one basis; skipped when empty so the
    /// schema-matrix golden fixture (which predates this field) still
    /// compares equal. The one schema-matrix exception is
    /// `mutability_readOnly`'s PATCH judgement, which cites §3.5.2 as its
    /// primary basis plus Table 9's `mutability` row (§3.12) here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secondary: Vec<Basis>,
}
