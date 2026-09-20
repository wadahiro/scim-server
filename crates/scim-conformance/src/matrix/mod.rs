pub mod cells;
pub mod exec;

pub use cells::{
    cells_from_decls, is_container_skip, is_group_member_ref, is_group_member_subattr, Cell,
    Characteristic, Method,
};
pub use exec::run_cells;

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
}

impl Verdict {
    pub fn tag(&self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
            Verdict::Error => "ERROR",
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
    /// in [`crate::probes`]. `None` for schema-matrix cells (see
    /// `crate::matrix::exec`), which describe everything in `detail`
    /// instead; skipped so the schema-matrix golden fixture (which predates
    /// this field) still compares equal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed: Option<String>,
}
