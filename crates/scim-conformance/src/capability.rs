//! Reads a provider's own `GET /ServiceProviderConfig` response into a
//! [`Capabilities`] struct, and gates generated checks whose
//! `requires_capability` (see [`crate::matrix::Cell`]) names a capability
//! the provider has explicitly advertised as unsupported
//! (`"<member>.supported": false`).
//!
//! Absence of a capability member -- or of its `supported` sub-member, or a
//! non-boolean value there -- parses as `None` ("the provider didn't say"),
//! never as `Some(false)`. Only an explicit `false` gates a check: a
//! provider that simply omits the member is not thereby assumed not to
//! support it.

use serde_json::Value;

use crate::client::ScimClient;
use crate::matrix::{Cell, Outcome, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    Patch,
    Filter,
    Sort,
    Bulk,
    Etag,
    ChangePassword,
}

impl Capability {
    /// The JSON member name in `/ServiceProviderConfig`'s response, and the
    /// token used in a skip reason (`"<name>.supported=false"`).
    pub fn name(&self) -> &'static str {
        match self {
            Capability::Patch => "patch",
            Capability::Filter => "filter",
            Capability::Sort => "sort",
            Capability::Bulk => "bulk",
            Capability::Etag => "etag",
            Capability::ChangePassword => "changePassword",
        }
    }
}

/// `patch/filter/sort/bulk/etag/changePassword.supported`, as declared by a
/// provider's own `/ServiceProviderConfig`. Every field is `Option<bool>`:
/// `None` means the provider didn't say (see module docs).
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    pub patch: Option<bool>,
    pub filter: Option<bool>,
    pub sort: Option<bool>,
    pub bulk: Option<bool>,
    pub etag: Option<bool>,
    pub change_password: Option<bool>,
}

impl Capabilities {
    /// Parses `<member>.supported` for each of the six known members out of
    /// a `/ServiceProviderConfig` JSON body.
    pub fn from_service_provider_config(spc: &Value) -> Self {
        fn supported(spc: &Value, member: &str) -> Option<bool> {
            spc.get(member)?.get("supported")?.as_bool()
        }
        Capabilities {
            patch: supported(spc, "patch"),
            filter: supported(spc, "filter"),
            sort: supported(spc, "sort"),
            bulk: supported(spc, "bulk"),
            etag: supported(spc, "etag"),
            change_password: supported(spc, "changePassword"),
        }
    }

    /// A provider that hasn't told us anything (every member `None`). Used
    /// when `/ServiceProviderConfig` itself can't be fetched or parsed, so
    /// that failure degrades to "no gating" rather than skipping
    /// everything.
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn get(&self, cap: Capability) -> Option<bool> {
        match cap {
            Capability::Patch => self.patch,
            Capability::Filter => self.filter,
            Capability::Sort => self.sort,
            Capability::Bulk => self.bulk,
            Capability::Etag => self.etag,
            Capability::ChangePassword => self.change_password,
        }
    }
}

/// Fetches `GET /ServiceProviderConfig` and parses it into [`Capabilities`].
/// A non-2xx response or an unparseable body degrades to
/// [`Capabilities::unknown`] rather than erroring the whole run.
pub async fn fetch(client: &ScimClient) -> Capabilities {
    match client.get("/ServiceProviderConfig").await {
        Ok(r) if r.is_success() => {
            Capabilities::from_service_provider_config(&r.body.unwrap_or(Value::Null))
        }
        _ => Capabilities::unknown(),
    }
}

/// The result of gating one cell against a provider's [`Capabilities`].
#[derive(Debug)]
pub enum Gated {
    /// Run the cell normally.
    Run,
    /// Skip without sending any request; carries the finished [`Outcome`].
    Skip(Outcome),
}

/// Decides, for each cell in `cells`, whether its `requires_capability` (if
/// any) names a capability explicitly advertised as unsupported (`Some(cap)`
/// and `caps.get(cap) == Some(false)`). Pure and deterministic: no I/O, and
/// callable with no server at all -- see the unit tests below, and
/// `tests/conformance_capability_gate.rs`, which builds `cells` and `caps`
/// from exactly two `GET`s and never touches any other endpoint to compute
/// the gating decision itself.
pub fn gate(cells: &[Cell], caps: &Capabilities) -> Vec<Gated> {
    cells
        .iter()
        .map(|cell| match cell.requires_capability {
            Some(cap) if caps.get(cap) == Some(false) => Gated::Skip(skip_outcome(cell, cap)),
            _ => Gated::Run,
        })
        .collect()
}

fn skip_outcome(cell: &Cell, cap: Capability) -> Outcome {
    Outcome {
        attribute: cell.decl.path.clone(),
        schema: cell.decl.schema.clone(),
        resource: cell.resource,
        characteristic: cell.characteristic,
        method: cell.method,
        verdict: Verdict::Skip,
        basis: cell.basis,
        detail: format!("{}.supported=false", cap.name()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matrix::Method;
    use crate::schema::{AttrDecl, AttrType, Mutability, Resource, Returned, Uniqueness};
    use serde_json::json;

    fn patch_cell() -> Cell {
        let decl = AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: "userName".to_string(),
            parent: None,
            r#type: AttrType::String,
            mutability: Mutability::ReadOnly,
            returned: Returned::Default,
            uniqueness: Uniqueness::None,
            case_exact: false,
            required: false,
            multi_valued: false,
            top_multi_valued: false,
            canonical_values: None,
            has_sub_attributes: false,
        };
        Cell {
            resource: decl.resource,
            basis: crate::basis::MUTABILITY_READ_ONLY,
            characteristic: crate::matrix::Characteristic::MutabilityReadOnly,
            method: Method::Patch,
            requires_capability: Some(Capability::Patch),
            decl,
        }
    }

    fn non_gated_cell() -> Cell {
        let mut c = patch_cell();
        c.method = Method::Post;
        c.requires_capability = None;
        c
    }

    #[test]
    fn unsupported_capability_skips_without_a_reason_leak() {
        let caps = Capabilities {
            patch: Some(false),
            ..Capabilities::unknown()
        };
        let cells = vec![patch_cell()];
        let gated = gate(&cells, &caps);
        assert_eq!(gated.len(), 1);
        match &gated[0] {
            Gated::Skip(o) => {
                assert_eq!(o.verdict, Verdict::Skip);
                assert_eq!(o.detail, "patch.supported=false");
            }
            Gated::Run => panic!("expected Skip"),
        }
    }

    #[test]
    fn supported_capability_runs() {
        let caps = Capabilities {
            patch: Some(true),
            ..Capabilities::unknown()
        };
        let cells = vec![patch_cell()];
        let gated = gate(&cells, &caps);
        assert!(matches!(gated[0], Gated::Run));
    }

    #[test]
    fn absent_capability_does_not_skip() {
        // None ("the provider didn't say") must not be treated as false.
        let caps = Capabilities::unknown();
        let cells = vec![patch_cell()];
        let gated = gate(&cells, &caps);
        assert!(matches!(gated[0], Gated::Run));
    }

    #[test]
    fn cells_with_no_capability_requirement_always_run() {
        let caps = Capabilities {
            patch: Some(false),
            ..Capabilities::unknown()
        };
        let cells = vec![non_gated_cell()];
        let gated = gate(&cells, &caps);
        assert!(matches!(gated[0], Gated::Run));
    }

    #[test]
    fn from_service_provider_config_reads_each_member() {
        let spc = json!({
            "patch": {"supported": false},
            "filter": {"supported": true},
            "sort": {"supported": true},
            "bulk": {"supported": false},
            "etag": {"supported": true},
            "changePassword": {"supported": false},
        });
        let caps = Capabilities::from_service_provider_config(&spc);
        assert_eq!(caps.patch, Some(false));
        assert_eq!(caps.filter, Some(true));
        assert_eq!(caps.sort, Some(true));
        assert_eq!(caps.bulk, Some(false));
        assert_eq!(caps.etag, Some(true));
        assert_eq!(caps.change_password, Some(false));
    }

    #[test]
    fn missing_member_parses_as_none_not_false() {
        let caps = Capabilities::from_service_provider_config(&json!({}));
        assert_eq!(caps.patch, None);
        assert_eq!(caps.get(Capability::Patch), None);
    }
}
