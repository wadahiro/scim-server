//! Reads a provider's own `GET /ServiceProviderConfig` response into a
//! [`Capabilities`] struct, used to gate axes whose `Axis::cost` needs a
//! capability the provider has explicitly advertised as unsupported
//! (`"<member>.supported": false`).
//!
//! Absence of a capability member -- or of its `supported` sub-member, or a
//! non-boolean value there -- parses as `None` ("the provider didn't say"),
//! never as `Some(false)`. Only an explicit `false` gates an axis: a
//! provider that simply omits the member is not thereby assumed not to
//! support it.
//!
//! Ported from `feat/rfc-extract`'s `crates/scim-conformance/src/capability.rs`
//! (`Capability`, `Capabilities`, `fetch` taken as-is). The `gate`/`Gated`
//! machinery from that file is dropped here: it gated a `Cell` from the
//! schema-driven matrix, which this crate does not port -- axis gating on
//! capability is instead inline in `crate::runner`, next to the
//! `Cost`/`--allow-writes` gating it shares a call site with.

use serde_json::Value;

use crate::client::ScimClient;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
