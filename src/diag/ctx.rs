//! Per-run state threaded through every check.

use std::sync::Arc;

use serde_json::Value;

use crate::diag::cli::DiagOptions;
use crate::diag::client::ScimClient;
use crate::diag::fixtures::FixtureSet;

pub struct DiagContext {
    pub client: ScimClient,
    pub opts: DiagOptions,
    /// ServiceProviderConfig, the input to Tier 3. `None` if it could not
    /// be fetched (which would already have aborted the run via
    /// `DiagError` during preflight, so in practice this is always `Some`
    /// by the time checks run).
    pub spc: Option<Value>,
    /// The parent holds a clone of this `Arc` too, so ids survive an
    /// abort/panic of the runner task.
    ///
    /// Never hold the `MutexGuard` across an `.await` (see `CheckFuture`'s
    /// `Send` bound, §5.9 of the design note): lock, `clone()` the
    /// `Fixture` you need, drop the guard, *then* `.await`.
    pub fixtures: Arc<std::sync::Mutex<FixtureSet>>,
    /// `Some(reason)` means every check with `Need::Writes` is Skipped with
    /// that reason.
    pub writes_disabled: Option<String>,
    /// Negotiated request Content-Type: `"application/scim+json"` or
    /// `"application/json"`.
    pub content_type: &'static str,
    pub state: ProbeState,
}

/// What `fixtures::provision` observed while creating U1 — the only
/// fixture creation that negotiates Content-Type (§5.10's note on
/// `rfc.content_type`). `rfc.content_type`, `rfc.create_user`, and
/// `rfc.location_roundtrip` all read this instead of making their own
/// request: the POST already happened once, up front, during provisioning.
#[derive(Debug, Clone)]
pub struct CreateProbe {
    pub status: u16,
    /// `true` if the first attempt (`application/scim+json`) got a 415 and
    /// a retry with plain `application/json` was needed.
    pub retried_with_plain_json: bool,
    pub location: Option<String>,
    pub id: Option<String>,
    pub resource_type: Option<String>,
    pub detail: String,
}

/// Observations checks hand off to each other. Tier 3's advertised-vs-
/// observed comparisons are the main consumer.
#[derive(Debug, Default, Clone)]
pub struct ProbeState {
    /// The count of "our own fixtures" that `rfc.filter_sw` observed;
    /// `rfc.pagination` uses this to know how far to page.
    pub n_own: Option<i64>,
    pub etag_seen: Option<String>,
    pub patch_observed: Option<bool>,
    pub filter_observed: Option<bool>,
    pub sort_observed: Option<bool>,
    pub etag_observed: Option<bool>,
    /// U1's creation result, filled in by `fixtures::provision`.
    pub create_u1: Option<CreateProbe>,
    /// The status/body-presence of `rfc.patch_add_remove`'s `add`
    /// operation, consumed by `rfc.patch_204_or_200`.
    pub patch_response_status: Option<u16>,
    pub patch_response_had_body: Option<bool>,
    /// `spc.change_password_supported`'s PATCH response body, consumed by
    /// `rfc.password_never_returned` (which also does its own `GET
    /// /Users/{U3}` — it doesn't need the PATCH's status, just its body).
    /// `Some(Value::Null)` means the PATCH was sent but the response had no
    /// (or unparseable) JSON body; `None` means `spc.change_password_supported`
    /// never ran at all (write mode off, `changePassword.supported: false`,
    /// or U3 missing).
    pub change_password_response: Option<Value>,
}
