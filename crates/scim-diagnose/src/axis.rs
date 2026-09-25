//! Core types: one observable behavioural dimension ([`Axis`]) of a SCIM
//! provider, one run's finding on that dimension ([`Observation`]), and a
//! full run's results ([`Profile`]). See the crate's top-level docs
//! (`lib.rs`) for how these relate to `crate::render`'s three derived
//! views.

use crate::client::Exchange;
use crate::rfc::RfcPosition;
use serde::Serialize;

/// One observable dimension of a provider's behaviour.
#[derive(Debug, Clone, Copy)]
pub struct Axis {
    /// Stable id, e.g. `"empty_multivalued_rendering"`. Used as the sort
    /// key in `profile_json` and as the axis identity across runs, so it
    /// must never change once an axis ships.
    pub id: &'static str,
    /// One line: what is being observed.
    pub about: &'static str,
    pub rfc: RfcPosition,
    /// The `CompatibilityConfig` field (`src/config.rs`) that emulates this
    /// dimension, if any. `None` means: observing a value here is a
    /// candidate for a new option, not evidence for an existing one.
    pub knob: Option<&'static str>,
    pub cost: Cost,
    /// Values this axis can name. An observation outside this set is a
    /// discovery (`Value::Unknown`), not an error.
    pub known: &'static [&'static str],
}

/// What it costs, in write budget, to observe an axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Cost {
    /// Read-only: `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`,
    /// or a GET/filter query against existing data. Always run.
    DiscoveryOnly,
    /// Requires creating (and cleaning up) at least one User. Only run
    /// with `--allow-writes`, since creating a User may send real mail to
    /// a real person on a production tenant.
    NeedsUser,
    /// Requires creating a User and a Group (or a Group referencing a
    /// User). Only run with `--allow-writes`.
    NeedsUserAndGroup,
}

/// One run's finding for one [`Axis`] (a static axis's `id`, or -- as of
/// the schema-derived families in `crate::matrix` -- a `DerivedAxis`'s
/// owned, generated id such as `"mutability_readonly/User.manager.$ref/PATCH"`).
/// Owned rather than `&'static str` because a derived id is built at run
/// time from the target's own `GET /Schemas` response, not known at compile
/// time the way the seven static axes' ids are.
#[derive(Debug, Clone)]
pub struct Observation {
    pub axis: String,
    pub value: Value,
    /// Always populated when `value` is `Value::Unknown` (the discovery
    /// signal needs full evidence to be useful); otherwise populated only
    /// as the caller's verbosity requests (`crate::runner` always
    /// attaches it -- `render`'s text view is what trims it back down for
    /// a terse default).
    pub evidence: Vec<Exchange>,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub enum Value {
    Known(&'static str),
    /// Something with no name in `Axis::known`. The discovery signal: a
    /// value here is the strongest evidence that a new compatibility knob
    /// is needed.
    Unknown(String),
    Unobservable(Unobservable),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unobservable {
    /// The provider advertised (via `/ServiceProviderConfig`) that it does
    /// not support the capability this axis needs (e.g. `filter`).
    CapabilityNotAdvertised(&'static str),
    /// This axis's `Cost` was `NeedsUser`/`NeedsUserAndGroup` but the run
    /// did not pass `--allow-writes`.
    NeedsWrite,
    /// The axis depends on an attribute or capability that `GET /Schemas`
    /// did not declare for this provider.
    NotDeclaredBySchema,
    /// The probe ran but could not reach a conclusion (fixture creation
    /// failed, an unexpected status came back, etc).
    ProbeFailed(String),
}

impl Unobservable {
    /// Stable, machine-readable token for `profile_json` / `render`.
    pub fn token(&self) -> String {
        match self {
            Unobservable::CapabilityNotAdvertised(cap) => {
                format!("capability_not_advertised:{cap}")
            }
            Unobservable::NeedsWrite => "needs_write".to_string(),
            Unobservable::NotDeclaredBySchema => "not_declared_by_schema".to_string(),
            Unobservable::ProbeFailed(msg) => format!("probe_failed:{msg}"),
        }
    }
}

/// A full diagnostic run against one target.
#[derive(Debug, Clone)]
pub struct Profile {
    pub target: String,
    pub observed_at: String,
    pub observations: Vec<Observation>,
}

impl Profile {
    pub fn get(&self, axis_id: &str) -> Option<&Observation> {
        self.observations.iter().find(|o| o.axis == axis_id)
    }
}
