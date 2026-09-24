//! T11: a single flat shape every check family in this crate converts
//! into, so `diagnose` (and the `scim-server diagnose` CLI built on it) can
//! print one report that mixes the schema-driven matrix
//! ([`crate::matrix::Outcome`], T9b/T10c), the ledger-generated checks
//! (also `Outcome`, T10), and the discovery presence checks
//! ([`crate::gen::attrdefs::AttrdefCheck`], T9) without the caller having
//! to know which family a given check came from.
//!
//! [`Outcome`] already carries almost every field [`Finding`] needs
//! (`verdict`, `basis`, `secondary`, `detail`, `observed`); what it
//! doesn't carry is a single stable string identifying *which* check this
//! is -- that's assembled into [`Finding::key`] from `Outcome`'s
//! `resource`/`attribute`/`characteristic`/`method`. `AttrdefCheck` is
//! smaller (no `secondary`, no `observed` -- see its own doc comment for
//! why) and converts with defaults for those.

use crate::basis::Basis;
use crate::gen::attrdefs::AttrdefCheck;
use crate::matrix::{Characteristic, Keyword, Method, Outcome, Verdict};
use crate::schema::Resource;

/// One generated check, flattened out of whichever family produced it.
///
/// `family` is one of `"schema"` (schema-driven matrix, T9b), `"probe"`
/// (protocol probes, T10c), `"ledger"` (RFC 7644 §3.5.2 ledger-generated
/// checks, T10), or `"discovery"` (RFC 7643 §5/§6/§7 and RFC 7644 §3.4.2
/// required-member presence checks, T9).
#[derive(Debug, Clone)]
pub struct Finding {
    pub family: &'static str,
    /// A stable identifier for this check, e.g.
    /// `"EnterpriseUser.manager.$ref/mutability_readOnly/PUT"` (schema/
    /// probe/ledger findings) or `"discovery/7643§5/authenticationSchemes.type"`
    /// (discovery findings -- the RFC section is folded into the key
    /// because `attribute` alone is not unique across the four discovery
    /// targets, see `From<AttrdefCheck>` below).
    pub key: String,
    pub verdict: Verdict,
    pub basis: Basis,
    pub secondary: Vec<Basis>,
    pub detail: String,
    pub observed: Option<String>,
    /// The RFC 2119 strength of the rule this finding judges -- see
    /// [`Keyword`]. `None` for every family that predates the §3.14
    /// ETag/versioning family (`crate::etag`), which introduced the
    /// distinction.
    pub keyword: Option<Keyword>,
}

/// Renders a `#[derive(Serialize)]` enum variant the same way `serde_json`
/// would (its already-declared `#[serde(rename = ...)]` strings, e.g.
/// `"mutability_readOnly"` for `Characteristic::MutabilityReadOnly`),
/// rather than re-typing every rename as a second, easily-drifting match
/// arm. Matches the pattern `tests/conformance_schema_matrix.rs` already
/// uses for the same purpose.
fn ser_tag<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|j| j.as_str().map(str::to_string))
        .unwrap_or_else(|| "?".to_string())
}

fn resource_tag(r: Resource) -> String {
    ser_tag(&r)
}

fn outcome_key(
    resource: Resource,
    attribute: &str,
    characteristic: Characteristic,
    method: Method,
) -> String {
    format!(
        "{}.{}/{}/{}",
        resource_tag(resource),
        attribute,
        ser_tag(&characteristic),
        ser_tag(&method)
    )
}

/// `"schema"` for the schema-driven matrix's own characteristics,
/// `"probe"` for T10c's protocol probes, `"ledger"` for T10's
/// ledger-generated checks -- the three families [`crate::full_suite`]
/// composes, distinguished purely by which `Characteristic` variant a
/// given `Outcome` carries.
fn family_for(characteristic: Characteristic) -> &'static str {
    use Characteristic::*;
    match characteristic {
        LedgerP27Projection | LedgerP26Status | LedgerP23Sequence | LedgerP24Conditional
        | LedgerP25Atomicity => "ledger",
        EtagRepresentation | EtagConditionalRead | EtagConditionalWrite => "etag",
        ProbeMetaDatetime
        | ProbeEmptyMembersShape
        | ProbeUserGroupsPresence
        | ProbeGroupMembersFilter
        | ProbeGroupDisplaynameFilter
        | ProbePatchReplaceEmptyArray
        | ProbePatchReplaceEmptyValue => "probe",
        MutabilityReadOnly | MutabilityImmutable | Required | CaseExact | Uniqueness
        | ReturnedNever | TypeWrong | TypeValid => "schema",
    }
}

impl From<Outcome> for Finding {
    fn from(o: Outcome) -> Self {
        Finding {
            family: family_for(o.characteristic),
            key: outcome_key(o.resource, &o.attribute, o.characteristic, o.method),
            verdict: o.verdict,
            basis: o.basis,
            secondary: o.secondary,
            detail: o.detail,
            observed: o.observed,
            keyword: o.keyword,
        }
    }
}

impl From<AttrdefCheck> for Finding {
    fn from(c: AttrdefCheck) -> Self {
        // `attribute` alone collides: "id", "name", and "description" each
        // name an attribute in more than one of the four TARGETS sections
        // (e.g. `ResourceType.id` (§6) and `Schema.id` (§7) are both just
        // "id"). `rfc_section` (`"RFC 7643 §6"`) disambiguates them --
        // folded in as `"7643§6"` so the key stays one path-like token.
        let section_tag = c.rfc_section.trim_start_matches("RFC ").replace(' ', "");
        Finding {
            family: "discovery",
            key: format!("discovery/{section_tag}/{}", c.attribute),
            verdict: c.verdict,
            basis: c.basis,
            secondary: Vec::new(),
            detail: c.detail,
            observed: None,
            keyword: None,
        }
    }
}

/// Tally of [`Finding::verdict`] across a [`DiagnosticReport`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub pass: usize,
    pub fail: usize,
    pub skip: usize,
    pub info: usize,
    pub error: usize,
}

impl Counts {
    pub fn tally(findings: &[Finding]) -> Self {
        let mut c = Counts::default();
        for f in findings {
            match f.verdict {
                Verdict::Pass => c.pass += 1,
                Verdict::Fail => c.fail += 1,
                Verdict::Skip => c.skip += 1,
                Verdict::Info => c.info += 1,
                Verdict::Error => c.error += 1,
            }
        }
        c
    }

    pub fn total(&self) -> usize {
        self.pass + self.fail + self.skip + self.info + self.error
    }
}

/// Everything `diagnose`/`diag::run` produced against one target.
#[derive(Debug, Clone)]
pub struct DiagnosticReport {
    pub target: String,
    pub findings: Vec<Finding>,
    pub counts: Counts,
}
