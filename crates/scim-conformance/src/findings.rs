//! T12: the five schema-matrix non-conformances this crate's generated
//! checks found while evaluating this repository's own reference server
//! (the other two findings this generation effort produced live in the
//! ledger-matrix checks and are not classified here -- see
//! `crate::scoreboard`'s `regression_guards` section for the full set of
//! seven). All five were **fixed in PR #72**. `classify_regression` is
//! kept, post-fix, purely as a regression-diagnosis label: it no longer
//! demonstrates that this suite *catches* these findings (a fixed server
//! has nothing left to catch), it only names which historical finding a
//! FAIL outcome would have belonged to, if one reappeared.
//!
//! `patch-readonly-not-rejected`'s arm (PATCH against a readOnly
//! attribute) used to be reported as having a live, narrow residual on
//! `Group.members.display`: that conclusion was wrong. The *probe* for
//! that one cell was unsound (see
//! `crates/scim-conformance/src/matrix/exec.rs`'s `container_is_readonly`
//! doc comment and `tests/conformance_schema_matrix.rs`'s
//! `patch_mutability_readonly_fails_are_zero`), not the server; PR #73
//! corrected the probe to target the sub-attribute precisely with a value
//! filter, and the cell now measures PASS like every other
//! `patch-readonly-not-rejected` cell.
//!
//! `classify_regression` used to be a private function duplicated inside
//! `tests/conformance_schema_matrix.rs`. T12's scoreboard (`crate::
//! scoreboard`) needs the exact same classification to report the
//! regression-guard section, so it is factored out here as the one shared,
//! testable definition; the test file now imports it instead of keeping
//! its own copy.

use crate::matrix::Characteristic::*;
use crate::matrix::{Method, Outcome};
use crate::schema::Resource;

/// Classifies a FAIL outcome as one of the five known, now-fixed
/// non-conformances found while evaluating this generator against this
/// server. Anything else is a candidate *new* finding and must not be
/// silently added here.
pub fn classify_regression(o: &Outcome) -> Option<&'static str> {
    let attr = o.attribute.as_str();
    match (o.resource, o.characteristic, attr, o.method) {
        // patch-readonly-not-rejected: PATCH targeting a readOnly attribute
        // is silently ignored (2xx) instead of being rejected with 400
        // scimType=mutability -- RFC 7644 §3.5.2 L1886-1894, Table 9's
        // mutability row (§3.12). Every mutability_readOnly PATCH cell is
        // judged by this rule, not by readonly-extension-subattr-echo's
        // echo-back predicate below, so this arm must come first: it takes
        // precedence for PATCH even for manager.$ref / manager.displayName,
        // which also happen to echo the forged value.
        (_, MutabilityReadOnly, _, Method::Patch) => Some("patch-readonly-not-rejected"),

        // readonly-extension-subattr-echo: readOnly manager.$ref /
        // manager.displayName (enterprise extension) forged values are
        // echoed back on POST/PUT -- RFC 7644 §3.3 L583-584 (POST) /
        // §3.5.1 L1665 (PUT).
        (
            Resource::EnterpriseUser,
            MutabilityReadOnly,
            "manager.$ref",
            Method::Post | Method::Put,
        ) => Some("readonly-extension-subattr-echo"),
        (
            Resource::EnterpriseUser,
            MutabilityReadOnly,
            "manager.displayName",
            Method::Post | Method::Put,
        ) => Some("readonly-extension-subattr-echo"),

        // required-on-put: PUT /Groups/{id} without displayName -> 200
        // (required not enforced on PUT) -- RFC 7643 §7 L1731-1732.
        (Resource::Group, Required, "displayName", Method::PutOmit) => Some("required-on-put"),

        // type-validation-bypass: wrong-typed values accepted -- RFC 7643
        // §2.3 L438.
        (Resource::Group, TypeWrong, "externalId", Method::Post | Method::Put) => {
            Some("type-validation-bypass")
        }
        (Resource::Group, TypeWrong, a, Method::Post | Method::Put)
            if a == "members" || a.starts_with("members.") =>
        {
            Some("type-validation-bypass")
        }
        (Resource::User, TypeWrong, a, Method::Post | Method::Put)
            if a.starts_with("addresses.") =>
        {
            Some("type-validation-bypass")
        }

        // readonly-multivalued-echo-on-create: readOnly User.groups forged
        // values appear in the POST response (GET shows []) -- RFC 7644
        // §3.3.
        (Resource::User, MutabilityReadOnly, a, Method::Post)
            if a == "groups.value" || a == "groups.$ref" || a == "groups.display" =>
        {
            Some("readonly-multivalued-echo-on-create")
        }

        _ => None,
    }
}
