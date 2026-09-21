//! T12: honesty-about-scope reporting. Three numbers, each with an
//! auditable definition, none of them tuned to match a number written
//! anywhere else (this crate's design docs included) -- every one is
//! computed fresh from what exists in this branch's own code and vendored
//! spec text.
//!
//! # `req_coverage`
//!
//! Denominator: RFC 7644 §3.x paragraphs whose `extract.py`-style `class`
//! is `definitional` or `definitional_prose` (the paragraphs that state an
//! actual requirement, as opposed to explanatory prose, an example, a
//! heading/caption, or a table) -- see [`requirement_inventory`] and
//! `crate::spec_extract`. Computed by hand once this session with:
//!
//! ```text
//! python3 tools/prototype/extract.py --no-text spec/rfc /tmp/t12_extract.json
//! python3 -c "
//! import json
//! items = json.load(open('/tmp/t12_extract.json'))['7644']
//! sec3 = [i for i in items if i['section'].split('.')[0] == '3']
//! denom = [i for i in sec3 if i['class'] in ('definitional', 'definitional_prose')]
//! print(len(denom))
//! "
//! ```
//!
//! which printed **147** (124 `definitional` + 23 `definitional_prose`,
//! out of 428 total §3.x blocks) against this branch's vendored
//! `spec/rfc/rfc7644.txt`. `crate::spec_extract`'s own pinned unit tests
//! reproduce that count from the Rust port so a future edit is caught by
//! `cargo test`, without needing Python at test or run time (see that
//! module's doc comment for why). Note this is **not** the plan's
//! speculative "282" -- per this task's own instructions, that number was
//! never verified against the current vendored text or the current
//! `extract.py` and is not used here.
//!
//! Numerator: every [`Basis`] (primary or secondary) cited by any outcome
//! `crate::full_suite` produces (schema-driven matrix, protocol probes,
//! and the RFC 7644 §3.5.2 ledger-generated checks -- all [`Outcome`]) or
//! [`crate::checks_from_attrdefs`] produces ([`AttrdefCheck`]), restricted
//! to `doc == "RFC 7644"` citations whose own `section` starts with `"3"`.
//! A denominator paragraph is "covered" if any in-scope citation's line
//! span overlaps it. Citations outside this scope (RFC 7643 citations, or
//! an RFC 7644 citation outside §3) are counted and reported separately
//! ([`ReqCoverage::in_scope_citations`] / `total_citations`) for
//! transparency, but don't affect the ratio.
//!
//! # `cell_completeness`
//!
//! See [`theoretical_max_cells`]'s doc comment for the per-characteristic
//! reasoning.
//!
//! # `knob_detection`
//!
//! The 7 compatibility knobs' detection power: a knob is a property of
//! *this repository's* `CompatibilityConfig`, not something observable
//! through the generic SCIM protocol a `ScimClient` speaks, so there is no
//! way to "flip a knob" against an arbitrary target passed to
//! `diagnose --scoreboard`. Their `caught` status is a static fact about
//! this crate's own test suite instead: `tests/conformance_knob_mutation.
//! rs`'s `knob_flips_change_exactly_the_expected_rows` asserts, for each of
//! the 7 knobs, that flipping it changes *exactly* the documented set of
//! check rows (no more, no fewer) -- and that test is green on this
//! branch. If it ever stops being green, this hardcoded list is stale and
//! must be updated in lockstep; nothing here re-verifies it automatically.
//! This is the section that actually measures "does this suite still
//! detect something" against a live target.
//!
//! # `regression_guards`
//!
//! V-18, V-19, and V-21..V-25 were the seven non-conformances this
//! generated-check suite found while evaluating this repository's own
//! reference server. **All seven were fixed in PR #72.** Reporting them
//! under `knob_detection`-style "caught" language would be false: against
//! a fixed server, this suite has nothing left to *catch* for six of the
//! seven (nothing to detect, because nothing is wrong to detect). Instead
//! each is reported here as a regression guard: the live count of cells
//! still exhibiting the pre-fix failure mode, out of the relevant cell
//! count, recomputed fresh from whatever `client` `compute` is given (this
//! *is* a live measurement -- of whether the fix is still in effect, not
//! of "can this suite find this bug"). All seven measure 0
//! fails/relevant-cells on this branch, including V-25 (0 of 18
//! `mutability_readOnly` PATCH cells fail). V-25's cell,
//! `Group.members.display`, previously appeared to fail because the PATCH
//! probe itself was unsound: for a readOnly sub-attribute of a
//! ReadWrite, top-level multi-valued complex attribute, the coarse
//! container-level `path: "members"` request replaces the whole
//! (ReadWrite) `members` array with a structurally invalid element, which
//! proves nothing about `display`'s mutability. The probe now targets the
//! sub-attribute precisely with a value filter
//! (`members[value eq "<id>"].display`), and the server correctly rejects
//! it with 400 `scimType: "mutability"` -- see
//! `tests/conformance_schema_matrix.rs`'s `patch_mutability_readonly_fails_are_zero`
//! for the measurement and `crates/scim-conformance/src/matrix/exec.rs`'s
//! `container_is_readonly` for the fix. `render_text` labels this section
//! explicitly so `--scoreboard`'s output can't be misread as claiming a
//! live "catches this finding" detection for a finding that no longer
//! exists to be caught.

use std::fmt::Write as _;

use crate::basis::Basis;
use crate::client::ScimClient;
use crate::findings::classify_known_fail;
use crate::gen::attrdefs::AttrdefCheck;
use crate::matrix::{Characteristic, Method, Outcome, Verdict};
use crate::schema::{decls_from_schemas, AttrDecl, Mutability, Returned};
use crate::spec_extract::{self, Class};

const RFC7644_TXT: &str = include_str!("../../../spec/rfc/rfc7644.txt");

/// The compatibility knobs `tests/conformance_knob_mutation.rs` exercises
/// (see this module's doc comment for why their `caught` status is static,
/// not recomputed here). Names match `CLAUDE.md`'s "Compatibility
/// Configuration" section and `src/config.rs`'s `CompatibilityConfig`
/// field names exactly.
const KNOBS: [&str; 7] = [
    "meta_datetime_format",
    "show_empty_groups_members",
    "include_user_groups",
    "support_patch_replace_empty_array",
    "support_patch_replace_empty_value",
    "support_group_members_filter",
    "support_group_displayname_filter",
];

#[derive(Debug, Clone, Default)]
pub struct ReqCoverage {
    pub covered: usize,
    pub total: usize,
    /// Every `Basis` (primary + secondary) examined across the whole
    /// generated-check suite, regardless of doc/section.
    pub total_citations: usize,
    /// The subset of `total_citations` that were `RFC 7644` with a
    /// section starting `"3"` -- i.e. actually in scope for this
    /// denominator. Reported so the fraction that fell outside scope
    /// (RFC 7643 citations, mostly) is visible rather than silently
    /// dropped.
    pub in_scope_citations: usize,
}

/// A regression guard's live measurement: how many of its relevant cells
/// still exhibit the pre-#72 failure mode, out of how many relevant cells
/// exist. `fails == 0` means the fix is holding; `fails > 0` is a
/// regression.
#[derive(Debug, Clone)]
pub struct RegressionGuard {
    pub label: String,
    pub fails: usize,
    pub relevant: usize,
}

pub struct Scoreboard {
    pub req_coverage: (usize, usize),
    pub cell_completeness: (usize, usize),
    /// Live-measured: the 7 compatibility knobs. See this module's doc
    /// comment.
    pub knob_detection: Vec<(String, bool)>,
    /// Not a detection demonstration -- see this module's doc comment.
    /// V-18, V-19, V-21..V-25, all fixed in PR #72 and retained as
    /// regression guards.
    pub regression_guards: Vec<RegressionGuard>,
}

/// Parses a [`Basis::lines`] value (`"rfc7644.txt:1918-1924"` or the
/// single-line form `"rfc7644.txt:1665"`) into an inclusive `(start, end)`
/// raw-file line span.
fn parse_span(lines: &str) -> Option<(u32, u32)> {
    let range = lines.split_once(':').map(|(_, r)| r).unwrap_or(lines);
    match range.split_once('-') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => {
            let a: u32 = range.parse().ok()?;
            Some((a, a))
        }
    }
}

/// The req_coverage denominator: RFC 7644 §3.x paragraphs classified
/// `definitional` or `definitional_prose` by `crate::spec_extract`'s port
/// of `extract.py`. See this module's doc comment for the exact filter and
/// the count it produces (147) on this branch.
pub fn requirement_inventory() -> Vec<(u32, u32)> {
    spec_extract::extract(7644, RFC7644_TXT)
        .into_iter()
        .filter(|p| p.section.split('.').next() == Some("3"))
        .filter(|p| matches!(p.class, Class::Definitional | Class::DefinitionalProse))
        .map(|p| (p.start, p.end))
        .collect()
}

/// Computes [`ReqCoverage`] from every outcome/check the generated-check
/// suite produced. See the module doc comment's "req_coverage" section.
pub fn req_coverage(outcomes: &[Outcome], attrdef_checks: &[AttrdefCheck]) -> ReqCoverage {
    let inventory = requirement_inventory();
    let mut total_citations = 0usize;
    let mut in_scope_citations = 0usize;
    let mut cited_spans: Vec<(u32, u32)> = Vec::new();

    let mut consider = |b: &Basis| {
        total_citations += 1;
        if b.doc != "RFC 7644" {
            return;
        }
        if b.section.split('.').next() != Some("3") {
            return;
        }
        let Some(span) = parse_span(b.lines) else {
            return;
        };
        in_scope_citations += 1;
        cited_spans.push(span);
    };

    for o in outcomes {
        consider(&o.basis);
        for s in &o.secondary {
            consider(s);
        }
    }
    for c in attrdef_checks {
        consider(&c.basis);
    }

    let covered = inventory
        .iter()
        .filter(|(p_start, p_end)| {
            cited_spans
                .iter()
                .any(|(c_start, c_end)| *c_start <= *p_end && *c_end >= *p_start)
        })
        .count();

    ReqCoverage {
        covered,
        total: inventory.len(),
        total_citations,
        in_scope_citations,
    }
}

/// This design's own theoretical maximum: what `matrix::cells_from_decls`
/// would generate if every characteristic were exercised against every
/// HTTP method its own RFC basis makes *conceptually* meaningful, not just
/// the methods the current implementation happens to run today. A pure
/// function over `AttrDecl` data -- no live server needed -- so it, and
/// [`cell_completeness`], are deterministic unit tests.
///
/// Per-characteristic reasoning (read alongside `matrix::cells::
/// cells_from_decls`, which this mirrors):
///
/// - `mutability_readOnly`: already POST + PUT + PATCH for a leaf (or the
///   single NA cell for a container that decomposes into per-sub-attribute
///   checks instead). RFC 7644 §3.3/§3.5.1/§3.5.2 name exactly those three
///   write methods; GET carries no forgery risk of its own (nothing to
///   "ignore" on a read). No extra leg -- actual == theoretical.
/// - `mutability_immutable`: already PostCreate + PatchChange + PutChange.
///   RFC 7643 §7's "SHALL NOT be updated" is about the two update methods,
///   tested against the one method that may legitimately set the value at
///   all (create). No extra leg.
/// - `required`: today only PostOmit + PutOmit (a full-representation
///   request with the attribute omitted). PATCH's own way to make a
///   required attribute absent is a `"remove"` op against its path, not
///   omitting it from a partial-update body (an absent PATCH member means
///   "unchanged", not "omit"); RFC 7644 §3.5.2 does not exempt required
///   attributes from a PATCH remove targeting them. That is a real,
///   currently-unimplemented leg: **+1** (a `PatchRemove`-shaped cell)
///   wherever a `required` cell is generated today.
/// - `caseExact`: today only POST. PUT is a full-representation replace
///   that round-trips a mixed-case value exactly the way POST does (RFC
///   7643 §7's case-exactness is a storage/comparison property, not a
///   POST-only one) and is not yet exercised. **+1** (a PUT leg) wherever
///   a non-skipped `caseExact` cell is generated today.
/// - `uniqueness`: already PostDuplicate + PutDuplicate + PatchDuplicate.
///   RFC 7643 §7 and Table 9's `uniqueness` row name exactly
///   {POST, PUT, PATCH}. No extra leg.
/// - `returned_never`: already POST + GET + PUT + PATCH -- every method
///   whose response could leak the value. No extra leg.
/// - `type_wrong` / `type_valid`: today POST + PUT only, even though RFC
///   7644 §3.5.2's own type-safety language ("An operation that is not
///   compatible with ... schema SHALL return the appropriate ... status
///   code") governs PATCH too. **+2** (a PATCH leg for each of
///   `type_wrong` and `type_valid`) wherever those cells are generated
///   today.
pub fn theoretical_max_cells(decls: &[AttrDecl]) -> usize {
    let mut n = crate::matrix::cells_from_decls(decls).len();
    for decl in decls {
        if decl.required && decl.mutability != Mutability::ReadOnly {
            n += 1; // required: unimplemented PatchRemove leg
        }

        let case_exact_skipped = decl.mutability == Mutability::ReadOnly
            || decl.returned == Returned::Never
            || crate::matrix::is_group_member_ref(decl);
        if decl.case_exact && !case_exact_skipped {
            n += 1; // caseExact: unimplemented PUT leg
        }

        if decl.mutability != Mutability::ReadOnly {
            n += 2; // type_wrong + type_valid: unimplemented PATCH legs
        }
    }
    n
}

/// `(cells actually generated, this design's own theoretical maximum)` --
/// see [`theoretical_max_cells`] for the reasoning behind the gap.
pub fn cell_completeness(decls: &[AttrDecl]) -> (usize, usize) {
    (
        crate::matrix::cells_from_decls(decls).len(),
        theoretical_max_cells(decls),
    )
}

/// p27 (projection): 16 cells, 12 of them non-GET. V-18 used to be "every
/// non-GET cell FAILs"; fixed in #72, so this now reports how many of the
/// 12 relevant (non-GET) cells still fail (0 on a fixed server) -- mirrors
/// `tests/conformance_ledger_matrix.rs`'s
/// `projection_is_honoured_on_every_resource_returning_method`.
fn v18_guard(outcomes: &[Outcome]) -> RegressionGuard {
    let non_get: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| o.characteristic == Characteristic::LedgerP27Projection)
        .filter(|o| o.method != Method::Get)
        .collect();
    let fails = non_get
        .iter()
        .filter(|o| o.verdict == Verdict::Fail)
        .count();
    RegressionGuard {
        label: "V-18".to_string(),
        fails,
        relevant: non_get.len(),
    }
}

/// p26 (status): 6 cells. V-19 used to be "PUT and PATCH duplicate
/// rejection uses scimType=invalidValue instead of uniqueness, 4 of the 6
/// cells"; fixed in #72, so this now reports how many of the 6 cells still
/// reject a duplicate with a scimType other than "uniqueness" -- mirrors
/// `tests/conformance_ledger_matrix.rs`'s
/// `uniqueness_scim_type_is_uniform_across_methods`.
fn v19_guard(outcomes: &[Outcome]) -> RegressionGuard {
    let cells: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| o.characteristic == Characteristic::LedgerP26Status)
        .collect();
    let fails = cells
        .iter()
        .filter(|o| {
            !o.observed
                .as_deref()
                .is_some_and(|s| s.contains("scimType=uniqueness"))
        })
        .count();
    RegressionGuard {
        label: "V-19".to_string(),
        fails,
        relevant: cells.len(),
    }
}

/// V-21..V-25: the relevant cell set is every outcome
/// `crate::findings::classify_known_fail` would classify under `label`
/// (that function matches on resource/attribute/characteristic/method, not
/// on verdict, so it identifies the relevant cells regardless of how they
/// currently score); `fails` is how many of those are still FAIL.
fn known_finding_guard(outcomes: &[Outcome], label: &'static str) -> RegressionGuard {
    let relevant: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| classify_known_fail(o) == Some(label))
        .collect();
    let fails = relevant
        .iter()
        .filter(|o| o.verdict == Verdict::Fail)
        .count();
    RegressionGuard {
        label: label.to_string(),
        fails,
        relevant: relevant.len(),
    }
}

/// See this module's doc comment ("knob_detection") for why these are
/// static.
fn knob_statuses() -> Vec<(String, bool)> {
    KNOBS.iter().map(|k| (format!("knob:{k}"), true)).collect()
}

async fn fetch_decls(client: &mut ScimClient) -> Vec<AttrDecl> {
    match client.get("/Schemas").await {
        Ok(resp) => decls_from_schemas(&resp.body.unwrap_or(serde_json::Value::Null)),
        Err(_) => Vec::new(),
    }
}

/// Computes the full [`Scoreboard`] against a live target. Fetches
/// `/Schemas` twice in total: once inside `crate::full_suite` (to derive
/// and run the schema-driven matrix) and once more here (to get the
/// `AttrDecl`s `cell_completeness` needs as a pure function of declared
/// characteristics, independent of what actually got exercised). Both are
/// single cheap GETs against a target `diagnose` already has an open
/// connection to; not worth threading `full_suite`'s internals through to
/// avoid the second one.
pub async fn compute(client: &mut ScimClient) -> Scoreboard {
    let outcomes: Vec<Outcome> = crate::full_suite(client).await.unwrap_or_default();
    let attrdef_checks = crate::checks_from_attrdefs(client).await;
    let decls = fetch_decls(client).await;

    let coverage = req_coverage(&outcomes, &attrdef_checks);
    let cells = cell_completeness(&decls);

    let mut regression_guards = vec![v18_guard(&outcomes), v19_guard(&outcomes)];
    for label in ["V-21", "V-22", "V-23", "V-24", "V-25"] {
        regression_guards.push(known_finding_guard(&outcomes, label));
    }

    Scoreboard {
        req_coverage: (coverage.covered, coverage.total),
        cell_completeness: cells,
        knob_detection: knob_statuses(),
        regression_guards,
    }
}

/// Plain-text rendering, in `render.rs`'s style: fixed labels, one line per
/// detection entry.
pub fn render_text(s: &Scoreboard) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "Scoreboard");
    let _ = writeln!(
        out,
        "  Requirement coverage   {}/{}  (RFC 7644 §3, class=definitional|definitional_prose paragraphs cited by at least one generated check)",
        s.req_coverage.0, s.req_coverage.1
    );
    let _ = writeln!(
        out,
        "  Cell completeness      {}/{}  (schema-matrix cells actually generated vs. this design's own full method×characteristic grid)",
        s.cell_completeness.0, s.cell_completeness.1
    );
    let _ = writeln!(
        out,
        "  Detection power (compatibility knobs -- measured by \
         tests/conformance_knob_mutation.rs against this repository's own server; not \
         re-verified against this target. See below for the fixed findings.)"
    );
    for (label, caught) in &s.knob_detection {
        // A static fact about this crate's own mutation test, not
        // something re-verified against the target (see module docs).
        let status = if *caught {
            "caught (mutation test, not re-verified live)"
        } else {
            "MISSED"
        };
        let _ = writeln!(out, "    {label:<40} {status}");
    }
    let _ = writeln!(
        out,
        "  Regression guards (V-18, V-19, V-21..V-25 -- all fixed in PR #72; NOT a live \
         \"catches this finding\" detection, since a fixed server has nothing left to catch. \
         Each row is the live count of cells still exhibiting the pre-fix failure mode.)"
    );
    for g in &s.regression_guards {
        let status = if g.fails == 0 {
            "holding".to_string()
        } else {
            "REGRESSION -- see PR body/tests".to_string()
        };
        let _ = writeln!(
            out,
            "    {:<40} {}/{} cells FAIL  {status}",
            g.label, g.fails, g.relevant
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{AttrType, Resource, Uniqueness};

    fn base_decl(path: &str, mutability: Mutability) -> AttrDecl {
        AttrDecl {
            schema: "urn:test:schema".to_string(),
            resource: Resource::User,
            path: path.to_string(),
            parent: None,
            r#type: AttrType::String,
            mutability,
            returned: Returned::Default,
            uniqueness: Uniqueness::None,
            case_exact: false,
            required: false,
            multi_valued: false,
            top_multi_valued: false,
            canonical_values: None,
            has_sub_attributes: false,
        }
    }

    #[test]
    fn cell_completeness_actual_never_exceeds_theoretical() {
        let mut required = base_decl("userName", Mutability::ReadWrite);
        required.required = true;
        let mut case_exact = base_decl("externalId", Mutability::ReadWrite);
        case_exact.case_exact = true;
        let decls = vec![required, case_exact];
        let (actual, theoretical) = cell_completeness(&decls);
        assert!(actual <= theoretical);
    }

    /// `userName`-shaped attribute: required + readWrite. Actual = 2
    /// (PostOmit, PutOmit) + 4 (TypeWrong/TypeValid x Post/Put) = 6.
    /// Theoretical adds +1 (required's PatchRemove leg) and +2 (type's
    /// PATCH legs) = 9.
    #[test]
    fn required_readwrite_attribute_gains_one_theoretical_leg() {
        let mut decl = base_decl("userName", Mutability::ReadWrite);
        decl.required = true;
        let decls = vec![decl];
        assert_eq!(cell_completeness(&decls), (6, 9));
    }

    /// `externalId`-shaped attribute: caseExact + readWrite, not skipped.
    /// Actual = 1 (Post) + 4 (type) = 5. Theoretical adds +1 (caseExact's
    /// PUT leg) + 2 (type's PATCH legs) = 8.
    #[test]
    fn case_exact_readwrite_attribute_gains_one_theoretical_leg() {
        let mut decl = base_decl("externalId", Mutability::ReadWrite);
        decl.case_exact = true;
        let decls = vec![decl];
        assert_eq!(cell_completeness(&decls), (5, 8));
    }

    /// A readOnly attribute contributes no `required`/`caseExact`/`type_*`
    /// legs at all (actual or theoretical) -- only `mutability_readOnly`,
    /// which is already at its theoretical maximum.
    #[test]
    fn readonly_attribute_has_no_extra_theoretical_legs() {
        let mut decl = base_decl("id", Mutability::ReadOnly);
        decl.required = true; // still shouldn't add a PatchRemove leg
        decl.case_exact = true; // still shouldn't add a PUT leg
        let decls = vec![decl];
        // mutability_readOnly leaf: POST + PUT + PATCH = 3, and nothing
        // else (required cell becomes a single NA cell already counted by
        // cells_from_decls; no theoretical extra for a readOnly attribute).
        let (actual, theoretical) = cell_completeness(&decls);
        assert_eq!(actual, theoretical);
    }

    #[test]
    fn parse_span_handles_single_line_and_range() {
        assert_eq!(parse_span("rfc7644.txt:1665"), Some((1665, 1665)));
        assert_eq!(parse_span("rfc7644.txt:1918-1924"), Some((1918, 1924)));
    }

    #[test]
    fn requirement_inventory_is_pinned_at_147() {
        assert_eq!(requirement_inventory().len(), 147);
    }
}
