//! T11: turns a [`DiagnosticReport`] into the CLI's plain-text report.
//!
//! Deliberately narrow -- text only. No markdown renderer, no
//! `--emit-config-snippet`, no Tier/Severity model: this crate's T11 scope
//! is "print every finding with its RFC citation," not a scoreboard (T12,
//! separate task) or a config-authoring tool.

use crate::client::truncate;
use crate::matrix::Verdict;
use crate::report::DiagnosticReport;

/// Fixed print order for the five families [`crate::report::Finding::family`]
/// can hold; a family with no findings is skipped entirely.
const FAMILY_ORDER: [&str; 5] = ["schema", "probe", "etag", "ledger", "discovery"];

/// Renders `report` as plain text, one line per finding: a fixed-width
/// verdict tag, the finding's stable key, and its RFC citation (via
/// [`crate::basis::Basis`]'s `Display` impl, e.g. `RFC 7644 §3.3
/// L583-584`), followed by any secondary citations. `detail` is appended
/// for FAIL/ERROR findings always (untruncated when `verbose`, otherwise
/// bounded to a fixed width), and for every finding when `verbose` is set
/// (the CLI's `-v`/`--verbose`) -- this one boolean parameter is the only
/// deviation from the plan's literal `render_text(&DiagnosticReport) ->
/// String` signature; the task's final report explains why plumbing `-v`
/// needs it.
pub fn render_text(report: &DiagnosticReport, verbose: bool) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(out, "diagnose: {}", report.target);

    for family in FAMILY_ORDER {
        let items: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.family == family)
            .collect();
        if items.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n[{family}] ({} findings)", items.len());
        for f in items {
            let tag = f.verdict.tag(); // PASS/FAIL/SKIP/ERROR/INFO, already <=5 chars
            let mut line = format!("  {tag:<5} {}  {}", f.key, f.basis);
            if let Some(kw) = f.keyword {
                // Only the §3.14 family (and any future one) sets this --
                // makes a SHOULD/MAY deviation visually distinct from a
                // MUST/SHALL violation instead of both reading as a bare
                // PASS/FAIL/INFO tag.
                let _ = write!(line, " [{}]", kw.tag());
            }
            for sec in &f.secondary {
                let _ = write!(line, "; also {sec}");
            }
            let show_detail = verbose || matches!(f.verdict, Verdict::Fail | Verdict::Error);
            if show_detail && !f.detail.is_empty() {
                // Verbose shows the whole thing (truncating a FAIL's
                // detail at a fixed width can cut off the actionable
                // tail, e.g. which scimType was expected); the default,
                // non-verbose view still bounds it.
                if verbose {
                    let _ = write!(line, " -- {}", f.detail);
                } else {
                    let _ = write!(line, " -- {}", truncate(&f.detail, 200));
                }
            }
            let _ = writeln!(out, "{line}");
        }
    }

    let c = &report.counts;
    let _ = writeln!(
        out,
        "\n{} findings: {} pass, {} fail, {} skip, {} info, {} error",
        report.findings.len(),
        c.pass,
        c.fail,
        c.skip,
        c.info,
        c.error
    );
    out
}
