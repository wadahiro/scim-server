//! Markdown rendering (§5.11): a 2-column header table, one table per tier,
//! and request/response transcripts folded into `<details>` blocks so a
//! long report stays skimmable when pasted into an issue or a PR
//! description.
//!
//! Same content as `render::text`, different shape — this is not a
//! Markdown-to-text transliteration; it's built straight from `Report`
//! just like `text::render` is.

use std::fmt::Write as _;

use crate::diag::model::{CheckOutcome, CleanupReport, Exchange, KnobValue, Report, Tier};

pub fn render(report: &Report) -> String {
    let mut out = String::new();

    writeln!(out, "# SCIM 2.0 Diagnostic Report").ok();
    out.push('\n');
    render_header_table(&mut out, report);
    render_warnings(&mut out, report);

    for tier in Tier::ALL {
        let outcomes: Vec<&CheckOutcome> =
            report.outcomes.iter().filter(|o| o.tier == tier).collect();
        if outcomes.is_empty() {
            continue;
        }
        out.push('\n');
        writeln!(out, "## {}", tier.title()).ok();
        out.push('\n');
        render_tier_table(&mut out, &outcomes, tier == Tier::Compat);
        render_transcripts(&mut out, &outcomes, report.header.verbose);
    }

    out.push('\n');
    render_summary(&mut out, report);
    if let Some(cleanup) = &report.cleanup {
        render_cleanup(&mut out, cleanup);
    }

    out
}

/// Escapes the two characters that would otherwise break a Markdown table
/// cell: `|` (column separator) and newlines (cells can't span lines).
fn md_escape(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', "<br>")
}

fn render_header_table(out: &mut String, report: &Report) {
    let h = &report.header;
    writeln!(out, "| Field | Value |").ok();
    writeln!(out, "|---|---|").ok();
    writeln!(out, "| Target | {} |", md_escape(&h.target)).ok();
    writeln!(out, "| Auth | {} |", md_escape(&h.auth)).ok();
    writeln!(out, "| TLS | {} |", md_escape(&h.tls)).ok();
    writeln!(out, "| Mode | {} |", md_escape(&h.mode)).ok();
    writeln!(out, "| Prefix | {} |", md_escape(&h.prefix)).ok();
    if let Some(email) = &h.probe_email {
        writeln!(out, "| Probe email | {} |", md_escape(email)).ok();
    }
    writeln!(
        out,
        "| Probe attribute | {} |",
        md_escape(&h.probe_attribute)
    )
    .ok();
    writeln!(out, "| Started | {} |", md_escape(&h.started)).ok();
    writeln!(out, "| Duration | {:.1}s |", h.duration_ms as f64 / 1000.0).ok();
    writeln!(out, "| Tool | scim-server {} |", h.tool_version).ok();
}

fn render_warnings(out: &mut String, report: &Report) {
    for w in &report.header.warnings {
        out.push('\n');
        writeln!(out, "> ⚠ {}", md_escape(w)).ok();
    }
}

fn render_tier_table(out: &mut String, outcomes: &[&CheckOutcome], is_tier1: bool) {
    if is_tier1 {
        // A fourth Detail column (absent from the §5.11 mockup, which only
        // shows knobs that Pass/Quirk) so a Skip's reason, or
        // `compat.groups_consistency`'s asymmetry note (that check's whole
        // point — it has no knob of its own), aren't silently dropped from
        // Markdown while `render::text` still shows them.
        writeln!(out, "| Status | Knob | Detected | Detail |").ok();
        writeln!(out, "|---|---|---|---|").ok();
        for o in outcomes {
            let detected = o
                .verdict
                .detected()
                .map(|v| match v {
                    KnobValue::Bool(b) => b.to_string(),
                    KnobValue::Str(s) => format!("{s:?}"),
                })
                .unwrap_or_default();
            let knob_cell = match o.knob {
                Some(knob) => format!("`{}`", md_escape(knob)),
                None => md_escape(o.title),
            };
            let detail = outcome_detail_cell(o);
            writeln!(
                out,
                "| {} | {} | {} | {} |",
                o.status_word(),
                knob_cell,
                md_escape(&detected),
                md_escape(&detail)
            )
            .ok();
        }
    } else {
        writeln!(out, "| Status | Check | Detail |").ok();
        writeln!(out, "|---|---|---|").ok();
        for o in outcomes {
            let detail = outcome_detail_cell(o);
            writeln!(
                out,
                "| {} | {} | {} |",
                o.status_word(),
                md_escape(o.title),
                md_escape(&detail)
            )
            .ok();
        }
    }
}

/// The Detail/Note column: `Fail`/`Error` detail, or `Skip` reason, plus
/// any `note` appended — same precedence `render::text::render_outcome`
/// uses, just joined onto one line instead of stacked underneath.
fn outcome_detail_cell(o: &CheckOutcome) -> String {
    let mut parts = Vec::new();
    match &o.verdict {
        crate::diag::model::Verdict::Fail { detail }
        | crate::diag::model::Verdict::Error { detail } => parts.push(detail.clone()),
        crate::diag::model::Verdict::Skip { reason } => parts.push(format!("reason: {reason}")),
        _ => {}
    }
    if let Some(note) = &o.note {
        parts.push(note.clone());
    }
    parts.join(" — ")
}

/// One `<details>` block per outcome that would show a transcript in
/// `render::text` too: `verbose >= 1`, or any `Fail`/`Error` regardless of
/// verbosity (same rule, so the two renderers never disagree about what's
/// visible by default).
fn render_transcripts(out: &mut String, outcomes: &[&CheckOutcome], verbose: u8) {
    for o in outcomes {
        let is_fail_or_error = matches!(
            o.verdict,
            crate::diag::model::Verdict::Fail { .. } | crate::diag::model::Verdict::Error { .. }
        );
        if o.transcript.is_empty() || !(verbose >= 1 || is_fail_or_error) {
            continue;
        }
        out.push('\n');
        writeln!(out, "<details>").ok();
        writeln!(out, "<summary>{} — request log</summary>", o.id).ok();
        out.push('\n');
        writeln!(out, "```").ok();
        for ex in &o.transcript {
            render_exchange(out, ex, verbose);
        }
        writeln!(out, "```").ok();
        out.push('\n');
        writeln!(out, "</details>").ok();
    }
}

fn render_exchange(out: &mut String, ex: &Exchange, verbose: u8) {
    let status = ex
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    writeln!(
        out,
        "{} {} -> {} ({}ms)",
        ex.method, ex.url, status, ex.elapsed_ms
    )
    .ok();
    if verbose >= 2 {
        if let Some(rb) = &ex.request_body {
            writeln!(out, "  > {rb}").ok();
        }
        if let Some(rb) = &ex.response_body {
            writeln!(out, "  < {rb}").ok();
        }
    }
}

fn render_summary(out: &mut String, report: &Report) {
    let c = report.counts();
    let total = c.pass + c.fail + c.quirk + c.skip + c.error;
    writeln!(out, "## Summary").ok();
    out.push('\n');
    writeln!(
        out,
        "{total} checks: {} pass, {} fail, {} quirk, {} skip, {} error",
        c.pass, c.fail, c.quirk, c.skip, c.error
    )
    .ok();
}

fn render_cleanup(out: &mut String, cleanup: &CleanupReport) {
    out.push('\n');
    writeln!(out, "## Cleanup").ok();
    out.push('\n');
    if cleanup.attempted == 0 {
        writeln!(out, "Nothing to clean up.").ok();
    } else {
        writeln!(
            out,
            "{} of {} probe resources deleted.",
            cleanup.deleted, cleanup.attempted
        )
        .ok();
    }
    for f in &cleanup.failures {
        writeln!(out, "- {}", md_escape(f)).ok();
    }
}
