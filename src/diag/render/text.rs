//! Plain-text rendering. See `render/mod.rs` for why this stays colorless.

use std::fmt::Write as _;

use crate::diag::model::{CheckOutcome, CleanupReport, Exchange, KnobValue, Report, Tier, Verdict};

pub fn render(report: &Report) -> String {
    let mut out = String::new();

    render_header(&mut out, report);
    out.push('\n');

    for tier in Tier::ALL {
        let outcomes: Vec<&CheckOutcome> =
            report.outcomes.iter().filter(|o| o.tier == tier).collect();
        if outcomes.is_empty() {
            continue;
        }
        writeln!(out, "{}", tier.title()).ok();
        for outcome in &outcomes {
            render_outcome(
                &mut out,
                outcome,
                report.header.verbose,
                tier == Tier::Compat,
            );
        }
        out.push('\n');
    }

    render_summary(&mut out, report);
    if let Some(cleanup) = &report.cleanup {
        render_cleanup(&mut out, cleanup);
    }

    out
}

fn render_header(out: &mut String, report: &Report) {
    let h = &report.header;
    writeln!(out, "SCIM 2.0 Diagnostic Report").ok();
    writeln!(out, "  Target          {}", h.target).ok();
    writeln!(out, "  Auth            {}", h.auth).ok();
    writeln!(out, "  TLS             {}", h.tls).ok();
    writeln!(out, "  Mode            {:<18}Prefix  {}", h.mode, h.prefix).ok();
    if let Some(email) = &h.probe_email {
        writeln!(out, "  Probe email     {email}").ok();
    }
    writeln!(out, "  Probe attribute {}", h.probe_attribute).ok();
    writeln!(
        out,
        "  Started         {}     Duration  {:.1}s",
        h.started,
        h.duration_ms as f64 / 1000.0
    )
    .ok();
    writeln!(out, "  Tool            scim-server {}", h.tool_version).ok();
    for w in &h.warnings {
        writeln!(out, "  ! {w}").ok();
    }
}

/// The 7-character fixed tag tokens, built from `CheckOutcome::status_word`
/// (shared with `render::markdown`).
fn display_tag(o: &CheckOutcome) -> &'static str {
    match o.status_word() {
        "OK" => "[ OK  ]",
        "FAIL" => "[FAIL ]",
        "QUIRK" => "[QUIRK]",
        "SKIP" => "[SKIP ]",
        "INFO" => "[INFO ]",
        _ => "[ERROR]",
    }
}

fn render_outcome(out: &mut String, o: &CheckOutcome, verbose: u8, is_tier1: bool) {
    let tag = display_tag(o);

    if is_tier1 {
        let title = o.knob.unwrap_or(o.title);
        let detected = o
            .verdict
            .detected()
            .map(|v| match v {
                KnobValue::Bool(b) => b.to_string(),
                KnobValue::Str(s) => format!("{s:?}"),
            })
            .unwrap_or_default();
        if detected.is_empty() {
            writeln!(out, "  {tag} {title:.<56}").ok();
        } else {
            writeln!(out, "  {tag} {title:.<56} {detected}").ok();
        }
    } else {
        writeln!(out, "  {tag} {}", o.title).ok();
    }

    match &o.verdict {
        Verdict::Fail { detail } | Verdict::Error { detail } => {
            writeln!(out, "          {detail}").ok();
        }
        Verdict::Skip { reason } => {
            writeln!(out, "          reason: {reason}").ok();
        }
        _ => {}
    }
    if let Some(note) = &o.note {
        writeln!(out, "          {note}").ok();
    }

    let is_fail_or_error = matches!(o.verdict, Verdict::Fail { .. } | Verdict::Error { .. });
    if verbose >= 1 || is_fail_or_error {
        for ex in &o.transcript {
            render_exchange(out, ex, verbose);
        }
    }
}

fn render_exchange(out: &mut String, ex: &Exchange, verbose: u8) {
    let status = ex
        .status
        .map(|s| s.to_string())
        .unwrap_or_else(|| "-".to_string());
    writeln!(
        out,
        "          {} {} -> {} ({}ms)",
        ex.method, ex.url, status, ex.elapsed_ms
    )
    .ok();
    if verbose >= 2 {
        if let Some(rb) = &ex.request_body {
            writeln!(out, "            > {rb}").ok();
        }
        if let Some(rb) = &ex.response_body {
            writeln!(out, "            < {rb}").ok();
        }
    }
}

fn render_summary(out: &mut String, report: &Report) {
    let c = report.counts();
    let total = c.pass + c.fail + c.quirk + c.skip + c.error;
    writeln!(
        out,
        "Summary   {total} checks: {} pass  {} fail  {} quirk  {} skip  {} error",
        c.pass, c.fail, c.quirk, c.skip, c.error
    )
    .ok();
}

fn render_cleanup(out: &mut String, cleanup: &CleanupReport) {
    if cleanup.attempted == 0 {
        writeln!(out, "Cleanup   nothing to clean up").ok();
    } else {
        writeln!(
            out,
            "Cleanup   {} of {} probe resources deleted",
            cleanup.deleted, cleanup.attempted
        )
        .ok();
    }
    for f in &cleanup.failures {
        writeln!(out, "  ! {f}").ok();
    }
}
