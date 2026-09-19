//! `--emit-config-snippet`: renders `Report::detected_knobs()` as a
//! paste-ready `compatibility:` YAML block, marking knobs that differ from
//! this scim-server's own defaults with a trailing `# quirk` comment.
//!
//! Available from both `render::text` and `render::markdown` — this module
//! only produces the YAML lines themselves; each renderer wraps them in its
//! own heading/prose (a Markdown fenced code block vs a plain-text
//! sub-heading).

use std::fmt::Write as _;

use crate::config::CompatibilityConfig;
use crate::diag::model::{KnobValue, Report};

/// `CompatibilityConfig`'s field order (`src/config.rs:137-197`) — fixed
/// here rather than trusting `Report::detected_knobs()`'s iteration order,
/// so a future re-ordering of `checks::catalog()` can't silently reorder
/// this output.
const CANONICAL_ORDER: [&str; 7] = [
    "meta_datetime_format",
    "show_empty_groups_members",
    "include_user_groups",
    "support_group_members_filter",
    "support_group_displayname_filter",
    "support_patch_replace_empty_array",
    "support_patch_replace_empty_value",
];

fn default_value(knob: &str) -> KnobValue {
    let d = CompatibilityConfig::default();
    match knob {
        "meta_datetime_format" => KnobValue::Str(d.meta_datetime_format),
        "show_empty_groups_members" => KnobValue::Bool(d.show_empty_groups_members),
        "include_user_groups" => KnobValue::Bool(d.include_user_groups),
        "support_group_members_filter" => KnobValue::Bool(d.support_group_members_filter),
        "support_group_displayname_filter" => KnobValue::Bool(d.support_group_displayname_filter),
        "support_patch_replace_empty_array" => KnobValue::Bool(d.support_patch_replace_empty_array),
        "support_patch_replace_empty_value" => KnobValue::Bool(d.support_patch_replace_empty_value),
        other => unreachable!("{other} is not one of CANONICAL_ORDER"),
    }
}

/// Just the YAML lines (`compatibility:` plus one line per *detected*
/// knob) — no heading, no explanatory prose, no code fence. Knobs that
/// were `Skip`ped are absent from `Report::detected_knobs()` already
/// (`model::Report::detected_knobs`'s doc comment), so they are simply
/// omitted here rather than guessed at.
pub fn render(report: &Report) -> String {
    let detected: std::collections::HashMap<&str, KnobValue> =
        report.detected_knobs().into_iter().collect();

    let mut out = String::new();
    writeln!(out, "compatibility:").ok();
    let mut any = false;
    for knob in CANONICAL_ORDER {
        let Some(value) = detected.get(knob) else {
            continue;
        };
        any = true;
        let is_quirk = *value != default_value(knob);
        if is_quirk {
            writeln!(out, "  {knob}: {}  # quirk", value.to_yaml()).ok();
        } else {
            writeln!(out, "  {knob}: {}", value.to_yaml()).ok();
        }
    }
    if !any {
        writeln!(out, "  # no knobs were observed (all Skipped)").ok();
    }
    out
}
