//! Turns a [`crate::diag::model::Report`] into a printable string.
//!
//! `render()` never parses its own output back (tests assert against the
//! `Report` directly) and is a pure function of its inputs — no terminal
//! detection, no ambient state — see `style.rs` for why that matters.

pub mod markdown;
pub mod style;
pub mod text;
pub mod yaml_snippet;

use crate::diag::cli::Format;
use crate::diag::model::Report;

/// Renders the report body, then — if `emit_config_snippet` — appends the
/// `--emit-config-snippet` block (§5.11) in whichever shape matches
/// `format`. Available in both formats, per the design note (§8 PR4).
pub fn render(report: &Report, format: Format, emit_config_snippet: bool) -> String {
    let mut out = match format {
        Format::Text => text::render(report),
        Format::Markdown => markdown::render(report),
    };

    if emit_config_snippet {
        out.push('\n');
        match format {
            Format::Text => {
                out.push_str("Suggested `compatibility:` configuration\n");
                out.push_str(
                    "  (paste into config.yaml to make this scim-server behave like the\n",
                );
                out.push_str(
                    "   diagnosed target; knobs that could not be observed (SKIP) are omitted\n",
                );
                out.push_str("   rather than guessed)\n\n");
                out.push_str(&yaml_snippet::render(report));
            }
            Format::Markdown => {
                out.push_str("## Suggested `compatibility:` configuration\n\n");
                out.push_str(
                    "> Paste this block into `config.yaml` to make this scim-server behave\n",
                );
                out.push_str("> like the diagnosed target. Knobs that could not be observed\n");
                out.push_str("> (SKIP) are omitted rather than guessed.\n\n");
                out.push_str("```yaml\n");
                out.push_str(&yaml_snippet::render(report));
                out.push_str("```\n");
            }
        }
    }

    out
}
