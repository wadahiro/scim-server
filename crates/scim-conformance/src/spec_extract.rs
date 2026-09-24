//! A small, self-contained Rust implementation of RFC paragraph
//! segmentation and classification -- just enough of it to answer one
//! question at `scoreboard::compute` runtime with no external dependency:
//! "which raw-file paragraphs of a vendored RFC text state an actual
//! requirement (`definitional` / `definitional_prose`), as opposed to
//! explanatory prose, an example, a heading/caption, or a table?"
//!
//! # Why a pure-Rust implementation
//!
//! `scim-server diagnose <url> --scoreboard` is the *shipped binary* (see
//! the release Dockerfile's distroless target), and it has no scripting
//! runtime available at all. Computing `req_coverage` by shelling out to
//! an external script would make it silently unavailable (or a hard
//! failure) in exactly the deployment this feature is meant to run in. A
//! pure-Rust implementation over the same vendored `spec/rfc/rfc7644.txt`
//! (already `include_str!`-ed unmodified elsewhere in this crate, e.g.
//! `gen::attrdefs`) keeps the whole computation dependency-free and
//! deterministic at both test time and run time.
//!
//! The tradeoff: this classification logic was cross-checked once, by
//! hand, against an independent Python implementation's output on this
//! branch's vendored spec text during development of this module (that
//! script never shipped in this repository, and no longer exists anywhere
//! this crate can reach). This module's own unit tests pin the resulting
//! counts, so a future edit that changes the classification -- or a change
//! to the vendored spec text -- is caught as a test failure; what they can
//! no longer do is prove agreement with that other implementation, since
//! there is nothing left here to re-run the comparison against. Treat the
//! pinned numbers as a regression guard on this module's own determinism,
//! not as a live differential check.  It intentionally implements only the
//! subset of classification needed to compute `class` (paragraph
//! segmentation + `kind` + the `KW10`/`OUTCOME` regexes) -- not `keywords`, `kw7`,
//! `cardinality_only`, or `attr_def`, none of which `scoreboard` needs.

use regex::Regex;
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Definitional,
    DefinitionalProse,
    Example,
    Meta,
    Table,
    Explanatory,
}

#[derive(Debug, Clone)]
pub struct Paragraph {
    pub rfc: u32,
    pub section: String,
    /// 1-based, inclusive, raw-file line numbers (matching every other
    /// span in this crate, e.g. `Basis::lines`).
    pub start: u32,
    pub end: u32,
    pub class: Class,
}

// ---- classification regexes -------------------------------------------

static FURNITURE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)").unwrap());
static HEADING: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(\d+(?:\.\d+)*)\.\s+(\S.*)$").unwrap());
static FIGCAP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s+(Figure|Table) \d+[:.]").unwrap());
static ABNF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s{2,}[A-Za-z][A-Za-z0-9-]*\s*=\s").unwrap());
static TABLEROW: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\s*[|+]").unwrap());
static HTTP_EXAMPLE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(GET|POST|PUT|PATCH|DELETE|HTTP/1\.1) ").unwrap());
static KW10: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(MUST NOT|MUST|SHALL NOT|SHALL|SHOULD NOT|SHOULD|RECOMMENDED|REQUIRED|OPTIONAL|MAY)\b",
    )
    .unwrap()
});
static OUTCOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(fails?|returns?|is (ignored|applied|replaced|equivalent|assumed)|are applied|status code|treated as|considered|SHALL be|responds?|rejects?)\b",
    )
    .unwrap()
});
// PP-1 page-boundary merge heuristic (`segment()`'s inner `if`).
static MERGE_START: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"^ {3}[a-z)'"]"#).unwrap());
static MERGE_BULLET: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^ {3}o\s").unwrap());
static WS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s+").unwrap());

struct Block {
    start: u32,
    end: u32,
    body: Vec<String>,
}

/// `segment()`'s step 1+2: drop page furniture / form-feed lines, then
/// split what remains into blank-line-delimited blocks, each carrying its
/// raw-file line range.
fn make_blocks(lines: &[&str]) -> Vec<Block> {
    let mut keep: Vec<(u32, String)> = Vec::new();
    for (i, ln) in lines.iter().enumerate() {
        let no_ff = ln.replace('\u{000C}', "");
        let s = no_ff.trim_end().to_string();
        if FURNITURE.is_match(s.trim()) || ln.contains('\u{000C}') {
            continue;
        }
        keep.push(((i + 1) as u32, s));
    }

    let mut blocks = Vec::new();
    let mut cur: Vec<(u32, String)> = Vec::new();
    let mut start: Option<u32> = None;
    for (lineno, s) in &keep {
        if s.trim().is_empty() {
            if !cur.is_empty() {
                let end = cur.last().unwrap().0;
                blocks.push(Block {
                    start: start.unwrap(),
                    end,
                    body: cur.iter().map(|(_, t)| t.clone()).collect(),
                });
                cur.clear();
                start = None;
            }
        } else {
            if start.is_none() {
                start = Some(*lineno);
            }
            cur.push((*lineno, s.clone()));
        }
    }
    if !cur.is_empty() {
        let end = cur.last().unwrap().0;
        blocks.push(Block {
            start: start.unwrap(),
            end,
            body: cur.iter().map(|(_, t)| t.clone()).collect(),
        });
    }
    blocks
}

/// `segment()`'s step 3 (PP-1): re-joins a paragraph that a page break
/// split into two blocks.
fn merge_pp1(blocks: Vec<Block>) -> Vec<Block> {
    let mut merged: Vec<Block> = Vec::new();
    for b in blocks {
        let mut merge = false;
        if let Some(prev) = merged.last() {
            let ptext = prev.body.last().unwrap().trim_end();
            let ntext = &b.body[0];
            let ends_sentence = ptext
                .chars()
                .last()
                .is_some_and(|c| matches!(c, '.' | ':' | ';' | '?' | '!'));
            merge = !ends_sentence
                && ptext.chars().count() > 50
                && MERGE_START.is_match(ntext)
                && !MERGE_BULLET.is_match(ntext);
        }
        if merge {
            let prev = merged.last_mut().unwrap();
            prev.end = b.end;
            prev.body.extend(b.body);
        } else {
            merged.push(b);
        }
    }
    merged
}

fn collapse_ws(s: &str) -> String {
    WS.replace_all(s, " ").trim().to_string()
}

/// `classify()`'s `kind` value.
fn classify_kind(body: &[String]) -> &'static str {
    let first = &body[0];
    let flat = collapse_ws(&body.join(" "));
    if HEADING.is_match(first.trim()) && body.len() <= 2 && flat.chars().count() < 90 {
        return "heading";
    }
    if FIGCAP.is_match(first) {
        return "caption";
    }
    let tbl = body.iter().filter(|l| TABLEROW.is_match(l)).count();
    if tbl > 0 && (tbl as f64) >= (body.len() as f64) * 0.5 {
        return "table";
    }
    let st = first.trim();
    if st.starts_with('{') || st.starts_with('[') || st.starts_with('"') {
        return "json";
    }
    let abnf = body.iter().filter(|l| ABNF.is_match(l)).count();
    if (abnf as f64) >= (1.0f64).max(body.len() as f64 * 0.5) {
        return "abnf";
    }
    if HTTP_EXAMPLE.is_match(first) {
        return "http_example";
    }
    "prose"
}

/// The `class` assignment: checks `kind` first, then a keyword match,
/// then a looser outcome-verb match, falling back to explanatory.
fn classify_class(kind: &str, flat: &str) -> Class {
    match kind {
        "json" | "abnf" | "http_example" => Class::Example,
        "heading" | "caption" => Class::Meta,
        "table" => Class::Table,
        _ => {
            if KW10.is_match(flat) {
                Class::Definitional
            } else if OUTCOME.is_match(flat) {
                Class::DefinitionalProse
            } else {
                Class::Explanatory
            }
        }
    }
}

/// `section_index()` + `sec_of()`: a raw-file-line -> section-number
/// lookup built from unindented `N(.N)*. Title` heading lines.
fn section_index(lines: &[&str]) -> Vec<(u32, String)> {
    let mut marks = Vec::new();
    for (i, ln) in lines.iter().enumerate() {
        if ln.starts_with(' ') {
            continue;
        }
        if let Some(caps) = HEADING.captures(ln.trim_end()) {
            marks.push(((i + 1) as u32, caps[1].to_string()));
        }
    }
    marks
}

fn sec_of(marks: &[(u32, String)], lineno: u32) -> String {
    let mut cur = "0".to_string();
    for (ln, sec) in marks {
        if *ln <= lineno {
            cur = sec.clone();
        } else {
            break;
        }
    }
    cur
}

/// Segments and classifies every paragraph of `text` (a full, vendored RFC
/// document's raw text, e.g. `spec/rfc/rfc7644.txt`'s contents), tagging
/// each with `rfc` and its raw-file line span.
pub fn extract(rfc: u32, text: &str) -> Vec<Paragraph> {
    let lines: Vec<&str> = text.split('\n').collect();
    let marks = section_index(&lines);
    let blocks = merge_pp1(make_blocks(&lines));

    let mut out = Vec::with_capacity(blocks.len());
    for b in blocks {
        let kind = classify_kind(&b.body);
        let flat = collapse_ws(&b.body.join(" "));
        let class = classify_class(kind, &flat);
        let section = sec_of(&marks, b.start);
        out.push(Paragraph {
            rfc,
            section,
            start: b.start,
            end: b.end,
            class,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC7644_TXT: &str = include_str!("../spec/rfc/rfc7644.txt");

    /// Pinned against this branch's vendored `spec/rfc/rfc7644.txt`. This
    /// count was cross-checked once, by hand, against an independent
    /// Python implementation's output during this module's development;
    /// that script was never part of this repository and no longer exists
    /// anywhere this crate can reach, so the pin below can no longer be
    /// re-verified against it. What it still does, and does honestly: it
    /// catches silent drift, either in this module's own segmentation and
    /// classification logic, or in the vendored spec text (which shouldn't
    /// change -- it's frozen IETF text). If this test ever fails, work out
    /// which of those two changed before updating the pinned number; there
    /// is no oracle left to re-run a differential check against.
    #[test]
    fn rfc7644_paragraph_count_is_pinned() {
        let paras = extract(7644, RFC7644_TXT);
        assert_eq!(
            paras.len(),
            635,
            "RFC 7644 paragraph count changed -- see this test's doc comment"
        );
    }

    #[test]
    fn rfc7644_section3_requirement_paragraph_count_is_pinned() {
        let paras = extract(7644, RFC7644_TXT);
        let denom: Vec<&Paragraph> = paras
            .iter()
            .filter(|p| p.section.split('.').next() == Some("3"))
            .filter(|p| matches!(p.class, Class::Definitional | Class::DefinitionalProse))
            .collect();
        assert_eq!(
            denom.len(),
            147,
            "RFC 7644 section-3 definitional/definitional_prose paragraph count \
             (124 definitional + 23 definitional_prose = 147 in section 3.*) -- \
             see rfc7644_paragraph_count_is_pinned's doc comment"
        );
    }

    #[test]
    fn section_index_finds_3_5_2() {
        let paras = extract(7644, RFC7644_TXT);
        assert!(paras.iter().any(|p| p.section == "3.5.2"));
    }
}
