//! A line-for-line port of `tools/prototype/extract_attrdefs.py`'s
//! `extract()` function: it parses RFC 7643/7644's definition-list
//! attribute syntax (`"   name"` on its own line, or `"   name  Description
//! text"` inline, with nested sub-attributes indented one level deeper) and
//! tracks each definition's parent through a simple indent stack.
//!
//! This module exists for exactly one purpose -- [`crate::gen::attrdefs`]
//! needs, for each of the 61 entries in
//! `tools/prototype/golden/attrdefs.json`, the raw-file line its
//! `name`/`attribute` is actually defined at, so it can cite a
//! [`crate::basis::Basis`] the same way every other generated check in this
//! crate does. The golden JSON's own `start`/`end` fields happen to already
//! be those line numbers (they came out of this exact extraction), but T9's
//! job is to *re-derive* the citation from the vendored `spec/rfc/*.txt`
//! text, not to trust a number sitting in a fixture -- so this scans the
//! raw text itself and the caller matches golden entries to the result by
//! `(rfc, section, attribute)`, which is unique across all 61 entries
//! (checked by `attrdefs`'s own test).
//!
//! Ported quirks-and-all rather than "cleaned up": in particular, the
//! indent stack is pushed for *every* definition-shaped line, whether or
//! not that line turned out to carry a recognized `REQUIRED`/`OPTIONAL`/
//! `RECOMMENDED` cardinality (see the `stack.push` below, which sits
//! outside the `if let Some(cm) = ...` block) -- matching that exactly is
//! what makes parent tracking agree with the Python prototype's output.

use regex::Regex;

/// One attribute-definition site found in the raw RFC text: enough to
/// match a golden `attrdefs.json` entry by `(rfc, section, attribute)` and
/// recover the raw-file line it was defined at.
#[derive(Debug, Clone)]
pub struct ScannedDef {
    pub rfc: u32,
    pub section: String,
    pub start: u32,
    pub end: u32,
    pub attribute: String,
    pub parent: Option<String>,
    pub name: String,
    pub cardinality: String,
    pub conditional: bool,
}

struct Section {
    line: u32,
    num: String,
}

/// Every top-level (unindented) `N[.N...].  Title` heading and the raw
/// line it starts at -- `extract_attrdefs.py`'s `sections()`.
fn sections(lines: &[&str]) -> Vec<Section> {
    let head = Regex::new(r"^(\d+(?:\.\d+)*)\.\s+(\S.*)$").expect("static regex");
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.starts_with(' ') {
            continue;
        }
        if let Some(caps) = head.captures(line.trim_end()) {
            out.push(Section {
                line: (i + 1) as u32,
                num: caps[1].to_string(),
            });
        }
    }
    out
}

/// The section number in effect at raw line `n` -- `extract_attrdefs.py`'s
/// `sec_at()` (its `title` return value is unused by the caller here, so
/// it's dropped).
fn sec_at(secs: &[Section], n: u32) -> String {
    let mut cur = "0".to_string();
    for s in secs {
        if s.line <= n {
            cur = s.num.clone();
        } else {
            break;
        }
    }
    cur
}

fn leading_spaces(s: &str) -> usize {
    s.len() - s.trim_start_matches(' ').len()
}

/// Parses one vendored RFC text file (`raw`, unmodified) into its
/// attribute-definition sites. `rfc` is just carried through to the output
/// (7643 or 7644); it plays no part in parsing.
pub fn scan(rfc: u32, raw: &str) -> Vec<ScannedDef> {
    let furniture = Regex::new(r"^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)").expect("static regex");
    let card = Regex::new(r"\b(REQUIRED|OPTIONAL|RECOMMENDED)\b").expect("static regex");
    let def = Regex::new(r"^( +)([A-Za-z][A-Za-z0-9_$]*)(?:  +(\S.*))?$").expect("static regex");
    let cond_re = Regex::new(r"(?i)^(if|when|unless)\b").expect("static regex");

    let raw_lines: Vec<&str> = raw.split('\n').collect();
    let secs = sections(&raw_lines);

    // Page furniture (running headers/footers) and any line carrying a
    // form-feed are dropped entirely, matching the Python prototype's
    // `body` comprehension.
    let body: Vec<(u32, String)> = raw_lines
        .iter()
        .enumerate()
        .filter(|(_, ln)| {
            let no_ff = ln.replace('\u{000C}', "");
            !furniture.is_match(no_ff.trim()) && !ln.contains('\u{000C}')
        })
        .map(|(i, ln)| {
            let no_ff = ln.replace('\u{000C}', "");
            ((i + 1) as u32, no_ff.trim_end().to_string())
        })
        .collect();

    let mut out = Vec::new();
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let (lineno, ln) = &body[i];
        let Some(caps) = def.captures(ln) else {
            i += 1;
            continue;
        };
        let indent = caps[1].len();
        let name = caps[2].to_string();
        let inline = caps.get(3).map(|m| m.as_str().to_string());
        if !matches!(indent, 3 | 6 | 9) {
            i += 1;
            continue;
        }

        // Collect the description body: every following line indented
        // deeper than this definition, allowing one blank line to be
        // skipped when it's a page break followed by a genuine
        // continuation (not a new definition).
        let mut buf: Vec<String> = match &inline {
            Some(s) => vec![s.clone()],
            None => vec![],
        };
        let mut end = *lineno;
        let mut j = i + 1;
        while j < body.len() {
            let (n2, l2) = &body[j];
            if l2.trim().is_empty() {
                if j + 1 < body.len() {
                    let (_, l3) = &body[j + 1];
                    if !l3.trim().is_empty()
                        && leading_spaces(l3) > indent
                        && def.captures(l3).is_none()
                    {
                        j += 1;
                        continue;
                    }
                }
                break;
            }
            let ind2 = leading_spaces(l2);
            if ind2 <= indent {
                break;
            }
            if def.captures(l2).is_some() && matches!(ind2, 6 | 9) {
                break; // the next sub-attribute
            }
            buf.push(l2.trim().to_string());
            end = *n2;
            j += 1;
        }

        let text = buf
            .join(" ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if text.is_empty() || text.len() < 12 {
            i = j.max(i + 1);
            continue;
        }

        if let Some(cm) = card.find(&text) {
            while let Some(top) = stack.last() {
                if top.0 >= indent {
                    stack.pop();
                } else {
                    break;
                }
            }
            let parent = stack.last().map(|(_, n)| n.clone());
            let tail = text[cm.end()..].trim().to_string();
            let conditional = cond_re.is_match(&tail);
            let section = sec_at(&secs, *lineno);
            let attribute = match &parent {
                Some(p) => format!("{p}.{name}"),
                None => name.clone(),
            };
            out.push(ScannedDef {
                rfc,
                section,
                start: *lineno,
                end,
                attribute,
                parent: parent.clone(),
                name: name.clone(),
                cardinality: cm.as_str().to_string(),
                conditional,
            });
        }
        // Pushed unconditionally -- see the module doc comment.
        stack.push((indent, name));
        i = j.max(i + 1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC7643_TXT: &str = include_str!("../../../../spec/rfc/rfc7643.txt");
    const RFC7644_TXT: &str = include_str!("../../../../spec/rfc/rfc7644.txt");

    /// The Python prototype (`extract_attrdefs.py`), run fresh against the
    /// same vendored text, produces exactly 61 entries
    /// (`tools/prototype/golden/attrdefs.json`). This is the same
    /// mechanical check, ported: same input, same count.
    #[test]
    fn scan_produces_61_entries_across_both_rfcs() {
        let mut all = scan(7643, RFC7643_TXT);
        all.extend(scan(7644, RFC7644_TXT));
        assert_eq!(all.len(), 61, "scanned entries: {all:#?}");
    }
}
