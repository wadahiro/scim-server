//! Loads the hand-curated RFC 7644 §3.5.2 requirement ledger
//! (`spec/ledger/rfc7644-3.5.2.yaml`) and mechanically verifies its
//! quotations against the vendored, unmodified RFC text in `spec/rfc/`.
//!
//! The ledger is the "authored" input to `crate::requirement` /
//! `crate::templates`: a human read §3.5.2 once, recorded one entry per
//! paragraph with its raw-file line span and (for definitional paragraphs)
//! a verbatim quote, and this module is the only place that quote is
//! trusted -- [`verify_quotes`] re-derives it from the span and refuses to
//! agree if it doesn't match, so "verbatim" is a checked property of the
//! ledger, not a promise about how it was typed.

use regex::Regex;
use serde::Deserialize;

/// One paragraph of the ledger. Extra YAML keys not listed here (`refs`,
/// `coverage_detail`, `finding`, ...) are present in
/// `spec/ledger/rfc7644-3.5.2.yaml` for human context but are not needed by
/// the generated-check path and are silently ignored by serde.
#[derive(Debug, Clone, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    /// Raw-file (`spec/rfc/rfc7644.txt`) 1-based inclusive line span, e.g.
    /// `(1939, 1944)`.
    pub lines: (u32, u32),
    pub class: EntryClass,
    #[serde(default)]
    pub keywords: Vec<String>,
    pub quote: Option<String>,
    /// YAML 1.1 bare `yes`/`no` (as used throughout the ledger, e.g.
    /// `testable: yes`) parses under serde_yaml's YAML-1.2-core rules as a
    /// plain string, not a bool -- [`de_optional_yes_no`] accepts either
    /// spelling.
    #[serde(default, deserialize_with = "de_optional_yes_no")]
    pub testable: Option<bool>,
    #[serde(default)]
    pub checks: Vec<String>,
    pub coverage: Option<String>,
    pub note: Option<String>,
}

/// Deserializes an `Option<bool>` field that may be written in the YAML as
/// an actual boolean (`true`/`false`) or as a bare `yes`/`no` string (YAML
/// 1.1 boolean spelling, which serde_yaml's YAML-1.2-core parser reads back
/// as a plain string rather than a bool).
fn de_optional_yes_no<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrYesNo {
        Bool(bool),
        Str(String),
    }
    let opt: Option<BoolOrYesNo> = Option::deserialize(deserializer)?;
    Ok(opt.map(|v| match v {
        BoolOrYesNo::Bool(b) => b,
        BoolOrYesNo::Str(s) => matches!(s.to_ascii_lowercase().as_str(), "yes" | "true"),
    }))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryClass {
    Definitional,
    Explanatory,
    Example,
    Meta,
}

/// The full ledger for one RFC section. `lines` is the section's own raw
/// span (e.g. `(1780, 1966)` for RFC 7644 §3.5.2); every entry's `lines`
/// must fall within it (checked by `tests/conformance_ledger_matrix.rs`,
/// not here -- this module only checks quotes).
#[derive(Debug, Clone, Deserialize)]
pub struct Ledger {
    pub section: String,
    pub doc: String,
    pub lines: (u32, u32),
    pub entries: Vec<LedgerEntry>,
}

/// Loads `spec/ledger/rfc7644-3.5.2.yaml`, baked into the binary at compile
/// time (never read from disk at runtime -- there is no "wrong working
/// directory" failure mode).
pub fn load_rfc7644_3_5_2() -> Ledger {
    const RAW: &str = include_str!("../../../spec/ledger/rfc7644-3.5.2.yaml");
    serde_yaml::from_str(RAW).expect("spec/ledger/rfc7644-3.5.2.yaml must parse as a Ledger")
}

/// One entry whose `quote` could not be found, verbatim (whitespace
/// normalized, page furniture removed) inside its own `lines` span of
/// `raw_text`.
#[derive(Debug, Clone)]
pub struct QuoteMismatch {
    pub id: String,
    pub reason: String,
}

/// Page furniture: running headers/footers repeated on every page of the
/// plain-text RFC (`RFC 7644               SCIM Protocol ...`, `Hunt, et
/// al.  ...`, `... [Page N]`). Matches `tools/prototype/relocate_ledger.py`
/// and `verify-quotes.rb`'s rule exactly, including the same three
/// alternatives; a line containing a form-feed is treated as furniture
/// separately (checked in [`is_furniture`], not by this pattern).
fn furniture_re() -> Regex {
    Regex::new(r"^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)").expect("static regex")
}

fn is_furniture(re: &Regex, line: &str) -> bool {
    re.is_match(line) || line.contains('\u{000C}')
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// For every entry with a `quote`, checks that the quote occurs
/// (whitespace-normalized) inside `raw_text`'s `entry.lines` span, after
/// furniture lines are dropped from that span. Returns every entry that
/// fails; an empty result means every quotation in the ledger is verbatim.
pub fn verify_quotes(ledger: &Ledger, raw_text: &str) -> Vec<QuoteMismatch> {
    let re = furniture_re();
    let raw_lines: Vec<&str> = raw_text.lines().collect();
    let mut mismatches = Vec::new();

    for entry in &ledger.entries {
        let Some(quote) = &entry.quote else {
            continue;
        };
        let (start, end) = entry.lines;
        if start == 0 || start > end || end as usize > raw_lines.len() {
            mismatches.push(QuoteMismatch {
                id: entry.id.clone(),
                reason: format!(
                    "span [{start}, {end}] is out of bounds (raw text has {} lines)",
                    raw_lines.len()
                ),
            });
            continue;
        }
        let span = &raw_lines[(start as usize - 1)..(end as usize)];
        let kept: Vec<&str> = span
            .iter()
            .filter(|l| !is_furniture(&re, l))
            .copied()
            .collect();
        let body = normalize_ws(&kept.join(" "));
        let q = normalize_ws(quote);
        if !body.contains(&q) {
            mismatches.push(QuoteMismatch {
                id: entry.id.clone(),
                reason: format!(
                    "quote not found verbatim in raw L{start}-{end}\n    quote: {:?}\n    raw:   {:?}",
                    crate::client::truncate(&q, 150),
                    crate::client::truncate(&body, 150),
                ),
            });
        }
    }
    mismatches
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn rfc7644_3_5_2_ledger_has_27_entries_and_verified_quotes() {
        let ledger = load_rfc7644_3_5_2();
        assert_eq!(ledger.entries.len(), 27);

        let raw = include_str!("../../../spec/rfc/rfc7644.txt");
        let mismatches = verify_quotes(&ledger, raw);
        assert!(mismatches.is_empty(), "quote mismatches: {:#?}", mismatches);

        let mut tally: BTreeMap<&'static str, usize> = BTreeMap::new();
        for e in &ledger.entries {
            let key = match e.class {
                EntryClass::Definitional => "definitional",
                EntryClass::Explanatory => "explanatory",
                EntryClass::Example => "example",
                EntryClass::Meta => "meta",
            };
            *tally.entry(key).or_default() += 1;
        }
        assert_eq!(tally.get("definitional").copied().unwrap_or(0), 11);
        assert_eq!(tally.get("explanatory").copied().unwrap_or(0), 2);
        assert_eq!(tally.get("example").copied().unwrap_or(0), 7);
        assert_eq!(tally.get("meta").copied().unwrap_or(0), 7);
    }

    #[test]
    fn every_entry_span_lies_within_the_section_span() {
        let ledger = load_rfc7644_3_5_2();
        for e in &ledger.entries {
            assert!(
                e.lines.0 >= ledger.lines.0 && e.lines.1 <= ledger.lines.1,
                "{} span {:?} escapes section span {:?}",
                e.id,
                e.lines,
                ledger.lines
            );
        }
    }
}
