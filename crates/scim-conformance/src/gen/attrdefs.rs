//! T9: generates presence checks for RFC 7643's `ServiceProviderConfig`
//! (§5), `ResourceType` (§6), and `Schema` (§7) required-member tables,
//! plus RFC 7644 §3.4.2's list-response envelope, against the four fixed
//! discovery endpoints those sections describe.
//!
//! This is a direct port of `tools/prototype/run_attrdef_checks.py`
//! (`TARGETS`, `present()`, and the verdict logic in `main()`), driven by
//! the same differential-oracle input, `tools/prototype/golden/
//! attrdefs.json` (61 entries extracted by `tools/prototype/
//! extract_attrdefs.py`). Only 38 of the 61 entries name a `(rfc, section)`
//! this crate has a target for (`TARGETS` below); the rest describe
//! attributes of resources this module doesn't check (e.g. RFC 7643 §2.2's
//! and §4.*'s User-schema entries) and are skipped, exactly as the Python
//! prototype does.
//!
//! Unlike `crate::matrix` (attribute x method cells derived from the
//! server's own `/Schemas`) this is a small, fixed family of single-
//! resource presence checks against four hardcoded paths -- there's no
//! natural `Method`/`Characteristic` axis to cross, so it doesn't reuse
//! `crate::matrix::Cell`/`Outcome`; it's shaped enough like them
//! ([`AttrdefCheck`] carries the same `Basis` and the shared
//! `crate::matrix::Verdict`) that a future scoreboard can still walk both
//! uniformly.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::basis::Basis;
use crate::client::ScimClient;
use crate::matrix::Verdict;
use crate::requirement::basis_from_span;

use super::attrdef_scan::{scan, ScannedDef};

const GOLDEN_JSON: &str = include_str!("../../../../tools/prototype/golden/attrdefs.json");
const RFC7643_TXT: &str = include_str!("../../../../spec/rfc/rfc7643.txt");
const RFC7644_TXT: &str = include_str!("../../../../spec/rfc/rfc7644.txt");

/// One entry of `tools/prototype/golden/attrdefs.json`, as specified by
/// T9. `start`/`end` (present in the JSON but not read here) are the
/// extractor's own raw-file line numbers; this module re-derives a
/// citation from `spec/rfc/*.txt` via [`attrdef_scan::scan`] instead of
/// trusting them (see [`resolve_basis`]).
#[derive(Debug, Clone, Deserialize)]
struct DefItemRaw {
    attribute: String,
    cardinality: String,
    condition: Option<String>,
    conditional: bool,
    #[allow(dead_code)]
    parent: Option<String>,
    rfc: u32,
    section: String,
    #[allow(dead_code)]
    section_title: String,
    #[allow(dead_code)]
    name: String,
}

fn load_defs() -> Vec<DefItemRaw> {
    serde_json::from_str(GOLDEN_JSON).expect("tools/prototype/golden/attrdefs.json must parse")
}

fn scanned_defs() -> Vec<ScannedDef> {
    let mut all = scan(7643, RFC7643_TXT);
    all.extend(scan(7644, RFC7644_TXT));
    all
}

/// How a matched `(rfc, section)`'s response body is walked when checking
/// presence -- `run_attrdef_checks.py`'s `'single'`/`'list'`/`'envelope'`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// The fetched body itself is the one target (`ServiceProviderConfig`,
    /// and the `/Users` list-response envelope -- RFC 7644 §3.4.2's
    /// entries name envelope fields like `totalResults`, not per-resource
    /// ones, so the envelope is checked directly, not each `Resources[]`
    /// element).
    Single,
    /// The body's `Resources` array; every element must carry the
    /// attribute.
    List,
}

/// `(rfc, section) -> (path, shape)`, copied unchanged from
/// `run_attrdef_checks.py`'s `TARGETS`.
fn targets() -> HashMap<(u32, &'static str), (&'static str, Shape)> {
    HashMap::from([
        ((7643, "5"), ("/ServiceProviderConfig", Shape::Single)),
        ((7643, "6"), ("/ResourceTypes", Shape::List)),
        ((7643, "7"), ("/Schemas", Shape::List)),
        ((7644, "3.4.2"), ("/Users", Shape::Single)),
    ])
}

/// One generated check: a single attribute's required-ness, tested against
/// one discovery endpoint, with its RFC citation and verdict.
#[derive(Debug, Clone, Serialize)]
pub struct AttrdefCheck {
    pub attribute: String,
    pub rfc_section: &'static str,
    pub basis: Basis,
    pub verdict: Verdict,
    pub detail: String,
}

/// Tri-state presence classification -- `present()` in
/// `run_attrdef_checks.py`. Distinguishes "the parent itself is missing"
/// from "the parent is present but this attribute isn't", because a
/// `REQUIRED` child of an `OPTIONAL`, absent parent is not a `FAIL`: its
/// requirement is conditional on the parent existing at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    AbsentParent,
    Missing,
    Ok,
}

/// Walks `dotted` (e.g. `"authenticationSchemes.type"`) through `obj`. If a
/// traversed segment's value is an array, every element of it must carry
/// the next segment -- matches the Python docstring: "if the path passes
/// through an array, require presence in every element".
fn present(obj: &Value, dotted: &str) -> Presence {
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut cur: Vec<&Value> = vec![obj];
    for part in &parts[..parts.len() - 1] {
        let mut next: Vec<&Value> = Vec::new();
        for c in &cur {
            let Some(map) = c.as_object() else {
                return Presence::AbsentParent;
            };
            let Some(v) = map.get(*part) else {
                return Presence::AbsentParent;
            };
            match v {
                Value::Array(items) => next.extend(items.iter()),
                other => next.push(other),
            }
        }
        if next.is_empty() {
            return Presence::AbsentParent; // empty array: no element to ask
        }
        cur = next;
    }
    let last = parts[parts.len() - 1];
    for c in &cur {
        match c.as_object() {
            Some(map) if map.contains_key(last) => {}
            _ => return Presence::Missing,
        }
    }
    Presence::Ok
}

/// `verdict_for()` in `run_attrdef_checks.py`: aggregates one
/// [`Presence`] per target into a verdict + detail message.
fn verdict_for(targets: &[&Value], attr: &str, label: &str) -> (Verdict, String) {
    let res: Vec<Presence> = targets.iter().map(|t| present(t, attr)).collect();
    let miss = res.iter().filter(|p| **p == Presence::Missing).count();
    let noparent = res.iter().filter(|p| **p == Presence::AbsentParent).count();
    if miss > 0 {
        return (
            Verdict::Fail,
            format!("{label}: missing in {miss} of {} target(s)", res.len()),
        );
    }
    if noparent == res.len() {
        return (
            Verdict::Skip,
            format!("{label}: parent is OPTIONAL and absent in every target"),
        );
    }
    if noparent > 0 {
        return (
            Verdict::Pass,
            format!(
                "{label}: satisfied in all {} target(s) with the parent present \
                 ({noparent} excluded -- parent absent)",
                res.len() - noparent
            ),
        );
    }
    (Verdict::Pass, label.to_string())
}

/// Re-derives an entry's citation from the vendored RFC text rather than
/// trusting `attrdefs.json`'s own `start`/`end` fields: finds the one
/// [`ScannedDef`] produced by scanning `spec/rfc/rfc{7643,7644}.txt`
/// (`attrdef_scan::scan`) whose `(rfc, section, attribute)` matches this
/// entry's -- unique across all 61 golden entries (checked by
/// `all_61_entries_resolve_to_a_basis_span` below) -- and builds a
/// [`Basis`] from its raw-file span via `crate::requirement::
/// basis_from_span`, the same helper the ledger-driven checks use.
fn resolve_basis(def: &DefItemRaw, scanned: &[ScannedDef]) -> Option<Basis> {
    let hit = scanned
        .iter()
        .find(|s| s.rfc == def.rfc && s.section == def.section && s.attribute == def.attribute)?;
    let doc = format!("RFC {}", def.rfc);
    Some(basis_from_span(&doc, &def.section, (hit.start, hit.end)))
}

enum Fetch {
    Ok { status: u16, body: Value },
    Err(String),
}

/// Generates and runs every check this crate can derive from the RFC 7643
/// required-member tables and RFC 7644 §3.4.2's envelope, against the
/// four `TARGETS` endpoints. Deterministic order: `attrdefs.json`'s own
/// entry order (filtered to entries with a `TARGETS` mapping).
pub async fn checks_from_attrdefs(client: &mut ScimClient) -> Vec<AttrdefCheck> {
    let defs = load_defs();
    let scanned = scanned_defs();
    let targets = targets();
    let mut cache: HashMap<&'static str, Fetch> = HashMap::new();
    let mut out = Vec::new();

    for def in &defs {
        let Some(&(path, shape)) = targets.get(&(def.rfc, def.section.as_str())) else {
            continue;
        };

        let basis = resolve_basis(def, &scanned).unwrap_or_else(|| {
            panic!(
                "no scanned definition site matches golden entry rfc={} section={} attribute={:?} \
                 -- attrdef_scan::scan and tools/prototype/extract_attrdefs.py have drifted apart",
                def.rfc, def.section, def.attribute
            )
        });
        let rfc_section: &'static str =
            Box::leak(format!("RFC {} §{}", def.rfc, def.section).into_boxed_str());

        if def.conditional {
            out.push(AttrdefCheck {
                attribute: def.attribute.clone(),
                rfc_section,
                basis,
                verdict: Verdict::Skip,
                detail: format!(
                    "conditional: {}",
                    def.condition.as_deref().unwrap_or("(no condition text)")
                ),
            });
            continue;
        }
        if def.cardinality != "REQUIRED" {
            // OPTIONAL (or RECOMMENDED, not present in the 38 matched
            // entries today): informational only, never judged -- matches
            // the Python prototype's INFO bucket, which doesn't even fetch
            // the endpoint for these.
            out.push(AttrdefCheck {
                attribute: def.attribute.clone(),
                rfc_section,
                basis,
                verdict: Verdict::Info,
                detail: format!("{} (not judged)", def.cardinality),
            });
            continue;
        }

        if !cache.contains_key(path) {
            let resolved = match path {
                "/Users" => client.get_query("/Users", &[("count", "1")]).await,
                other => client.get(other).await,
            };
            let resolved = match resolved {
                Ok(r) => Fetch::Ok {
                    status: r.status,
                    body: r.body.unwrap_or(Value::Null),
                },
                Err(e) => Fetch::Err(e.to_string()),
            };
            cache.insert(path, resolved);
        }

        let label = format!("GET {path}");
        let (verdict, detail) = match cache.get(path).expect("just inserted") {
            Fetch::Err(e) => (Verdict::Error, format!("{label} -> transport error: {e}")),
            Fetch::Ok { status, .. } if *status != 200 => {
                (Verdict::Error, format!("{label} -> {status}"))
            }
            Fetch::Ok { body, .. } => match shape {
                Shape::Single => verdict_for(&[body], &def.attribute, &label),
                Shape::List => {
                    let items: Vec<&Value> = body
                        .get("Resources")
                        .and_then(Value::as_array)
                        .map(|a| a.iter().collect())
                        .unwrap_or_default();
                    if items.is_empty() {
                        (Verdict::Error, format!("{label} returned no Resources"))
                    } else {
                        verdict_for(&items, &def.attribute, &label)
                    }
                }
            },
        };
        out.push(AttrdefCheck {
            attribute: def.attribute.clone(),
            rfc_section,
            basis,
            verdict,
            detail,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn all_61_entries_resolve_to_a_basis_span() {
        let defs = load_defs();
        assert_eq!(defs.len(), 61, "golden fixture changed size unexpectedly");
        let scanned = scanned_defs();

        let unresolved: Vec<&str> = defs
            .iter()
            .filter(|d| resolve_basis(d, &scanned).is_none())
            .map(|d| d.attribute.as_str())
            .collect();
        assert!(
            unresolved.is_empty(),
            "entries with no resolved basis span: {unresolved:?}"
        );
    }

    #[test]
    fn thirty_eight_entries_map_to_a_targets_section() {
        let defs = load_defs();
        let targets = targets();
        let matched = defs
            .iter()
            .filter(|d| targets.contains_key(&(d.rfc, d.section.as_str())))
            .count();
        assert_eq!(matched, 38, "TARGETS-matched entry count changed");
    }

    #[test]
    fn present_required_field_missing_is_missing() {
        let obj = json!({"schemas": ["x"]});
        assert_eq!(present(&obj, "totalResults"), Presence::Missing);
    }

    #[test]
    fn present_optional_parent_absent_is_absent_parent() {
        let obj = json!({"patch": {}});
        // "bulk.supported" -- "bulk" itself is absent from this body.
        assert_eq!(present(&obj, "bulk.supported"), Presence::AbsentParent);
    }

    #[test]
    fn present_optional_parent_absent_via_empty_array_is_absent_parent() {
        let obj = json!({"authenticationSchemes": []});
        assert_eq!(
            present(&obj, "authenticationSchemes.type"),
            Presence::AbsentParent
        );
    }

    #[test]
    fn present_everything_present_is_ok() {
        let obj = json!({"bulk": {"supported": true, "maxOperations": 1, "maxPayloadSize": 1}});
        assert_eq!(present(&obj, "bulk.supported"), Presence::Ok);
        assert_eq!(present(&obj, "bulk"), Presence::Ok);
    }

    #[test]
    fn present_array_parent_requires_every_element_to_carry_the_child() {
        let ok = json!({
            "authenticationSchemes": [
                {"type": "oauthbearertoken"},
                {"type": "httpbasic"}
            ]
        });
        assert_eq!(present(&ok, "authenticationSchemes.type"), Presence::Ok);

        let partial = json!({
            "authenticationSchemes": [
                {"type": "oauthbearertoken"},
                {"other": "x"}
            ]
        });
        assert_eq!(
            present(&partial, "authenticationSchemes.type"),
            Presence::Missing
        );
    }

    #[test]
    fn verdict_for_required_missing_in_some_targets_fails() {
        let a = json!({"attr": 1});
        let b = json!({});
        let (v, _) = verdict_for(&[&a, &b], "attr", "GET /x");
        assert_eq!(v, Verdict::Fail);
    }

    #[test]
    fn verdict_for_optional_parent_absent_in_every_target_skips() {
        let a = json!({});
        let b = json!({});
        let (v, _) = verdict_for(&[&a, &b], "bulk.supported", "GET /x");
        assert_eq!(v, Verdict::Skip);
    }

    #[test]
    fn verdict_for_all_present_passes() {
        let a = json!({"attr": 1});
        let b = json!({"attr": 2});
        let (v, _) = verdict_for(&[&a, &b], "attr", "GET /x");
        assert_eq!(v, Verdict::Pass);
    }
}
