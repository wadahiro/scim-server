//! Three derived views over a [`Profile`]: `render_profile` (human text),
//! `profile_json` (stable, diffable machine format), and
//! `compatibility_config` (the payoff -- a `compatibility:` YAML block a
//! human can paste straight into `scim-server`'s config, see `CLAUDE.md`).
//!
//! No direct source-branch equivalent: that branch's `report.rs`/
//! `render.rs` rendered pass/fail findings against a schema-driven matrix.
//! This module is a rewrite for the profile shape (see the brief this
//! crate was built from -- "expect to rewrite most of it").

use std::collections::BTreeMap;

use crate::axes::AXES;
use crate::axis::{Axis, Observation, Profile, Value};
use crate::matrix::{self, Method};
use crate::rfc::{self, Keyword, RfcPosition};

fn axis_for(id: &str) -> Option<&'static Axis> {
    AXES.iter().find(|a| a.id == id)
}

/// Whether `obs`'s value is a fault against `axis`'s `RfcPosition` --
/// `None` when the axis has no fixed expectation to violate (`Permitted`,
/// `Silent`, or the value itself is `Unobservable`).
///
/// `pub(crate)` (not `fn`, the way every other helper in this module stays
/// private) specifically so `crate::axes::etag_token_tests` can exercise
/// this actual predicate -- the one that decides whether an "advertised
/// but not honoured" `etag_conditional_write/*/stale` observation
/// (`Known("accepted_despite_stale")`) really does render as a fault --
/// rather than a copy of its `match` reimplemented in the test. See that
/// module's doc comment and `CLAUDE.md`'s "never duplicate production
/// logic in a test" rule.
pub(crate) fn is_fault(axis: &Axis, obs: &Observation) -> Option<bool> {
    let Value::Known(v) = &obs.value else {
        return None;
    };
    match axis.rfc {
        RfcPosition::Mandated {
            keyword, expected, ..
        } => Some(keyword.is_fault(*v == expected)),
        RfcPosition::Permitted { .. } | RfcPosition::Silent { .. } => None,
        RfcPosition::SelfDeclared { .. } => Some(rfc::self_declared_is_fault(v)),
    }
}

fn value_token(v: &Value) -> String {
    match v {
        Value::Known(s) => s.to_string(),
        Value::Unknown(s) => format!("unknown:{s}"),
        Value::Unobservable(u) => format!("unobservable:{}", u.token()),
    }
}

// --------------------------------------------------------------- text view

pub fn render_profile(profile: &Profile) -> String {
    let mut out = String::new();
    out.push_str(&format!("target: {}\n", profile.target));
    out.push_str(&format!("observed_at: {}\n", profile.observed_at));
    out.push_str(&format!(
        "axes: {} observed\n\n",
        profile.observations.len()
    ));

    for obs in &profile.observations {
        let Some(axis) = axis_for(&obs.axis) else {
            continue;
        };
        out.push_str(&format!("{}\n", axis.id));
        out.push_str(&format!("  about:  {}\n", axis.about));
        match axis.rfc {
            RfcPosition::Mandated {
                basis,
                keyword,
                expected,
            } => {
                let kw = match keyword {
                    Keyword::Must => "MUST",
                    Keyword::Should => "SHOULD",
                    Keyword::May => "MAY",
                };
                out.push_str(&format!(
                    "  rfc:    mandated ({kw} be {expected:?}) -- {basis}\n"
                ));
            }
            RfcPosition::Permitted { basis } => {
                out.push_str(&format!(
                    "  rfc:    permitted (either value conforms) -- {basis}\n"
                ));
            }
            RfcPosition::Silent { basis } => match basis {
                // Show what established the silence, so the classification
                // is auditable rather than an assertion.
                Some(b) => out.push_str(&format!(
                    "  rfc:    silent (left open by the text) -- {b}\n"
                )),
                None => out.push_str(
                    "  rfc:    silent -- not regulated by RFC 7643/7644 (no single passage)\n",
                ),
            },
            RfcPosition::SelfDeclared { basis, declares } => {
                out.push_str(&format!(
                    "  rfc:    self-declared (bound by the target's own declaration of {declares}) -- {basis}\n"
                ));
            }
        }
        out.push_str(&format!(
            "  knob:   {}\n",
            axis.knob.unwrap_or("(none -- candidate for a new option)")
        ));
        out.push_str(&format!("  observed: {}\n", value_token(&obs.value)));
        match (is_fault(axis, obs), axis.rfc) {
            (Some(true), RfcPosition::SelfDeclared { .. }) => {
                out.push_str("  verdict: VIOLATION (contradicts the target's own declaration)\n")
            }
            (Some(true), _) => {
                out.push_str("  verdict: VIOLATION (deviates from a mandated value)\n")
            }
            (Some(false), _) => out.push_str("  verdict: conforms\n"),
            (None, _) => out.push_str("  verdict: n/a (permitted, silent, or unobservable)\n"),
        }
        if matches!(obs.value, Value::Unknown(_)) {
            out.push_str("  ** discovery: this value has no name -- a candidate for a new compatibility option **\n");
        }
        if !obs.detail.is_empty() {
            out.push_str(&format!("  detail: {}\n", obs.detail));
        }
        out.push('\n');
    }

    render_derived_summary(profile, &mut out);

    out
}

/// Parses a `DerivedAxis::id`/`Observation::axis` string
/// (`"<family_prefix>/<Resource>.<attr path>/<method>"`) into its three
/// components. `None` for anything that isn't a derived id (the sixteen
/// static axes' ids, which contain no `/`).
fn parse_derived_id(axis: &str) -> Option<(&str, &str, &str)> {
    let mut parts = axis.splitn(3, '/');
    let family = parts.next()?;
    let attr = parts.next()?;
    let method = parts.next()?;
    Some((family, attr, method))
}

/// 389 individual lines is unusable against a real provider (see the brief
/// this was built from). `profile_json` still records every instance
/// individually -- that's what makes it diffable and evidence-bearing --
/// but the text view aggregates: one line per (family x method x observed
/// value) with a count, then the instances that deviate from their
/// (family, method)'s majority value listed individually. A provider that
/// ignores readOnly on PATCH across the board reads as one line; a
/// provider that does it for exactly one attribute reads as a one-line
/// exception worth looking at. A family whose majority value is itself a
/// fault is flagged as a compatibility-option candidate -- every derived
/// family has `knob: None` (none of these eight characteristics has a
/// `CompatibilityConfig` field today), so a consistent non-conforming
/// majority is exactly the signal the brief calls "the tool's purpose, not
/// a footnote."
fn render_derived_summary(profile: &Profile, out: &mut String) {
    // family_prefix -> method_str -> observed token -> matching observations
    let mut groups: BTreeMap<&str, BTreeMap<&str, BTreeMap<String, Vec<&Observation>>>> =
        BTreeMap::new();
    for obs in &profile.observations {
        let Some((family_prefix, _attr, method_str)) = parse_derived_id(&obs.axis) else {
            continue;
        };
        if matrix::family_for(&obs.axis).is_none() {
            continue;
        }
        groups
            .entry(family_prefix)
            .or_default()
            .entry(method_str)
            .or_default()
            .entry(value_token(&obs.value))
            .or_default()
            .push(obs);
    }
    if groups.is_empty() {
        return;
    }

    let total: usize = groups
        .values()
        .flat_map(|by_method| by_method.values())
        .flat_map(|by_value| by_value.values())
        .map(|v| v.len())
        .sum();
    out.push_str("schema-derived characteristics\n");
    out.push_str(&format!(
        "  {total} instances across {} families, aggregated by family x method x observed \
         value (see --format json for every individual instance)\n\n",
        groups.len()
    ));

    for (family_prefix, by_method) in &groups {
        out.push_str(&format!("{family_prefix}\n"));
        if let Some(family) = matrix::DERIVED_FAMILIES
            .iter()
            .find(|f| f.id_prefix == *family_prefix)
        {
            out.push_str(&format!("  about: {}\n", family.about));
        }
        for (method_str, by_value) in by_method {
            let majority = by_value.iter().max_by_key(|(_, obs)| obs.len());
            let line = by_value
                .iter()
                .map(|(token, obs)| format!("{token} x{}", obs.len()))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("  {method_str}: {line}"));

            let is_fault_fn = Method::parse(method_str)
                .and_then(|m| matrix::known_and_fault_for(family_prefix, m))
                .map(|(_, f)| f);
            if let (Some((maj_token, _)), Some(is_fault)) = (majority, is_fault_fn) {
                if is_fault(maj_token) {
                    out.push_str(&format!(
                        " -- ** majority value {maj_token:?} is non-conforming; no knob covers \
                         {family_prefix} -- candidate for a new compatibility option **"
                    ));
                }
            }
            out.push('\n');

            if let Some((maj_token, _)) = majority {
                for (token, obs_list) in by_value {
                    if token == maj_token {
                        continue;
                    }
                    for obs in obs_list {
                        out.push_str(&format!("    deviates: {} -> {token}", obs.axis));
                        if !obs.detail.is_empty() {
                            out.push_str(&format!(" ({})", obs.detail));
                        }
                        out.push('\n');
                    }
                }
            }
        }
        out.push('\n');
    }
}

// --------------------------------------------------------------- json view

/// A stable, diffable JSON record for one axis. Field order is fixed by
/// struct declaration order (serde_json preserves insertion order), and no
/// timestamp lives inside a per-axis record -- only `Profile::observed_at`
/// at the top level carries one, so two runs against the same unchanged
/// target produce byte-identical per-axis bytes.
#[derive(serde::Serialize)]
struct JsonAxis<'a> {
    id: &'a str,
    observed: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<Vec<JsonExchange<'a>>>,
}

#[derive(serde::Serialize)]
struct JsonExchange<'a> {
    method: &'a str,
    url: &'a str,
    status: Option<u16>,
}

#[derive(serde::Serialize)]
struct JsonProfile<'a> {
    target: &'a str,
    axes: Vec<JsonAxis<'a>>,
}

/// Sorted by axis id; evidence omitted unless the value is `Unknown`
/// (the discovery signal is the one case where a diff needs to see why).
/// No timestamps inside per-axis records. Two calls against the same
/// `Profile` produce byte-identical output (see
/// `tests::profile_json_is_byte_stable_across_two_calls`).
pub fn profile_json(profile: &Profile) -> String {
    let mut axes: Vec<JsonAxis> = profile
        .observations
        .iter()
        .map(|obs| JsonAxis {
            id: &obs.axis,
            observed: value_token(&obs.value),
            evidence: if matches!(obs.value, Value::Unknown(_)) {
                Some(
                    obs.evidence
                        .iter()
                        .map(|e| JsonExchange {
                            method: &e.method,
                            url: &e.url,
                            status: e.status,
                        })
                        .collect(),
                )
            } else {
                None
            },
        })
        .collect();
    axes.sort_by(|a, b| a.id.cmp(b.id));

    let jp = JsonProfile {
        target: &profile.target,
        axes,
    };
    serde_json::to_string_pretty(&jp).unwrap_or_default()
}

// ------------------------------------------------------ compatibility.yaml

/// Emits the `compatibility:` YAML block that makes `scim-server` behave
/// like the diagnosed target -- one line per axis whose observed value
/// maps to a knob value, commented with the axis it came from. Axes that
/// were `Unobservable` are omitted rather than guessed at.
pub fn compatibility_config(profile: &Profile) -> String {
    let mut lines = vec!["compatibility:".to_string()];
    let mut any = false;

    for obs in &profile.observations {
        let Some(axis) = axis_for(&obs.axis) else {
            continue;
        };
        let Some(field) = axis.knob else { continue };
        let Value::Known(value) = &obs.value else {
            continue;
        };
        any = true;
        lines.push(format!("  # from axis: {}", axis.id));
        lines.push(format!("  {field}: {}", knob_yaml_value(field, value)));
    }

    if !any {
        return "compatibility: {}  # no axis produced an emittable knob value\n".to_string();
    }

    lines.push(String::new());
    lines.join("\n")
}

/// Translates an axis's `Value::Known` token into the literal YAML value
/// `scim-server`'s `CompatibilityConfig` expects for `field` -- most knobs
/// are booleans keyed by a different truthy token per axis
/// (`support_patch_replace_empty_array` is `true` for `"cleared"`, for
/// instance), while `meta_datetime_format` is a string enum and passes its
/// token straight through.
fn knob_yaml_value(field: &str, observed: &str) -> String {
    match field {
        "meta_datetime_format" => format!("\"{observed}\""),
        "show_empty_groups_members" => bool_str(observed == "empty_array").to_string(),
        // `observed` is a `declares_<value>_<present|absent>` token (see
        // `crate::axes::self_declared_token`): the knob tracks the actual
        // observed presence, independent of whether the declaration was
        // self-consistent.
        "include_user_groups" => bool_str(observed.ends_with("_present")).to_string(),
        "support_group_members_filter" => bool_str(observed == "processed").to_string(),
        "support_group_displayname_filter" => bool_str(observed == "processed").to_string(),
        "support_patch_replace_empty_array" => bool_str(observed == "cleared").to_string(),
        "support_patch_replace_empty_value" => bool_str(observed == "cleared").to_string(),
        _ => format!("\"{observed}\""),
    }
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::Exchange;

    fn hand_built_profile() -> Profile {
        Profile {
            target: "https://example.test/scim/v2".to_string(),
            observed_at: "2026-09-24T00:00:00Z".to_string(),
            observations: vec![
                // Known, mandated, matches expected -> conforms.
                Observation {
                    axis: "meta_datetime_format".to_string(),
                    value: Value::Known("rfc3339"),
                    evidence: vec![Exchange {
                        method: "POST".to_string(),
                        url: "https://example.test/scim/v2/Users".to_string(),
                        status: Some(201),
                        elapsed_ms: 5,
                        request_body: None,
                        response_body: None,
                    }],
                    detail: "meta.created/lastModified parse as RFC 3339".to_string(),
                },
                // Permitted -> never a fault regardless of value.
                Observation {
                    axis: "empty_multivalued_rendering".to_string(),
                    value: Value::Known("omitted"),
                    evidence: Vec::new(),
                    detail: "members omitted entirely".to_string(),
                },
                // Silent, Unknown -> the discovery signal, carries evidence.
                Observation {
                    axis: "group_members_filter".to_string(),
                    value: Value::Unknown("processed_but_case_insensitive".to_string()),
                    evidence: vec![Exchange {
                        method: "GET".to_string(),
                        url: "https://example.test/scim/v2/Groups?filter=...".to_string(),
                        status: Some(200),
                        elapsed_ms: 3,
                        request_body: None,
                        response_body: Some("{\"Resources\":[]}".to_string()),
                    }],
                    detail: "filter matched case-insensitively, an unnamed behaviour".to_string(),
                },
                // Unobservable: one of each variant.
                Observation {
                    axis: "group_displayname_filter".to_string(),
                    value: Value::Unobservable(crate::axis::Unobservable::CapabilityNotAdvertised(
                        "filter",
                    )),
                    evidence: Vec::new(),
                    detail: String::new(),
                },
                Observation {
                    axis: "user_groups_presence".to_string(),
                    value: Value::Unobservable(crate::axis::Unobservable::NeedsWrite),
                    evidence: Vec::new(),
                    detail: "skipped: would create a User and a Group".to_string(),
                },
                Observation {
                    axis: "patch_replace_empty_array".to_string(),
                    value: Value::Unobservable(crate::axis::Unobservable::NotDeclaredBySchema),
                    evidence: Vec::new(),
                    detail: String::new(),
                },
                Observation {
                    axis: "patch_replace_empty_value".to_string(),
                    value: Value::Unobservable(crate::axis::Unobservable::ProbeFailed(
                        "fixture POST failed: 500".to_string(),
                    )),
                    evidence: Vec::new(),
                    detail: String::new(),
                },
            ],
        }
    }

    #[test]
    fn render_profile_shows_verdict_and_discovery_flag() {
        let text = render_profile(&hand_built_profile());
        assert!(text.contains("meta_datetime_format"));
        assert!(text.contains("verdict: conforms"));
        assert!(text.contains("discovery: this value has no name"));
        assert!(text.contains("unobservable:capability_not_advertised:filter"));
        assert!(text.contains("unobservable:needs_write"));
    }

    #[test]
    fn profile_json_is_sorted_and_omits_evidence_except_for_unknown() {
        let json = profile_json(&hand_built_profile());
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        let axes = parsed["axes"].as_array().unwrap();
        let ids: Vec<&str> = axes.iter().map(|a| a["id"].as_str().unwrap()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "axes must be sorted by id");

        let unknown_axis = axes
            .iter()
            .find(|a| a["id"] == "group_members_filter")
            .unwrap();
        assert!(unknown_axis.get("evidence").is_some());
        assert_eq!(
            unknown_axis["observed"],
            "unknown:processed_but_case_insensitive"
        );

        let known_axis = axes
            .iter()
            .find(|a| a["id"] == "meta_datetime_format")
            .unwrap();
        assert!(
            known_axis.get("evidence").is_none(),
            "evidence must be omitted for a Known value"
        );

        assert!(
            !json.to_lowercase().contains("2026"),
            "per-axis records must carry no timestamp, so two runs diff cleanly"
        );
    }

    #[test]
    fn profile_json_is_byte_stable_across_two_calls() {
        let profile = hand_built_profile();
        assert_eq!(profile_json(&profile), profile_json(&profile));
    }

    #[test]
    fn compatibility_config_emits_only_known_knobbed_axes() {
        let yaml = compatibility_config(&hand_built_profile());
        assert!(yaml.contains("meta_datetime_format: \"rfc3339\""));
        assert!(yaml.contains("show_empty_groups_members: false"));
        assert!(yaml.contains("# from axis: meta_datetime_format"));
        // Unknown, Unobservable, and no-knob axes never appear as a knob line.
        assert!(!yaml.contains("support_group_members_filter"));
        assert!(!yaml.contains("include_user_groups"));
    }

    #[test]
    fn compatibility_config_with_no_emittable_axis_says_so() {
        let profile = Profile {
            target: "t".to_string(),
            observed_at: "now".to_string(),
            observations: vec![Observation {
                axis: "meta_datetime_format".to_string(),
                value: Value::Unobservable(crate::axis::Unobservable::NeedsWrite),
                evidence: Vec::new(),
                detail: String::new(),
            }],
        };
        let yaml = compatibility_config(&profile);
        assert!(yaml.contains("no axis produced an emittable knob value"));
    }
}
