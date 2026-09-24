//! Three derived views over a [`Profile`]: `render_profile` (human text),
//! `profile_json` (stable, diffable machine format), and
//! `compatibility_config` (the payoff -- a `compatibility:` YAML block a
//! human can paste straight into `scim-server`'s config, see `CLAUDE.md`).
//!
//! No direct source-branch equivalent: that branch's `report.rs`/
//! `render.rs` rendered pass/fail findings against a schema-driven matrix.
//! This module is a rewrite for the profile shape (see the brief this
//! crate was built from -- "expect to rewrite most of it").

use crate::axes::AXES;
use crate::axis::{Axis, Observation, Profile, Value};
use crate::rfc::{Keyword, RfcPosition};

fn axis_for(id: &str) -> Option<&'static Axis> {
    AXES.iter().find(|a| a.id == id)
}

/// Whether `obs`'s value is a fault against `axis`'s `RfcPosition` --
/// `None` when the axis has no fixed expectation to violate (`Permitted`,
/// `Silent`, or the value itself is `Unobservable`).
fn is_fault(axis: &Axis, obs: &Observation) -> Option<bool> {
    let Value::Known(v) = &obs.value else {
        return None;
    };
    match axis.rfc {
        RfcPosition::Mandated {
            keyword, expected, ..
        } => Some(keyword.is_fault(*v == expected)),
        RfcPosition::Permitted { .. } | RfcPosition::Silent => None,
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
        let Some(axis) = axis_for(obs.axis) else {
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
            RfcPosition::Silent => {
                out.push_str("  rfc:    silent -- not regulated by RFC 7643/7644\n");
            }
        }
        out.push_str(&format!(
            "  knob:   {}\n",
            axis.knob.unwrap_or("(none -- candidate for a new option)")
        ));
        out.push_str(&format!("  observed: {}\n", value_token(&obs.value)));
        match is_fault(axis, obs) {
            Some(true) => out.push_str("  verdict: VIOLATION (deviates from a mandated value)\n"),
            Some(false) => out.push_str("  verdict: conforms\n"),
            None => out.push_str("  verdict: n/a (permitted, silent, or unobservable)\n"),
        }
        if matches!(obs.value, Value::Unknown(_)) {
            out.push_str("  ** discovery: this value has no name -- a candidate for a new compatibility option **\n");
        }
        if !obs.detail.is_empty() {
            out.push_str(&format!("  detail: {}\n", obs.detail));
        }
        out.push('\n');
    }

    out
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
            id: obs.axis,
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
        let Some(axis) = axis_for(obs.axis) else {
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
        "include_user_groups" => bool_str(observed == "present").to_string(),
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
                    axis: "meta_datetime_format",
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
                    axis: "empty_multivalued_rendering",
                    value: Value::Known("omitted"),
                    evidence: Vec::new(),
                    detail: "members omitted entirely".to_string(),
                },
                // Silent, Unknown -> the discovery signal, carries evidence.
                Observation {
                    axis: "group_members_filter",
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
                    axis: "group_displayname_filter",
                    value: Value::Unobservable(crate::axis::Unobservable::CapabilityNotAdvertised(
                        "filter",
                    )),
                    evidence: Vec::new(),
                    detail: String::new(),
                },
                Observation {
                    axis: "user_groups_presence",
                    value: Value::Unobservable(crate::axis::Unobservable::NeedsWrite),
                    evidence: Vec::new(),
                    detail: "skipped: would create a User and a Group".to_string(),
                },
                Observation {
                    axis: "patch_replace_empty_array",
                    value: Value::Unobservable(crate::axis::Unobservable::NotDeclaredBySchema),
                    evidence: Vec::new(),
                    detail: String::new(),
                },
                Observation {
                    axis: "patch_replace_empty_value",
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
                axis: "meta_datetime_format",
                value: Value::Unobservable(crate::axis::Unobservable::NeedsWrite),
                evidence: Vec::new(),
                detail: String::new(),
            }],
        };
        let yaml = compatibility_config(&profile);
        assert!(yaml.contains("no axis produced an emittable knob value"));
    }
}
