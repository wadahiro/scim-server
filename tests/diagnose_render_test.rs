//! Renderer snapshot tests (§6.3's "renderer snapshot" row): a hand-built
//! `Report` (no HTTP, no server) rendered through `render::text` and
//! `render::markdown` and compared against fixed strings, so a formatting
//! change shows up as a diff here rather than silently in the wild.

use scim_server::diag::cli::Format;
use scim_server::diag::model::{
    CheckOutcome, CleanupReport, Exchange, KnobValue, Report, ReportHeader, Severity, Tier, Verdict,
};
use scim_server::diag::render;

/// Covers: a `Quirk` and a `Pass` knob (Tier 1), a `Skip` knob (dropped
/// from the `--emit-config-snippet` output), a Tier 2 `Fail` carrying a
/// transcript (must show its Exchange line even at `verbose: 0` — the
/// "Fail/Error always shows the request log" rule both renderers share),
/// and a Tier 4 `Severity::Info` `Pass` (renders as `INFO`, not `OK`).
fn sample_report() -> Report {
    let header = ReportHeader {
        target: "https://api.example.test/scim/v2".to_string(),
        auth: "bearer (token from SCIM_DIAG_TOKEN)".to_string(),
        tls: "verified (built-in Mozilla roots)".to_string(),
        mode: "read-write".to_string(),
        prefix: "scimdiag-abc12345".to_string(),
        probe_email: Some("scimdiag-abc12345+{n}@corp.example.test".to_string()),
        probe_attribute: "phoneNumbers".to_string(),
        started: "2026-01-01T00:00:00Z".to_string(),
        duration_ms: 11400,
        tool_version: "0.0.0-test",
        verbose: 0,
        warnings: vec!["TLS verification DISABLED (--insecure)".to_string()],
    };

    let outcomes = vec![
        CheckOutcome {
            id: "compat.meta_datetime_format",
            title: "meta.created/lastModified format",
            tier: Tier::Compat,
            severity: Severity::Warning,
            knob: Some("meta_datetime_format"),
            verdict: Verdict::Quirk {
                detected: KnobValue::Str("epoch".to_string()),
            },
            note: None,
            transcript: vec![],
        },
        CheckOutcome {
            id: "compat.show_empty_groups_members",
            title: "Empty Group.members is shown as []",
            tier: Tier::Compat,
            severity: Severity::Warning,
            knob: Some("show_empty_groups_members"),
            verdict: Verdict::Pass {
                detected: Some(KnobValue::Bool(true)),
            },
            note: None,
            transcript: vec![],
        },
        CheckOutcome {
            id: "compat.support_group_members_filter",
            title: "Groups filterable by members.value",
            tier: Tier::Compat,
            severity: Severity::Warning,
            knob: Some("support_group_members_filter"),
            verdict: Verdict::Skip {
                reason: "requires fixture G1, which was not created".to_string(),
            },
            note: None,
            transcript: vec![],
        },
        CheckOutcome {
            id: "rfc.connect",
            title: "ServiceProviderConfig reachable",
            tier: Tier::Rfc7644,
            severity: Severity::Error,
            knob: None,
            verdict: Verdict::Pass { detected: None },
            note: None,
            transcript: vec![],
        },
        CheckOutcome {
            id: "rfc.error_status_is_string",
            title: "Error response `status` is a string",
            tier: Tier::Rfc7644,
            severity: Severity::Warning,
            knob: None,
            verdict: Verdict::Fail {
                detail: "got \"status\": 404 | not a string".to_string(),
            },
            note: None,
            transcript: vec![Exchange {
                method: "GET".to_string(),
                url: "https://api.example.test/scim/v2/Users/00000000-0000-4000-8000-0000000diag0"
                    .to_string(),
                status: Some(404),
                elapsed_ms: 42,
                request_body: None,
                response_body: Some("{\"status\":404}".to_string()),
            }],
        },
        CheckOutcome {
            id: "etag.if_none_match_weak_compare",
            title: "If-None-Match comparison semantics (weak vs byte-exact)",
            tier: Tier::Etag,
            severity: Severity::Info,
            knob: None,
            verdict: Verdict::Pass { detected: None },
            note: Some("byte-exact comparison only".to_string()),
            transcript: vec![],
        },
    ];

    let cleanup = CleanupReport {
        attempted: 2,
        deleted: 1,
        failures: vec![
            "Group 9f21 \"scimdiag-abc12345 probe group 1\" (DELETE -> 500)".to_string(),
        ],
    };

    Report {
        header,
        outcomes,
        cleanup: Some(cleanup),
    }
}

#[test]
fn text_render_matches_snapshot() {
    let report = sample_report();
    let rendered = render::render(&report, Format::Text, false);
    assert_eq!(
        rendered,
        r#"SCIM 2.0 Diagnostic Report
  Target          https://api.example.test/scim/v2
  Auth            bearer (token from SCIM_DIAG_TOKEN)
  TLS             verified (built-in Mozilla roots)
  Mode            read-write        Prefix  scimdiag-abc12345
  Probe email     scimdiag-abc12345+{n}@corp.example.test
  Probe attribute phoneNumbers
  Started         2026-01-01T00:00:00Z     Duration  11.4s
  Tool            scim-server 0.0.0-test
  ! TLS verification DISABLED (--insecure)

Tier 1 — Compatibility knobs
  [QUIRK] meta_datetime_format.................................... "epoch"
  [ OK  ] show_empty_groups_members............................... true
  [SKIP ] support_group_members_filter............................
          reason: requires fixture G1, which was not created

Tier 2 — RFC 7644 conformance
  [ OK  ] ServiceProviderConfig reachable
  [FAIL ] Error response `status` is a string
          got "status": 404 | not a string
          GET https://api.example.test/scim/v2/Users/00000000-0000-4000-8000-0000000diag0 -> 404 (42ms)

Tier 4 — ETag / RFC 7232 conditional requests
  [INFO ] If-None-Match comparison semantics (weak vs byte-exact)
          byte-exact comparison only

Summary   6 checks: 3 pass  1 fail  1 quirk  1 skip  0 error
Cleanup   1 of 2 probe resources deleted
  ! Group 9f21 "scimdiag-abc12345 probe group 1" (DELETE -> 500)
"#
    );
}

#[test]
fn text_render_emits_config_snippet() {
    let report = sample_report();
    let rendered = render::render(&report, Format::Text, true);
    // The Skip'd `support_group_members_filter` knob is omitted; the two
    // detected knobs are present, and the non-default one is marked.
    assert!(rendered.contains("Suggested `compatibility:` configuration"));
    let (_, snippet) = rendered
        .split_once("compatibility:\n")
        .expect("snippet section");
    assert!(snippet.contains("  meta_datetime_format: \"epoch\"  # quirk\n"));
    assert!(snippet.contains("  show_empty_groups_members: true\n"));
    assert!(!snippet.contains("support_group_members_filter"));
}

#[test]
fn markdown_render_matches_snapshot() {
    let report = sample_report();
    let rendered = render::render(&report, Format::Markdown, false);
    assert_eq!(
        rendered,
        r#"# SCIM 2.0 Diagnostic Report

| Field | Value |
|---|---|
| Target | https://api.example.test/scim/v2 |
| Auth | bearer (token from SCIM_DIAG_TOKEN) |
| TLS | verified (built-in Mozilla roots) |
| Mode | read-write |
| Prefix | scimdiag-abc12345 |
| Probe email | scimdiag-abc12345+{n}@corp.example.test |
| Probe attribute | phoneNumbers |
| Started | 2026-01-01T00:00:00Z |
| Duration | 11.4s |
| Tool | scim-server 0.0.0-test |

> ⚠ TLS verification DISABLED (--insecure)

## Tier 1 — Compatibility knobs

| Status | Knob | Detected | Detail |
|---|---|---|---|
| QUIRK | `meta_datetime_format` | "epoch" |  |
| OK | `show_empty_groups_members` | true |  |
| SKIP | `support_group_members_filter` |  | reason: requires fixture G1, which was not created |

## Tier 2 — RFC 7644 conformance

| Status | Check | Detail |
|---|---|---|
| OK | ServiceProviderConfig reachable |  |
| FAIL | Error response `status` is a string | got "status": 404 \| not a string |

<details>
<summary>rfc.error_status_is_string — request log</summary>

```
GET https://api.example.test/scim/v2/Users/00000000-0000-4000-8000-0000000diag0 -> 404 (42ms)
```

</details>

## Tier 4 — ETag / RFC 7232 conditional requests

| Status | Check | Detail |
|---|---|---|
| INFO | If-None-Match comparison semantics (weak vs byte-exact) | byte-exact comparison only |

## Summary

6 checks: 3 pass, 1 fail, 1 quirk, 1 skip, 0 error

## Cleanup

1 of 2 probe resources deleted.
- Group 9f21 "scimdiag-abc12345 probe group 1" (DELETE -> 500)
"#
    );
}

#[test]
fn markdown_render_emits_config_snippet() {
    let report = sample_report();
    let rendered = render::render(&report, Format::Markdown, true);
    assert!(rendered.contains("## Suggested `compatibility:` configuration"));
    let (_, snippet) = rendered
        .split_once("```yaml\ncompatibility:\n")
        .expect("fenced yaml snippet section");
    assert!(snippet.contains("  meta_datetime_format: \"epoch\"  # quirk\n"));
    assert!(!snippet.contains("support_group_members_filter"));
}
