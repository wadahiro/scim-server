//! T10c: the 7 `compatibility:` knobs (`src/config.rs`'s
//! `CompatibilityConfig`) are deliberate deviations from a strict default.
//! Flipping each one from its default must change *exactly* the set of
//! check rows that knob is documented to affect (`CLAUDE.md`'s
//! "Compatibility Configuration" section) -- no more, no fewer. This is the
//! detection-power oracle for `scim_conformance::full_suite`: if a knob flip
//! doesn't move the row it's supposed to move, that row isn't actually
//! checking what it claims to; if it moves more rows than expected, either
//! the extra row is a real (and previously unknown) side effect that needs
//! explaining, or a probe is entangled with more than one knob.
//!
//! Each of the 8 servers below (1 baseline + 7 one-knob-flipped) runs the
//! full schema matrix (~389 cells) once, so this file budgets ~2 minutes
//! total (matrix run: ~8s/server empirically).

use std::collections::BTreeMap;
use std::time::Duration;

use scim_conformance::client::{Auth, ClientConfig, ScimClient};
use scim_conformance::{Outcome, Verdict};
use scim_server::config::{AppConfig, CompatibilityConfig};
use tokio::sync::OnceCell;

mod common;

/// The baseline (all-default `CompatibilityConfig`) run, computed once and
/// shared across every `#[tokio::test]` in this file -- both
/// `baseline_has_no_error_verdicts` and `knob_flips_change_exactly_the_expected_rows`
/// need it, and running it twice would double this file's slowest cost for
/// no reason.
static BASELINE: OnceCell<Vec<Outcome>> = OnceCell::const_new();

async fn get_baseline() -> &'static Vec<Outcome> {
    BASELINE
        .get_or_init(|| run_suite(config_with_compat(CompatibilityConfig::default())))
        .await
}

#[tokio::test]
async fn baseline_has_no_error_verdicts() {
    let outcomes = get_baseline().await;
    let error_rows: Vec<&Outcome> = outcomes
        .iter()
        .filter(|o| matches!(o.verdict, Verdict::Error))
        .collect();
    assert!(
        error_rows.is_empty(),
        "baseline must have no ERROR verdicts (a probe/executor bug, not a finding): {:#?}",
        error_rows
            .iter()
            .map(|o| (
                o.resource,
                &o.attribute,
                o.characteristic,
                o.method,
                &o.detail
            ))
            .collect::<Vec<_>>()
    );
}

/// `(resource, attribute, schema, characteristic, method)` -- the same key
/// `tests/conformance_schema_matrix.rs` uses, extended transparently to
/// probe rows (whose `characteristic` is one of the `probe_*` variants).
type Key = (String, String, String, String, String);

fn key_of(o: &Outcome) -> Key {
    let characteristic = serde_json::to_value(o.characteristic)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let method = serde_json::to_value(o.method)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let resource = serde_json::to_value(o.resource)
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    (
        resource,
        o.attribute.clone(),
        o.schema.clone(),
        characteristic,
        method,
    )
}

/// `(verdict, observed)` -- what a knob flip is allowed to change about a
/// row. `detail` is deliberately excluded: it's free-text and varies with
/// ids/timestamps even when nothing about compliance changed.
type Fingerprint = (&'static str, Option<String>);

fn fingerprint_of(o: &Outcome) -> Fingerprint {
    (o.verdict.tag(), o.observed.clone())
}

/// Builds an `AppConfig` with `compat` set as both the global default and
/// every tenant's own override. Necessary because a tenant `compatibility:`
/// block *replaces* the whole struct (`AppConfig::get_effective_compatibility`
/// in `src/config.rs`): if only the global default were set, the tenant's
/// own (absent) override would fall back to per-field defaults instead,
/// silently resetting every knob but the one this test means to flip.
fn config_with_compat(compat: CompatibilityConfig) -> AppConfig {
    let mut cfg = common::create_test_app_config();
    cfg.compatibility = compat.clone();
    for tenant in cfg.tenants.iter_mut() {
        tenant.compatibility = Some(compat.clone().into());
    }
    cfg
}

/// Spawns a real server with `cfg`, runs the full suite against it, and
/// shuts the server down again (8 servers are spawned in this file; letting
/// each one leak, as the single-server schema-matrix test does, would hold
/// 8 listeners and backends open for no reason).
async fn run_suite(cfg: AppConfig) -> Vec<Outcome> {
    let server = common::spawn_real_server(cfg).await;
    let mut client = ScimClient::new(ClientConfig {
        base_url: server.base_url.clone(),
        auth: Auth::None,
        timeout: Duration::from_secs(10),
    })
    .expect("client construction");
    let outcomes = scim_conformance::full_suite(&mut client)
        .await
        .expect("full_suite");
    server.shutdown().await;
    outcomes
}

fn to_map(outcomes: &[Outcome]) -> BTreeMap<Key, Fingerprint> {
    outcomes
        .iter()
        .map(|o| (key_of(o), fingerprint_of(o)))
        .collect()
}

/// The set of keys whose fingerprint differs between `baseline` and
/// `mutated`, including keys present on only one side (`include_user_groups`
/// legitimately adds `returned_never` cells for `User.groups` to the
/// schema-driven matrix once `/Schemas` itself starts declaring that
/// attribute `returned: never` -- see that knob's block below for why).
fn changed_keys(
    baseline: &BTreeMap<Key, Fingerprint>,
    mutated: &BTreeMap<Key, Fingerprint>,
) -> Vec<Key> {
    let all_keys: std::collections::BTreeSet<&Key> =
        baseline.keys().chain(mutated.keys()).collect();
    all_keys
        .into_iter()
        .filter(|k| baseline.get(*k) != mutated.get(*k))
        .cloned()
        .collect()
}

fn assert_changed_exactly(
    baseline: &BTreeMap<Key, Fingerprint>,
    mutated: &BTreeMap<Key, Fingerprint>,
    expected: &[Key],
    knob: &str,
) {
    let mut actual = changed_keys(baseline, mutated);
    actual.sort();
    let mut expected = expected.to_vec();
    expected.sort();
    if actual != expected {
        let mut report = format!("knob {knob}: changed-key set mismatch\n");
        for k in &actual {
            if !expected.contains(k) {
                report.push_str(&format!(
                    "  UNEXPECTED changed: {k:?} baseline={:?} mutated={:?}\n",
                    baseline.get(k),
                    mutated.get(k)
                ));
            }
        }
        for k in &expected {
            if !actual.contains(k) {
                report.push_str(&format!(
                    "  EXPECTED but unchanged: {k:?} baseline={:?} mutated={:?}\n",
                    baseline.get(k),
                    mutated.get(k)
                ));
            }
        }
        panic!("{report}");
    }
}

fn user_key(attribute: &str, schema: &str, characteristic: &str, method: &str) -> Key {
    (
        "User".to_string(),
        attribute.to_string(),
        schema.to_string(),
        characteristic.to_string(),
        method.to_string(),
    )
}

fn group_key(attribute: &str, schema: &str, characteristic: &str, method: &str) -> Key {
    (
        "Group".to_string(),
        attribute.to_string(),
        schema.to_string(),
        characteristic.to_string(),
        method.to_string(),
    )
}

const USER_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
const GROUP_URN: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";

#[tokio::test]
async fn knob_flips_change_exactly_the_expected_rows() {
    let baseline_outcomes = get_baseline().await;
    let baseline = to_map(baseline_outcomes);

    let mut by_verdict: BTreeMap<&'static str, usize> = BTreeMap::new();
    for o in baseline_outcomes {
        *by_verdict.entry(o.verdict.tag()).or_default() += 1;
    }
    eprintln!(
        "baseline verdict distribution: {by_verdict:?} (total {})",
        baseline_outcomes.len()
    );

    // ---------------------------------------------------------- meta_datetime_format: epoch
    // Expected: only the meta_datetime probe's own row. The schema matrix
    // never type-checks meta.created/lastModified (they're readOnly, so no
    // TypeWrong/TypeValid cells exist for them; the readOnly-forgery check
    // compares against a literal forged string that never matches either
    // rfc3339 or epoch server output, so its verdict is unaffected).
    {
        let cfg = config_with_compat(CompatibilityConfig {
            meta_datetime_format: "epoch".to_string(),
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![user_key(
            "meta.created,meta.lastModified",
            USER_URN,
            "probe_meta_datetime",
            "POST",
        )];
        assert_changed_exactly(&baseline, &mutated, &expected, "meta_datetime_format=epoch");
    }

    // ---------------------------------------------------- show_empty_groups_members: false
    // Expected: only the empty_members_shape probe's observed token
    // (empty_array -> absent); its verdict stays PASS either way (RFC 7643
    // §2.5: both shapes are equivalent).
    {
        let cfg = config_with_compat(CompatibilityConfig {
            show_empty_groups_members: false,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![group_key(
            "members",
            GROUP_URN,
            "probe_empty_members_shape",
            "POST",
        )];
        assert_changed_exactly(
            &baseline,
            &mutated,
            &expected,
            "show_empty_groups_members=false",
        );
    }

    // -------------------------------------------------------- include_user_groups: false
    // Expected (re-measured against this rebase, post PR #72): only the
    // user_groups_presence probe (PASS present -> FAIL absent) PLUS the 4
    // newly-generated `returned_never` cells described below.
    //
    // Before #72, this knob's flip *also* changed the 3
    // `readonly-multivalued-echo-on-create` schema-matrix rows for
    // User.groups.{value,$ref,display} MutabilityReadOnly POST
    // (FAIL -> PASS) -- masking, not a fix: once `groups` was never
    // rendered at all, a forged groups.value/$ref/display could no longer
    // be observed in the POST response, so the readOnly-forgery check
    // could no longer catch it. #72 fixed that guard directly (a forged
    // `User.groups` is no longer echoed on POST at all), so those 3 rows
    // are now PASS in the *baseline* too, and flipping this knob no longer
    // moves them -- they simply drop out of this knob's change set. That
    // this knob went from detecting 4 things to detecting 1 (plus the
    // schema-shape cells below) is expected and correct: it's the same
    // effect that guard's fix had everywhere else, just visible here as a
    // shrinking change set rather than a shrinking FAIL count.
    //
    // The remaining 4 keys: `include_user_groups` doesn't just change
    // response *rendering*, it changes what `/Schemas` itself declares.
    // `src/resource/schema.rs::build_schema_resources` rewrites
    // `User.groups`'s advertised `returned` from `"default"` to `"never"`
    // for exactly this tenant setting (with its own RFC 7643 §7 / §2.5
    // justification in that function's doc comment). Since the
    // schema-driven matrix (`crate::matrix::cells::cells_from_decls`)
    // derives its cells from that same `/Schemas` response, a `groups`
    // attribute now declared `returned: never` gains 4 brand-new
    // `returned_never` cells (POST/GET/PUT/PATCH) that don't exist in the
    // baseline matrix at all (baseline `groups` is `returned: default`, so
    // no such cells are generated for it there). `groups` is a complex
    // container with declared sub-attributes, so `matrix::exec` SKIPs these
    // 4 (see `exec_returned_never`'s `is_container_skip` guard): forging a
    // bare scalar into a multi-valued complex container isn't a
    // well-formed probe, and the meaningful "does this leak" question is
    // already answered per sub-attribute by the (now-PASSing)
    // `mutability_readOnly` rows.
    {
        let cfg = config_with_compat(CompatibilityConfig {
            include_user_groups: false,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![
            user_key("groups", USER_URN, "probe_user_groups_presence", "GET"),
            // Newly-generated cells (see comment above) -- not a
            // pre-existing row whose fingerprint changed, but a row that
            // exists only once the knob makes `/Schemas` declare
            // `groups` as `returned: never`.
            user_key("groups", USER_URN, "returned_never", "POST"),
            user_key("groups", USER_URN, "returned_never", "GET"),
            user_key("groups", USER_URN, "returned_never", "PUT"),
            user_key("groups", USER_URN, "returned_never", "PATCH"),
        ];
        assert_changed_exactly(&baseline, &mutated, &expected, "include_user_groups=false");
    }

    // ------------------------------------------------ support_group_members_filter: false
    {
        let cfg = config_with_compat(CompatibilityConfig {
            support_group_members_filter: false,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![group_key(
            "members",
            GROUP_URN,
            "probe_group_members_filter",
            "GET",
        )];
        assert_changed_exactly(
            &baseline,
            &mutated,
            &expected,
            "support_group_members_filter=false",
        );
    }

    // -------------------------------------------- support_group_displayname_filter: false
    {
        let cfg = config_with_compat(CompatibilityConfig {
            support_group_displayname_filter: false,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![group_key(
            "displayName",
            GROUP_URN,
            "probe_group_displayname_filter",
            "GET",
        )];
        assert_changed_exactly(
            &baseline,
            &mutated,
            &expected,
            "support_group_displayname_filter=false",
        );
    }

    // ------------------------------------------------ support_patch_replace_empty_array: false
    {
        let cfg = config_with_compat(CompatibilityConfig {
            support_patch_replace_empty_array: false,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![user_key(
            "phoneNumbers",
            USER_URN,
            "probe_patch_replace_empty_array",
            "PATCH",
        )];
        assert_changed_exactly(
            &baseline,
            &mutated,
            &expected,
            "support_patch_replace_empty_array=false",
        );
    }

    // ------------------------------------------------ support_patch_replace_empty_value: true
    // Expected: only the patch_replace_empty_value probe's own row
    // (PASS status=400 -> FAIL cleared -- see the probe's doc comment:
    // accepting this pattern makes the server rewrite "replace" as "clear"
    // for this one non-standard spelling, which is a real deviation from
    // RFC 7644 §3.5.2.3's replace semantics, not merely "supporting more").
    {
        let cfg = config_with_compat(CompatibilityConfig {
            support_patch_replace_empty_value: true,
            ..CompatibilityConfig::default()
        });
        let mutated = to_map(&run_suite(cfg).await);
        let expected = vec![user_key(
            "phoneNumbers",
            USER_URN,
            "probe_patch_replace_empty_value",
            "PATCH",
        )];
        assert_changed_exactly(
            &baseline,
            &mutated,
            &expected,
            "support_patch_replace_empty_value=true",
        );
    }
}
