//! Executes a selected, ordered list of checks against one [`DiagContext`].

use std::sync::{Arc, Mutex};

use crate::diag::ctx::DiagContext;
use crate::diag::fixtures::FixtureSet;
use crate::diag::model::{CheckDef, CheckOutcome, Need, Verdict};

/// Applies `--only`/`--skip` to the catalog, preserving `catalog()`'s
/// order. `tier1..tier4` expand to every check in that tier. An empty
/// `only` means "everything"; `skip` is applied after `only`.
///
/// Selector validity (known check id or `tierN`) is already enforced by
/// `cli::into_options`, so this never needs to report an error — an
/// unrecognized selector here would simply match nothing.
pub fn select(defs: Vec<CheckDef>, only: &[String], skip: &[String]) -> Vec<CheckDef> {
    let kept: Vec<CheckDef> = if only.is_empty() {
        defs
    } else {
        defs.into_iter()
            .filter(|d| matches_any_selector(d, only))
            .collect()
    };
    kept.into_iter()
        .filter(|d| !matches_any_selector(d, skip))
        .collect()
}

fn matches_any_selector(def: &CheckDef, selectors: &[String]) -> bool {
    selectors
        .iter()
        .any(|s| s == def.id || s.as_str() == def.tier.slug())
}

/// Runs every def in order against `ctx`, moved in because this gets
/// `tokio::spawn`ed by the caller — a `'static` future can't borrow.
///
/// Every entry in `defs` always produces exactly one `CheckOutcome`
/// (Skip included): nothing is silently dropped from the report.
pub async fn run_all(mut ctx: DiagContext, defs: Vec<CheckDef>) -> Vec<CheckOutcome> {
    let mut outcomes = Vec::with_capacity(defs.len());
    // Fixtures are created lazily, exactly once, right before the first def
    // in catalog order that actually needs them (`needs` always lists
    // `Need::Writes` alongside any specific fixture it needs — see the
    // catalog tables) — *before* that same def's own `unmet_need_reason`
    // check, so provisioning's result (including a same-run failure) is
    // what that gate sees, not a stale "nothing created yet".
    let mut fixtures_provisioned = false;

    for def in defs {
        if !fixtures_provisioned && def.needs.contains(&Need::Writes) {
            fixtures_provisioned = true;
            crate::diag::fixtures::provision(&mut ctx).await;
        }

        if let Some(reason) = unmet_need_reason(&ctx, def.needs) {
            if !ctx.opts.quiet {
                eprintln!("  [SKIP ] {} - {reason}", def.id);
            }
            outcomes.push(CheckOutcome {
                id: def.id,
                title: def.title,
                tier: def.tier,
                severity: def.severity,
                knob: def.knob,
                verdict: Verdict::Skip { reason },
                note: None,
                transcript: Vec::new(),
            });
            continue;
        }

        if !ctx.opts.quiet {
            eprintln!("  running {} ...", def.id);
        }

        let (mut verdict, note) = (def.run)(&mut ctx).await;
        let transcript = ctx.client.take_log();

        if ctx.opts.dry_run {
            verdict = Verdict::Skip {
                reason: "dry-run".to_string(),
            };
        }

        outcomes.push(CheckOutcome {
            id: def.id,
            title: def.title,
            tier: def.tier,
            severity: def.severity,
            knob: def.knob,
            verdict,
            note,
            transcript,
        });
    }

    outcomes
}

/// `Some(reason)` if a precondition in `needs` isn't met; the reason names
/// the specific missing precondition, per the design note's rule that Skip
/// reasons must be concrete.
fn unmet_need_reason(ctx: &DiagContext, needs: &[Need]) -> Option<String> {
    for need in needs {
        match *need {
            Need::Writes => {
                if let Some(reason) = &ctx.writes_disabled {
                    return Some(format!("requires write mode: {reason}"));
                }
            }
            Need::U1 => {
                if fixture_missing(&ctx.fixtures, |f| f.u1.is_none()) {
                    return Some("requires fixture U1, which was not created".to_string());
                }
            }
            Need::U2 => {
                if fixture_missing(&ctx.fixtures, |f| f.u2.is_none()) {
                    return Some("requires fixture U2, which was not created".to_string());
                }
            }
            Need::U3 => {
                if fixture_missing(&ctx.fixtures, |f| f.u3.is_none()) {
                    return Some("requires fixture U3, which was not created".to_string());
                }
            }
            Need::G1 => {
                if fixture_missing(&ctx.fixtures, |f| f.g1.is_none()) {
                    return Some("requires fixture G1, which was not created".to_string());
                }
            }
            Need::G2 => {
                if fixture_missing(&ctx.fixtures, |f| f.g2.is_none()) {
                    return Some("requires fixture G2, which was not created".to_string());
                }
            }
            Need::Membership => {
                if fixture_missing(&ctx.fixtures, |f| f.u1.is_none() || f.g1.is_none()) {
                    return Some(
                        "requires the U1-in-G1 membership fixture, which was not created"
                            .to_string(),
                    );
                }
            }
        }
    }
    None
}

fn fixture_missing(
    fixtures: &Arc<Mutex<FixtureSet>>,
    predicate: impl Fn(&FixtureSet) -> bool,
) -> bool {
    let guard = fixtures.lock().unwrap();
    predicate(&guard)
}
