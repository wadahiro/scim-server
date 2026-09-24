//! Drives all seven [`crate::axes::AXES`] against a live target and
//! assembles the resulting [`Profile`]. New here (no direct source-branch
//! equivalent -- that branch's `probes::run_all` had no write-budget
//! concept, since every probe it ran was always allowed to write): the
//! `Cost`/`--allow-writes` gate. When an axis is skipped for budget, the
//! profile records `Unobservable::NeedsWrite` for it -- never a silent
//! omission (see the brief this crate was built from: "the tool must be
//! able to report 'to learn axis X I would need to create a user'").

use crate::axes;
use crate::axis::{Cost, Observation, Profile, Unobservable, Value};
use crate::capability;
use crate::client::ScimClient;
use crate::fixtures::{cleanup, Bookkeeping};

/// Runs every axis in `crate::axes::AXES` against `client`.
///
/// `allow_writes` gates `Cost::NeedsUser`/`Cost::NeedsUserAndGroup` axes:
/// when false (the default), those axes are not probed at all and instead
/// record `Value::Unobservable(Unobservable::NeedsWrite)`.
pub async fn run(client: &mut ScimClient, target: &str, allow_writes: bool) -> Profile {
    let caps = capability::fetch(client).await;
    let mut bk = Bookkeeping::new();
    let mut observations = Vec::with_capacity(axes::AXES.len());

    for axis in axes::AXES {
        if !allow_writes && axis.cost != Cost::DiscoveryOnly {
            observations.push(Observation {
                axis: axis.id,
                value: Value::Unobservable(Unobservable::NeedsWrite),
                evidence: Vec::new(),
                detail: format!(
                    "skipped: observing {} would create a {}; pass --allow-writes to run it",
                    axis.id,
                    match axis.cost {
                        Cost::NeedsUser => "User",
                        Cost::NeedsUserAndGroup => "User and a Group",
                        Cost::DiscoveryOnly => unreachable!(),
                    }
                ),
            });
            continue;
        }

        let obs = match axis.id {
            "meta_datetime_format" => axes::probe_meta_datetime_format(client, &mut bk).await,
            "empty_multivalued_rendering" => {
                axes::probe_empty_multivalued_rendering(client, &mut bk).await
            }
            "user_groups_presence" => axes::probe_user_groups_presence(client, &mut bk).await,
            "group_members_filter" => {
                axes::probe_group_members_filter(client, &mut bk, &caps).await
            }
            "group_displayname_filter" => {
                axes::probe_group_displayname_filter(client, &mut bk, &caps).await
            }
            "patch_replace_empty_array" => {
                axes::probe_patch_replace_empty_array(client, &mut bk, &caps).await
            }
            "patch_replace_empty_value" => {
                axes::probe_patch_replace_empty_value(client, &mut bk, &caps).await
            }
            other => unreachable!("axis {other} has no probe wired in crate::runner::run"),
        };
        observations.push(obs);
    }

    cleanup(client, &bk).await;

    Profile {
        target: target.to_string(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        observations,
    }
}
