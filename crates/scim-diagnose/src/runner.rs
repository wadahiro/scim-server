//! Drives all thirty-two [`crate::axes::AXES`] against a live target and
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
use crate::matrix::{expand_all, run_derived_family};
use crate::schema::decls_from_schemas;

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
                axis: axis.id.to_string(),
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
            "uniqueness_scimtype/User/POST" => {
                axes::probe_uniqueness_scimtype_user_post(client, &mut bk).await
            }
            "uniqueness_scimtype/User/PUT" => {
                axes::probe_uniqueness_scimtype_user_put(client, &mut bk).await
            }
            "uniqueness_scimtype/User/PATCH" => {
                axes::probe_uniqueness_scimtype_user_patch(client, &mut bk, &caps).await
            }
            "uniqueness_scimtype/Group/POST" => {
                axes::probe_uniqueness_scimtype_group_post(client, &mut bk).await
            }
            "uniqueness_scimtype/Group/PUT" => {
                axes::probe_uniqueness_scimtype_group_put(client, &mut bk).await
            }
            "uniqueness_scimtype/Group/PATCH" => {
                axes::probe_uniqueness_scimtype_group_patch(client, &mut bk, &caps).await
            }
            "patch_sequential_application" => {
                axes::probe_patch_sequential_application(client, &mut bk, &caps).await
            }
            "patch_atomicity" => axes::probe_patch_atomicity(client, &mut bk, &caps).await,
            "patch_primary_demotion" => {
                axes::probe_patch_primary_demotion(client, &mut bk, &caps).await
            }
            "etag_response_header" => {
                axes::probe_etag_response_header(client, &mut bk, &caps).await
            }
            "etag_meta_version" => axes::probe_etag_meta_version(client, &mut bk, &caps).await,
            "etag_consistency" => axes::probe_etag_consistency(client, &mut bk, &caps).await,
            "etag_form" => axes::probe_etag_form(client, &mut bk, &caps).await,
            "etag_conditional_read/current" => {
                axes::probe_etag_conditional_read_current(client, &mut bk, &caps).await
            }
            "etag_conditional_read/stale" => {
                axes::probe_etag_conditional_read_stale(client, &mut bk, &caps).await
            }
            "etag_conditional_read/star" => {
                axes::probe_etag_conditional_read_star(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PUT/current" => {
                axes::probe_etag_conditional_write_put_current(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PUT/stale" => {
                axes::probe_etag_conditional_write_put_stale(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PUT/star" => {
                axes::probe_etag_conditional_write_put_star(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PATCH/current" => {
                axes::probe_etag_conditional_write_patch_current(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PATCH/stale" => {
                axes::probe_etag_conditional_write_patch_stale(client, &mut bk, &caps).await
            }
            "etag_conditional_write/PATCH/star" => {
                axes::probe_etag_conditional_write_patch_star(client, &mut bk, &caps).await
            }
            "etag_delete_if_match/current" => {
                axes::probe_etag_delete_if_match_current(client, &mut bk, &caps).await
            }
            "etag_delete_if_match/stale" => {
                axes::probe_etag_delete_if_match_stale(client, &mut bk, &caps).await
            }
            "etag_delete_if_match/star" => {
                axes::probe_etag_delete_if_match_star(client, &mut bk, &caps).await
            }
            other => unreachable!("axis {other} has no probe wired in crate::runner::run"),
        };
        observations.push(obs);
    }

    cleanup(client, &bk).await;

    // The 389 (attribute x characteristic x method) schema-derived
    // instances (`crate::matrix`), generated from the target's own `GET
    // /Schemas`. Gated by `--allow-writes` exactly like the sixteen static
    // axes above -- every derived family is `Cost::NeedsUser`.
    match client.get("/Schemas").await {
        Ok(r) if r.is_success() => {
            let decls = decls_from_schemas(&r.body.unwrap_or(serde_json::Value::Null));
            let derived_axes = expand_all(&decls);
            if allow_writes {
                observations.extend(run_derived_family(client, &derived_axes).await);
            } else {
                for instance in &derived_axes {
                    observations.push(Observation {
                        axis: instance.id.clone(),
                        value: Value::Unobservable(Unobservable::NeedsWrite),
                        evidence: Vec::new(),
                        detail: format!(
                            "skipped: observing {} would create a User; pass --allow-writes to \
                             run it",
                            instance.id
                        ),
                    });
                }
            }
        }
        _ => {
            // GET /Schemas itself failing means the schema-derived matrix
            // cannot be generated at all -- no instances to report, not an
            // error for the whole run (the sixteen static axes above still
            // stand on their own).
        }
    }

    Profile {
        target: target.to_string(),
        observed_at: chrono::Utc::now().to_rfc3339(),
        observations,
    }
}
