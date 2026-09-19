//! `catalog()` — the flat, ordered list of checks the runner executes.
//!
//! The order here is **not** grouped by tier; the renderer groups by tier
//! for display. The order instead reflects data dependencies between
//! checks (design note §5.9).

pub mod compat;
pub mod etag;
pub mod rfc7644;
pub mod spc;

use crate::check_def;
use crate::diag::model::{CheckDef, Need, Severity, Tier};

pub fn catalog() -> Vec<CheckDef> {
    vec![
        // ---- 1: read-only, no fixtures needed ----
        check_def!(
            "rfc.response_content_type",
            "Response Content-Type is application/scim+json",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[],
            rfc7644::response_content_type
        ),
        check_def!(
            "rfc.schemas_endpoint",
            "Schemas endpoint advertises core User and Group",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[],
            rfc7644::schemas_endpoint
        ),
        check_def!(
            "rfc.resource_types",
            "ResourceTypes endpoint advertises User and Group",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[],
            rfc7644::resource_types
        ),
        check_def!(
            "rfc.list_envelope",
            "List response envelope is well-formed",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[],
            rfc7644::list_envelope
        ),
        check_def!(
            "rfc.404_shape",
            "404 response uses the SCIM Error resource shape",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[],
            rfc7644::not_found_shape
        ),
        check_def!(
            "rfc.error_status_is_string",
            "Error response `status` is a string",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[],
            rfc7644::error_status_is_string
        ),
        // ---- 2: fixture creation happens lazily right before this,
        //         triggered by the first check below (`Need::Writes`) --
        //         see `runner::run_all` ----
        check_def!(
            "rfc.content_type",
            "Request Content-Type application/scim+json is accepted",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::content_type
        ),
        check_def!(
            "rfc.create_user",
            "POST /Users returns 201 with Location, id, and meta.resourceType",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::create_user
        ),
        check_def!(
            "rfc.location_roundtrip",
            "Location header resolves to the created resource",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::location_roundtrip
        ),
        // ---- 3: read-only observation over U1/G1 (works read-only too) ----
        check_def!(
            "compat.meta_datetime_format",
            "meta.created/lastModified format",
            Tier::Compat,
            Severity::Warning,
            Some("meta_datetime_format"),
            &[],
            compat::meta_datetime_format
        ),
        // ---- 4: needs U1, comes before Tier 3 so `spc.etag_supported`
        //         has `etag_observed` available ----
        check_def!(
            "etag.response_header",
            "GET response includes an ETag header",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::response_header
        ),
        check_def!(
            "etag.matches_meta_version",
            "ETag header matches meta.version",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::matches_meta_version
        ),
        check_def!(
            "etag.weak_form",
            "ETag is a well-formed entity-tag (RFC 7232 §2.3)",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::weak_form
        ),
        // ---- 5: G1/G2 read-only-ish observations, before U1 gets mutated ----
        check_def!(
            "compat.show_empty_groups_members",
            "Empty Group.members is shown as []",
            Tier::Compat,
            Severity::Warning,
            Some("show_empty_groups_members"),
            &[Need::Writes, Need::G2],
            compat::show_empty_groups_members
        ),
        check_def!(
            "compat.include_user_groups",
            "User.groups is populated",
            Tier::Compat,
            Severity::Warning,
            Some("include_user_groups"),
            &[Need::Writes, Need::U1, Need::G1, Need::Membership],
            compat::include_user_groups
        ),
        check_def!(
            "compat.groups_consistency",
            "Empty groups/members display is consistent between User and Group",
            Tier::Compat,
            Severity::Info,
            None,
            &[
                Need::Writes,
                Need::U1,
                Need::U2,
                Need::G1,
                Need::G2,
                Need::Membership
            ],
            compat::groups_consistency
        ),
        check_def!(
            "compat.support_group_members_filter",
            "Groups filterable by members.value",
            Tier::Compat,
            Severity::Warning,
            Some("support_group_members_filter"),
            &[Need::Writes, Need::U1, Need::G1, Need::Membership],
            compat::support_group_members_filter
        ),
        check_def!(
            "compat.support_group_displayname_filter",
            "Groups filterable by displayName",
            Tier::Compat,
            Severity::Warning,
            Some("support_group_displayname_filter"),
            &[Need::Writes, Need::G1],
            compat::support_group_displayname_filter
        ),
        // ---- 6: mutates U1's probe attribute ----
        check_def!(
            "compat.support_patch_replace_empty_array",
            "PATCH replace with [] clears a multi-valued attribute",
            Tier::Compat,
            Severity::Warning,
            Some("support_patch_replace_empty_array"),
            &[Need::Writes, Need::U1],
            compat::support_patch_replace_empty_array
        ),
        check_def!(
            "compat.support_patch_replace_empty_value",
            "PATCH replace with [{\"value\":\"\"}] clears a multi-valued attribute",
            Tier::Compat,
            Severity::Warning,
            Some("support_patch_replace_empty_value"),
            &[Need::Writes, Need::U1],
            compat::support_patch_replace_empty_value
        ),
        // ---- 7: more U1 writes ----
        check_def!(
            "rfc.duplicate_username",
            "Duplicate userName is rejected with 409 uniqueness",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::duplicate_username
        ),
        check_def!(
            "rfc.put_replace",
            "PUT replaces the resource and advances meta.lastModified",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::put_replace
        ),
        check_def!(
            "rfc.patch_add_remove",
            "PATCH add/remove is honoured",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::patch_add_remove
        ),
        check_def!(
            "rfc.patch_204_or_200",
            "PATCH response is 200+body or 204+no body",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::patch_204_or_200
        ),
        // ---- 8: needs U1/U2/U3 all present, before any of them are deleted ----
        check_def!(
            "rfc.filter_eq_username",
            "filter=userName eq \"...\" returns exactly the match",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::filter_eq_username
        ),
        check_def!(
            "rfc.filter_case_insensitive",
            "userName filter matching is case-insensitive",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::filter_case_insensitive
        ),
        check_def!(
            "rfc.filter_sw",
            "filter=userName sw \"prefix\" is supported",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::filter_sw
        ),
        check_def!(
            "rfc.pagination",
            "Pagination is stable and non-overlapping across pages",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1, Need::U2, Need::U3],
            rfc7644::pagination
        ),
        check_def!(
            "rfc.pagination_count_zero",
            "count=0 returns an empty page with the correct totalResults",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::pagination_count_zero
        ),
        check_def!(
            "rfc.sort",
            "sortOrder is honoured",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1, Need::U2, Need::U3],
            rfc7644::sort
        ),
        // ---- 9: read-only over U1 ----
        check_def!(
            "rfc.attributes_param",
            "attributes= projects the response",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::attributes_param
        ),
        check_def!(
            "rfc.excluded_attributes",
            "excludedAttributes= excludes from the response",
            Tier::Rfc7644,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            rfc7644::excluded_attributes
        ),
        // ---- 10: advertised-vs-observed, once upstream observations
        //          (`ctx.state`) have settled ----
        check_def!(
            "spc.wellformed",
            "ServiceProviderConfig has the required schema and members",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::wellformed
        ),
        check_def!(
            "spc.filter_supported",
            "filter.supported matches observed filter behaviour",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::filter_supported
        ),
        check_def!(
            "spc.filter_max_results",
            "itemsPerPage is clamped to the advertised filter.maxResults",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::filter_max_results
        ),
        check_def!(
            "spc.patch_supported",
            "patch.supported matches observed PATCH behaviour",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::patch_supported
        ),
        check_def!(
            "spc.sort_supported",
            "sort.supported matches observed sort behaviour",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::sort_supported
        ),
        check_def!(
            "spc.etag_supported",
            "etag.supported matches observed ETag behaviour",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::etag_supported
        ),
        check_def!(
            "spc.bulk_supported",
            "bulk.supported matches whether POST /Bulk exists",
            Tier::Spc,
            Severity::Warning,
            None,
            &[Need::Writes],
            spc::bulk_supported
        ),
        check_def!(
            "spc.change_password_supported",
            "changePassword.supported matches whether PATCH password works",
            Tier::Spc,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U3],
            spc::change_password_supported
        ),
        // ---- 11: rides on spc.change_password_supported's PATCH response ----
        check_def!(
            "rfc.password_never_returned",
            "A password change never echoes \"password\" back to the client",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U3],
            rfc7644::password_never_returned
        ),
        // ---- 12: no dependencies of its own ----
        check_def!(
            "spc.auth_schemes_match",
            "The auth scheme actually used is advertised in authenticationSchemes",
            Tier::Spc,
            Severity::Warning,
            None,
            &[],
            spc::auth_schemes_match
        ),
        // ---- 13: conditional writes over U1 ----
        check_def!(
            "etag.if_none_match_304",
            "If-None-Match with the current ETag returns 304",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::if_none_match_304
        ),
        check_def!(
            "etag.if_none_match_weak_compare",
            "If-None-Match comparison semantics (weak vs byte-exact)",
            Tier::Etag,
            Severity::Info,
            None,
            &[Need::Writes, Need::U1],
            etag::if_none_match_weak_compare
        ),
        check_def!(
            "etag.if_none_match_star",
            "If-None-Match: * returns 304 for an existing resource",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::if_none_match_star
        ),
        check_def!(
            "etag.if_none_match_stale",
            "If-None-Match with a bogus ETag returns 200",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::if_none_match_stale
        ),
        check_def!(
            "etag.if_match_412",
            "If-Match with a stale ETag returns 412 (optimistic concurrency)",
            Tier::Etag,
            Severity::Error,
            None,
            &[Need::Writes, Need::U1],
            etag::if_match_412
        ),
        check_def!(
            "etag.if_match_current",
            "If-Match with the current ETag succeeds and advances the version",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::if_match_current
        ),
        check_def!(
            "etag.if_match_star",
            "If-Match: * succeeds for an existing resource",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::if_match_star
        ),
        check_def!(
            "etag.patch_if_match",
            "PATCH honours If-Match (RFC 7644 §3.14)",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U1],
            etag::patch_if_match
        ),
        // ---- 14: consumes U3 -- after every other U3 consumer above ----
        check_def!(
            "etag.delete_if_match",
            "DELETE with a stale If-Match returns 412",
            Tier::Etag,
            Severity::Warning,
            None,
            &[Need::Writes, Need::U3],
            etag::delete_if_match
        ),
        // ---- 15: last -- consumes U2, which #8's pagination/sort need ----
        check_def!(
            "rfc.delete_then_get",
            "DELETE then GET returns 404 (no soft delete)",
            Tier::Rfc7644,
            Severity::Error,
            None,
            &[Need::Writes, Need::U2],
            rfc7644::delete_then_get
        ),
    ]
}

/// All check ids in the catalog, for `--only`/`--skip` validation.
pub fn catalog_ids() -> Vec<&'static str> {
    catalog().into_iter().map(|c| c.id).collect()
}
