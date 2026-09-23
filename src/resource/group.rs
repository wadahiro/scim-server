use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

use crate::extractors::ScimJson;

use super::attribute_filter::AttributeFilter;
use crate::auth::TenantInfo;
use crate::backend::ScimBackend;
use crate::config::AppConfig;
use crate::error::scim_error_response;
use crate::models::{Group, ScimListResponse, ScimPatchOp};
use crate::parser::filter_parser::{parse_filter, validate_filter_attribute_types};
use crate::parser::{ResourceType, SortSpec};

type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

// Helper function to extract resource ID from URI path
fn extract_resource_id_from_uri(uri: &Uri) -> Option<String> {
    let path = uri.path();
    // Expected paths: /scim/v2/Groups/{id}, /tenant-a/Groups/{id}, etc.
    let segments: Vec<&str> = path.split('/').collect();

    // Find "Users" or "Groups" segment and get the next one as ID
    for (i, segment) in segments.iter().enumerate() {
        if (*segment == "Users" || *segment == "Groups") && i + 1 < segments.len() {
            return Some(segments[i + 1].to_string());
        }
    }

    None
}

// Helper function to construct resource location URL
fn build_resource_location(
    tenant_info: &TenantInfo,
    resource_type: &str,
    resource_id: &str,
) -> String {
    // The base_path already includes the tenant path, so we just append the resource type and ID
    format!(
        "{}/{}/{}",
        tenant_info.base_path.trim_end_matches('/'),
        resource_type,
        resource_id
    )
}

// Helper function to set meta.location for a group
fn set_group_location(tenant_info: &TenantInfo, group: &mut Group) {
    let location = build_resource_location(tenant_info, "Groups", &group.base.id);

    // Ensure meta exists
    if group.base.meta.is_none() {
        let now = crate::utils::current_scim_datetime();
        group.base.meta = Some(scim_v2::models::scim_schema::Meta {
            created: Some(now.clone()),
            last_modified: Some(now),
            location: Some(location),
            resource_type: Some("Group".to_string()),
            version: None,
        });
    } else if let Some(ref mut meta) = group.base.meta {
        meta.location = Some(location);
    }
}

// Helper function to fix group refs with base URL and tenant path
fn fix_group_refs(tenant_info: &TenantInfo, group: &mut Group) {
    let tenant_id = tenant_info.tenant_id;

    // Fix meta location
    if let Some(ref mut meta) = group.base.meta {
        if let Some(ref mut location) = meta.location {
            if location.starts_with(&format!("/{}/", tenant_id)) {
                // Replace tenant ID-based path with full base URL + resource path
                let resource_path = location.replace(&format!("/{}/", tenant_id), "");
                *location = format!(
                    "{}/{}",
                    tenant_info.base_path.trim_end_matches('/'),
                    resource_path
                );
            }
        }
    }

    // Fix members $ref
    if let Some(ref mut members) = group.base.members {
        for member in members {
            if let Some(ref mut ref_) = member.ref_ {
                if ref_.starts_with(&format!("/{}/", tenant_id)) {
                    // Replace tenant ID-based path with full base URL + resource path
                    let resource_path = ref_.replace(&format!("/{}/", tenant_id), "");
                    *ref_ = format!(
                        "{}/{}",
                        tenant_info.base_path.trim_end_matches('/'),
                        resource_path
                    );
                }
            }
        }
    }
}

// Helper function to validate that all group members exist
async fn validate_group_members(
    backend: &Arc<dyn ScimBackend>,
    tenant_id: u32,
    members: &Option<Vec<scim_v2::models::group::Member>>,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if let Some(members) = members {
        for member in members {
            if let Some(member_id) = &member.value {
                // Check if the member type is User (default if not specified)
                let member_type = member.type_.as_deref().unwrap_or("User");

                // The set of acceptable member types comes from the schema's
                // `canonicalValues` for Group.members.type (RFC 7643 §7),
                // rather than being duplicated here.
                let allowed_types: &[&str] =
                    crate::schema::find_attribute(&crate::schema::GROUP_SCHEMA, "members.type")
                        .map(|attr| attr.canonical_values.as_slice())
                        .unwrap_or(&[]);

                if !allowed_types.contains(&member_type) {
                    return Err(scim_error_response(
                        StatusCode::BAD_REQUEST,
                        Some("invalidValue"),
                        &format!("Invalid member type '{}'.", member_type),
                    ));
                }

                match member_type {
                    "User" => {
                        match backend.find_user_by_id(tenant_id, member_id, false).await {
                            Ok(Some(_)) => continue, // User exists, continue
                            Ok(None) => {
                                return Err(scim_error_response(
                                    StatusCode::BAD_REQUEST,
                                    Some("invalidValue"),
                                    &format!("User with id '{}' does not exist.", member_id),
                                ));
                            }
                            Err(e) => {
                                eprintln!("Error checking user existence: {}", e);
                                return Err(scim_error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    None,
                                    "Error validating member",
                                ));
                            }
                        }
                    }
                    "Group" => {
                        match backend.find_group_by_id(tenant_id, member_id).await {
                            Ok(Some(_)) => continue, // Group exists, continue
                            Ok(None) => {
                                return Err(scim_error_response(
                                    StatusCode::BAD_REQUEST,
                                    Some("invalidValue"),
                                    &format!("Group with id '{}' does not exist.", member_id),
                                ));
                            }
                            Err(e) => {
                                eprintln!("Error checking group existence: {}", e);
                                return Err(scim_error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    None,
                                    "Error validating member",
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(scim_error_response(
                            StatusCode::BAD_REQUEST,
                            Some("invalidValue"),
                            &format!("Invalid member type '{}'.", member_type),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Parses `externalId` from a Group create/update request body.
///
/// RFC 7643 §3.1 declares `externalId` "A String that is an identifier for
/// the resource". `create_group`/`update_group` previously read it with
/// `payload.get("externalId").and_then(|v| v.as_str())`, which silently
/// treats a wrong-typed value (e.g. a JSON number) the same as an absent
/// one -- the client's value is dropped instead of the request being
/// rejected. This distinguishes "absent" (`Ok(None)`) from "present but not
/// a string" (rejected with `invalidSyntax`).
fn parse_group_external_id(
    payload: &serde_json::Value,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    match payload.get("externalId") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(scim_error_response(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            "'externalId' must be a string",
        )),
    }
}

/// Reads one optional `String` sub-attribute of a `members[]` element,
/// rejecting a present-but-wrong-typed value instead of silently treating
/// it as absent.
fn optional_member_string_field(
    member: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<String>, (StatusCode, Json<serde_json::Value>)> {
    match member.get(field) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(scim_error_response(
            StatusCode::BAD_REQUEST,
            Some("invalidSyntax"),
            &format!("'members[].{}' must be a string", field),
        )),
    }
}

/// Parses the `members` array of a Group create/update request body.
///
/// RFC 7643 §4.2 declares `members.value`, `members.$ref`,
/// `members.display`, and `members.type` all `String` (§2.3: Attribute
/// Data Types). `create_group`/`update_group` previously built each
/// `Member` with `.and_then(|v| v.as_str())` inside a `filter_map`, which
/// silently dropped a whole element when `value` was present but
/// wrong-typed, and silently dropped `$ref`/`display`/`type` individually
/// when they were wrong-typed -- accepting the request (201/200) instead of
/// rejecting the malformed input. This rejects any such type mismatch with
/// `invalidSyntax`. An element with no `value` at all is still skipped,
/// matching the server's prior behavior for that (distinct) case.
fn parse_group_members(
    payload: &serde_json::Value,
) -> Result<Option<Vec<scim_v2::models::group::Member>>, (StatusCode, Json<serde_json::Value>)> {
    let members_array = match payload.get("members") {
        None | Some(serde_json::Value::Null) => return Ok(None),
        Some(serde_json::Value::Array(arr)) => arr,
        Some(_) => {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "'members' must be an array",
            ))
        }
    };

    let mut members = Vec::with_capacity(members_array.len());
    for member_value in members_array {
        let member_obj = member_value.as_object().ok_or_else(|| {
            scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidSyntax"),
                "Each element of 'members' must be a JSON object",
            )
        })?;

        let value = optional_member_string_field(member_obj, "value")?;
        let ref_ = optional_member_string_field(member_obj, "$ref")?;
        let display = optional_member_string_field(member_obj, "display")?;
        let type_ = optional_member_string_field(member_obj, "type")?;

        if value.is_none() {
            continue;
        }

        members.push(scim_v2::models::group::Member {
            value,
            ref_,
            display,
            type_,
        });
    }

    Ok(if members.is_empty() {
        None
    } else {
        Some(members)
    })
}

// Helper function to apply attribute filtering to groups and create list response
fn create_filtered_group_list_response(
    groups: Vec<Group>,
    total: i64,
    start_index: Option<i64>,
    attribute_filter: &AttributeFilter,
) -> ScimListResponse {
    // Note: tenant_id and app_config are not available in this helper function
    // The individual handlers will call fix_group_refs separately
    // This is a limitation of the current architecture

    // Apply attribute filtering to each group
    let filtered_resources: Vec<serde_json::Value> = groups
        .into_iter()
        .map(|group| {
            let group_json = serde_json::to_value(&group).unwrap_or_default();
            attribute_filter.apply_to_resource(&group_json, ResourceType::Group)
        })
        .collect();

    ScimListResponse {
        schemas: vec!["urn:ietf:params:scim:api:messages:2.0:ListResponse".to_string()],
        total_results: total,
        start_index: Some(start_index.unwrap_or(1)),
        items_per_page: Some(filtered_resources.len() as i64),
        resources: filtered_resources,
    }
}

// Multi-tenant handlers with tenant_id extraction and validation
pub async fn create_group(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    Query(params): Query<HashMap<String, String>>,
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // RFC 7644 §3.9: clients MAY request a partial resource representation
    // on any operation that returns a resource within the response --
    // POST included, not just GET.
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    // Create a Group from the JSON payload
    let mut group = Group::default();

    // Extract required fields
    if let Some(display_name) = payload.get("displayName").and_then(|v| v.as_str()) {
        group.base.display_name = display_name.to_string();
    } else {
        return Err(scim_error_response(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "displayName is required",
        ));
    }

    // Extract optional fields
    if let Some(schemas) = payload.get("schemas").and_then(|v| v.as_array()) {
        group.base.schemas = schemas
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }

    group.external_id = parse_group_external_id(&payload)?;

    // Extract members with proper structure
    group.base.members = parse_group_members(&payload)?;

    // Validate that all group members exist before creating the group
    validate_group_members(&backend, tenant_id, &group.base.members).await?;

    match backend.create_group(tenant_id, &group).await {
        Ok(mut created_group) => {
            // Set meta.location for SCIM compliance
            set_group_location(&tenant_info, &mut created_group);

            fix_group_refs(&tenant_info, &mut created_group);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            created_group = crate::utils::convert_group_datetime_for_response(
                created_group,
                &compatibility.meta_datetime_format,
            );
            created_group = crate::utils::handle_group_empty_members_for_response(
                created_group,
                compatibility.show_empty_groups_members,
            );

            // Build Location header URL
            let location_url =
                build_resource_location(&tenant_info, "Groups", &created_group.base.id);

            // Convert to JSON and remove null fields to comply with SCIM specification
            let group_json = serde_json::to_value(&created_group).map_err(|_| {
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Serialization error",
                )
            })?;

            let cleaned_group_json =
                attribute_filter.apply_to_resource(&group_json, ResourceType::Group);

            // Create response with Location and ETag headers
            let mut headers = HeaderMap::new();
            headers.insert(
                "Location",
                HeaderValue::from_str(&location_url).map_err(|_| {
                    scim_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        None,
                        "Invalid location header",
                    )
                })?,
            );

            // Add ETag header (Phase 2: ETag response headers)
            if let Some(ref meta) = created_group.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            scim_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                None,
                                "Invalid ETag header",
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_group_json).into_response();
            *response.status_mut() = StatusCode::CREATED;
            response.headers_mut().extend(headers);

            Ok(response)
        }
        Err(e) => Err(e.to_response()),
    }
}

pub async fn get_group(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "Group ID not found in path",
            ))
        }
    };

    // Parse attribute filtering parameters
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    match backend.find_group_by_id(tenant_id, &id).await {
        Ok(Some(mut group)) => {
            // Set meta.location for SCIM compliance
            set_group_location(&tenant_info, &mut group);

            fix_group_refs(&tenant_info, &mut group);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            group = crate::utils::convert_group_datetime_for_response(
                group,
                &compatibility.meta_datetime_format,
            );
            group = crate::utils::handle_group_empty_members_for_response(
                group,
                compatibility.show_empty_groups_members,
            );

            // Phase 3: Handle conditional requests (If-None-Match)
            if let Some(if_none_match) = headers.get("if-none-match") {
                if let (Ok(if_none_match_str), Some(ref meta)) =
                    (if_none_match.to_str(), &group.base.meta)
                {
                    if let Some(ref current_version) = meta.version {
                        // `*` never satisfies If-None-Match on an existing
                        // resource, and an exact match doesn't either -
                        // both cases return 304 Not Modified (RFC 7232 §3.2).
                        if !crate::utils::if_none_match_satisfied(
                            if_none_match_str,
                            current_version,
                        ) {
                            let mut response =
                                axum::response::Response::new(axum::body::Body::empty());
                            *response.status_mut() = StatusCode::NOT_MODIFIED;
                            // Add ETag header even for 304 responses
                            if let Ok(etag_value) = HeaderValue::from_str(current_version) {
                                response.headers_mut().insert("ETag", etag_value);
                            }
                            return Ok(response);
                        }
                    }
                }
            }

            // Convert to JSON and apply attribute filtering
            let group_json = serde_json::to_value(&group).map_err(|_| {
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Serialization error",
                )
            })?;

            let filtered_group =
                attribute_filter.apply_to_resource(&group_json, ResourceType::Group);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = group.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            scim_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                None,
                                "Invalid ETag header",
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(filtered_group).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err(scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            "Group not found",
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn search_groups(
    state: State<AppState>,
    tenant_info: Extension<TenantInfo>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<ScimListResponse>), (StatusCode, Json<serde_json::Value>)> {
    search_groups_with_params(state, tenant_info, params).await
}

/// `POST /Groups/.search` (RFC 7644 §3.4.3): the same search as
/// `GET /Groups`, but with the query parameters carried in a JSON
/// `SearchRequest` body instead of the URL. Reuses the same
/// search/filter/projection code path as the GET form.
pub async fn search_groups_post(
    state: State<AppState>,
    tenant_info: Extension<TenantInfo>,
    ScimJson(search_request): ScimJson<crate::models::SearchRequest>,
) -> Result<(StatusCode, Json<ScimListResponse>), (StatusCode, Json<serde_json::Value>)> {
    let params = search_request.into_query_params()?;
    search_groups_with_params(state, tenant_info, params).await
}

async fn search_groups_with_params(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    params: HashMap<String, String>,
) -> Result<(StatusCode, Json<ScimListResponse>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    let filter = params.get("filter").map(String::as_str);
    let start_index = params.get("startIndex").and_then(|s| s.parse::<i64>().ok());
    let count = params.get("count").and_then(|s| s.parse::<i64>().ok());
    let sort_by = params.get("sortBy").cloned();
    let sort_order = params.get("sortOrder").cloned();

    // Parse attribute filtering parameters
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    // Get compatibility settings for this tenant
    let compatibility = app_config.get_effective_compatibility(tenant_id);

    // Handle filter for user membership: members[value eq "user-id"]
    if let Some(filter_str) = filter {
        if filter_str.starts_with("members[value eq ") && filter_str.ends_with("]") {
            // Check if group members filter is supported
            if !compatibility.support_group_members_filter {
                return Err(scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("unsupported"),
                    "Filtering Groups by members is not supported",
                ));
            }
            // Extract user ID from filter
            let start_quote = filter_str.find('"').ok_or_else(|| {
                scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "Invalid filter format",
                )
            })?;
            let end_quote = filter_str.rfind('"').ok_or_else(|| {
                scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "Invalid filter format",
                )
            })?;

            if start_quote >= end_quote {
                return Err(scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    "Invalid filter format",
                ));
            }

            let user_id = &filter_str[start_quote + 1..end_quote];

            // Get groups by user
            match backend.find_groups_by_user_id(tenant_id, user_id).await {
                Ok(mut groups) => {
                    // Set location and fix refs for all groups
                    for group in &mut groups {
                        set_group_location(&tenant_info, group);
                        fix_group_refs(&tenant_info, group);
                        // Apply compatibility transformations
                        *group = crate::utils::convert_group_datetime_for_response(
                            group.clone(),
                            &compatibility.meta_datetime_format,
                        );
                        *group = crate::utils::handle_group_empty_members_for_response(
                            group.clone(),
                            compatibility.show_empty_groups_members,
                        );
                    }
                    let total_results = groups.len() as i64;
                    let response = create_filtered_group_list_response(
                        groups,
                        total_results,
                        start_index,
                        &attribute_filter,
                    );
                    return Ok((StatusCode::OK, Json(response)));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    // Handle general filtering
    if let Some(filter_str) = filter {
        // Check if displayName filter is supported
        if (filter_str.contains("displayName") || filter_str.contains("displayname"))
            && !compatibility.support_group_displayname_filter
        {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("unsupported"),
                "Filtering Groups by displayName is not supported",
            ));
        }

        match parse_filter(filter_str).and_then(|filter_op| {
            validate_filter_attribute_types(&filter_op, ResourceType::Group)?;
            Ok(filter_op)
        }) {
            Ok(filter_op) => {
                let sort_spec = SortSpec::from_params_for_resource(
                    sort_by.as_deref(),
                    sort_order.as_deref(),
                    ResourceType::Group,
                );

                match backend
                    .find_groups_by_filter(
                        tenant_id,
                        &filter_op,
                        start_index,
                        count,
                        sort_spec.as_ref(),
                    )
                    .await
                {
                    Ok((mut groups, total)) => {
                        // Set location and fix refs for all groups
                        for group in &mut groups {
                            set_group_location(&tenant_info, group);
                            fix_group_refs(&tenant_info, group);
                            // Apply compatibility transformations
                            *group = crate::utils::convert_group_datetime_for_response(
                                group.clone(),
                                &compatibility.meta_datetime_format,
                            );
                            *group = crate::utils::handle_group_empty_members_for_response(
                                group.clone(),
                                compatibility.show_empty_groups_members,
                            );
                        }
                        let response = create_filtered_group_list_response(
                            groups,
                            total,
                            start_index,
                            &attribute_filter,
                        );
                        return Ok((StatusCode::OK, Json(response)));
                    }
                    Err(e) => return Err(e.to_response()),
                }
            }
            Err(e) => {
                eprintln!("Filter parsing error for '{}': {}", filter_str, e);
                return Err(scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("invalidFilter"),
                    &format!("Invalid filter: {}", e),
                ));
            }
        }
    }

    // Default behavior: get all groups paginated with optional sorting
    let sort_spec = SortSpec::from_params_for_resource(
        sort_by.as_deref(),
        sort_order.as_deref(),
        ResourceType::Group,
    );

    let result = if sort_spec.is_some() {
        backend
            .find_all_groups_sorted(tenant_id, start_index, count, sort_spec.as_ref())
            .await
    } else {
        backend.find_all_groups(tenant_id, start_index, count).await
    };

    match result {
        Ok((mut groups, total)) => {
            // Set location and fix refs for all groups
            for group in &mut groups {
                set_group_location(&tenant_info, group);
                fix_group_refs(&tenant_info, group);
                // Apply compatibility transformations
                *group = crate::utils::convert_group_datetime_for_response(
                    group.clone(),
                    &compatibility.meta_datetime_format,
                );
                *group = crate::utils::handle_group_empty_members_for_response(
                    group.clone(),
                    compatibility.show_empty_groups_members,
                );
            }
            let response =
                create_filtered_group_list_response(groups, total, start_index, &attribute_filter);
            Ok((StatusCode::OK, Json(response)))
        }
        Err(e) => Err(e.to_response()),
    }
}

pub async fn update_group(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "Group ID not found in path",
            ))
        }
    };

    // RFC 7644 §3.5.1: "Unless otherwise specified, a successful PUT
    // operation returns a 200 ... the entire resource", subject to the
    // §3.9 attribute-filtering query parameters like every other operation
    // that returns a resource within the response.
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    // Convert JSON payload to Group - similar to create
    let mut group = Group::default();
    group.base.id = id.clone();

    // Extract fields. `displayName` is required (RFC 7643 §4.2: "A
    // human-readable name for the Group. REQUIRED."), the same as
    // `create_group` enforces -- a PUT replaces the whole resource
    // (RFC 7644 §3.5.1), so it must satisfy the same required-attribute
    // constraint rather than silently falling back to `Group::default()`'s
    // placeholder `display_name`.
    if let Some(display_name) = payload.get("displayName").and_then(|v| v.as_str()) {
        group.base.display_name = display_name.to_string();
    } else {
        return Err(scim_error_response(
            StatusCode::BAD_REQUEST,
            Some("invalidValue"),
            "displayName is required",
        ));
    }

    if let Some(schemas) = payload.get("schemas").and_then(|v| v.as_array()) {
        group.base.schemas = schemas
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }

    group.external_id = parse_group_external_id(&payload)?;

    // Extract members
    group.base.members = parse_group_members(&payload)?;

    // Validate that all group members exist before updating the group
    validate_group_members(&backend, tenant_id, &group.base.members).await?;

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current group to check its version
            match backend.find_group_by_id(tenant_id, &id).await {
                Ok(Some(current_group)) => {
                    if let Some(ref meta) = current_group.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // `*` always matches an existing resource
                            // (RFC 7232 §3.1); otherwise require an exact
                            // match, else return 412 Precondition Failed.
                            if !crate::utils::if_match_satisfied(if_match_str, current_version) {
                                return Err((
                                    StatusCode::PRECONDITION_FAILED,
                                    Json(json!({
                                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                                        "detail": "Resource version mismatch",
                                        "status": "412",
                                        "scimType": "preconditionFailed"
                                    })),
                                ));
                            }
                        }
                    }
                }
                Ok(None) => {
                    return Err(scim_error_response(
                        StatusCode::NOT_FOUND,
                        None,
                        "Group not found",
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    match backend.update_group(tenant_id, &id, &group).await {
        Ok(Some(mut updated_group)) => {
            // Set meta.location for SCIM compliance
            set_group_location(&tenant_info, &mut updated_group);

            fix_group_refs(&tenant_info, &mut updated_group);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            updated_group = crate::utils::convert_group_datetime_for_response(
                updated_group,
                &compatibility.meta_datetime_format,
            );
            updated_group = crate::utils::handle_group_empty_members_for_response(
                updated_group,
                compatibility.show_empty_groups_members,
            );

            // Convert to JSON and remove null fields to comply with SCIM specification
            let group_json = serde_json::to_value(&updated_group).map_err(|_| {
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Serialization error",
                )
            })?;

            let cleaned_group_json =
                attribute_filter.apply_to_resource(&group_json, ResourceType::Group);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = updated_group.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            scim_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                None,
                                "Invalid ETag header",
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_group_json).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err(scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            "Group not found",
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn delete_group(
    State((backend, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "Group ID not found in path",
            ))
        }
    };

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current group to check its version
            match backend.find_group_by_id(tenant_id, &id).await {
                Ok(Some(current_group)) => {
                    if let Some(ref meta) = current_group.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // `*` always matches an existing resource
                            // (RFC 7232 §3.1); otherwise require an exact
                            // match, else return 412 Precondition Failed.
                            if !crate::utils::if_match_satisfied(if_match_str, current_version) {
                                return Err((
                                    StatusCode::PRECONDITION_FAILED,
                                    Json(json!({
                                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                                        "detail": "Resource version mismatch",
                                        "status": "412",
                                        "scimType": "preconditionFailed"
                                    })),
                                ));
                            }
                        }
                    }
                }
                Ok(None) => {
                    return Err(scim_error_response(
                        StatusCode::NOT_FOUND,
                        None,
                        "Group not found",
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    match backend.delete_group(tenant_id, &id).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            "Group not found",
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn patch_group(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
    ScimJson(patch_ops): ScimJson<ScimPatchOp>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err(scim_error_response(
                StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                "Group ID not found in path",
            ))
        }
    };

    // RFC 7644 §3.5.2: a successful PATCH's 200 OK response body is
    // "subject to the 'attributes' query parameter (see Section 3.9)",
    // same as every other operation returning a resource.
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current group to check its version
            match backend.find_group_by_id(tenant_id, &id).await {
                Ok(Some(current_group)) => {
                    if let Some(ref meta) = current_group.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // `*` always matches an existing resource
                            // (RFC 7232 §3.1); otherwise require an exact
                            // match, else return 412 Precondition Failed.
                            if !crate::utils::if_match_satisfied(if_match_str, current_version) {
                                return Err((
                                    StatusCode::PRECONDITION_FAILED,
                                    Json(json!({
                                        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
                                        "detail": "Resource version mismatch",
                                        "status": "412",
                                        "scimType": "preconditionFailed"
                                    })),
                                ));
                            }
                        }
                    }
                }
                Ok(None) => {
                    return Err(scim_error_response(
                        StatusCode::NOT_FOUND,
                        None,
                        "Group not found",
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    // Get compatibility settings for PATCH operation validation. Fetched
    // once up front so the pre-check below, the prospective-resource
    // validation, and the actual backend patch all see the same tenant
    // settings -- the same way patch_user does.
    let compatibility = app_config.get_effective_compatibility(tenant_id);

    // Validate PATCH operations based on compatibility settings
    // Only reject operations that are explicitly disabled
    for operation in &patch_ops.operations {
        if operation.op == "replace" {
            if let Some(serde_json::Value::Array(arr)) = &operation.value {
                // Check for empty array replacement (clearing multi-valued attributes)
                if arr.is_empty() && !compatibility.support_patch_replace_empty_array {
                    return Err(scim_error_response(
                        StatusCode::BAD_REQUEST,
                        Some("unsupported"),
                        "PATCH replace with empty array is not supported for this tenant",
                    ));
                }
                // Check for special empty value pattern [{"value":""}]
                if arr.len() == 1 {
                    if let serde_json::Value::Object(ref item) = arr[0] {
                        if item.len() == 1
                            && item.get("value") == Some(&serde_json::Value::String("".to_string()))
                            && !compatibility.support_patch_replace_empty_value
                        {
                            return Err(scim_error_response(
                                StatusCode::BAD_REQUEST,
                                Some("unsupported"),
                                "PATCH replace with empty value pattern is not supported for this tenant",
                            ));
                        }
                    }
                }
            }
        }
    }

    // Validate the post-patch resource with the same member-existence and
    // member-type checks `create_group`/`update_group` use, so PATCH cannot
    // introduce a member those paths would reject. This computes the
    // prospective patched resource in-memory (using the same `ScimPath`
    // logic the backend applies) purely for validation; the backend below
    // re-applies the operations for the actual write.
    if let Ok(Some(current_group)) = backend.find_group_by_id(tenant_id, &id).await {
        let mut prospective = current_group;
        for operation in &patch_ops.operations {
            let scim_path = crate::parser::patch_parser::ScimPath::parse(
                &operation.path.clone().unwrap_or_default(),
                crate::parser::ResourceType::Group,
            )
            .map_err(|e| e.to_response())?;
            let mut group_json = serde_json::to_value(&prospective).map_err(|_| {
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Serialization error",
                )
            })?;
            let op_value = operation.value.as_ref().unwrap_or(&serde_json::Value::Null);
            // RFC 7644 §3.5.2: reject an operation targeting a readOnly
            // attribute, or an immutable attribute that already holds a
            // different value, rather than silently ignoring it (contrast
            // POST/PUT, where a readOnly value is ignored per §3.3/§3.5.1).
            scim_path
                .check_patch_mutability(crate::parser::ResourceType::Group, &group_json, op_value)
                .map_err(|e| e.to_response())?;
            scim_path
                .apply_operation_with_compatibility(
                    &mut group_json,
                    &operation.op,
                    op_value,
                    &compatibility,
                )
                .map_err(|e| e.to_response())?;
            crate::schema::validate_required_attributes_present(
                &group_json,
                &crate::schema::GROUP_SCHEMA,
            )
            .map_err(|e| e.to_response())?;
            prospective = serde_json::from_value(group_json).map_err(|_| {
                scim_error_response(
                    StatusCode::BAD_REQUEST,
                    Some("invalidValue"),
                    "Invalid resource data after applying patch operations",
                )
            })?;
        }
        validate_group_members(&backend, tenant_id, &prospective.base.members).await?;
    }

    match backend
        .patch_group(tenant_id, &id, &patch_ops, &compatibility)
        .await
    {
        Ok(Some(mut group)) => {
            // Set meta.location for SCIM compliance
            set_group_location(&tenant_info, &mut group);

            fix_group_refs(&tenant_info, &mut group);

            // Apply compatibility transformations based on tenant settings
            group = crate::utils::convert_group_datetime_for_response(
                group,
                &compatibility.meta_datetime_format,
            );
            group = crate::utils::handle_group_empty_members_for_response(
                group,
                compatibility.show_empty_groups_members,
            );

            // Convert to JSON and remove null fields to comply with SCIM specification
            let group_json = serde_json::to_value(&group).map_err(|_| {
                scim_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    None,
                    "Serialization error",
                )
            })?;

            let cleaned_group_json =
                attribute_filter.apply_to_resource(&group_json, ResourceType::Group);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = group.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            scim_error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                None,
                                "Invalid ETag header",
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_group_json).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err(scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            "Group not found",
        )),
        Err(e) => Err(e.to_response()),
    }
}
