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
use crate::parser::filter_parser::parse_filter;
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

                match member_type {
                    "User" => {
                        match backend.find_user_by_id(tenant_id, member_id).await {
                            Ok(Some(_)) => continue, // User exists, continue
                            Ok(None) => {
                                return Err(scim_error_response(
                                    StatusCode::BAD_REQUEST,
                                    "invalidValue",
                                    &format!("User with id '{}' does not exist.", member_id),
                                ));
                            }
                            Err(e) => {
                                eprintln!("Error checking user existence: {}", e);
                                return Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"message": "Error validating member"})),
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
                                    "invalidValue",
                                    &format!("Group with id '{}' does not exist.", member_id),
                                ));
                            }
                            Err(e) => {
                                eprintln!("Error checking group existence: {}", e);
                                return Err((
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"message": "Error validating member"})),
                                ));
                            }
                        }
                    }
                    _ => {
                        return Err(scim_error_response(
                            StatusCode::BAD_REQUEST,
                            "invalidValue",
                            &format!("Invalid member type '{}'.", member_type),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
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
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Create a Group from the JSON payload
    let mut group = Group::default();

    // Extract required fields
    if let Some(display_name) = payload.get("displayName").and_then(|v| v.as_str()) {
        group.base.display_name = display_name.to_string();
    } else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "displayName is required"})),
        ));
    }

    // Extract optional fields
    if let Some(schemas) = payload.get("schemas").and_then(|v| v.as_array()) {
        group.base.schemas = schemas
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }

    if let Some(external_id) = payload.get("externalId").and_then(|v| v.as_str()) {
        group.external_id = Some(external_id.to_string());
    }

    // Extract members with proper structure
    if let Some(members_array) = payload.get("members").and_then(|v| v.as_array()) {
        let members: Vec<scim_v2::models::group::Member> = members_array
            .iter()
            .filter_map(|m| {
                if let Some(value) = m.get("value").and_then(|v| v.as_str()) {
                    Some(scim_v2::models::group::Member {
                        value: Some(value.to_string()),
                        ref_: m.get("$ref").and_then(|v| v.as_str()).map(String::from),
                        display: m.get("display").and_then(|v| v.as_str()).map(String::from),
                        type_: m.get("type").and_then(|v| v.as_str()).map(String::from),
                    })
                } else {
                    None
                }
            })
            .collect();

        if !members.is_empty() {
            group.base.members = Some(members);
        }
    }

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
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_group_json = AttributeFilter::remove_null_fields(&group_json);

            // Create response with Location header
            let mut headers = HeaderMap::new();
            headers.insert(
                "Location",
                HeaderValue::from_str(&location_url).map_err(|_| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"message": "Invalid location header"})),
                    )
                })?,
            );

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
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Group ID not found in path"})),
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

            // Convert to JSON and apply attribute filtering
            let group_json = serde_json::to_value(&group).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "Serialization error"})),
                )
            })?;

            let filtered_group =
                attribute_filter.apply_to_resource(&group_json, ResourceType::Group);
            Ok((StatusCode::OK, Json(filtered_group)))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn search_groups(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    Query(params): Query<HashMap<String, String>>,
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
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Filtering Groups by members is not supported"})),
                ));
            }
            // Extract user ID from filter
            let start_quote = filter_str.find('"').ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Invalid filter format"})),
                )
            })?;
            let end_quote = filter_str.rfind('"').ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Invalid filter format"})),
                )
            })?;

            if start_quote >= end_quote {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": "Invalid filter format"})),
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
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Filtering Groups by displayName is not supported"})),
            ));
        }

        match parse_filter(filter_str) {
            Ok(filter_op) => {
                let sort_spec = SortSpec::from_params(sort_by.as_deref(), sort_order.as_deref());

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
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"message": format!("Invalid filter: {}", e)})),
                ));
            }
        }
    }

    // Default behavior: get all groups paginated with optional sorting
    let sort_spec = SortSpec::from_params(sort_by.as_deref(), sort_order.as_deref());

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
    uri: Uri,
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Group ID not found in path"})),
            ))
        }
    };

    // Convert JSON payload to Group - similar to create
    let mut group = Group::default();
    group.base.id = id.clone();

    // Extract fields
    if let Some(display_name) = payload.get("displayName").and_then(|v| v.as_str()) {
        group.base.display_name = display_name.to_string();
    }

    if let Some(schemas) = payload.get("schemas").and_then(|v| v.as_array()) {
        group.base.schemas = schemas
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }

    if let Some(external_id) = payload.get("externalId").and_then(|v| v.as_str()) {
        group.external_id = Some(external_id.to_string());
    }

    // Extract members
    if let Some(members_array) = payload.get("members").and_then(|v| v.as_array()) {
        let members: Vec<scim_v2::models::group::Member> = members_array
            .iter()
            .filter_map(|m| {
                if let Some(value) = m.get("value").and_then(|v| v.as_str()) {
                    Some(scim_v2::models::group::Member {
                        value: Some(value.to_string()),
                        ref_: m.get("$ref").and_then(|v| v.as_str()).map(String::from),
                        display: m.get("display").and_then(|v| v.as_str()).map(String::from),
                        type_: m.get("type").and_then(|v| v.as_str()).map(String::from),
                    })
                } else {
                    None
                }
            })
            .collect();

        if !members.is_empty() {
            group.base.members = Some(members);
        }
    }

    // Validate that all group members exist before updating the group
    validate_group_members(&backend, tenant_id, &group.base.members).await?;

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
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_group_json = AttributeFilter::remove_null_fields(&group_json);

            Ok((StatusCode::OK, Json(cleaned_group_json)))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn delete_group(
    State((backend, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Group ID not found in path"})),
            ))
        }
    };

    match backend.delete_group(tenant_id, &id).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn patch_group(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
    ScimJson(patch_ops): ScimJson<ScimPatchOp>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "Group ID not found in path"})),
            ))
        }
    };

    match backend.patch_group(tenant_id, &id, &patch_ops).await {
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

            // Convert to JSON and remove null fields to comply with SCIM specification
            let group_json = serde_json::to_value(&group).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_group_json = AttributeFilter::remove_null_fields(&group_json);

            Ok((StatusCode::OK, Json(cleaned_group_json)))
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}
