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
use crate::models::{ScimListResponse, ScimPatchOp, User};
use crate::parser::filter_parser::parse_filter;
use crate::parser::{ResourceType, SortSpec};
use crate::schema::{should_fetch_external_attributes, validate_user};

type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

// Helper function to extract resource ID from URI path
fn extract_resource_id_from_uri(uri: &Uri) -> Option<String> {
    let path = uri.path();
    // Expected paths: /scim/v2/Users/{id}, /tenant-a/Users/{id}, etc.
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

// Helper function to set meta.location for a user
fn set_user_location(tenant_info: &TenantInfo, user: &mut User) {
    if let Some(ref user_id) = user.base.id {
        let location = build_resource_location(tenant_info, "Users", user_id);

        // Ensure meta exists
        if user.base.meta.is_none() {
            let now = crate::utils::current_scim_datetime();
            user.base.meta = Some(scim_v2::models::scim_schema::Meta {
                created: Some(now.clone()),
                last_modified: Some(now),
                location: Some(location),
                resource_type: Some("User".to_string()),
                version: None,
            });
        } else if let Some(ref mut meta) = user.base.meta {
            meta.location = Some(location);
        }
    }
}

// Helper function to fix user refs with base URL and tenant path
fn fix_user_refs(tenant_info: &TenantInfo, user: &mut User) {
    let tenant_id = tenant_info.tenant_id;

    // Fix meta location
    if let Some(ref mut meta) = user.base.meta {
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

    // Fix groups $ref
    if let Some(ref mut groups) = user.base.groups {
        for group in groups {
            if let Some(ref mut ref_) = group.ref_ {
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

// Helper function to apply attribute filtering to users and create list response
fn create_filtered_user_list_response(
    users: Vec<User>,
    total: i64,
    start_index: Option<i64>,
    attribute_filter: &AttributeFilter,
) -> ScimListResponse {
    // Note: tenant_id and app_config are not available in this helper function
    // The individual handlers will call fix_user_refs separately
    // This is a limitation of the current architecture

    // Apply attribute filtering to each user
    let filtered_resources: Vec<serde_json::Value> = users
        .into_iter()
        .map(|user| {
            let user_json = serde_json::to_value(&user).unwrap_or_default();
            attribute_filter.apply_to_resource(&user_json, ResourceType::User)
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

// Tenant-specific handlers

// Multi-tenant handlers with tenant_id extraction and validation
pub async fn create_user(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Convert JSON payload to our User model
    let user: User = match serde_json::from_value(payload) {
        Ok(user) => user,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": format!("Invalid user data: {}", e)})),
            ))
        }
    };

    // Validate user data
    if let Err(e) = validate_user(&user.base) {
        return Err(e.to_response());
    }

    match backend.create_user(tenant_id, &user).await {
        Ok(mut created_user) => {
            // Set meta.location for SCIM compliance
            set_user_location(&tenant_info, &mut created_user);

            // Fix refs with base URL
            fix_user_refs(&tenant_info, &mut created_user);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            created_user = crate::utils::convert_user_datetime_for_response(
                created_user,
                &compatibility.meta_datetime_format,
            );
            created_user = crate::utils::handle_user_groups_inclusion_for_response(
                created_user,
                compatibility.include_user_groups,
            );
            created_user = crate::utils::handle_user_empty_groups_for_response(
                created_user,
                compatibility.show_empty_groups_members,
            );

            // Build Location header URL
            let location_url = if let Some(ref user_id) = created_user.base.id {
                build_resource_location(&tenant_info, "Users", user_id)
            } else {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Created user missing ID"})),
                ));
            };

            // Convert to JSON and remove null fields to comply with SCIM specification
            let user_json = serde_json::to_value(&created_user).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_user_json = AttributeFilter::remove_null_fields(&user_json);

            // Create response with Location and ETag headers
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

            // Add ETag header (Phase 2: ETag response headers)
            if let Some(ref meta) = created_user.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"message": "Invalid ETag header"})),
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_user_json).into_response();
            *response.status_mut() = StatusCode::CREATED;
            response.headers_mut().extend(headers);

            Ok(response)
        }
        Err(e) => Err(e.to_response()),
    }
}

pub async fn get_user(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract user ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "User ID not found in path"})),
            ))
        }
    };

    // Parse attribute filtering parameters
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    // Get compatibility settings for this tenant to determine if we should include groups
    let compatibility = app_config.get_effective_compatibility(tenant_id);

    // Optimize: Only fetch groups if needed based on attribute filtering and compatibility
    let should_include_groups = should_fetch_external_attributes(
        &attribute_filter,
        ResourceType::User,
        compatibility.include_user_groups,
    );

    match backend
        .find_user_by_id(tenant_id, &id, should_include_groups)
        .await
    {
        Ok(Some(mut user)) => {
            // Set meta.location for SCIM compliance
            set_user_location(&tenant_info, &mut user);

            fix_user_refs(&tenant_info, &mut user);

            // Apply compatibility transformations based on tenant settings (already retrieved above)
            user = crate::utils::convert_user_datetime_for_response(
                user,
                &compatibility.meta_datetime_format,
            );
            // Note: groups field inclusion is already handled at the database level
            // Only need to handle empty array display behavior
            user = crate::utils::handle_user_empty_groups_for_response(
                user,
                compatibility.show_empty_groups_members,
            );

            // Phase 3: Handle conditional requests (If-None-Match)
            if let Some(if_none_match) = headers.get("if-none-match") {
                if let (Ok(if_none_match_str), Some(ref meta)) =
                    (if_none_match.to_str(), &user.base.meta)
                {
                    if let Some(ref current_version) = meta.version {
                        // If the ETag matches, return 304 Not Modified
                        if if_none_match_str == current_version {
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
            let user_json = serde_json::to_value(&user).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"message": "Serialization error"})),
                )
            })?;

            let filtered_user = attribute_filter.apply_to_resource(&user_json, ResourceType::User);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = user.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"message": "Invalid ETag header"})),
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(filtered_user).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "User not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn search_users(
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

    // Optimize: Only fetch groups if needed based on attribute filtering and compatibility
    let should_include_groups = should_fetch_external_attributes(
        &attribute_filter,
        ResourceType::User,
        compatibility.include_user_groups,
    );

    // Handle filter for group membership: groups[value eq "group-id"]
    if let Some(filter_str) = filter {
        if filter_str.starts_with("groups[value eq ") && filter_str.ends_with("]") {
            // Extract group ID from filter: groups[value eq "group-id"]
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

            let group_id = &filter_str[start_quote + 1..end_quote];

            // Get users by group
            match backend
                .find_users_by_group_id(tenant_id, group_id, should_include_groups)
                .await
            {
                Ok(mut users) => {
                    // Set location and fix refs for all users
                    for user in &mut users {
                        set_user_location(&tenant_info, user);
                        fix_user_refs(&tenant_info, user);
                        // Apply compatibility transformations
                        *user = crate::utils::convert_user_datetime_for_response(
                            user.clone(),
                            &compatibility.meta_datetime_format,
                        );
                        // Note: groups field inclusion is already handled at the database level
                        // Only need to handle empty array display behavior
                        *user = crate::utils::handle_user_empty_groups_for_response(
                            user.clone(),
                            compatibility.show_empty_groups_members,
                        );
                    }
                    let total_results = users.len() as i64;
                    let response = create_filtered_user_list_response(
                        users,
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
        match parse_filter(filter_str) {
            Ok(filter_op) => {
                let sort_spec = SortSpec::from_params(sort_by.as_deref(), sort_order.as_deref());

                match backend
                    .find_users_by_filter(
                        tenant_id,
                        &filter_op,
                        start_index,
                        count,
                        sort_spec.as_ref(),
                        should_include_groups,
                    )
                    .await
                {
                    Ok((mut users, total)) => {
                        // Set location and fix refs for all users
                        for user in &mut users {
                            set_user_location(&tenant_info, user);
                            fix_user_refs(&tenant_info, user);
                            // Apply compatibility transformations
                            *user = crate::utils::convert_user_datetime_for_response(
                                user.clone(),
                                &compatibility.meta_datetime_format,
                            );
                            // Note: groups field inclusion is already handled at the database level
                            // Only need to handle empty array display behavior
                            *user = crate::utils::handle_user_empty_groups_for_response(
                                user.clone(),
                                compatibility.show_empty_groups_members,
                            );
                        }
                        let response = create_filtered_user_list_response(
                            users,
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

    // Default behavior: get all users paginated with optional sorting
    let sort_spec = SortSpec::from_params(sort_by.as_deref(), sort_order.as_deref());

    let result = if sort_spec.is_some() {
        backend
            .find_all_users_sorted(
                tenant_id,
                start_index,
                count,
                sort_spec.as_ref(),
                should_include_groups,
            )
            .await
    } else {
        backend
            .find_all_users(tenant_id, start_index, count, should_include_groups)
            .await
    };

    match result {
        Ok((mut users, total)) => {
            // Set location and fix refs for all users
            for user in &mut users {
                set_user_location(&tenant_info, user);
                fix_user_refs(&tenant_info, user);
                // Apply compatibility transformations
                *user = crate::utils::convert_user_datetime_for_response(
                    user.clone(),
                    &compatibility.meta_datetime_format,
                );
                // Note: groups field inclusion is already handled at the database level
                // Only need to handle empty array display behavior
                *user = crate::utils::handle_user_empty_groups_for_response(
                    user.clone(),
                    compatibility.show_empty_groups_members,
                );
            }
            let response =
                create_filtered_user_list_response(users, total, start_index, &attribute_filter);
            Ok((StatusCode::OK, Json(response)))
        }
        Err(e) => Err(e.to_response()),
    }
}

pub async fn update_user(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    ScimJson(payload): ScimJson<serde_json::Value>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract user ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "User ID not found in path"})),
            ))
        }
    };

    // Convert JSON payload to our User model
    let user: User = match serde_json::from_value(payload) {
        Ok(user) => user,
        Err(e) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": format!("Invalid user data: {}", e)})),
            ))
        }
    };

    // Validate user data
    if let Err(e) = validate_user(&user.base) {
        return Err(e.to_response());
    }

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current user to check its version
            match backend.find_user_by_id(tenant_id, &id, false).await {
                Ok(Some(current_user)) => {
                    if let Some(ref meta) = current_user.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // If the ETag doesn't match, return 412 Precondition Failed
                            if if_match_str != current_version {
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
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(json!({"message": "User not found"})),
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    match backend.update_user(tenant_id, &id, &user).await {
        Ok(Some(mut updated_user)) => {
            // Set meta.location for SCIM compliance
            set_user_location(&tenant_info, &mut updated_user);

            fix_user_refs(&tenant_info, &mut updated_user);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            updated_user = crate::utils::convert_user_datetime_for_response(
                updated_user,
                &compatibility.meta_datetime_format,
            );
            // Note: groups field inclusion is already handled at the database level
            // Only need to handle empty array display behavior
            updated_user = crate::utils::handle_user_empty_groups_for_response(
                updated_user,
                compatibility.show_empty_groups_members,
            );

            // Convert to JSON and remove null fields to comply with SCIM specification
            let user_json = serde_json::to_value(&updated_user).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_user_json = AttributeFilter::remove_null_fields(&user_json);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = updated_user.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"message": "Invalid ETag header"})),
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_user_json).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "User not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn delete_user(
    State((backend, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract user ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "User ID not found in path"})),
            ))
        }
    };

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current user to check its version
            match backend.find_user_by_id(tenant_id, &id, false).await {
                Ok(Some(current_user)) => {
                    if let Some(ref meta) = current_user.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // If the ETag doesn't match, return 412 Precondition Failed
                            if if_match_str != current_version {
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
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(json!({"message": "User not found"})),
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    match backend.delete_user(tenant_id, &id).await {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "User not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn patch_user(
    State((backend, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    headers: HeaderMap,
    uri: Uri,
    ScimJson(patch_ops): ScimJson<ScimPatchOp>,
) -> Result<Response, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;

    // Extract user ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(json!({"message": "User ID not found in path"})),
            ))
        }
    };

    // Phase 3: Handle conditional requests (If-Match) - Optimistic Concurrency Control
    if let Some(if_match) = headers.get("if-match") {
        if let Ok(if_match_str) = if_match.to_str() {
            // First, get the current user to check its version
            match backend.find_user_by_id(tenant_id, &id, false).await {
                Ok(Some(current_user)) => {
                    if let Some(ref meta) = current_user.base.meta {
                        if let Some(ref current_version) = meta.version {
                            // If the ETag doesn't match, return 412 Precondition Failed
                            if if_match_str != current_version {
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
                    return Err((
                        StatusCode::NOT_FOUND,
                        Json(json!({"message": "User not found"})),
                    ));
                }
                Err(e) => return Err(e.to_response()),
            }
        }
    }

    match backend.patch_user(tenant_id, &id, &patch_ops).await {
        Ok(Some(mut user)) => {
            // Set meta.location for SCIM compliance
            set_user_location(&tenant_info, &mut user);

            fix_user_refs(&tenant_info, &mut user);

            // Apply compatibility transformations based on tenant settings
            let compatibility = app_config.get_effective_compatibility(tenant_id);
            user = crate::utils::convert_user_datetime_for_response(
                user,
                &compatibility.meta_datetime_format,
            );
            // Note: groups field inclusion is already handled at the database level
            // Only need to handle empty array display behavior
            user = crate::utils::handle_user_empty_groups_for_response(
                user,
                compatibility.show_empty_groups_members,
            );

            // Convert to JSON and remove null fields to comply with SCIM specification
            let user_json = serde_json::to_value(&user).map_err(|_| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message": "Serialization error"})),
                )
            })?;

            let cleaned_user_json = AttributeFilter::remove_null_fields(&user_json);

            // Build response with ETag header (Phase 2: ETag response headers)
            let mut headers = HeaderMap::new();
            if let Some(ref meta) = user.base.meta {
                if let Some(ref version) = meta.version {
                    headers.insert(
                        "ETag",
                        HeaderValue::from_str(version).map_err(|_| {
                            (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"message": "Invalid ETag header"})),
                            )
                        })?,
                    );
                }
            }

            let mut response = Json(cleaned_user_json).into_response();
            *response.status_mut() = StatusCode::OK;
            response.headers_mut().extend(headers);
            Ok(response)
        }
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "User not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}
