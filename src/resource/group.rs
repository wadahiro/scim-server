use axum::{
    extract::{Query, State, Extension},
    http::{StatusCode, Uri},
    Json,
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc};

use crate::auth::TenantInfo;
use crate::config::AppConfig;
use crate::models::{ScimPatchOp, Group, ScimListResponse};
use crate::backend::ScimBackend;
use crate::parser::{SortSpec, ResourceType};
use crate::parser::filter_parser::parse_filter;
use super::attribute_filter::AttributeFilter;

type AppState = (Arc<dyn ScimBackend>, Arc<String>, Arc<AppConfig>);


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

// Helper function to fix group refs with base URL and tenant path
fn fix_group_refs(base_url: &str, tenant_info: &TenantInfo, group: &mut Group) {
    let tenant_id = tenant_info.tenant_id;
    // Get the correct path from tenant configuration
    let tenant_path = if tenant_info.tenant_config.url.starts_with("http://") || tenant_info.tenant_config.url.starts_with("https://") {
        if let Ok(url) = url::Url::parse(&tenant_info.tenant_config.url) {
            url.path().trim_end_matches('/').to_string()
        } else {
            "/scim".to_string()
        }
    } else {
        tenant_info.tenant_config.url.trim_end_matches('/').to_string()
    };
    
    // Fix meta location
    if let Some(ref mut meta) = group.base.meta {
        if let Some(ref mut location) = meta.location {
            if location.starts_with('/') {
                *location = format!("{}{}", base_url, location);
            }
            if location.contains(&format!("/{}/", tenant_id)) {
                // Replace tenant ID-based URL with tenant path-based URL
                *location = location.replace(&format!("/{}/", tenant_id), &format!("{}/", tenant_path));
            }
        }
    }
    
    // Fix members $ref
    if let Some(ref mut members) = group.base.members {
        for member in members {
            if let Some(ref mut ref_) = member.ref_ {
                if ref_.starts_with('/') {
                    *ref_ = format!("{}{}", base_url, ref_);
                }
                if ref_.contains(&format!("/{}/", tenant_id)) {
                    // Replace tenant ID-based URL with tenant path-based URL
                    *ref_ = ref_.replace(&format!("/{}/", tenant_id), &format!("{}/", tenant_path));
                }
            }
        }
    }
}

// Helper function to apply attribute filtering to groups and create list response
fn create_filtered_group_list_response(
    groups: Vec<Group>,
    total: i64,
    start_index: Option<i64>,
    _base_url: &str,
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
    State((backend, base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    Json(payload): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<Group>), (StatusCode, Json<serde_json::Value>)> {
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
        group.base.schemas = schemas.iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }
    
    if let Some(external_id) = payload.get("externalId").and_then(|v| v.as_str()) {
        group.external_id = Some(external_id.to_string());
    }
    
    // Extract members with proper structure
    if let Some(members_array) = payload.get("members").and_then(|v| v.as_array()) {
        let members: Vec<scim_v2::models::group::Member> = members_array.iter()
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
    
    match backend.create_group(tenant_id, &group).await {
        Ok(mut created_group) => {
            fix_group_refs(&base_url, &tenant_info, &mut created_group);
            Ok((StatusCode::CREATED, Json(created_group)))
        },
        Err(e) => Err(e.to_response()),
    }
}

pub async fn get_group(
    State((backend, base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
    Query(params): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;
    
    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Group ID not found in path"})),
        )),
    };


    // Parse attribute filtering parameters
    let attribute_filter = AttributeFilter::from_params(
        params.get("attributes").map(String::as_str),
        params.get("excludedAttributes").map(String::as_str),
    );

    match backend.find_group_by_id(tenant_id, &id).await {
        Ok(Some(mut group)) => {
            fix_group_refs(&base_url, &tenant_info, &mut group);
            
            // Convert to JSON and apply attribute filtering
            let group_json = serde_json::to_value(&group).map_err(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"message": "Serialization error"})))
            })?;
            
            let filtered_group = attribute_filter.apply_to_resource(&group_json, ResourceType::Group);
            Ok((StatusCode::OK, Json(filtered_group)))
        },
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn search_groups(
    State((backend, base_url, _)): State<AppState>,
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

    // Handle filter for user membership: members[value eq "user-id"]
    if let Some(filter_str) = filter {
        if filter_str.starts_with("members[value eq ") && filter_str.ends_with("]") {
            // Extract user ID from filter
            let start_quote = filter_str.find('"').ok_or_else(|| {
                (StatusCode::BAD_REQUEST, Json(json!({"message": "Invalid filter format"})))
            })?;
            let end_quote = filter_str.rfind('"').ok_or_else(|| {
                (StatusCode::BAD_REQUEST, Json(json!({"message": "Invalid filter format"})))
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
                    // Fix refs for all groups
                    for group in &mut groups {
                        fix_group_refs(&base_url, &tenant_info, group);
                    }
                    let total_results = groups.len() as i64;
                    let response = create_filtered_group_list_response(
                        groups,
                        total_results,
                        start_index,
                        &base_url,
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
                
                match backend.find_groups_by_filter(tenant_id, &filter_op, start_index, count, sort_spec.as_ref()).await {
                    Ok((mut groups, total)) => {
                        // Fix refs for all groups
                        for group in &mut groups {
                            fix_group_refs(&base_url, &tenant_info, group);
                        }
                        let response = create_filtered_group_list_response(
                            groups,
                            total,
                            start_index,
                            &base_url,
                            &attribute_filter,
                        );
                        return Ok((StatusCode::OK, Json(response)));
                    },
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
        backend.find_all_groups_sorted(tenant_id, start_index, count, sort_spec.as_ref()).await
    } else {
        backend.find_all_groups(tenant_id, start_index, count).await
    };
    
    match result {
        Ok((mut groups, total)) => {
            // Fix refs for all groups
            for group in &mut groups {
                fix_group_refs(&base_url, &tenant_info, group);
            }
            let response = create_filtered_group_list_response(
                groups,
                total,
                start_index,
                &base_url,
                &attribute_filter,
            );
            Ok((StatusCode::OK, Json(response)))
        },
        Err(e) => Err(e.to_response()),
    }
}

pub async fn update_group(
    State((backend, base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
    Json(payload): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<Group>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;
    
    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Group ID not found in path"})),
        )),
    };


    // Convert JSON payload to Group - similar to create
    let mut group = Group::default();
    group.base.id = id.clone();
    
    // Extract fields
    if let Some(display_name) = payload.get("displayName").and_then(|v| v.as_str()) {
        group.base.display_name = display_name.to_string();
    }
    
    if let Some(schemas) = payload.get("schemas").and_then(|v| v.as_array()) {
        group.base.schemas = schemas.iter()
            .filter_map(|s| s.as_str().map(String::from))
            .collect();
    }
    
    if let Some(external_id) = payload.get("externalId").and_then(|v| v.as_str()) {
        group.external_id = Some(external_id.to_string());
    }
    
    // Extract members
    if let Some(members_array) = payload.get("members").and_then(|v| v.as_array()) {
        let members: Vec<scim_v2::models::group::Member> = members_array.iter()
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

    match backend.update_group(tenant_id, &id, &group).await {
        Ok(Some(mut updated_group)) => {
            fix_group_refs(&base_url, &tenant_info, &mut updated_group);
            Ok((StatusCode::OK, Json(updated_group)))
        },
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}

pub async fn delete_group(
    State((backend, _, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
) -> Result<StatusCode, (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;
    
    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Group ID not found in path"})),
        )),
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
    State((backend, base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    uri: Uri,
    Json(patch_ops): Json<ScimPatchOp>,
) -> Result<(StatusCode, Json<Group>), (StatusCode, Json<serde_json::Value>)> {
    let tenant_id = tenant_info.tenant_id;
    
    // Extract group ID from URI
    let id = match extract_resource_id_from_uri(&uri) {
        Some(id) => id,
        None => return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"message": "Group ID not found in path"})),
        )),
    };


    match backend.patch_group(tenant_id, &id, &patch_ops).await {
        Ok(Some(mut group)) => {
            fix_group_refs(&base_url, &tenant_info, &mut group);
            Ok((StatusCode::OK, Json(group)))
        },
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "Group not found"})),
        )),
        Err(e) => Err(e.to_response()),
    }
}