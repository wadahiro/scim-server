use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::TenantInfo;
use crate::backend::ScimBackend;
use crate::config::AppConfig;
use crate::schema::SCIM_SCHEMA_ENTERPRISE_USER;

type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

/// Build the `/ResourceTypes` resource list. Shared by the collection
/// endpoint and the single-resource-by-id endpoint (RFC 7644 §4).
///
/// RFC 7643 §3.1 defines `meta.location` as "The URI of the resource being
/// returned", i.e. an absolute URL consistent with the tenant's resolved
/// base URL -- not the bare `schema` URN, which is a separate field.
fn build_resource_type_resources(tenant_info: &TenantInfo) -> Vec<Value> {
    vec![
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "User",
            "name": "User",
            "endpoint": "/Users",
            "description": "User Account",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:User",
            "schemaExtensions": [
                {
                    "schema": SCIM_SCHEMA_ENTERPRISE_USER,
                    "required": false
                }
            ],
            "meta": {
                "resourceType": "ResourceType",
                "location": crate::utils::build_resource_location(tenant_info, "ResourceTypes/User")
            }
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
            "id": "Group",
            "name": "Group",
            "endpoint": "/Groups",
            "description": "Group",
            "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
            "schemaExtensions": [],
            "meta": {
                "resourceType": "ResourceType",
                "location": crate::utils::build_resource_location(tenant_info, "ResourceTypes/Group")
            }
        }),
    ]
}

pub async fn resource_types(
    State((_storage, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _tenant_id = tenant_info.tenant_id;

    let resource_list = build_resource_type_resources(&tenant_info);

    let resources = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": resource_list.len(),
        "Resources": resource_list
    });

    Ok((StatusCode::OK, Json(resources)))
}

/// `GET /ResourceTypes/{id}` (RFC 7644 §4).
pub async fn resource_type_by_id(
    State((_storage, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _tenant_id = tenant_info.tenant_id;

    let resource_list = build_resource_type_resources(&tenant_info);

    match resource_list
        .into_iter()
        .find(|r| r["id"] == Value::String(id.clone()))
    {
        Some(resource) => Ok((StatusCode::OK, Json(resource))),
        None => Err(crate::error::scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            &format!("ResourceType '{}' not found", id),
        )),
    }
}
