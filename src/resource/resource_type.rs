use axum::{extract::{State, Extension}, http::StatusCode, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::TenantInfo;
use crate::config::AppConfig;
use crate::backend::ScimBackend;
use crate::schema::SCIM_SCHEMA_ENTERPRISE_USER;


type AppState = (Arc<dyn ScimBackend>, Arc<String>, Arc<AppConfig>);

pub async fn resource_types(
    State((_storage, _base_url, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _tenant_id = tenant_info.tenant_id;


    let resources = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
        "totalResults": 2,
        "Resources": [
            {
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
                    "location": "urn:ietf:params:scim:schemas:core:2.0:User"
                }
            },
            {
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"],
                "id": "Group",
                "name": "Group",
                "endpoint": "/Groups",
                "description": "Group",
                "schema": "urn:ietf:params:scim:schemas:core:2.0:Group",
                "schemaExtensions": [],
                "meta": {
                    "resourceType": "ResourceType",
                    "location": "urn:ietf:params:scim:schemas:core:2.0:Group"
                }
            }
        ]
    });

    Ok((StatusCode::OK, Json(resources)))
}