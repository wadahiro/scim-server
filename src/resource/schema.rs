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
use crate::schema::{
    get_all_schemas, AttributeType, Mutability, Returned, Uniqueness,
    SCIM_API_MESSAGES_LIST_RESPONSE,
};

type AppState = (Arc<dyn ScimBackend>, Arc<AppConfig>);

// Convert AttributeType to JSON string representation
fn attribute_type_to_string(attr_type: &AttributeType) -> &'static str {
    match attr_type {
        AttributeType::String => "string",
        AttributeType::Boolean => "boolean",
        AttributeType::Integer => "integer",
        AttributeType::Decimal => "decimal",
        AttributeType::DateTime => "dateTime",
        AttributeType::Reference => "reference",
        AttributeType::Complex => "complex",
    }
}

// Convert Mutability to JSON string representation
fn mutability_to_string(mutability: &Mutability) -> &'static str {
    match mutability {
        Mutability::ReadOnly => "readOnly",
        Mutability::ReadWrite => "readWrite",
        Mutability::Immutable => "immutable",
        Mutability::WriteOnly => "writeOnly",
    }
}

// Convert Returned to JSON string representation
fn returned_to_string(returned: &Returned) -> &'static str {
    match returned {
        Returned::Always => "always",
        Returned::Never => "never",
        Returned::Default => "default",
        Returned::Request => "request",
    }
}

// Convert Uniqueness to JSON string representation
fn uniqueness_to_string(uniqueness: &Uniqueness) -> &'static str {
    match uniqueness {
        Uniqueness::None => "none",
        Uniqueness::Server => "server",
        Uniqueness::Global => "global",
    }
}

// Build attribute JSON from AttributeDefinition
fn build_attribute_json(attr: &crate::schema::AttributeDefinition) -> Value {
    let mut attr_json = json!({
        "name": attr.name,
        "type": attribute_type_to_string(&attr.attr_type),
        "multiValued": attr.multi_valued,
        "description": attr.description,
        "required": attr.required,
        "caseExact": attr.case_exact,
        "mutability": mutability_to_string(&attr.mutability),
        "returned": returned_to_string(&attr.returned),
        "uniqueness": uniqueness_to_string(&attr.uniqueness),
    });

    // Add subAttributes if present
    if !attr.sub_attributes.is_empty() {
        let sub_attrs: Vec<Value> = attr
            .sub_attributes
            .iter()
            .map(build_attribute_json)
            .collect();
        attr_json["subAttributes"] = json!(sub_attrs);
    }

    // Add canonical values for specific attributes
    match (attr.name, &attr.attr_type) {
        ("type", AttributeType::String) if attr.description.contains("email") => {
            attr_json["canonicalValues"] = json!(["work", "home", "other"]);
        }
        ("type", AttributeType::String) if attr.description.contains("phone") => {
            attr_json["canonicalValues"] =
                json!(["work", "home", "mobile", "fax", "pager", "other"]);
        }
        ("type", AttributeType::String) if attr.description.contains("member") => {
            attr_json["canonicalValues"] = json!(["User", "Group"]);
        }
        _ => {}
    }

    // Add referenceTypes for reference attributes
    if let AttributeType::Reference = &attr.attr_type {
        match attr.name {
            "$ref" if attr.description.contains("Group") => {
                attr_json["referenceTypes"] = json!(["Group"]);
            }
            "$ref" if attr.description.contains("member") => {
                attr_json["referenceTypes"] = json!(["User", "Group"]);
            }
            _ => {}
        }
    }

    attr_json
}

pub async fn schemas(
    State((_storage, _)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _tenant_id = tenant_info.tenant_id;

    // Get all schemas from the centralized schema module
    let all_schemas = get_all_schemas();

    // Build schema resources
    let mut resources = Vec::new();

    for schema_def in all_schemas {
        let attributes: Vec<Value> = schema_def
            .attributes
            .iter()
            .map(build_attribute_json)
            .collect();

        resources.push(json!({
            "id": schema_def.id,
            "name": schema_def.name,
            "description": schema_def.description,
            "attributes": attributes,
            "meta": {
                "resourceType": "Schema",
                "location": schema_def.id
            }
        }));
    }

    // Add ServiceProviderConfig schema (this is not a resource schema but a configuration schema)
    resources.push(json!({
        "id": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
        "name": "ServiceProviderConfig",
        "description": "Service Provider Configuration",
        "attributes": [
            {
                "name": "documentationUri",
                "type": "reference",
                "multiValued": false,
                "description": "HTTP-addressable URL for documentation",
                "required": false,
                "caseExact": false,
                "mutability": "readOnly",
                "returned": "default",
                "uniqueness": "none"
            },
            {
                "name": "patch",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which PATCH operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether PATCH is supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "bulk",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which bulk operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether bulk operations are supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    },
                    {
                        "name": "maxOperations",
                        "type": "integer",
                        "multiValued": false,
                        "description": "The maximum number of operations in a single bulk request",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    },
                    {
                        "name": "maxPayloadSize",
                        "type": "integer",
                        "multiValued": false,
                        "description": "The maximum size of the bulk operation payload in bytes",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "filter",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which filter operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether filter is supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    },
                    {
                        "name": "maxResults",
                        "type": "integer",
                        "multiValued": false,
                        "description": "The maximum number of results returned by a filter operation",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "changePassword",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which password operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether password change is supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "sort",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which sort operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether sorting is supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "etag",
                "type": "complex",
                "multiValued": false,
                "description": "A complex attribute indicating which ETag operations are supported",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "supported",
                        "type": "boolean",
                        "multiValued": false,
                        "description": "Boolean indicating whether ETag is supported",
                        "required": true,
                        "mutability": "readOnly",
                        "returned": "default"
                    }
                ]
            },
            {
                "name": "authenticationSchemes",
                "type": "complex",
                "multiValued": true,
                "description": "Supported authentication scheme properties",
                "required": true,
                "returned": "default",
                "mutability": "readOnly",
                "subAttributes": [
                    {
                        "name": "type",
                        "type": "string",
                        "multiValued": false,
                        "description": "Authentication scheme type",
                        "required": true,
                        "caseExact": false,
                        "mutability": "readOnly",
                        "returned": "default",
                        "uniqueness": "none"
                    },
                    {
                        "name": "name",
                        "type": "string",
                        "multiValued": false,
                        "description": "Common authentication scheme name",
                        "required": true,
                        "caseExact": false,
                        "mutability": "readOnly",
                        "returned": "default",
                        "uniqueness": "none"
                    },
                    {
                        "name": "description",
                        "type": "string",
                        "multiValued": false,
                        "description": "Authentication scheme description",
                        "required": true,
                        "caseExact": false,
                        "mutability": "readOnly",
                        "returned": "default",
                        "uniqueness": "none"
                    }
                ]
            }
        ],
        "meta": {
            "resourceType": "Schema",
            "location": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
        }
    }));

    let schemas = json!({
        "schemas": [SCIM_API_MESSAGES_LIST_RESPONSE],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources
    });

    Ok((StatusCode::OK, Json(schemas)))
}
