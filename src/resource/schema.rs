use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::auth::TenantInfo;
use crate::backend::ScimBackend;
use crate::config::{AppConfig, CompatibilityConfig};
use crate::schema::{
    get_all_schemas, AttributeType, Mutability, Returned, Uniqueness,
    SCIM_API_MESSAGES_LIST_RESPONSE, SCIM_SCHEMA_CORE_USER,
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
        AttributeType::Binary => "binary",
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

    // Add canonical values, if any are defined for this attribute (RFC 7643 §7).
    if !attr.canonical_values.is_empty() {
        attr_json["canonicalValues"] = json!(attr.canonical_values);
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

/// Build the full list of `/Schemas` resources (the core, extension, and
/// ServiceProviderConfig schema definitions). Shared by the collection
/// endpoint and the single-resource-by-id endpoint (RFC 7644 §4).
///
/// RFC 7643 §3.1 defines `meta.location` as "The URI of the resource being
/// returned", i.e. an absolute URL consistent with the tenant's resolved
/// base URL -- not the bare schema URN, which is already carried in `id`.
///
/// `compatibility` is the tenant's effective compatibility configuration.
/// RFC 7643 §7 defines "returned": "default" to mean the attribute is
/// returned by default, and "never" to mean it is never returned. When
/// `include_user_groups` is disabled, `User.groups` is structurally never
/// present in a response for this tenant, so it must be advertised as
/// "never" rather than "default" -- advertising "default" while never
/// returning the attribute would be a schema/behavior mismatch.
///
/// This is distinct from `show_empty_groups_members`, which only omits
/// `User.groups` / `Group.members` when the value is an *empty* array.
/// RFC 7643 §2.5 states: "Unassigned attributes, the null value, or an
/// empty array (in the case of a multi-valued attribute) SHALL be
/// considered to be equivalent in 'state'" and "When a resource is
/// expressed in JSON format, unassigned attributes, although they are
/// defined in schema, MAY be omitted for compactness." Omitting an empty
/// multi-valued attribute is therefore explicitly permitted by the
/// specification and remains consistent with "returned": "default"; it
/// must not be changed to "never".
fn build_schema_resources(
    tenant_info: &crate::auth::TenantInfo,
    compatibility: &CompatibilityConfig,
) -> Vec<Value> {
    // Get all schemas from the centralized schema module
    let all_schemas = get_all_schemas();

    // Build schema resources
    let mut resources = Vec::new();

    for schema_def in all_schemas {
        let attributes: Vec<Value> = schema_def
            .attributes
            .iter()
            .map(|attr| {
                let mut attr_json = build_attribute_json(attr);
                if schema_def.id == SCIM_SCHEMA_CORE_USER
                    && attr.name == "groups"
                    && !compatibility.include_user_groups
                {
                    attr_json["returned"] = json!(returned_to_string(&Returned::Never));
                }
                attr_json
            })
            .collect();

        resources.push(json!({
            "id": schema_def.id,
            "name": schema_def.name,
            "description": schema_def.description,
            "attributes": attributes,
            "meta": {
                "resourceType": "Schema",
                "location": crate::utils::build_resource_location(
                    tenant_info,
                    &format!("Schemas/{}", schema_def.id)
                )
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
            "location": crate::utils::build_resource_location(
                tenant_info,
                "Schemas/urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
            )
        }
    }));

    resources
}

pub async fn schemas(
    State((_storage, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let tenant_id = tenant_info.tenant_id;
    let compatibility = app_config.get_effective_compatibility(tenant_id);

    let resources = build_schema_resources(&tenant_info, compatibility);

    let schemas = json!({
        "schemas": [SCIM_API_MESSAGES_LIST_RESPONSE],
        "totalResults": resources.len(),
        "startIndex": 1,
        "itemsPerPage": resources.len(),
        "Resources": resources
    });

    Ok((StatusCode::OK, Json(schemas)))
}

/// `GET /Schemas/{id}` (RFC 7644 §4). A schema id is a URN (e.g.
/// `urn:ietf:params:scim:schemas:core:2.0:User`), so the route parameter
/// must tolerate colons -- axum path segments only split on `/`, so this
/// works without any special routing configuration.
pub async fn schema_by_id(
    State((_storage, app_config)): State<AppState>,
    Extension(tenant_info): Extension<TenantInfo>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let tenant_id = tenant_info.tenant_id;
    let compatibility = app_config.get_effective_compatibility(tenant_id);

    let resources = build_schema_resources(&tenant_info, compatibility);

    match resources
        .into_iter()
        .find(|r| r["id"] == Value::String(id.clone()))
    {
        Some(resource) => Ok((StatusCode::OK, Json(resource))),
        None => Err(crate::error::scim_error_response(
            StatusCode::NOT_FOUND,
            None,
            &format!("Schema '{}' not found", id),
        )),
    }
}
