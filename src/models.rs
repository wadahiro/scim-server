use scim_v2::models::{group::Group as ScimGroup, user::User as ScimUser};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// SCIM-compliant PatchOperation struct that matches RFC 7644 specification
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScimPatchOperation {
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

/// SCIM-compliant PatchOp struct that matches RFC 7644 specification
#[derive(Serialize, Deserialize, Debug)]
pub struct ScimPatchOp {
    pub schemas: Vec<String>,
    #[serde(rename = "Operations")]
    pub operations: Vec<ScimPatchOperation>,
}

impl ScimPatchOp {}

/// Extended User model with externalId support and arbitrary additional fields
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct User {
    #[serde(flatten)]
    pub base: ScimUser,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    /// Physical mailing addresses.
    ///
    /// RFC 7643 §4.1.2 defines a `primary` sub-attribute for `addresses`
    /// (as it does for `emails` and `phoneNumbers`), but the upstream
    /// `scim_v2::models::user::Address` type has no field for it. Declaring
    /// `addresses` here as raw JSON takes priority over the flattened
    /// `base.addresses` field of the same name during both serialization and
    /// deserialization, so `primary` (and any other sub-attribute) round-trips
    /// through requests, storage, and responses unchanged instead of being
    /// silently dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<serde_json::Value>>,
    // Support for arbitrary additional fields (for custom attributes and testing)
    #[serde(flatten)]
    pub additional_fields: std::collections::HashMap<String, serde_json::Value>,
}

impl User {
    /// Create a new User from ScimUser
    #[allow(dead_code)]
    pub fn from_scim_user(base: ScimUser) -> Self {
        Self {
            base,
            external_id: None,
            addresses: None,
            additional_fields: std::collections::HashMap::new(),
        }
    }

    /// Create a new User with externalId
    #[allow(dead_code)]
    pub fn with_external_id(base: ScimUser, external_id: Option<String>) -> Self {
        Self {
            base,
            external_id,
            addresses: None,
            additional_fields: std::collections::HashMap::new(),
        }
    }

    // Delegate common fields to base for easier access
    #[allow(dead_code)]
    pub fn id(&self) -> &Option<String> {
        &self.base.id
    }
    pub fn id_mut(&mut self) -> &mut Option<String> {
        &mut self.base.id
    }
    pub fn meta(&self) -> &Option<scim_v2::models::scim_schema::Meta> {
        &self.base.meta
    }
    pub fn meta_mut(&mut self) -> &mut Option<scim_v2::models::scim_schema::Meta> {
        &mut self.base.meta
    }
    pub fn groups_mut(&mut self) -> &mut Option<Vec<scim_v2::models::user::Group>> {
        &mut self.base.groups
    }
    pub fn password(&self) -> &Option<String> {
        &self.base.password
    }
    pub fn password_mut(&mut self) -> &mut Option<String> {
        &mut self.base.password
    }
}

impl Clone for User {
    fn clone(&self) -> Self {
        // Use JSON serialization/deserialization to properly clone all fields
        let json_value = serde_json::to_value(&self.base).expect("Failed to serialize ScimUser");
        let cloned_base: ScimUser =
            serde_json::from_value(json_value).expect("Failed to deserialize ScimUser");

        Self {
            base: cloned_base,
            external_id: self.external_id.clone(),
            addresses: self.addresses.clone(),
            additional_fields: self.additional_fields.clone(),
        }
    }
}

/// Extended Group model with externalId support
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Group {
    #[serde(flatten)]
    pub base: ScimGroup,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
}

impl Group {
    /// Create a new Group from ScimGroup
    #[allow(dead_code)]
    pub fn from_scim_group(base: ScimGroup) -> Self {
        Self {
            base,
            external_id: None,
        }
    }

    /// Create a new Group with externalId
    #[allow(dead_code)]
    pub fn with_external_id(base: ScimGroup, external_id: Option<String>) -> Self {
        Self { base, external_id }
    }

    // Delegate common fields to base for easier access
    #[allow(dead_code)]
    pub fn id(&self) -> &String {
        &self.base.id
    }
    pub fn id_mut(&mut self) -> &mut String {
        &mut self.base.id
    }
    pub fn meta(&self) -> &Option<scim_v2::models::scim_schema::Meta> {
        &self.base.meta
    }
    pub fn meta_mut(&mut self) -> &mut Option<scim_v2::models::scim_schema::Meta> {
        &mut self.base.meta
    }
    pub fn members(&self) -> &Option<Vec<scim_v2::models::group::Member>> {
        &self.base.members
    }
    pub fn members_mut(&mut self) -> &mut Option<Vec<scim_v2::models::group::Member>> {
        &mut self.base.members
    }
}

impl Clone for Group {
    fn clone(&self) -> Self {
        // Use JSON serialization/deserialization to properly clone all fields
        let json_value = serde_json::to_value(&self.base).expect("Failed to serialize ScimGroup");
        let cloned_base: ScimGroup =
            serde_json::from_value(json_value).expect("Failed to deserialize ScimGroup");

        Self {
            base: cloned_base,
            external_id: self.external_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScimListResponse {
    pub schemas: Vec<String>,
    #[serde(rename = "totalResults")]
    pub total_results: i64,
    #[serde(rename = "startIndex", skip_serializing_if = "Option::is_none")]
    pub start_index: Option<i64>,
    #[serde(rename = "itemsPerPage", skip_serializing_if = "Option::is_none")]
    pub items_per_page: Option<i64>,
    #[serde(rename = "Resources")]
    pub resources: Vec<serde_json::Value>,
}

/// The identifier for the SCIM search request message (RFC 7644 §3.4.3).
pub const SCIM_SEARCH_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";

/// Body of `POST /{Resource}/.search` (RFC 7644 §3.4.3). Carries the same
/// query parameters as the `GET` collection endpoint, for queries too large
/// to fit comfortably in a URL.
#[derive(Debug, Deserialize)]
pub struct SearchRequest {
    pub schemas: Vec<String>,
    #[serde(default)]
    pub filter: Option<String>,
    #[serde(default)]
    pub attributes: Option<Vec<String>>,
    #[serde(default, rename = "excludedAttributes")]
    pub excluded_attributes: Option<Vec<String>>,
    #[serde(default, rename = "sortBy")]
    pub sort_by: Option<String>,
    #[serde(default, rename = "sortOrder")]
    pub sort_order: Option<String>,
    #[serde(default, rename = "startIndex")]
    pub start_index: Option<i64>,
    #[serde(default)]
    pub count: Option<i64>,
}

impl SearchRequest {
    /// Validates `schemas` and converts this request into the same
    /// `HashMap<String, String>` query-parameter representation the `GET`
    /// search handlers use, so both entry points share one code path.
    pub fn into_query_params(
        self,
    ) -> Result<
        std::collections::HashMap<String, String>,
        (axum::http::StatusCode, axum::Json<serde_json::Value>),
    > {
        if !self.schemas.iter().any(|s| s == SCIM_SEARCH_REQUEST_SCHEMA) {
            return Err(crate::error::scim_error_response(
                axum::http::StatusCode::BAD_REQUEST,
                Some("invalidValue"),
                &format!(
                    "SearchRequest 'schemas' must contain '{}'",
                    SCIM_SEARCH_REQUEST_SCHEMA
                ),
            ));
        }

        let mut params = std::collections::HashMap::new();
        if let Some(filter) = self.filter {
            params.insert("filter".to_string(), filter);
        }
        if let Some(attributes) = self.attributes {
            params.insert("attributes".to_string(), attributes.join(","));
        }
        if let Some(excluded) = self.excluded_attributes {
            params.insert("excludedAttributes".to_string(), excluded.join(","));
        }
        if let Some(sort_by) = self.sort_by {
            params.insert("sortBy".to_string(), sort_by);
        }
        if let Some(sort_order) = self.sort_order {
            params.insert("sortOrder".to_string(), sort_order);
        }
        if let Some(start_index) = self.start_index {
            params.insert("startIndex".to_string(), start_index.to_string());
        }
        if let Some(count) = self.count {
            params.insert("count".to_string(), count.to_string());
        }

        Ok(params)
    }
}
