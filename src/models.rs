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
#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    #[serde(flatten)]
    pub base: ScimUser,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
    // Support for arbitrary additional fields (for custom attributes and testing)
    #[serde(flatten)]
    pub additional_fields: std::collections::HashMap<String, serde_json::Value>,
}

impl User {
    /// Create a new User from ScimUser
    pub fn from_scim_user(base: ScimUser) -> Self {
        Self {
            base,
            external_id: None,
            additional_fields: std::collections::HashMap::new(),
        }
    }

    /// Create a new User with externalId
    pub fn with_external_id(base: ScimUser, external_id: Option<String>) -> Self {
        Self {
            base,
            external_id,
            additional_fields: std::collections::HashMap::new(),
        }
    }

    // Delegate common fields to base for easier access
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
            additional_fields: self.additional_fields.clone(),
        }
    }
}

impl Default for User {
    fn default() -> Self {
        Self {
            base: ScimUser::default(),
            external_id: None,
            additional_fields: std::collections::HashMap::new(),
        }
    }
}

/// Extended Group model with externalId support
#[derive(Serialize, Deserialize, Debug)]
pub struct Group {
    #[serde(flatten)]
    pub base: ScimGroup,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "externalId")]
    pub external_id: Option<String>,
}

impl Group {
    /// Create a new Group from ScimGroup
    pub fn from_scim_group(base: ScimGroup) -> Self {
        Self {
            base,
            external_id: None,
        }
    }

    /// Create a new Group with externalId
    pub fn with_external_id(base: ScimGroup, external_id: Option<String>) -> Self {
        Self { base, external_id }
    }

    // Delegate common fields to base for easier access
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

impl Default for Group {
    fn default() -> Self {
        Self {
            base: ScimGroup::default(),
            external_id: None,
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
