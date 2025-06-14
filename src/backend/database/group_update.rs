use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::Group;

/// Common trait for group update operations across different database backends
#[async_trait]
pub trait GroupUpdater: Send + Sync {
    /// Execute group update and return the updated group
    ///
    /// This should handle both the group data update and member relationship management
    /// in a transactional manner to ensure data consistency.
    async fn execute_group_update(
        &self,
        tenant_id: u32,
        id: &str,
        data: PreparedGroupUpdateData,
    ) -> AppResult<Option<Group>>;
}

/// Prepared group data for database update operations
///
/// This struct contains all the processed and validated data needed
/// for updating a group in the database, including member relationships.
pub struct PreparedGroupUpdateData {
    pub group: Group,
    pub id: String,
    pub display_name: String,
    pub external_id: Option<String>,
    pub members: Option<Vec<scim_v2::models::group::Member>>,
    pub data_orig: Value,
    pub data_norm: Value,
    pub timestamp: DateTime<Utc>,
}

/// Processor for common group update business logic
///
/// This handles all the shared preparation logic that is the same
/// across PostgreSQL and SQLite implementations.
pub struct GroupUpdateProcessor;

impl GroupUpdateProcessor {
    /// Prepare group data for database update
    ///
    /// This validates data, sets metadata, extracts members for separate storage,
    /// and prepares JSON data for the main group record.
    pub fn prepare_group_for_update(id: &str, group: &Group) -> AppResult<PreparedGroupUpdateData> {
        let mut group = group.clone();

        // Ensure ID matches the path parameter
        *group.id_mut() = id.to_string();

        // Update metadata
        let timestamp = Utc::now();
        Self::set_group_metadata(&mut group, &timestamp);

        let display_name = group.base.display_name.clone();
        let external_id = group.external_id.clone();

        // Extract members for separate storage in group_memberships table
        let members = group.members().as_ref().map(|members| {
            members
                .iter()
                .map(|member| scim_v2::models::group::Member {
                    value: member.value.clone(),
                    display: member.display.clone(),
                    ref_: member.ref_.clone(),
                    type_: member.type_.clone(),
                })
                .collect()
        });

        // Create group for storage without members (they go in separate table)
        let mut group_for_storage = group.clone();
        *group_for_storage.members_mut() = None;

        // Serialize group data for storage (without members)
        let data_orig =
            serde_json::to_value(&group_for_storage).map_err(AppError::Serialization)?;

        // Normalize data for filtering capabilities
        let normalized_data = crate::schema::normalization::normalize_scim_data(
            &data_orig,
            crate::parser::ResourceType::Group,
        );
        let data_norm = serde_json::to_value(&normalized_data).map_err(AppError::Serialization)?;

        Ok(PreparedGroupUpdateData {
            group,
            id: id.to_string(),
            display_name,
            external_id,
            members,
            data_orig,
            data_norm,
            timestamp,
        })
    }

    /// Validate that the group ID is not empty or whitespace
    pub fn validate_group_id(id: &str) -> AppResult<()> {
        if id.trim().is_empty() {
            return Err(AppError::BadRequest("Group ID cannot be empty".to_string()));
        }
        Ok(())
    }

    /// Set group metadata for update operations
    ///
    /// This updates the lastModified timestamp in the SCIM meta attribute.
    fn set_group_metadata(group: &mut Group, timestamp: &DateTime<Utc>) {
        if let Some(meta) = group.meta_mut() {
            meta.last_modified = Some(crate::utils::format_scim_datetime(*timestamp));
        }
    }
}

/// Unified group update operations handler
///
/// This provides a consistent interface for group update operations
/// while delegating to database-specific implementations.
pub struct UnifiedGroupUpdateOps<T: GroupUpdater> {
    updater: T,
}

impl<T: GroupUpdater> UnifiedGroupUpdateOps<T> {
    pub fn new(updater: T) -> Self {
        Self { updater }
    }

    /// Update a group with full validation and processing
    ///
    /// This handles both the group data and member relationship updates
    /// in a transactional manner.
    pub async fn update_group(
        &self,
        tenant_id: u32,
        id: &str,
        group: &Group,
    ) -> AppResult<Option<Group>> {
        // Validate inputs
        GroupUpdateProcessor::validate_group_id(id)?;

        // Prepare group data for update
        let prepared = GroupUpdateProcessor::prepare_group_for_update(id, group)?;

        // Execute the update via database-specific implementation
        self.updater
            .execute_group_update(tenant_id, id, prepared)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_group_id() {
        // Valid IDs
        assert!(GroupUpdateProcessor::validate_group_id("valid-id").is_ok());
        assert!(
            GroupUpdateProcessor::validate_group_id("123e4567-e89b-12d3-a456-426614174000").is_ok()
        );

        // Invalid IDs
        assert!(GroupUpdateProcessor::validate_group_id("").is_err());
        assert!(GroupUpdateProcessor::validate_group_id("   ").is_err());
    }

    #[test]
    fn test_prepare_group_for_update() {
        let mut group = Group::default();
        group.base.display_name = "Test Group".to_string();

        let prepared = GroupUpdateProcessor::prepare_group_for_update("test-id", &group).unwrap();

        assert_eq!(prepared.id, "test-id");
        assert_eq!(prepared.display_name, "Test Group");
        assert_eq!(prepared.group.id(), "test-id");
        assert!(prepared.data_orig.is_object());
        assert!(prepared.data_norm.is_object());
        assert!(prepared.members.is_none()); // No members in this test
        assert!(prepared.timestamp.timestamp() > 0);
    }

    #[test]
    fn test_group_with_members_preparation() {
        let mut group = Group::default();
        group.base.display_name = "Test Group with Members".to_string();

        // Add some members
        let members = vec![
            scim_v2::models::group::Member {
                value: Some("user-1".to_string()),
                display: Some("User One".to_string()),
                ref_: None,
                type_: Some("User".to_string()),
            },
            scim_v2::models::group::Member {
                value: Some("user-2".to_string()),
                display: Some("User Two".to_string()),
                ref_: None,
                type_: Some("User".to_string()),
            },
        ];
        *group.members_mut() = Some(members);

        let prepared = GroupUpdateProcessor::prepare_group_for_update("test-id", &group).unwrap();

        assert_eq!(prepared.display_name, "Test Group with Members");
        assert_eq!(prepared.id, "test-id");

        // Verify members were extracted for separate storage
        assert!(prepared.members.is_some());
        let extracted_members = prepared.members.unwrap();
        assert_eq!(extracted_members.len(), 2);
        assert_eq!(extracted_members[0].value, Some("user-1".to_string()));
        assert_eq!(extracted_members[1].value, Some("user-2".to_string()));

        // Verify members were removed from JSON data (for separate storage)
        let data_obj = prepared.data_orig.as_object().unwrap();
        if let Some(base_obj) = data_obj.get("base") {
            if let Some(base_obj) = base_obj.as_object() {
                // Members should be an empty array in the serialized data
                if let Some(members_value) = base_obj.get("members") {
                    assert!(
                        members_value.is_array() && members_value.as_array().unwrap().is_empty(),
                        "Members should be an empty array in JSON data, but was: {:?}",
                        members_value
                    );
                } else {
                    panic!("Members key should exist in JSON data");
                }
            }
        }
    }
}
