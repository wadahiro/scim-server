use async_trait::async_trait;
use serde_json::Value;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::Group;

/// Prepared group data for database insertion
#[derive(Debug)]
pub struct PreparedGroupData {
    pub group: Group,
    pub id: String,
    pub external_id: Option<String>,
    pub display_name: String,
    pub members: Option<Vec<scim_v2::models::group::Member>>,
    pub data_orig: Value,
    pub data_norm: Value,
    pub timestamp: DateTime<Utc>,
}

/// Database-specific adapter for group INSERT operations
#[async_trait]
pub trait GroupInserter: Send + Sync {
    /// Execute group insert and return the created group
    async fn execute_group_insert(
        &self,
        tenant_id: u32,
        data: PreparedGroupData,
    ) -> AppResult<Group>;
}

/// Shared business logic for group INSERT operations
pub struct GroupInsertProcessor;

impl GroupInsertProcessor {
    /// Prepare group data for database insertion
    pub fn prepare_group_for_insert(group: &Group) -> AppResult<PreparedGroupData> {
        let mut group = group.clone();
        
        // Always generate a new ID (SCIM 2.0 doesn't allow client-specified IDs in POST)
        let id = Uuid::new_v4().to_string();
        *group.id_mut() = id.clone();
        
        let external_id = group.external_id.clone();
        let display_name = group.base.display_name.clone();
        
        // Set metadata timestamps
        let timestamp = Utc::now();
        Self::set_group_metadata(&mut group, &timestamp);
        
        // Extract members (stored separately in group_memberships table)
        let members = group.base.members.as_ref().map(|members| {
            members.iter().map(|m| scim_v2::models::group::Member {
                value: m.value.clone(),
                ref_: m.ref_.clone(),
                display: m.display.clone(),
                type_: m.type_.clone(),
            }).collect()
        });
        // Remove members from group JSON data (they'll be stored separately)
        let mut group_without_members = group.clone();
        group_without_members.base.members = None;
        
        // Serialize group data (without members)
        let data_orig = serde_json::to_value(&group_without_members)
            .map_err(|e| AppError::Serialization(e))?;
        let normalized_data = crate::schema::normalization::normalize_scim_data(&data_orig, crate::parser::ResourceType::Group);
        let data_norm = serde_json::to_value(&normalized_data)
            .map_err(|e| AppError::Serialization(e))?;
        
        Ok(PreparedGroupData {
            group,
            id,
            external_id,
            display_name,
            members,
            data_orig,
            data_norm,
            timestamp,
        })
    }
    
    /// Set group metadata with timestamps
    fn set_group_metadata(group: &mut Group, timestamp: &DateTime<Utc>) {
        let meta = scim_v2::models::scim_schema::Meta {
            resource_type: Some("Group".to_string()),
            created: Some(timestamp.to_rfc3339()),
            last_modified: Some(timestamp.to_rfc3339()),
            location: None,
            version: None,
        };
        *group.meta_mut() = Some(meta);
    }
}



/// Unified group INSERT operations using the adapter pattern
pub struct UnifiedGroupInsertOps<T: GroupInserter> {
    inserter: T,
}

impl<T: GroupInserter> UnifiedGroupInsertOps<T> {
    pub fn new(inserter: T) -> Self {
        Self { inserter }
    }
    
    /// Create a new group using shared logic and database-specific execution
    pub async fn create_group(&self, tenant_id: u32, group: &Group) -> AppResult<Group> {
        // Prepare data using shared business logic
        let prepared_data = GroupInsertProcessor::prepare_group_for_insert(group)?;
        
        // Execute database-specific insertion
        let created_group = self.inserter.execute_group_insert(tenant_id, prepared_data).await?;
        
        Ok(created_group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_prepare_group_for_insert() {
        // Create a test group directly using our models
        let mut group = Group::default();
        group.base.display_name = "Test Group".to_string();
        
        let result = GroupInsertProcessor::prepare_group_for_insert(&group);
        assert!(result.is_ok());
        
        let prepared = result.unwrap();
        assert_eq!(prepared.display_name, "Test Group");
        assert!(!prepared.id.is_empty()); // Should have generated an ID
        assert!(uuid::Uuid::parse_str(&prepared.id).is_ok()); // Should be a valid UUID
    }
    
}