use async_trait::async_trait;

use crate::error::AppResult;

/// Database-specific adapter for group DELETE operations
#[async_trait]
pub trait GroupDeleter: Send + Sync {
    /// Execute group delete with cascading membership cleanup
    /// Returns whether the group was found and deleted
    async fn execute_group_delete(&self, tenant_id: u32, id: &str) -> AppResult<bool>;
}

/// Shared business logic for group DELETE operations
pub struct GroupDeleteProcessor;

impl GroupDeleteProcessor {
    /// Validate group ID for deletion
    ///
    /// This handles common validation:
    /// - ID format validation (where applicable)
    /// - Non-empty ID check
    pub fn validate_group_id(id: &str) -> AppResult<()> {
        if id.trim().is_empty() {
            return Err(crate::error::AppError::BadRequest(
                "Group ID cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// Unified group DELETE operations using the adapter pattern
pub struct UnifiedGroupDeleteOps<T: GroupDeleter> {
    deleter: T,
}

impl<T: GroupDeleter> UnifiedGroupDeleteOps<T> {
    pub fn new(deleter: T) -> Self {
        Self { deleter }
    }

    /// Delete a group using shared logic and database-specific execution
    ///
    /// This handles:
    /// - Group deletion
    /// - Cascading membership cleanup (implemented in database-specific layer)
    pub async fn delete_group(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        // Validate ID using shared business logic
        GroupDeleteProcessor::validate_group_id(id)?;

        // Execute database-specific deletion (includes membership cleanup)
        self.deleter.execute_group_delete(tenant_id, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_group_id() {
        // Valid ID
        assert!(GroupDeleteProcessor::validate_group_id("valid-id").is_ok());
        assert!(
            GroupDeleteProcessor::validate_group_id("123e4567-e89b-12d3-a456-426614174000").is_ok()
        );

        // Invalid IDs
        assert!(GroupDeleteProcessor::validate_group_id("").is_err());
        assert!(GroupDeleteProcessor::validate_group_id("   ").is_err());
    }
}
