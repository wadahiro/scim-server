use async_trait::async_trait;

use crate::error::AppResult;

/// Database-specific adapter for user DELETE operations
#[async_trait]
pub trait UserDeleter: Send + Sync {
    /// Execute user delete and return whether the user was found and deleted
    async fn execute_user_delete(
        &self,
        tenant_id: u32,
        id: &str,
    ) -> AppResult<bool>;
}

/// Shared business logic for user DELETE operations
pub struct UserDeleteProcessor;

impl UserDeleteProcessor {
    /// Validate user ID for deletion
    /// 
    /// This handles common validation:
    /// - ID format validation (where applicable)
    /// - Non-empty ID check
    pub fn validate_user_id(id: &str) -> AppResult<()> {
        if id.trim().is_empty() {
            return Err(crate::error::AppError::BadRequest("User ID cannot be empty".to_string()));
        }
        Ok(())
    }
}

/// Unified user DELETE operations using the adapter pattern
pub struct UnifiedUserDeleteOps<T: UserDeleter> {
    deleter: T,
}

impl<T: UserDeleter> UnifiedUserDeleteOps<T> {
    pub fn new(deleter: T) -> Self {
        Self { deleter }
    }
    
    /// Delete a user using shared logic and database-specific execution
    pub async fn delete_user(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        // Validate ID using shared business logic
        UserDeleteProcessor::validate_user_id(id)?;
        
        // Execute database-specific deletion
        self.deleter.execute_user_delete(tenant_id, id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_user_id() {
        // Valid ID
        assert!(UserDeleteProcessor::validate_user_id("valid-id").is_ok());
        assert!(UserDeleteProcessor::validate_user_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
        
        // Invalid IDs
        assert!(UserDeleteProcessor::validate_user_id("").is_err());
        assert!(UserDeleteProcessor::validate_user_id("   ").is_err());
    }
}