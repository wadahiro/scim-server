use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use super::super::group_delete::GroupDeleter;

/// PostgreSQL-specific implementation of GroupDeleter
/// 
/// This handles PostgreSQL's UUID data types and transactional group deletion
/// with cascading membership cleanup.
pub struct PostgresGroupDeleter {
    pool: PgPool,
}

impl PostgresGroupDeleter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
    
    /// Validate UUID format for PostgreSQL
    fn validate_uuid_format(id: &str) -> AppResult<()> {
        Uuid::parse_str(id)
            .map_err(|_| AppError::BadRequest("Invalid UUID format".to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl GroupDeleter for PostgresGroupDeleter {
    async fn execute_group_delete(
        &self,
        tenant_id: u32,
        id: &str,
    ) -> AppResult<bool> {
        // Validate UUID format for PostgreSQL
        Self::validate_uuid_format(id)?;
        
        // Begin transaction for atomic group + membership deletion
        let mut tx = self.pool.begin().await
            .map_err(|e| AppError::Database(format!("Failed to begin transaction: {}", e)))?;
        
        // First, delete group memberships
        let membership_table = format!("t{}_group_memberships", tenant_id);
        let membership_sql = format!(
            "DELETE FROM {} WHERE group_id = $1::uuid",
            membership_table
        );
        
        sqlx::query(&membership_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete group memberships: {}", e)))?;
        
        // Then, delete the group itself
        let group_table = format!("t{}_groups", tenant_id);
        let group_sql = format!(
            "DELETE FROM {} WHERE id = $1::uuid",
            group_table
        );
        
        let result = sqlx::query(&group_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete group: {}", e)))?;
        
        let group_deleted = result.rows_affected() > 0;
        
        // Commit transaction
        tx.commit().await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;
            
        Ok(group_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_uuid_format() {
        // Valid UUIDs
        assert!(PostgresGroupDeleter::validate_uuid_format("123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(PostgresGroupDeleter::validate_uuid_format("00000000-0000-0000-0000-000000000000").is_ok());
        
        // Invalid UUIDs
        assert!(PostgresGroupDeleter::validate_uuid_format("invalid-uuid").is_err());
        assert!(PostgresGroupDeleter::validate_uuid_format("123").is_err());
        assert!(PostgresGroupDeleter::validate_uuid_format("").is_err());
    }
}