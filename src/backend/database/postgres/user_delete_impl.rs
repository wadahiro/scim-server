use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use super::super::user_delete::UserDeleter;

/// PostgreSQL-specific implementation of UserDeleter
/// 
/// This handles PostgreSQL's UUID data types and specific SQL syntax.
pub struct PostgresUserDeleter {
    pool: PgPool,
}

impl PostgresUserDeleter {
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
impl UserDeleter for PostgresUserDeleter {
    async fn execute_user_delete(
        &self,
        tenant_id: u32,
        id: &str,
    ) -> AppResult<bool> {
        // Validate UUID format for PostgreSQL
        Self::validate_uuid_format(id)?;
        
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "DELETE FROM {} WHERE id = $1::uuid",
            table_name
        );
        
        let result = sqlx::query(&sql)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete user: {}", e)))?;
            
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_validate_uuid_format() {
        // Valid UUIDs
        assert!(PostgresUserDeleter::validate_uuid_format("123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(PostgresUserDeleter::validate_uuid_format("00000000-0000-0000-0000-000000000000").is_ok());
        
        // Invalid UUIDs
        assert!(PostgresUserDeleter::validate_uuid_format("invalid-uuid").is_err());
        assert!(PostgresUserDeleter::validate_uuid_format("123").is_err());
        assert!(PostgresUserDeleter::validate_uuid_format("").is_err());
    }
}