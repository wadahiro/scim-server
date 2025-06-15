use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use super::super::user_delete::UserDeleter;
use crate::error::{AppError, AppResult};

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
        Uuid::parse_str(id).map_err(|_| AppError::BadRequest("Invalid UUID format".to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl UserDeleter for PostgresUserDeleter {
    async fn execute_user_delete(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        // Validate UUID format for PostgreSQL
        Self::validate_uuid_format(id)?;

        let users_table = format!("t{}_users", tenant_id);
        let memberships_table = format!("t{}_group_memberships", tenant_id);

        // Start a transaction to ensure atomic operation
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Database(format!("Failed to start transaction: {}", e)))?;

        // First, delete the user from group memberships
        let membership_sql = format!(
            "DELETE FROM {} WHERE member_id = $1::uuid AND member_type = 'User'",
            memberships_table
        );

        sqlx::query(&membership_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to delete user group memberships: {}", e))
            })?;

        // Then, delete the user from users table
        let user_sql = format!("DELETE FROM {} WHERE id = $1::uuid", users_table);

        let result = sqlx::query(&user_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete user: {}", e)))?;

        let user_was_deleted = result.rows_affected() > 0;

        // Commit the transaction
        tx.commit()
            .await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;

        Ok(user_was_deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_uuid_format() {
        // Valid UUIDs
        assert!(
            PostgresUserDeleter::validate_uuid_format("123e4567-e89b-12d3-a456-426614174000")
                .is_ok()
        );
        assert!(
            PostgresUserDeleter::validate_uuid_format("00000000-0000-0000-0000-000000000000")
                .is_ok()
        );

        // Invalid UUIDs
        assert!(PostgresUserDeleter::validate_uuid_format("invalid-uuid").is_err());
        assert!(PostgresUserDeleter::validate_uuid_format("123").is_err());
        assert!(PostgresUserDeleter::validate_uuid_format("").is_err());
    }
}
