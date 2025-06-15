use async_trait::async_trait;
use sqlx::SqlitePool;

use super::super::user_delete::UserDeleter;
use crate::error::{AppError, AppResult};

/// SQLite-specific implementation of UserDeleter
///
/// This handles SQLite's TEXT-based IDs and SQL syntax.
pub struct SqliteUserDeleter {
    pool: SqlitePool,
}

impl SqliteUserDeleter {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserDeleter for SqliteUserDeleter {
    async fn execute_user_delete(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
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
            "DELETE FROM {} WHERE member_id = ?1 AND member_type = 'User'",
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
        let user_sql = format!("DELETE FROM {} WHERE id = ?1", users_table);

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

    async fn create_test_pool() -> SqlitePool {
        SqlitePool::connect(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_deleter_creation() {
        let pool = create_test_pool().await;
        let deleter = SqliteUserDeleter::new(pool);
        // Just verify the deleter can be created
        assert!(format!("{:?}", &deleter as *const _).len() > 0);
    }
}
