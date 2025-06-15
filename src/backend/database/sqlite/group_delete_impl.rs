use async_trait::async_trait;
use sqlx::SqlitePool;

use super::super::group_delete::GroupDeleter;
use crate::error::{AppError, AppResult};

/// SQLite-specific implementation of GroupDeleter
///
/// This handles SQLite's TEXT-based IDs and transactional group deletion
/// with cascading membership cleanup.
pub struct SqliteGroupDeleter {
    pool: SqlitePool,
}

impl SqliteGroupDeleter {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupDeleter for SqliteGroupDeleter {
    async fn execute_group_delete(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        // Begin transaction for atomic group + membership deletion
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Database(format!("Failed to begin transaction: {}", e)))?;

        // First, delete group memberships where this group is the parent
        let membership_table = format!("`t{}_group_memberships`", tenant_id);
        let parent_membership_sql = format!("DELETE FROM {} WHERE group_id = ?1", membership_table);

        sqlx::query(&parent_membership_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to delete group parent memberships: {}", e))
            })?;

        // Second, delete memberships where this group is a member of other groups
        let child_membership_sql = format!("DELETE FROM {} WHERE member_id = ?1 AND member_type = 'Group'", membership_table);

        sqlx::query(&child_membership_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to delete group child memberships: {}", e))
            })?;

        // Then, delete the group itself
        let group_table = format!("`t{}_groups`", tenant_id);
        let group_sql = format!("DELETE FROM {} WHERE id = ?1", group_table);

        let result = sqlx::query(&group_sql)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete group: {}", e)))?;

        let group_deleted = result.rows_affected() > 0;

        // Commit transaction
        tx.commit()
            .await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;

        Ok(group_deleted)
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
        let deleter = SqliteGroupDeleter::new(pool);
        // Just verify the deleter can be created
        assert!(format!("{:?}", &deleter as *const _).len() > 0);
    }
}
