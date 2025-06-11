use async_trait::async_trait;
use sqlx::SqlitePool;

use crate::error::{AppError, AppResult};
use super::super::user_delete::UserDeleter;

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
    async fn execute_user_delete(
        &self,
        tenant_id: u32,
        id: &str,
    ) -> AppResult<bool> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "DELETE FROM {} WHERE id = ?1",
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