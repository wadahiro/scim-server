use async_trait::async_trait;
use sqlx::SqlitePool;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::User;
use super::super::user_update::{UserUpdater, PreparedUserUpdateData};

/// SQLite-specific implementation of UserUpdater
/// 
/// This handles SQLite's TEXT-based ID storage and JSON TEXT format
/// for user update operations.
pub struct SqliteUserUpdater {
    pool: SqlitePool,
}

impl SqliteUserUpdater {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    
    /// Check for case-insensitive duplicate username excluding current user
    async fn check_duplicate_username(&self, tenant_id: u32, username: &str, exclude_id: &str) -> AppResult<()> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!("SELECT COUNT(*) FROM {} WHERE LOWER(username) = LOWER(?1) AND id != ?2", table_name);
        
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(username)
            .bind(exclude_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to check duplicate username: {}", e)))?;
            
        if count > 0 {
            return Err(AppError::BadRequest("User already exists".to_string()));
        }
        
        Ok(())
    }
}

#[async_trait]
impl UserUpdater for SqliteUserUpdater {
    async fn execute_user_update(
        &self,
        tenant_id: u32,
        _id: &str,
        data: PreparedUserUpdateData,
    ) -> AppResult<Option<User>> {
        // Check for case-insensitive duplicate username before update
        self.check_duplicate_username(tenant_id, &data.username, &data.id).await?;
        
        // Build table name
        let table_name = format!("t{}_users", tenant_id);
        
        // Convert JSONB Values to JSON strings for SQLite TEXT storage
        let data_orig_str = json_value_to_string(&data.data_orig)?;
        let data_norm_str = json_value_to_string(&data.data_norm)?;
        
        // SQLite UPDATE SQL with TEXT-based parameter binding
        let sql = format!(
            "UPDATE {} SET username = ?1, external_id = ?2, data_orig = ?3, data_norm = ?4, updated_at = ?5 WHERE id = ?6",
            table_name
        );
        
        let result = sqlx::query(&sql)
            .bind(&data.username)
            .bind(&data.external_id)
            .bind(&data_orig_str)    // SQLite uses TEXT
            .bind(&data_norm_str)    // SQLite uses TEXT
            .bind(&data.timestamp)
            .bind(&data.id)
            .execute(&self.pool)
            .await
            .map_err(|e| map_database_error(e, "User"))?;
        
        if result.rows_affected() > 0 {
            Ok(Some(data.user))
        } else {
            Ok(None)
        }
    }
}

/// Convert a JSON Value to a string for SQLite TEXT storage
/// 
/// This ensures consistent JSON serialization for SQLite databases.
fn json_value_to_string(value: &Value) -> AppResult<String> {
    serde_json::to_string(value)
        .map_err(|e| AppError::Serialization(e))
}

/// Map SQLite-specific database errors to appropriate application errors
pub fn map_database_error(e: sqlx::Error, resource_type: &str) -> AppError {
    match e {
        sqlx::Error::Database(db_err) => {
            let error_message = db_err.message();
            
            // Handle unique constraint violations  
            if error_message.contains("UNIQUE constraint failed") {
                if error_message.contains("username") {
                    return AppError::BadRequest(format!("A {} with this username already exists", resource_type.to_lowercase()));
                } else if error_message.contains("external_id") {
                    return AppError::BadRequest(format!("A {} with this external ID already exists", resource_type.to_lowercase()));
                }
                return AppError::BadRequest(format!("{} already exists", resource_type));
            }
            
            // Handle other database errors
            AppError::Database(format!("Database error: {}", error_message))
        }
        _ => AppError::Database(format!("Failed to update {}: {}", resource_type.to_lowercase(), e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    async fn create_test_pool() -> SqlitePool {
        SqlitePool::connect(":memory:").await.unwrap()
    }
    
    #[tokio::test]
    async fn test_updater_creation() {
        let pool = create_test_pool().await;
        let updater = SqliteUserUpdater::new(pool);
        // Just verify the updater can be created
        assert!(format!("{:?}", &updater as *const _).len() > 0);
    }
    
    #[test]
    fn test_json_value_to_string() {
        let value = serde_json::json!({"key": "value", "number": 42});
        let result = json_value_to_string(&value).unwrap();
        assert!(result.contains("key"));
        assert!(result.contains("value"));
        assert!(result.contains("42"));
    }
}