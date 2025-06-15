use async_trait::async_trait;
use serde_json::Value;
use sqlx::SqlitePool;

use super::super::user_insert::{PreparedUserData, UserInsertProcessor, UserInserter};
use crate::error::{AppError, AppResult};
use crate::models::User;

/// SQLite-specific implementation of UserInserter
///
/// This handles SQLite's JSON TEXT storage while using shared SQL generation.
pub struct SqliteUserInserter {
    pool: SqlitePool,
}

impl SqliteUserInserter {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert JSON Value to String for SQLite TEXT storage
    fn json_value_to_string(&self, value: &Value) -> AppResult<String> {
        serde_json::to_string(value).map_err(AppError::Serialization)
    }

    /// Check for case-insensitive duplicate username
    async fn check_duplicate_username(&self, tenant_id: u32, username: &str) -> AppResult<()> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE LOWER(username) = LOWER(?1)",
            table_name
        );

        let count: i64 = sqlx::query_scalar(&sql)
            .bind(username)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to check duplicate username: {}", e))
            })?;

        if count > 0 {
            return Err(AppError::BadRequest("User already exists".to_string()));
        }

        Ok(())
    }
}

#[async_trait]
impl UserInserter for SqliteUserInserter {
    async fn execute_user_insert(&self, tenant_id: u32, data: PreparedUserData) -> AppResult<User> {
        // Check for case-insensitive duplicate username before insertion
        self.check_duplicate_username(tenant_id, &data.username)
            .await?;

        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "INSERT INTO {} (id, username, external_id, data_orig, data_norm, version, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            table_name
        );

        // SQLite: convert JSON to strings
        let data_orig_str = self.json_value_to_string(&data.data_orig)?;
        let data_norm_str = self.json_value_to_string(&data.data_norm)?;

        sqlx::query(&sql)
            .bind(&data.id)
            .bind(&data.username)
            .bind(&data.external_id)
            .bind(&data_orig_str) // SQLite: JSON as TEXT
            .bind(&data_norm_str)
            .bind(1i64) // version = 1 for new records
            .bind(data.timestamp)
            .bind(data.timestamp)
            .execute(&self.pool)
            .await
            .map_err(|e| map_database_error(e, "User"))?;

        Ok(UserInsertProcessor::finalize_user_response(data.user))
    }
}

/// Map database errors to AppError using common logic
pub fn map_database_error(error: sqlx::Error, resource_type: &str) -> AppError {
    let error_str = error.to_string();
    if error_str.contains("duplicate key") || error_str.contains("UNIQUE constraint") {
        if error_str.contains("username") {
            AppError::BadRequest("Username already exists".to_string())
        } else if error_str.contains("external_id") {
            AppError::BadRequest("External ID already exists".to_string())
        } else if error_str.contains("display_name") {
            AppError::BadRequest("Display name already exists".to_string())
        } else {
            AppError::BadRequest("User already exists".to_string())
        }
    } else {
        AppError::Database(format!("Failed to create {}: {}", resource_type, error_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_pool() -> SqlitePool {
        SqlitePool::connect(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_json_value_to_string() {
        let pool = create_test_pool().await;
        let inserter = SqliteUserInserter::new(pool);

        let test_value = serde_json::json!({"test": "value"});
        let result = inserter.json_value_to_string(&test_value);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"test":"value"}"#);
    }
}
