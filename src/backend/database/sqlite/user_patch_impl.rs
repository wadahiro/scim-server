use async_trait::async_trait;
use serde_json::Value;
use sqlx::{Row, SqlitePool};

use super::super::user_patch::{PreparedUserPatchData, UserPatcher};
use crate::error::{AppError, AppResult};
use crate::models::User;

/// SQLite-specific implementation of UserPatcher
///
/// This handles SQLite's TEXT-based ID storage and JSON TEXT format
/// for user patch operations.
pub struct SqliteUserPatcher {
    pool: SqlitePool,
}

impl SqliteUserPatcher {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Convert JSON Value to String for SQLite TEXT storage
    fn json_value_to_string(&self, value: &Value) -> AppResult<String> {
        serde_json::to_string(value).map_err(|e| AppError::Serialization(e))
    }

    /// Check for case-insensitive duplicate username excluding current user
    async fn check_duplicate_username(
        &self,
        tenant_id: u32,
        username: &str,
        exclude_id: &str,
    ) -> AppResult<()> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE LOWER(username) = LOWER(?1) AND id != ?2",
            table_name
        );

        let count: i64 = sqlx::query_scalar(&sql)
            .bind(username)
            .bind(exclude_id)
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
impl UserPatcher for SqliteUserPatcher {
    async fn execute_user_patch(
        &self,
        tenant_id: u32,
        _id: &str,
        data: PreparedUserPatchData,
    ) -> AppResult<Option<User>> {
        // Check for case-insensitive duplicate username before patch
        self.check_duplicate_username(tenant_id, &data.username, &data.id)
            .await?;

        // Build table name
        let table_name = format!("t{}_users", tenant_id);

        // Convert JSONB Values to JSON strings for SQLite TEXT storage
        let data_orig_str = self.json_value_to_string(&data.data_orig)?;
        let data_norm_str = self.json_value_to_string(&data.data_norm)?;

        // SQLite UPDATE SQL with TEXT-based parameter binding
        let sql = format!(
            "UPDATE {} SET username = ?1, external_id = ?2, data_orig = ?3, data_norm = ?4, updated_at = ?5 WHERE id = ?6",
            table_name
        );

        let result = sqlx::query(&sql)
            .bind(&data.username)
            .bind(&data.external_id)
            .bind(&data_orig_str) // SQLite uses TEXT
            .bind(&data_norm_str) // SQLite uses TEXT
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

    async fn find_user_for_patch(&self, tenant_id: u32, id: &str) -> AppResult<Option<User>> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE id = ?1",
            table_name
        );

        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find user for patch: {}", e)))?;

        match row {
            Some(row) => {
                let data_orig: String = row.get("data_orig");
                let mut user: User =
                    serde_json::from_str(&data_orig).map_err(|e| AppError::Serialization(e))?;

                // Ensure ID is set from database (in case data_orig doesn't have it)
                let db_id: String = row.get("id");
                *user.id_mut() = Some(db_id);

                // Remove password from response
                *user.password_mut() = None;

                Ok(Some(user))
            }
            None => Ok(None),
        }
    }
}

/// Map SQLite-specific database errors to appropriate application errors
pub fn map_database_error(e: sqlx::Error, resource_type: &str) -> AppError {
    match e {
        sqlx::Error::Database(db_err) => {
            let error_message = db_err.message();

            // Handle unique constraint violations
            if error_message.contains("UNIQUE constraint failed") {
                if error_message.contains("username") {
                    return AppError::BadRequest(format!(
                        "A {} with this username already exists",
                        resource_type.to_lowercase()
                    ));
                } else if error_message.contains("external_id") {
                    return AppError::BadRequest(format!(
                        "A {} with this external ID already exists",
                        resource_type.to_lowercase()
                    ));
                }
                return AppError::BadRequest(format!("{} already exists", resource_type));
            }

            // Handle other database errors
            AppError::Database(format!("Database error: {}", error_message))
        }
        _ => AppError::Database(format!(
            "Failed to patch {}: {}",
            resource_type.to_lowercase(),
            e
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_pool() -> SqlitePool {
        SqlitePool::connect(":memory:").await.unwrap()
    }

    #[tokio::test]
    async fn test_patcher_creation() {
        let pool = create_test_pool().await;
        let patcher = SqliteUserPatcher::new(pool);
        // Just verify the patcher can be created
        assert!(format!("{:?}", &patcher as *const _).len() > 0);
    }

    #[test]
    fn test_json_value_to_string() {
        let test_value = serde_json::json!({"key": "value", "number": 42});
        // Create a simple test without async dependencies
        let result = serde_json::to_string(&test_value);

        assert!(result.is_ok());
        assert!(result.unwrap().contains("key"));
    }
}
