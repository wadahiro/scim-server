use async_trait::async_trait;
use serde_json::Value;
use sqlx::SqlitePool;

use super::super::group_insert::{GroupInserter, PreparedGroupData};
use super::super::group_read::GroupReader;
use super::group_read_impl::SqliteGroupReader;
use crate::error::{AppError, AppResult};
use crate::models::Group;

/// SQLite-specific implementation of GroupInserter
///
/// This handles SQLite's JSON TEXT storage while using shared SQL generation.
pub struct SqliteGroupInserter {
    pool: SqlitePool,
    group_reader: SqliteGroupReader,
}

impl SqliteGroupInserter {
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            group_reader: SqliteGroupReader::new(pool.clone()),
            pool,
        }
    }

    /// Convert JSON Value to String for SQLite TEXT storage
    fn json_value_to_string(&self, value: &Value) -> AppResult<String> {
        serde_json::to_string(value).map_err(AppError::Serialization)
    }

    /// Check for case-insensitive duplicate displayName
    async fn check_duplicate_display_name(
        &self,
        tenant_id: u32,
        display_name: &str,
    ) -> AppResult<()> {
        let table_name = format!("t{}_groups", tenant_id);
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE LOWER(display_name) = LOWER(?1)",
            table_name
        );

        let count: i64 = sqlx::query_scalar(&sql)
            .bind(display_name)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                AppError::Database(format!("Failed to check duplicate displayName: {}", e))
            })?;

        if count > 0 {
            return Err(AppError::BadRequest("Group already exists".to_string()));
        }

        Ok(())
    }
}

#[async_trait]
impl GroupInserter for SqliteGroupInserter {
    async fn execute_group_insert(
        &self,
        tenant_id: u32,
        data: PreparedGroupData,
    ) -> AppResult<Group> {
        // Check for case-insensitive duplicate displayName before insertion
        self.check_duplicate_display_name(tenant_id, &data.display_name)
            .await?;

        // Begin transaction for atomic group + membership insertion
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AppError::Database(format!("Failed to begin transaction: {}", e)))?;

        // Insert the group record
        let group_table = format!("t{}_groups", tenant_id);
        let group_sql = format!(
            "INSERT INTO {} (id, display_name, external_id, data_orig, data_norm, version, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            group_table
        );

        // SQLite: convert JSON to strings
        let data_orig_str = self.json_value_to_string(&data.data_orig)?;
        let data_norm_str = self.json_value_to_string(&data.data_norm)?;

        sqlx::query(&group_sql)
            .bind(&data.id)
            .bind(&data.display_name)
            .bind(&data.external_id)
            .bind(&data_orig_str) // SQLite: JSON as TEXT
            .bind(&data_norm_str)
            .bind(1i64) // version = 1 for new records
            .bind(data.timestamp)
            .bind(data.timestamp)
            .execute(&mut *tx)
            .await
            .map_err(|e| super::user_insert_impl::map_database_error(e, "Group"))?;

        // Insert group memberships if present
        if let Some(members) = &data.members {
            let membership_table = format!("t{}_group_memberships", tenant_id);
            let membership_sql = format!(
                "INSERT INTO {} (group_id, member_id, member_type) VALUES (?1, ?2, ?3)",
                membership_table
            );

            for member in members {
                if let Some(member_id) = &member.value {
                    let member_type = member.type_.as_deref().unwrap_or("User");

                    sqlx::query(&membership_sql)
                        .bind(&data.id)
                        .bind(member_id)
                        .bind(member_type)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| {
                            AppError::Database(format!("Failed to insert group member: {}", e))
                        })?;
                }
            }
        }

        // Commit transaction
        tx.commit()
            .await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;

        // Fetch the created group with properly populated members
        match self
            .group_reader
            .find_group_by_id(tenant_id, &data.group.base.id)
            .await?
        {
            Some(group) => Ok(group),
            None => Err(AppError::Database(
                "Failed to fetch created group".to_string(),
            )),
        }
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
        let inserter = SqliteGroupInserter::new(pool);

        let test_value = serde_json::json!({"test": "value"});
        let result = inserter.json_value_to_string(&test_value);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), r#"{"test":"value"}"#);
    }
}
