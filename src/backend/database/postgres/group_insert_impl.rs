use async_trait::async_trait;
use sqlx::PgPool;

use super::super::group_insert::{GroupInserter, PreparedGroupData};
use super::super::group_read::GroupReader;
use super::group_read_impl::PostgresGroupReader;
use crate::error::{AppError, AppResult};
use crate::models::Group;

/// PostgreSQL-specific implementation of GroupInserter
///
/// This handles PostgreSQL's JSONB data types while using shared SQL generation.
pub struct PostgresGroupInserter {
    pool: PgPool,
    group_reader: PostgresGroupReader,
}

impl PostgresGroupInserter {
    pub fn new(pool: PgPool) -> Self {
        Self { 
            group_reader: PostgresGroupReader::new(pool.clone()),
            pool,
        }
    }

    /// Check for case-insensitive duplicate displayName
    async fn check_duplicate_display_name(
        &self,
        tenant_id: u32,
        display_name: &str,
    ) -> AppResult<()> {
        let table_name = format!("t{}_groups", tenant_id);
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE LOWER(display_name) = LOWER($1)",
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
impl GroupInserter for PostgresGroupInserter {
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
        let table_name = format!("t{}_groups", tenant_id);
        let group_sql = format!(
            "INSERT INTO {} (id, display_name, external_id, data_orig, data_norm, created_at, updated_at) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)",
            table_name
        );

        sqlx::query(&group_sql)
            .bind(&data.id)
            .bind(&data.display_name)
            .bind(&data.external_id)
            .bind(&data.data_orig) // PostgreSQL: direct JSONB binding
            .bind(&data.data_norm)
            .bind(&data.timestamp)
            .bind(&data.timestamp)
            .execute(&mut *tx)
            .await
            .map_err(|e| super::user_insert_impl::map_database_error(e, "Group"))?;

        // Insert group memberships if present
        if let Some(members) = &data.members {
            let membership_table = format!("t{}_group_memberships", tenant_id);
            let membership_sql = format!(
                "INSERT INTO {} (group_id, member_id, member_type) VALUES ($1::uuid, $2::uuid, $3)",
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
                            crate::error::AppError::Database(format!(
                                "Failed to insert group member: {}",
                                e
                            ))
                        })?;
                }
            }
        }

        // Commit transaction
        tx.commit().await.map_err(|e| {
            crate::error::AppError::Database(format!("Failed to commit transaction: {}", e))
        })?;

        // Fetch the created group with properly populated members
        match self.group_reader.find_group_by_id(tenant_id, &data.group.base.id).await? {
            Some(group) => Ok(group),
            None => Err(AppError::Database("Failed to fetch created group".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {}
