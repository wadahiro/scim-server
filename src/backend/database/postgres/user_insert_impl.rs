use async_trait::async_trait;
use sqlx::PgPool;

use super::super::user_insert::{PreparedUserData, UserInsertProcessor, UserInserter};
use crate::error::{AppError, AppResult};
use crate::models::User;

/// PostgreSQL-specific implementation of UserInserter
///
/// This handles PostgreSQL's JSONB data types while using shared SQL generation.
pub struct PostgresUserInserter {
    pool: PgPool,
}

impl PostgresUserInserter {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Check for case-insensitive duplicate username
    async fn check_duplicate_username(&self, tenant_id: u32, username: &str) -> AppResult<()> {
        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "SELECT COUNT(*) FROM {} WHERE LOWER(username) = LOWER($1)",
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
impl UserInserter for PostgresUserInserter {
    async fn execute_user_insert(&self, tenant_id: u32, data: PreparedUserData) -> AppResult<User> {
        // Check for case-insensitive duplicate username before insertion
        self.check_duplicate_username(tenant_id, &data.username)
            .await?;

        let table_name = format!("t{}_users", tenant_id);
        let sql = format!(
            "INSERT INTO {} (id, username, external_id, data_orig, data_norm, created_at, updated_at) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)",
            table_name
        );

        sqlx::query(&sql)
            .bind(&data.id)
            .bind(&data.username)
            .bind(&data.external_id)
            .bind(&data.data_orig) // PostgreSQL: direct JSONB binding
            .bind(&data.data_norm)
            .bind(&data.timestamp)
            .bind(&data.timestamp)
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
        } else {
            AppError::BadRequest("User already exists".to_string())
        }
    } else {
        AppError::Database(format!("Failed to create {}: {}", resource_type, error_str))
    }
}

#[cfg(test)]
mod tests {}
