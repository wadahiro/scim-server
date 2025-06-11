use async_trait::async_trait;
use sqlx::{PgPool, Row};

use super::super::user_patch::{PreparedUserPatchData, UserPatcher};
use crate::error::{AppError, AppResult};
use crate::models::User;

/// PostgreSQL-specific implementation of UserPatcher
///
/// This handles PostgreSQL's UUID types and JSONB storage format
/// for user patch operations.
pub struct PostgresUserPatcher {
    pool: PgPool,
}

impl PostgresUserPatcher {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
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
            "SELECT COUNT(*) FROM {} WHERE LOWER(username) = LOWER($1) AND id != $2::uuid",
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
impl UserPatcher for PostgresUserPatcher {
    async fn execute_user_patch(
        &self,
        tenant_id: u32,
        id: &str,
        data: PreparedUserPatchData,
    ) -> AppResult<Option<User>> {
        // Validate UUID format for PostgreSQL
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(None);
        }

        // Check for case-insensitive duplicate username before patch
        self.check_duplicate_username(tenant_id, &data.username, &data.id)
            .await?;

        // Build table name
        let table_name = format!("t{}_users", tenant_id);

        // PostgreSQL UPDATE SQL with UUID casting and JSONB storage
        let sql = format!(
            "UPDATE {} SET username = $1, external_id = $2, data_orig = $3, data_norm = $4, updated_at = $5 WHERE id = $6::uuid",
            table_name
        );

        let result = sqlx::query(&sql)
            .bind(&data.username)
            .bind(&data.external_id)
            .bind(&data.data_orig) // PostgreSQL uses JSONB
            .bind(&data.data_norm) // PostgreSQL uses JSONB
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
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE id = $1::uuid",
            table_name
        );

        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find user for patch: {}", e)))?;

        match row {
            Some(row) => {
                let mut user: User = serde_json::from_value(row.get("data_orig"))
                    .map_err(|e| AppError::Serialization(e))?;

                // Ensure ID is set from database (in case data_orig doesn't have it)
                let db_id: uuid::Uuid = row.get("id");
                *user.id_mut() = Some(db_id.to_string());

                // Remove password from response
                *user.password_mut() = None;

                Ok(Some(user))
            }
            None => Ok(None),
        }
    }
}

/// Map PostgreSQL-specific database errors to appropriate application errors
pub fn map_database_error(e: sqlx::Error, resource_type: &str) -> AppError {
    match e {
        sqlx::Error::Database(db_err) => {
            let error_message = db_err.message();

            // Handle unique constraint violations
            if error_message.contains("duplicate key") {
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

    #[test]
    fn test_validate_uuid_format() {
        // Valid UUID
        assert!(uuid::Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000").is_ok());

        // Invalid UUID
        assert!(uuid::Uuid::parse_str("not-a-uuid").is_err());
        assert!(uuid::Uuid::parse_str("").is_err());
    }
}
