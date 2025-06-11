use async_trait::async_trait;
use sqlx::{SqlitePool, Row};
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::Group;
use super::super::group_update::{GroupUpdater, PreparedGroupUpdateData};

/// SQLite-specific implementation of GroupUpdater
/// 
/// This handles SQLite's TEXT-based ID storage, JSON TEXT format,
/// and transactional group membership management.
pub struct SqliteGroupUpdater {
    pool: SqlitePool,
}

impl SqliteGroupUpdater {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    
    /// Check for case-insensitive duplicate displayName excluding current group
    async fn check_duplicate_display_name(&self, tenant_id: u32, display_name: &str, exclude_id: &str) -> AppResult<()> {
        let table_name = format!("`t{}_groups`", tenant_id);
        let sql = format!("SELECT COUNT(*) FROM {} WHERE LOWER(display_name) = LOWER(?1) AND id != ?2", table_name);
        
        let count: i64 = sqlx::query_scalar(&sql)
            .bind(display_name)
            .bind(exclude_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to check duplicate displayName: {}", e)))?;
            
        if count > 0 {
            return Err(AppError::BadRequest("Group already exists".to_string()));
        }
        
        Ok(())
    }
    
    /// Helper function to fetch a group with its members
    async fn fetch_group_with_members(
        &self,
        tenant_id: u32,
        id: &str,
    ) -> AppResult<Option<Group>> {
        // Return None for empty IDs
        if id.is_empty() {
            return Ok(None);
        }
        
        let table_name = format!("`t{}_groups`", tenant_id);
        let sql = format!(
            "SELECT id, display_name, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE id = ?1",
            table_name
        );
        
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find group: {}", e)))?;
        
        match row {
            Some(row) => {
                let data_orig: String = row.get("data_orig");
                let mut group: Group = serde_json::from_str(&data_orig)
                    .map_err(|e| AppError::Serialization(e))?;
                
                // Fetch members
                let members = self.fetch_group_members(tenant_id, id).await?;
                *group.members_mut() = if members.is_empty() { None } else { Some(members) };
                
                Ok(Some(group))
            }
            None => Ok(None),
        }
    }
    
    /// Helper function to fetch group members
    async fn fetch_group_members(
        &self,
        tenant_id: u32,
        group_id: &str,
    ) -> AppResult<Vec<scim_v2::models::group::Member>> {
        let users_table = format!("`t{}_users`", tenant_id);
        let groups_table = format!("`t{}_groups`", tenant_id);
        let memberships_table = format!("`t{}_group_memberships`", tenant_id);
        
        let sql = format!(
            r#"
            SELECT 
                m.member_id,
                m.member_type,
                CASE 
                    WHEN m.member_type = 'User' THEN COALESCE(
                        json_extract(u.data_orig, '$.displayName'), 
                        json_extract(u.data_orig, '$.name.formatted'), 
                        (json_extract(u.data_orig, '$.name.givenName') || ' ' || json_extract(u.data_orig, '$.name.familyName'))
                    )
                    WHEN m.member_type = 'Group' THEN json_extract(g.data_orig, '$.displayName')
                END as display_name
            FROM {} m
            LEFT JOIN {} u ON m.member_id = u.id AND m.member_type = 'User'
            LEFT JOIN {} g ON m.member_id = g.id AND m.member_type = 'Group'
            WHERE m.group_id = ?1
            ORDER BY m.created_at
            "#,
            memberships_table, users_table, groups_table
        );
        
        let rows = sqlx::query(&sql)
            .bind(group_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch group members: {}", e)))?;
        
        let mut members = Vec::new();
        for row in rows {
            let member_id: String = row.get("member_id");
            let member_type: String = row.get("member_type");
            let display_name: Option<String> = row.get("display_name");
            
            // Construct the proper $ref path based on member type (base URL will be added later)
            let ref_path = match member_type.as_str() {
                "User" => format!("/{}/Users/{}", tenant_id, member_id),
                "Group" => format!("/{}/Groups/{}", tenant_id, member_id),
                _ => format!("/{}/Resources/{}", tenant_id, member_id),
            };
            
            members.push(scim_v2::models::group::Member {
                value: Some(member_id),
                ref_: Some(ref_path),
                display: display_name,
                type_: Some(member_type),
            });
        }
        
        Ok(members)
    }
}

#[async_trait]
impl GroupUpdater for SqliteGroupUpdater {
    async fn execute_group_update(
        &self,
        tenant_id: u32,
        _id: &str,
        data: PreparedGroupUpdateData,
    ) -> AppResult<Option<Group>> {
        // Check for case-insensitive duplicate displayName before update
        self.check_duplicate_display_name(tenant_id, &data.display_name, &data.id).await?;
        
        // Begin transaction for atomic group + membership update
        let mut tx = self.pool.begin().await
            .map_err(|e| AppError::Database(format!("Failed to begin transaction: {}", e)))?;
        
        // Build table names
        let groups_table = format!("`t{}_groups`", tenant_id);
        let memberships_table = format!("`t{}_group_memberships`", tenant_id);
        
        // Convert JSONB Values to JSON strings for SQLite TEXT storage
        let data_orig_str = json_value_to_string(&data.data_orig)?;
        let data_norm_str = json_value_to_string(&data.data_norm)?;
        
        // Update the group record
        let group_sql = format!(
            "UPDATE {} SET display_name = ?1, external_id = ?2, data_orig = ?3, data_norm = ?4, updated_at = ?5 WHERE id = ?6",
            groups_table
        );
        
        let result = sqlx::query(&group_sql)
            .bind(&data.display_name)
            .bind(&data.external_id)
            .bind(&data_orig_str)    // SQLite uses TEXT
            .bind(&data_norm_str)    // SQLite uses TEXT
            .bind(&data.timestamp)
            .bind(&data.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| super::user_update_impl::map_database_error(e, "Group"))?;
        
        if result.rows_affected() == 0 {
            // Group not found
            return Ok(None);
        }
        
        // Delete existing group memberships
        let delete_members_sql = format!(
            "DELETE FROM {} WHERE group_id = ?1",
            memberships_table
        );
        
        sqlx::query(&delete_members_sql)
            .bind(&data.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AppError::Database(format!("Failed to delete group memberships: {}", e)))?;
        
        // Insert new group memberships if present
        if let Some(members) = &data.members {
            let insert_member_sql = format!(
                "INSERT INTO {} (group_id, member_id, member_type) VALUES (?1, ?2, ?3)",
                memberships_table
            );
            
            for member in members {
                if let Some(member_id) = &member.value {
                    let member_type = member.type_.as_deref().unwrap_or("User");
                    
                    sqlx::query(&insert_member_sql)
                        .bind(&data.id)
                        .bind(member_id)
                        .bind(member_type)
                        .execute(&mut *tx)
                        .await
                        .map_err(|e| AppError::Database(format!("Failed to insert group member: {}", e)))?;
                }
            }
        }
        
        // Commit transaction
        tx.commit().await
            .map_err(|e| AppError::Database(format!("Failed to commit transaction: {}", e)))?;
        
        // Fetch the updated group with properly populated members
        self.fetch_group_with_members(tenant_id, &data.id).await
    }
}

/// Convert a JSON Value to a string for SQLite TEXT storage
/// 
/// This ensures consistent JSON serialization for SQLite databases.
fn json_value_to_string(value: &Value) -> AppResult<String> {
    serde_json::to_string(value)
        .map_err(|e| AppError::Serialization(e))
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
        let updater = SqliteGroupUpdater::new(pool);
        // Just verify the updater can be created
        assert!(format!("{:?}", &updater as *const _).len() > 0);
    }
    
    #[test]
    fn test_json_value_to_string() {
        let value = serde_json::json!({"displayName": "Test Group", "members": []});
        let result = json_value_to_string(&value).unwrap();
        assert!(result.contains("displayName"));
        assert!(result.contains("Test Group"));
    }
}