use async_trait::async_trait;
use scim_v2::models::user::Group as UserGroup;
use sqlx::{Row, SqlitePool};

use super::super::user_read::UserReader;
use crate::backend::database::filter::FilterConverter;
use crate::error::{AppError, AppResult};
use crate::models::User;
use crate::parser::filter_operator::FilterOperator;
use crate::parser::ResourceType;
use crate::parser::{SortOrder, SortSpec};

/// SQLite-specific implementation of UserReader
pub struct SqliteUserReader {
    pool: SqlitePool,
}

impl SqliteUserReader {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// Generate table name for a resource type and tenant
    fn table_name(&self, resource: &str, tenant_id: u32) -> String {
        format!("t{}_{}", tenant_id, resource)
    }

    /// Get users table name for a tenant
    fn users_table(&self, tenant_id: u32) -> String {
        self.table_name("users", tenant_id)
    }

    /// Get groups table name for a tenant
    fn groups_table(&self, tenant_id: u32) -> String {
        self.table_name("groups", tenant_id)
    }

    /// Get group memberships table name for a tenant
    fn memberships_table(&self, tenant_id: u32) -> String {
        self.table_name("group_memberships", tenant_id)
    }

    /// Convert SCIM attribute to SQLite column or JSON path for sorting
    fn get_sort_column(&self, sort_spec: &SortSpec) -> String {
        match sort_spec.attribute.as_str() {
            // Special attributes stored in dedicated columns
            "userName" => "LOWER(username)".to_string(),
            "displayName" => "LOWER(display_name)".to_string(),
            "id" => "id".to_string(),
            "externalId" => "external_id".to_string(),
            "meta.created" => "created_at".to_string(),
            "meta.lastModified" => "updated_at".to_string(),
            // JSON attributes - use case-insensitive sorting
            _ => {
                // Normalize attribute name to lowercase for JSON path
                let normalized_attr = sort_spec.attribute.to_lowercase();
                let json_path = normalized_attr.replace('.', ".");
                format!("LOWER(json_extract(data_orig, '$.{}'))", json_path)
            }
        }
    }

    /// Build ORDER BY clause from SortSpec
    fn build_order_by(&self, sort_spec: Option<&SortSpec>) -> String {
        match sort_spec {
            Some(spec) => {
                let column = self.get_sort_column(spec);
                let direction = match spec.order {
                    SortOrder::Ascending => "ASC",
                    SortOrder::Descending => "DESC",
                };
                format!(" ORDER BY {} {}", column, direction)
            }
            None => " ORDER BY created_at".to_string(), // Default sort
        }
    }

    /// Helper function to fetch a user with their groups
    async fn fetch_user_with_groups(&self, tenant_id: u32, id: &str) -> AppResult<Option<User>> {
        let table_name = self.users_table(tenant_id);
        let sql = format!(
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE id = ?1",
            table_name
        );

        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find user: {}", e)))?;

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

                // Fetch groups and always set them (compatibility settings will handle empty array display)
                let groups = self.fetch_user_groups(tenant_id, id).await?;
                *user.groups_mut() = Some(groups);

                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    /// Helper function to fetch groups that a user belongs to
    async fn fetch_user_groups(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<UserGroup>> {
        let groups_table = self.groups_table(tenant_id);
        let memberships_table = self.memberships_table(tenant_id);

        let sql = format!(
            r#"
            SELECT 
                g.id,
                json_extract(g.data_orig, '$.displayName') as display_name
            FROM {} g
            INNER JOIN {} m ON g.id = m.group_id
            WHERE m.member_id = ?1 AND m.member_type = 'User'
            ORDER BY g.created_at
            "#,
            groups_table, memberships_table
        );

        let rows = sqlx::query(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch user groups: {}", e)))?;

        let mut groups = Vec::new();
        for row in rows {
            let group_id: String = row.get("id");
            let display_name: Option<String> = row.get("display_name");

            // TODO: We should get the base URL from configuration/context
            // For now, we'll use a format that works with the test expectations
            // In production, this should come from the request context or configuration
            // Generate relative URL that will be fixed by the resource handler
            let ref_url = format!("/{}/Groups/{}", tenant_id, group_id);

            groups.push(UserGroup {
                value: Some(group_id),
                ref_: Some(ref_url),
                display: display_name,
                type_: Some("direct".to_string()),
            });
        }

        Ok(groups)
    }

    /// Create a filter converter for this tenant
    fn filter_converter(
        &self,
    ) -> crate::backend::database::sqlite::filter_impl::SqliteFilterConverter {
        crate::backend::database::sqlite::filter_impl::SqliteFilterConverter::new()
    }
}

#[async_trait]
impl UserReader for SqliteUserReader {
    async fn find_user_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<User>> {
        self.fetch_user_with_groups(tenant_id, id).await
    }

    async fn find_user_by_username(
        &self,
        tenant_id: u32,
        username: &str,
    ) -> AppResult<Option<User>> {
        let table_name = self.users_table(tenant_id);
        let sql = format!(
            "SELECT id FROM {} WHERE LOWER(username) = LOWER(?1)",
            table_name
        );

        let row = sqlx::query(&sql)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find user by username: {}", e)))?;

        match row {
            Some(row) => {
                let id: String = row.get("id");
                self.fetch_user_with_groups(tenant_id, &id).await
            }
            None => Ok(None),
        }
    }

    async fn find_all_users(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<User>, i64)> {
        let table_name = self.users_table(tenant_id);

        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM {}", table_name);
        let total: (i64,) = sqlx::query_as(&count_sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count users: {}", e)))?;

        // Get users with pagination
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000); // Max 1000 per page

        let sql = format!(
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {} ORDER BY created_at LIMIT ?1 OFFSET ?2",
            table_name
        );

        let rows = sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch users: {}", e)))?;

        let mut users = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            if let Some(user) = self.fetch_user_with_groups(tenant_id, &id).await? {
                users.push(user);
            }
        }

        Ok((users, total.0))
    }

    async fn find_all_users_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<User>, i64)> {
        if sort_spec.is_none() {
            return self.find_all_users(tenant_id, start_index, count).await;
        }

        let table_name = self.users_table(tenant_id);

        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM {}", table_name);
        let total: (i64,) = sqlx::query_as(&count_sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count users: {}", e)))?;

        // Get users with pagination and sorting
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000); // Max 1000 per page

        let order_by = self.build_order_by(sort_spec);
        let sql = format!(
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {}{} LIMIT ?1 OFFSET ?2",
            table_name, order_by
        );

        let rows = sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch sorted users: {}", e)))?;

        let mut users = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            if let Some(user) = self.fetch_user_with_groups(tenant_id, &id).await? {
                users.push(user);
            }
        }

        Ok((users, total.0))
    }

    async fn find_users_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<User>, i64)> {
        let table_name = self.users_table(tenant_id);

        // Convert filter to SQL
        let (where_clause, params) = self
            .filter_converter()
            .to_where_clause(filter, ResourceType::User)?;

        // Get total count with filter
        let count_sql = format!(
            "SELECT COUNT(*) FROM {} WHERE ({})",
            table_name, where_clause
        );

        let mut count_query = sqlx::query_as::<_, (i64,)>(&count_sql);
        for param in &params {
            count_query = count_query.bind(param);
        }

        let total = count_query
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count filtered users: {}", e)))?
            .0;

        // Get users with filter and pagination
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000);

        let order_by = self.build_order_by(sort_spec);
        let sql = format!(
            "SELECT id, username, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE ({}){} LIMIT ?{} OFFSET ?{}",
            table_name, where_clause, order_by, params.len() + 1, params.len() + 2
        );

        let mut query = sqlx::query(&sql);
        for param in &params {
            query = query.bind(param);
        }
        query = query.bind(limit).bind(offset);

        let rows = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch filtered users: {}", e)))?;

        let mut users = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            if let Some(user) = self.fetch_user_with_groups(tenant_id, &id).await? {
                users.push(user);
            }
        }

        Ok((users, total))
    }

    async fn find_users_by_group_id(&self, tenant_id: u32, group_id: &str) -> AppResult<Vec<User>> {
        let users_table = self.users_table(tenant_id);
        let memberships_table = self.memberships_table(tenant_id);

        let sql = format!(
            r#"
            SELECT u.id, u.username, u.external_id, u.data_orig, u.data_norm, u.created_at, u.updated_at
            FROM {} u
            INNER JOIN {} m ON u.id = m.member_id
            WHERE m.group_id = ?1 AND m.member_type = 'User'
            ORDER BY u.created_at
            "#,
            users_table, memberships_table
        );

        let rows = sqlx::query(&sql)
            .bind(group_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find users by group: {}", e)))?;

        let mut users = Vec::new();
        for row in rows {
            let id: String = row.get("id");
            if let Some(user) = self.fetch_user_with_groups(tenant_id, &id).await? {
                users.push(user);
            }
        }

        Ok(users)
    }
}
