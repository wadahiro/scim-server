use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use scim_v2::models::group::Member;
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::{Group, ScimPatchOp};
use crate::parser::patch_parser::ScimPath;
use crate::parser::{SortSpec, SortOrder};
use crate::parser::filter_operator::FilterOperator;
use crate::parser::ResourceType;
use super::super::group_read::GroupReader;
use crate::backend::database::filter::FilterConverter;
use super::super::group_update::UnifiedGroupUpdateOps;
use super::PostgresGroupUpdater;

/// PostgreSQL-specific implementation of GroupReader
pub struct PostgresGroupReader {
    pool: PgPool,
}

impl PostgresGroupReader {
    pub fn new(pool: PgPool) -> Self {
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
    
    /// Convert SCIM attribute to PostgreSQL column or JSON path for sorting
    fn get_sort_column(&self, sort_spec: &SortSpec) -> String {
        match sort_spec.attribute.as_str() {
            // Special attributes stored in dedicated columns
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
                format!("LOWER(data_orig->>'{}'))", json_path)
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
        
        // Check if it's a valid UUID format first - if not, return None instead of database error
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(None);
        }
        
        let table_name = self.groups_table(tenant_id);
        let sql = format!(
            "SELECT id, display_name, external_id, data_orig, data_norm, created_at, updated_at FROM {} WHERE id = $1::uuid",
            table_name
        );
        
        let row = sqlx::query(&sql)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find group: {}", e)))?;
        
        match row {
            Some(row) => {
                let mut group: Group = serde_json::from_value(row.get("data_orig"))
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
    ) -> AppResult<Vec<Member>> {
        let users_table = self.users_table(tenant_id);
        let groups_table = self.groups_table(tenant_id);
        let memberships_table = self.memberships_table(tenant_id);
        
        let sql = format!(
            r#"
            SELECT 
                m.member_id,
                m.member_type,
                CASE 
                    WHEN m.member_type = 'User' THEN COALESCE(u.data_orig->>'displayName', u.data_orig->'name'->>'formatted', CONCAT(u.data_orig->'name'->>'givenName', ' ', u.data_orig->'name'->>'familyName'))
                    WHEN m.member_type = 'Group' THEN g.data_orig->>'displayName'
                END as display_name
            FROM {} m
            LEFT JOIN {} u ON m.member_id = u.id AND m.member_type = 'User'
            LEFT JOIN {} g ON m.member_id = g.id AND m.member_type = 'Group'
            WHERE m.group_id = $1::uuid
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
            let member_id: Uuid = row.get("member_id");
            let member_id_string = member_id.to_string();
            let member_type: String = row.get("member_type");
            let display_name: Option<String> = row.get("display_name");
            
            // Construct the proper $ref path based on member type (base URL will be added later)
            let ref_path = match member_type.as_str() {
                "User" => format!("/{}/Users/{}", tenant_id, member_id_string),
                "Group" => format!("/{}/Groups/{}", tenant_id, member_id_string),
                _ => format!("/{}/Resources/{}", tenant_id, member_id_string),
            };
            
            members.push(Member {
                value: Some(member_id_string),
                ref_: Some(ref_path),
                display: display_name,
                type_: Some(member_type),
            });
        }
        
        Ok(members)
    }
    
    /// Create a filter converter for this tenant
    fn filter_converter(&self) -> crate::backend::database::postgres::filter_impl::PostgresFilterConverter {
        crate::backend::database::postgres::filter_impl::PostgresFilterConverter::new()
    }
}

#[async_trait]
impl GroupReader for PostgresGroupReader {
    async fn find_group_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<Group>> {
        self.fetch_group_with_members(tenant_id, id).await
    }
    
    async fn find_group_by_display_name(&self, tenant_id: u32, display_name: &str) -> AppResult<Option<Group>> {
        let table_name = self.groups_table(tenant_id);
        let sql = format!(
            "SELECT id FROM {} WHERE LOWER(display_name) = LOWER($1)",
            table_name
        );
        
        let row = sqlx::query(&sql)
            .bind(display_name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find group by display name: {}", e)))?;
        
        match row {
            Some(row) => {
                let id: Uuid = row.get("id");
                let id_string = id.to_string();
                self.fetch_group_with_members(tenant_id, &id_string).await
            }
            None => Ok(None),
        }
    }
    
    async fn find_all_groups(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<Group>, i64)> {
        let table_name = self.groups_table(tenant_id);
        
        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM {}", table_name);
        let total: (i64,) = sqlx::query_as(&count_sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count groups: {}", e)))?;
        
        // Get groups with pagination
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000); // Max 1000 per page
        
        let sql = format!(
            "SELECT id FROM {} ORDER BY created_at LIMIT $1 OFFSET $2",
            table_name
        );
        
        let rows = sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch groups: {}", e)))?;
        
        let mut groups = Vec::new();
        for row in rows {
            let id: Uuid = row.get("id");
            let id_string = id.to_string();
            if let Some(group) = self.fetch_group_with_members(tenant_id, &id_string).await? {
                groups.push(group);
            }
        }
        
        Ok((groups, total.0))
    }
    
    async fn find_all_groups_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        if sort_spec.is_none() {
            return self.find_all_groups(tenant_id, start_index, count).await;
        }
        
        let table_name = self.groups_table(tenant_id);
        
        // Get total count
        let count_sql = format!("SELECT COUNT(*) FROM {}", table_name);
        let total: (i64,) = sqlx::query_as(&count_sql)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to count groups: {}", e)))?;
        
        // Get groups with pagination and sorting
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000); // Max 1000 per page
        
        let order_by = self.build_order_by(sort_spec);
        let sql = format!(
            "SELECT id FROM {}{} LIMIT $1 OFFSET $2",
            table_name, order_by
        );
        
        let rows = sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to fetch sorted groups: {}", e)))?;
        
        let mut groups = Vec::new();
        for row in rows {
            let id: Uuid = row.get("id");
            let id_string = id.to_string();
            if let Some(group) = self.fetch_group_with_members(tenant_id, &id_string).await? {
                groups.push(group);
            }
        }
        
        Ok((groups, total.0))
    }
    
    async fn find_groups_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        let table_name = self.groups_table(tenant_id);
        
        // Convert filter to SQL
        let (where_clause, params) = self
            .filter_converter()
            .to_where_clause(filter, ResourceType::Group)?;
        
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
            .map_err(|e| AppError::Database(format!("Failed to count filtered groups: {}", e)))?
            .0;
        
        // Get groups with filter and pagination
        let offset = start_index.unwrap_or(1).saturating_sub(1).max(0);
        let limit = count.unwrap_or(100).min(1000);
        
        let order_by = self.build_order_by(sort_spec);
        let sql = format!(
            "SELECT id FROM {} WHERE ({}){} LIMIT ${} OFFSET ${}",
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
            .map_err(|e| AppError::Database(format!("Failed to fetch filtered groups: {}", e)))?;
        
        let mut groups = Vec::new();
        for row in rows {
            let id: Uuid = row.get("id");
            let id_string = id.to_string();
            if let Some(group) = self.fetch_group_with_members(tenant_id, &id_string).await? {
                groups.push(group);
            }
        }
        
        Ok((groups, total))
    }
    
    async fn find_groups_by_user_id(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<Group>> {
        // Return empty for invalid UUIDs like "default_id"
        if user_id.is_empty() || user_id == "default_id" || uuid::Uuid::parse_str(user_id).is_err() {
            return Ok(Vec::new());
        }
        let groups_table = self.groups_table(tenant_id);
        let memberships_table = self.memberships_table(tenant_id);
        
        let sql = format!(
            r#"
            SELECT g.id
            FROM {} g
            INNER JOIN {} m ON g.id = m.group_id
            WHERE m.member_id = $1::uuid AND m.member_type = 'User'
            ORDER BY g.created_at
            "#,
            groups_table, memberships_table
        );
        
        let rows = sqlx::query(&sql)
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to find groups by user: {}", e)))?;
        
        let mut groups = Vec::new();
        for row in rows {
            let id: Uuid = row.get("id");
            let id_string = id.to_string();
            if let Some(group) = self.fetch_group_with_members(tenant_id, &id_string).await? {
                groups.push(group);
            }
        }
        
        Ok(groups)
    }
    
    async fn patch_group(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<Group>> {
        // Return None for empty IDs
        if id.is_empty() {
            return Ok(None);
        }
        
        // Check if it's a valid UUID format first
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(None);
        }
        
        // First, find the existing group
        let mut group = match self.find_group_by_id(tenant_id, id).await? {
            Some(group) => group,
            None => return Ok(None),
        };
        
        // Apply patch operations
        for operation in &patch_ops.operations {
            let scim_path = ScimPath::parse(&operation.path.clone().unwrap_or_default())?;
            
            // Convert group to JSON for patch operations
            let mut group_json = serde_json::to_value(&group)
                .map_err(|e| AppError::Serialization(e))?;
            
            // Apply the operation
            scim_path.apply_operation(&mut group_json, &operation.op, &operation.value.as_ref().unwrap_or(&Value::Null).clone())?;
            
            // Convert back to Group
            group = serde_json::from_value(group_json)
                .map_err(|e| AppError::Serialization(e))?;
        }
        
        // Use the new update system to save the patched group
        let group_updater = PostgresGroupUpdater::new(self.pool.clone());
        let update_ops = UnifiedGroupUpdateOps::new(group_updater);
        update_ops.update_group(tenant_id, id, &group).await
    }
}