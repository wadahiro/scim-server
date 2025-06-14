use async_trait::async_trait;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use std::time::Duration;

use super::super::config::DatabaseBackendConfig;
use crate::backend::database::{
    PostgresGroupDeleter, PostgresGroupInserter, PostgresGroupReader, PostgresGroupUpdater,
    PostgresUserDeleter, PostgresUserInserter, PostgresUserPatcher, PostgresUserReader,
    PostgresUserUpdater, UnifiedGroupDeleteOps, UnifiedGroupInsertOps, UnifiedGroupReadOps,
    UnifiedGroupUpdateOps, UnifiedUserDeleteOps, UnifiedUserInsertOps, UnifiedUserPatchOps,
    UnifiedUserReadOps, UnifiedUserUpdateOps,
};
use crate::backend::{Backend, GroupBackend, UserBackend};
use crate::error::{AppError, AppResult};
use crate::models::ScimPatchOp;
use crate::models::{Group, User};
use crate::parser::filter_operator::FilterOperator;
use crate::parser::SortSpec;

use super::filter_impl::PostgresFilterConverter;

/// PostgreSQL database backend implementation
///
/// This provides a complete SCIM 2.0 database backend using PostgreSQL
/// with support for JSONB columns, complex filtering, and tenant isolation.
pub struct PostgresBackend {
    pool: PgPool,
    filter_converter: PostgresFilterConverter,
    // New operations
    user_insert_ops: UnifiedUserInsertOps<PostgresUserInserter>,
    user_update_ops: UnifiedUserUpdateOps<PostgresUserUpdater>,
    user_delete_ops: UnifiedUserDeleteOps<PostgresUserDeleter>,
    user_patch_ops: UnifiedUserPatchOps<PostgresUserPatcher>,
    user_read_ops: UnifiedUserReadOps<PostgresUserReader>,
    group_insert_ops: UnifiedGroupInsertOps<PostgresGroupInserter>,
    group_update_ops: UnifiedGroupUpdateOps<PostgresGroupUpdater>,
    group_delete_ops: UnifiedGroupDeleteOps<PostgresGroupDeleter>,
    group_read_ops: UnifiedGroupReadOps<PostgresGroupReader>,
}

impl PostgresBackend {
    /// Create a new PostgreSQL backend instance
    pub fn new(pool: PgPool) -> Self {
        // Create database-specific adapters
        let user_inserter = PostgresUserInserter::new(pool.clone());
        let user_updater = PostgresUserUpdater::new(pool.clone());
        let user_deleter = PostgresUserDeleter::new(pool.clone());
        let user_patcher = PostgresUserPatcher::new(pool.clone());
        let user_reader = PostgresUserReader::new(pool.clone());
        let group_inserter = PostgresGroupInserter::new(pool.clone());
        let group_updater = PostgresGroupUpdater::new(pool.clone());
        let group_deleter = PostgresGroupDeleter::new(pool.clone());
        let group_reader = PostgresGroupReader::new(pool.clone());

        Self {
            pool,
            filter_converter: PostgresFilterConverter::new(),
            // Initialize unified operations
            user_insert_ops: UnifiedUserInsertOps::new(user_inserter),
            user_update_ops: UnifiedUserUpdateOps::new(user_updater),
            user_delete_ops: UnifiedUserDeleteOps::new(user_deleter),
            user_patch_ops: UnifiedUserPatchOps::new(user_patcher),
            user_read_ops: UnifiedUserReadOps::new(user_reader),
            group_insert_ops: UnifiedGroupInsertOps::new(group_inserter),
            group_update_ops: UnifiedGroupUpdateOps::new(group_updater),
            group_delete_ops: UnifiedGroupDeleteOps::new(group_deleter),
            group_read_ops: UnifiedGroupReadOps::new(group_reader),
        }
    }

    /// Get the connection pool reference
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Get the filter converter reference
    pub fn filter_converter(&self) -> &PostgresFilterConverter {
        &self.filter_converter
    }

    /// Generate table name for a resource type and tenant  
    /// Tables are named as: t{tenant_id}_{resource}
    pub fn table_name(&self, resource: &str, tenant_id: u32) -> String {
        format!("t{}_{}", tenant_id, resource)
    }

    /// Get users table name for a tenant
    pub fn users_table(&self, tenant_id: u32) -> String {
        self.table_name("users", tenant_id)
    }

    /// Get groups table name for a tenant
    pub fn groups_table(&self, tenant_id: u32) -> String {
        self.table_name("groups", tenant_id)
    }

    /// Get group memberships table name for a tenant
    pub fn memberships_table(&self, tenant_id: u32) -> String {
        self.table_name("group_memberships", tenant_id)
    }
}

#[async_trait]
impl Backend for PostgresBackend {
    async fn connect(config: &DatabaseBackendConfig) -> AppResult<Self> {
        // Validate configuration
        config
            .validate()
            .map_err(|e| AppError::Internal(format!("Invalid backend config: {}", e)))?;

        // Create connection pool
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .acquire_timeout(Duration::from_secs(config.connection_timeout))
            .connect(&config.connection_path)
            .await
            .map_err(|e| AppError::Database(format!("Failed to connect to PostgreSQL: {}", e)))?;

        Ok(Self::new(pool))
    }

    async fn health_check(&self) -> AppResult<()> {
        sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::Database(format!("Health check failed: {}", e)))?;

        Ok(())
    }

    async fn init_tenant(&self, tenant_id: u32) -> AppResult<()> {
        super::schema::init_tenant_schema(&self.pool, tenant_id).await
    }
}

#[async_trait]
impl UserBackend for PostgresBackend {
    async fn create_user(&self, tenant_id: u32, user: &User) -> AppResult<User> {
        self.user_insert_ops.create_user(tenant_id, user).await
    }

    async fn find_user_by_id(&self, tenant_id: u32, id: &str, include_groups: bool) -> AppResult<Option<User>> {
        self.user_read_ops.find_user_by_id(tenant_id, id, include_groups).await
    }

    async fn find_user_by_username(
        &self,
        tenant_id: u32,
        username: &str,
        include_groups: bool,
    ) -> AppResult<Option<User>> {
        self.user_read_ops
            .find_user_by_username(tenant_id, username, include_groups)
            .await
    }

    async fn find_all_users(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.user_read_ops
            .find_all_users(tenant_id, start_index, count, include_groups)
            .await
    }

    async fn find_all_users_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.user_read_ops
            .find_all_users_sorted(tenant_id, start_index, count, sort_spec, include_groups)
            .await
    }

    async fn find_users_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.user_read_ops
            .find_users_by_filter(tenant_id, filter, start_index, count, sort_spec, include_groups)
            .await
    }

    async fn update_user(&self, tenant_id: u32, id: &str, user: &User) -> AppResult<Option<User>> {
        // Perform the update using the unified operations
        match self
            .user_update_ops
            .update_user(tenant_id, id, user)
            .await?
        {
            Some(_) => {
                // After successful update, fetch the user with groups populated
                self.user_read_ops.find_user_by_id(tenant_id, id, true).await
            }
            None => Ok(None),
        }
    }

    async fn patch_user(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<User>> {
        // Perform the patch using the unified operations
        match self
            .user_patch_ops
            .patch_user(tenant_id, id, patch_ops)
            .await?
        {
            Some(_) => {
                // After successful patch, fetch the user with groups populated
                self.user_read_ops.find_user_by_id(tenant_id, id, true).await
            }
            None => Ok(None),
        }
    }

    async fn delete_user(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        self.user_delete_ops.delete_user(tenant_id, id).await
    }

    async fn find_users_by_group_id(&self, tenant_id: u32, group_id: &str, include_groups: bool) -> AppResult<Vec<User>> {
        self.user_read_ops
            .find_users_by_group_id(tenant_id, group_id, include_groups)
            .await
    }
}

#[async_trait]
impl GroupBackend for PostgresBackend {
    async fn create_group(&self, tenant_id: u32, group: &Group) -> AppResult<Group> {
        self.group_insert_ops.create_group(tenant_id, group).await
    }

    async fn find_group_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<Group>> {
        self.group_read_ops.find_group_by_id(tenant_id, id).await
    }

    async fn find_group_by_display_name(
        &self,
        tenant_id: u32,
        display_name: &str,
    ) -> AppResult<Option<Group>> {
        self.group_read_ops
            .find_group_by_display_name(tenant_id, display_name)
            .await
    }

    async fn find_all_groups(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.group_read_ops
            .find_all_groups(tenant_id, start_index, count)
            .await
    }

    async fn find_all_groups_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.group_read_ops
            .find_all_groups_sorted(tenant_id, start_index, count, sort_spec)
            .await
    }

    async fn find_groups_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.group_read_ops
            .find_groups_by_filter(tenant_id, filter, start_index, count, sort_spec)
            .await
    }

    async fn update_group(
        &self,
        tenant_id: u32,
        id: &str,
        group: &Group,
    ) -> AppResult<Option<Group>> {
        self.group_update_ops
            .update_group(tenant_id, id, group)
            .await
    }

    async fn patch_group(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<Group>> {
        // Perform the patch using the group read ops
        match self
            .group_read_ops
            .patch_group(tenant_id, id, patch_ops)
            .await?
        {
            Some(_) => {
                // After successful patch, fetch the group with members populated
                self.group_read_ops.find_group_by_id(tenant_id, id).await
            }
            None => Ok(None),
        }
    }

    async fn delete_group(&self, tenant_id: u32, id: &str) -> AppResult<bool> {
        self.group_delete_ops.delete_group(tenant_id, id).await
    }

    async fn find_groups_by_user_id(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<Group>> {
        self.group_read_ops
            .find_groups_by_user_id(tenant_id, user_id)
            .await
    }
}
