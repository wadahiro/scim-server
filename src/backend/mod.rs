use crate::error::AppResult;
use crate::models::ScimPatchOp;
use crate::models::{Group, User};
use crate::parser::filter_operator::FilterOperator;
use crate::parser::SortSpec;
use async_trait::async_trait;
use std::sync::Arc;

pub mod database;

/// Supported database backend types
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    PostgreSQL,
    SQLite,
}

/// Core backend abstraction for SCIM resources
///
/// This trait defines the fundamental backend operations that any backend
/// must implement to support SCIM 2.0 operations. Each backend implementation
/// (PostgreSQL, SQLite, Redis, etc.) implements this trait.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Connect and initialize the storage backend
    async fn connect(config: &crate::backend::database::DatabaseBackendConfig) -> AppResult<Self>
    where
        Self: Sized;

    /// Check if the storage backend is healthy and accessible
    async fn health_check(&self) -> AppResult<()>;

    /// Initialize tenant-specific schemas/tables if needed
    async fn init_tenant(&self, tenant_id: u32) -> AppResult<()>;

    /// Clean up resources when storage is no longer needed
    async fn cleanup(&self) -> AppResult<()> {
        Ok(())
    }
}

/// User-specific backend operations
///
/// Handles all SCIM User resource CRUD operations with tenant isolation,
/// filtering, sorting, and pagination support.
#[async_trait]
pub trait UserBackend: Backend {
    /// Create a new user in the specified tenant
    async fn create_user(&self, tenant_id: u32, user: &User) -> AppResult<User>;

    /// Find a user by ID within a tenant
    async fn find_user_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<User>>;

    /// Find a user by username (case-insensitive per SCIM 2.0)
    async fn find_user_by_username(
        &self,
        tenant_id: u32,
        username: &str,
    ) -> AppResult<Option<User>>;

    /// Find all users in a tenant with pagination
    async fn find_all_users(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Find all users with sorting support
    async fn find_all_users_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Find users by SCIM filter with pagination and sorting
    async fn find_users_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Update an existing user (full replacement)
    async fn update_user(&self, tenant_id: u32, id: &str, user: &User) -> AppResult<Option<User>>;

    /// Apply SCIM PATCH operations to a user
    async fn patch_user(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<User>>;

    /// Delete a user from the tenant
    async fn delete_user(&self, tenant_id: u32, id: &str) -> AppResult<bool>;

    /// Find users that are members of a specific group
    async fn find_users_by_group_id(&self, tenant_id: u32, group_id: &str) -> AppResult<Vec<User>>;
}

/// Group-specific backend operations
///
/// Handles all SCIM Group resource CRUD operations with member management,
/// tenant isolation, filtering, sorting, and pagination support.
#[async_trait]
pub trait GroupBackend: Backend {
    /// Create a new group in the specified tenant
    async fn create_group(&self, tenant_id: u32, group: &Group) -> AppResult<Group>;

    /// Find a group by ID within a tenant
    async fn find_group_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<Group>>;

    /// Find a group by display name (case-insensitive per SCIM 2.0)
    async fn find_group_by_display_name(
        &self,
        tenant_id: u32,
        display_name: &str,
    ) -> AppResult<Option<Group>>;

    /// Find all groups in a tenant with pagination
    async fn find_all_groups(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<Group>, i64)>;

    /// Find all groups with sorting support
    async fn find_all_groups_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)>;

    /// Find groups by SCIM filter with pagination and sorting
    async fn find_groups_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)>;

    /// Update an existing group (full replacement)
    async fn update_group(
        &self,
        tenant_id: u32,
        id: &str,
        group: &Group,
    ) -> AppResult<Option<Group>>;

    /// Apply SCIM PATCH operations to a group
    async fn patch_group(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<Group>>;

    /// Delete a group from the tenant
    async fn delete_group(&self, tenant_id: u32, id: &str) -> AppResult<bool>;

    /// Find groups that contain a specific user as a member
    async fn find_groups_by_user_id(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<Group>>;
}

/// Combined backend interface for both users and groups
///
/// This trait combines UserBackend and GroupBackend for backends that
/// handle both resource types in a unified manner.
pub trait ScimBackend: UserBackend + GroupBackend {}

/// Automatic implementation for any type that implements both traits
impl<T> ScimBackend for T where T: UserBackend + GroupBackend {}

/// Factory for creating backend instances
pub struct BackendFactory;

impl BackendFactory {
    /// Create a backend based on configuration
    pub async fn create(
        config: &crate::backend::database::DatabaseBackendConfig,
    ) -> AppResult<Arc<dyn ScimBackend>> {
        let backend = Self::create_backend(config).await?;
        Ok(Arc::from(backend))
    }

    /// Create a backend based on configuration (returns Box)
    pub async fn create_backend(
        config: &crate::backend::database::DatabaseBackendConfig,
    ) -> AppResult<Box<dyn ScimBackend>> {
        match config.database_type {
            DatabaseType::PostgreSQL => {
                let backend =
                    crate::backend::database::postgres::PostgresBackend::connect(config).await?;
                Ok(Box::new(backend))
            }
            DatabaseType::SQLite => {
                let backend =
                    crate::backend::database::sqlite::SqliteBackend::connect(config).await?;
                Ok(Box::new(backend))
            }
        }
    }
}
