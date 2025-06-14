//! User read operations
//!
//! This module provides common interfaces for user read operations
//! that work across different database backends.

use crate::error::AppResult;
use crate::models::User;
use crate::parser::filter_operator::FilterOperator;
use crate::parser::SortSpec;
use async_trait::async_trait;

/// Trait for user read operations
#[async_trait]
pub trait UserReader: Send + Sync {
    /// Find a user by ID
    async fn find_user_by_id(&self, tenant_id: u32, id: &str, include_groups: bool) -> AppResult<Option<User>>;

    /// Find a user by username (case-insensitive)
    async fn find_user_by_username(
        &self,
        tenant_id: u32,
        username: &str,
        include_groups: bool,
    ) -> AppResult<Option<User>>;

    /// Find all users with pagination
    async fn find_all_users(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Find all users with sorting
    async fn find_all_users_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Find users by SCIM filter
    async fn find_users_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)>;

    /// Find users by group ID
    async fn find_users_by_group_id(&self, tenant_id: u32, group_id: &str, include_groups: bool) -> AppResult<Vec<User>>;
}

/// Unified user read operations
///
/// This struct provides a unified interface for user read operations
/// that can work with any database backend implementation.
pub struct UnifiedUserReadOps<T: UserReader> {
    reader: T,
}

impl<T: UserReader> UnifiedUserReadOps<T> {
    pub fn new(reader: T) -> Self {
        Self { reader }
    }

    /// Find a user by ID
    pub async fn find_user_by_id(&self, tenant_id: u32, id: &str, include_groups: bool) -> AppResult<Option<User>> {
        self.reader.find_user_by_id(tenant_id, id, include_groups).await
    }

    /// Find a user by username (case-insensitive)
    pub async fn find_user_by_username(
        &self,
        tenant_id: u32,
        username: &str,
        include_groups: bool,
    ) -> AppResult<Option<User>> {
        self.reader.find_user_by_username(tenant_id, username, include_groups).await
    }

    /// Find all users with pagination
    pub async fn find_all_users(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.reader
            .find_all_users(tenant_id, start_index, count, include_groups)
            .await
    }

    /// Find all users with sorting
    pub async fn find_all_users_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.reader
            .find_all_users_sorted(tenant_id, start_index, count, sort_spec, include_groups)
            .await
    }

    /// Find users by SCIM filter
    pub async fn find_users_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
        include_groups: bool,
    ) -> AppResult<(Vec<User>, i64)> {
        self.reader
            .find_users_by_filter(tenant_id, filter, start_index, count, sort_spec, include_groups)
            .await
    }

    /// Find users by group ID
    pub async fn find_users_by_group_id(
        &self,
        tenant_id: u32,
        group_id: &str,
        include_groups: bool,
    ) -> AppResult<Vec<User>> {
        self.reader
            .find_users_by_group_id(tenant_id, group_id, include_groups)
            .await
    }
}
