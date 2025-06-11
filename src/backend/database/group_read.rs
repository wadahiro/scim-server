//! Group read operations
//! 
//! This module provides common interfaces for group read operations
//! that work across different database backends.

use async_trait::async_trait;
use crate::error::AppResult;
use crate::models::{Group, ScimPatchOp};
use crate::parser::SortSpec;
use crate::parser::filter_operator::FilterOperator;

/// Trait for group read operations
#[async_trait]
pub trait GroupReader: Send + Sync {
    /// Find a group by ID
    async fn find_group_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<Group>>;
    
    /// Find a group by display name (case-insensitive)
    async fn find_group_by_display_name(&self, tenant_id: u32, display_name: &str) -> AppResult<Option<Group>>;
    
    /// Find all groups with pagination
    async fn find_all_groups(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<Group>, i64)>;
    
    /// Find all groups with sorting
    async fn find_all_groups_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)>;
    
    /// Find groups by SCIM filter
    async fn find_groups_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)>;
    
    /// Find groups by user ID
    async fn find_groups_by_user_id(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<Group>>;
    
    /// Apply SCIM PATCH operations to a group (needs read for validation)
    async fn patch_group(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<Group>>;
}

/// Unified group read operations
/// 
/// This struct provides a unified interface for group read operations
/// that can work with any database backend implementation.
pub struct UnifiedGroupReadOps<T: GroupReader> {
    reader: T,
}

impl<T: GroupReader> UnifiedGroupReadOps<T> {
    pub fn new(reader: T) -> Self {
        Self { reader }
    }
    
    /// Find a group by ID
    pub async fn find_group_by_id(&self, tenant_id: u32, id: &str) -> AppResult<Option<Group>> {
        self.reader.find_group_by_id(tenant_id, id).await
    }
    
    /// Find a group by display name (case-insensitive)
    pub async fn find_group_by_display_name(&self, tenant_id: u32, display_name: &str) -> AppResult<Option<Group>> {
        self.reader.find_group_by_display_name(tenant_id, display_name).await
    }
    
    /// Find all groups with pagination
    pub async fn find_all_groups(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.reader.find_all_groups(tenant_id, start_index, count).await
    }
    
    /// Find all groups with sorting
    pub async fn find_all_groups_sorted(
        &self,
        tenant_id: u32,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.reader.find_all_groups_sorted(tenant_id, start_index, count, sort_spec).await
    }
    
    /// Find groups by SCIM filter
    pub async fn find_groups_by_filter(
        &self,
        tenant_id: u32,
        filter: &FilterOperator,
        start_index: Option<i64>,
        count: Option<i64>,
        sort_spec: Option<&SortSpec>,
    ) -> AppResult<(Vec<Group>, i64)> {
        self.reader.find_groups_by_filter(tenant_id, filter, start_index, count, sort_spec).await
    }
    
    /// Find groups by user ID
    pub async fn find_groups_by_user_id(&self, tenant_id: u32, user_id: &str) -> AppResult<Vec<Group>> {
        self.reader.find_groups_by_user_id(tenant_id, user_id).await
    }
    
    /// Apply SCIM PATCH operations to a group
    pub async fn patch_group(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
    ) -> AppResult<Option<Group>> {
        self.reader.patch_group(tenant_id, id, patch_ops).await
    }
}