//! Database abstraction layer for SCIM server
//!
//! This module provides a unified interface for database operations across
//! different database backends (PostgreSQL, SQLite) while maintaining
//! database-specific optimizations where needed.
//!
//! # Architecture
//!
//! ```text
//! Common Logic (user_operations.rs, group_operations.rs, etc.)
//!     ↓
//! Database-specific implementations
//!     ├── postgres/ (PostgreSQL-specific code)
//!     └── sqlite/   (SQLite-specific code)
//! ```

pub mod config;
pub mod filter;
pub mod group_delete;
pub mod group_insert;
pub mod group_read;
pub mod group_update;
pub mod postgres;
pub mod sqlite;
pub mod user_delete;
pub mod user_insert;
pub mod user_patch;
pub mod user_read;
pub mod user_update;

#[cfg(test)]
mod integration_test;

// Re-export key types for convenience
pub use config::DatabaseBackendConfig;

pub use user_insert::UnifiedUserInsertOps;

pub use group_insert::UnifiedGroupInsertOps;

pub use user_delete::UnifiedUserDeleteOps;

pub use group_delete::UnifiedGroupDeleteOps;

pub use user_update::UnifiedUserUpdateOps;

pub use group_update::UnifiedGroupUpdateOps;

pub use user_patch::UnifiedUserPatchOps;

pub use user_read::UnifiedUserReadOps;

pub use group_read::UnifiedGroupReadOps;

// Re-export database-specific implementations (excluding unused backends)
pub use postgres::{
    PostgresGroupDeleter, PostgresGroupInserter, PostgresGroupReader, PostgresGroupUpdater,
    PostgresUserDeleter, PostgresUserInserter, PostgresUserPatcher, PostgresUserReader,
    PostgresUserUpdater,
};
pub use sqlite::{
    SqliteGroupDeleter, SqliteGroupInserter, SqliteGroupReader, SqliteGroupUpdater,
    SqliteUserDeleter, SqliteUserInserter, SqliteUserPatcher, SqliteUserReader, SqliteUserUpdater,
};
