use crate::error::{AppError, AppResult};
use sqlx::SqlitePool;

/// Initialize tenant-specific database schema for SQLite
///
/// This creates the necessary tables for a tenant including users, groups,
/// and group memberships with proper indexes and constraints.
pub async fn init_tenant_schema(pool: &SqlitePool, tenant_id: u32) -> AppResult<()> {
    let users_table = format!("t{}_users", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let memberships_table = format!("t{}_group_memberships", tenant_id);

    // Create users table
    let users_sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            external_id TEXT UNIQUE,
            data_orig TEXT NOT NULL,
            data_norm TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        users_table
    );

    sqlx::query(&users_sql)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create users table: {}", e)))?;

    // Create groups table
    let groups_sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL UNIQUE,
            external_id TEXT UNIQUE,
            data_orig TEXT NOT NULL,
            data_norm TEXT NOT NULL,
            version INTEGER NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
        groups_table
    );

    sqlx::query(&groups_sql)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create groups table: {}", e)))?;

    // Create group memberships table
    let memberships_sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT NOT NULL,
            member_id TEXT NOT NULL,
            member_type TEXT NOT NULL CHECK (member_type IN ('User', 'Group')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(group_id, member_id, member_type),
            FOREIGN KEY (group_id) REFERENCES {} (id) ON DELETE CASCADE
        )
        "#,
        memberships_table, groups_table
    );

    sqlx::query(&memberships_sql)
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to create memberships table: {}", e)))?;

    // Create indexes for better performance
    create_indexes(pool, tenant_id).await?;

    Ok(())
}

/// Create performance indexes for tenant tables
async fn create_indexes(pool: &SqlitePool, tenant_id: u32) -> AppResult<()> {
    let users_table = format!("t{}_users", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let memberships_table = format!("t{}_group_memberships", tenant_id);

    // For numeric tenant IDs, no sanitization needed
    let sanitized_tenant_id = tenant_id;

    // Users table indexes
    let user_indexes = vec![
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_users_username ON {} (LOWER(username))",
            sanitized_tenant_id, users_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_users_external_id ON {} (external_id)",
            sanitized_tenant_id, users_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_users_created_at ON {} (created_at)",
            sanitized_tenant_id, users_table
        ),
    ];

    // Groups table indexes
    let group_indexes = vec![
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_groups_display_name ON {} (LOWER(display_name))",
            sanitized_tenant_id, groups_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_groups_external_id ON {} (external_id)",
            sanitized_tenant_id, groups_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_groups_created_at ON {} (created_at)",
            sanitized_tenant_id, groups_table
        ),
    ];

    // Memberships table indexes
    let membership_indexes = vec![
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_memberships_group_id ON {} (group_id)",
            sanitized_tenant_id, memberships_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_memberships_member_id ON {} (member_id)",
            sanitized_tenant_id, memberships_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS idx_{}_memberships_member_type ON {} (member_type)",
            sanitized_tenant_id, memberships_table
        ),
    ];

    // Execute all index creation queries
    for sql in user_indexes
        .iter()
        .chain(group_indexes.iter())
        .chain(membership_indexes.iter())
    {
        sqlx::query(sql)
            .execute(pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to create index: {}", e)))?;
    }

    Ok(())
}

/// Drop tenant-specific schema (for cleanup/testing)
#[allow(dead_code)]
pub async fn drop_tenant_schema(pool: &SqlitePool, tenant_id: u32) -> AppResult<()> {
    let memberships_table = format!("t{}_group_memberships", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let users_table = format!("t{}_users", tenant_id);

    // Drop tables in reverse order due to foreign key constraints
    for table in [&memberships_table, &groups_table, &users_table] {
        let sql = format!("DROP TABLE IF EXISTS {}", table);
        sqlx::query(&sql)
            .execute(pool)
            .await
            .map_err(|e| AppError::Database(format!("Failed to drop table {}: {}", table, e)))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn test_schema_creation() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();

        let tenant_id = 1u32;

        // Create schema
        init_tenant_schema(&pool, tenant_id).await.unwrap();

        // Verify tables exist
        let users_table = format!("t{}_users", tenant_id);
        let count: (i64,) = sqlx::query_as(&format!("SELECT COUNT(*) FROM {}", users_table))
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(count.0, 0);

        // Clean up
        drop_tenant_schema(&pool, tenant_id).await.unwrap();
    }
}
