use crate::error::{AppError, AppResult};
use sqlx::PgPool;

/// Initialize tenant-specific database schema for PostgreSQL
///
/// This creates the necessary tables for a tenant including users, groups,
/// and group memberships with proper indexes and constraints.
pub async fn init_tenant_schema(pool: &PgPool, tenant_id: u32) -> AppResult<()> {
    let users_table = format!("t{}_users", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let memberships_table = format!("t{}_group_memberships", tenant_id);

    // Enable uuid generation extension if not exists
    sqlx::query("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
        .execute(pool)
        .await
        .map_err(|e| AppError::Database(format!("Failed to enable uuid-ossp extension: {}", e)))?;

    // Create users table
    let users_sql = format!(
        r#"
        CREATE TABLE IF NOT EXISTS {} (
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            username TEXT NOT NULL UNIQUE,
            external_id TEXT UNIQUE,
            data_orig JSONB NOT NULL,
            data_norm JSONB NOT NULL,
            version BIGINT NOT NULL DEFAULT 1,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
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
            id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
            display_name TEXT NOT NULL UNIQUE,
            external_id TEXT UNIQUE,
            data_orig JSONB NOT NULL,
            data_norm JSONB NOT NULL,
            version BIGINT NOT NULL DEFAULT 1,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
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
            id SERIAL PRIMARY KEY,
            group_id UUID NOT NULL,
            member_id UUID NOT NULL,
            member_type TEXT NOT NULL CHECK (member_type IN ('User', 'Group')),
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
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
async fn create_indexes(pool: &PgPool, tenant_id: u32) -> AppResult<()> {
    let users_table = format!("t{}_users", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let memberships_table = format!("t{}_group_memberships", tenant_id);

    // Users table indexes
    let user_indexes = vec![
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_users_username_lower\" ON {} (LOWER(username))", tenant_id, users_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_users_external_id\" ON {} (external_id) WHERE external_id IS NOT NULL", tenant_id, users_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_users_data_orig_gin\" ON {} USING GIN (data_orig)", tenant_id, users_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_users_data_norm_gin\" ON {} USING GIN (data_norm)", tenant_id, users_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_users_created_at\" ON {} (created_at)", tenant_id, users_table),
    ];

    // Groups table indexes
    let group_indexes = vec![
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_groups_display_name_lower\" ON {} (LOWER(display_name))", tenant_id, groups_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_groups_external_id\" ON {} (external_id) WHERE external_id IS NOT NULL", tenant_id, groups_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_groups_data_orig_gin\" ON {} USING GIN (data_orig)", tenant_id, groups_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_groups_data_norm_gin\" ON {} USING GIN (data_norm)", tenant_id, groups_table),
        format!("CREATE INDEX IF NOT EXISTS \"idx_{}_groups_created_at\" ON {} (created_at)", tenant_id, groups_table),
    ];

    // Memberships table indexes
    let membership_indexes = vec![
        format!(
            "CREATE INDEX IF NOT EXISTS \"idx_{}_memberships_group_id\" ON {} (group_id)",
            tenant_id, memberships_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS \"idx_{}_memberships_member_id\" ON {} (member_id)",
            tenant_id, memberships_table
        ),
        format!(
            "CREATE INDEX IF NOT EXISTS \"idx_{}_memberships_member_type\" ON {} (member_type)",
            tenant_id, memberships_table
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
pub async fn drop_tenant_schema(pool: &PgPool, tenant_id: u32) -> AppResult<()> {
    let memberships_table = format!("t{}_group_memberships", tenant_id);
    let groups_table = format!("t{}_groups", tenant_id);
    let users_table = format!("t{}_users", tenant_id);

    // Drop tables in reverse order due to foreign key constraints
    for table in [&memberships_table, &groups_table, &users_table] {
        let sql = format!("DROP TABLE IF EXISTS {} CASCADE", table);
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
    use sqlx::postgres::PgPoolOptions;

    #[tokio::test]
    async fn test_schema_creation() {
        // This test requires a running PostgreSQL instance
        // Skip if DATABASE_URL is not set
        if std::env::var("DATABASE_URL").is_err() {
            return;
        }

        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(&std::env::var("DATABASE_URL").unwrap())
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
