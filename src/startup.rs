use crate::backend::database::DatabaseBackendConfig;
use crate::backend::BackendFactory;
use crate::config::AppConfig;
use crate::error::AppResult;

pub async fn initialize_tenant_schemas(config: &AppConfig) -> AppResult<()> {
    // Create backend configuration from app config
    if config.backend.backend_type != "database" {
        return Err(crate::error::AppError::Configuration(format!(
            "Unsupported backend type: {}",
            config.backend.backend_type
        )));
    }

    let database_config = config.backend.database.as_ref().ok_or_else(|| {
        crate::error::AppError::Configuration(
            "Database configuration is required when backend type is 'database'".to_string(),
        )
    })?;

    let backend_config = DatabaseBackendConfig {
        database_type: match database_config.db_type.as_str() {
            "postgresql" => crate::backend::DatabaseType::PostgreSQL,
            "sqlite" => crate::backend::DatabaseType::SQLite,
            _ => {
                return Err(crate::error::AppError::Configuration(format!(
                    "Unsupported database type: {}",
                    database_config.db_type
                )))
            }
        },
        connection_url: database_config.url.clone(),
        max_connections: database_config.max_connections,
        connection_timeout: 30,
        options: std::collections::HashMap::new(),
    };

    // Create backend instance
    let backend = BackendFactory::create(&backend_config).await?;

    // Initialize schemas for each tenant
    for tenant in &config.tenants {
        backend.init_tenant(tenant.id).await?;
        println!("✅ Initialized backend for tenant: {}", tenant.id);
    }

    Ok(())
}
