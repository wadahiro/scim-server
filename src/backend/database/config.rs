use crate::backend::DatabaseType;
use std::collections::HashMap;

/// Configuration for database backends
///
/// This structure holds all configuration needed to connect to and
/// operate any database backend. It's designed to be backend-agnostic
/// while providing specific options for different database types.
#[derive(Debug, Clone)]
pub struct DatabaseBackendConfig {
    /// The type of database backend to use
    pub database_type: DatabaseType,

    /// Connection URL for the storage backend
    /// Examples:
    /// - PostgreSQL: "postgresql://user:pass@localhost/dbname"
    /// - SQLite: "sqlite:./scim.db" or "sqlite::memory:"
    pub connection_url: String,

    /// Maximum number of connections in the pool
    pub max_connections: u32,

    /// Connection timeout in seconds
    pub connection_timeout: u64,

    /// Additional backend-specific options
    /// This allows for database-specific configurations without
    /// polluting the main config structure
    pub options: HashMap<String, String>,
}

impl DatabaseBackendConfig {
    /// Create a new storage configuration
    pub fn new(database_type: DatabaseType, connection_url: String) -> Self {
        Self {
            database_type,
            connection_url,
            max_connections: 10,
            connection_timeout: 30,
            options: HashMap::new(),
        }
    }

    /// Create a PostgreSQL configuration
    pub fn postgres(connection_url: String) -> Self {
        Self::new(DatabaseType::PostgreSQL, connection_url)
    }

    /// Create a SQLite configuration
    pub fn sqlite(connection_url: String) -> Self {
        Self::new(DatabaseType::SQLite, connection_url)
    }

    /// Create an in-memory SQLite configuration for testing
    pub fn memory_sqlite() -> Self {
        Self::new(DatabaseType::SQLite, ":memory:".to_string())
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max_connections: u32) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, timeout_seconds: u64) -> Self {
        self.connection_timeout = timeout_seconds;
        self
    }

    /// Add a backend-specific option
    pub fn with_option(mut self, key: String, value: String) -> Self {
        self.options.insert(key, value);
        self
    }

    /// Get a backend-specific option
    pub fn get_option(&self, key: &str) -> Option<&String> {
        self.options.get(key)
    }

    /// Check if this is an in-memory database
    pub fn is_memory_database(&self) -> bool {
        self.connection_url == ":memory:"
    }

    /// Get the table name for a specific resource and tenant
    /// Tables are named as: t{tenant_id}_{resource}
    /// e.g., t1_users, t2_groups, etc.
    pub fn table_name(&self, resource: &str, tenant_id: u32) -> String {
        format!("t{}_{}", tenant_id, resource)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.connection_url.is_empty() {
            return Err("Connection URL cannot be empty".to_string());
        }

        if self.max_connections == 0 {
            return Err("Max connections must be greater than 0".to_string());
        }

        match self.database_type {
            DatabaseType::PostgreSQL => {
                if !self.connection_url.starts_with("postgres://")
                    && !self.connection_url.starts_with("postgresql://")
                {
                    return Err("PostgreSQL connection URL must start with 'postgres://' or 'postgresql://'".to_string());
                }
            }
            DatabaseType::SQLite => {
                if !self.connection_url.starts_with("sqlite:")
                    && self.connection_url != ":memory:"
                    && !self.connection_url.ends_with(".db")
                    && !self.connection_url.ends_with(".sqlite")
                {
                    return Err("SQLite connection URL must start with 'sqlite:', be ':memory:', or end with '.db' or '.sqlite'".to_string());
                }
            }
        }

        Ok(())
    }
}

impl Default for DatabaseBackendConfig {
    fn default() -> Self {
        Self::memory_sqlite()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_postgres_config() {
        let config =
            DatabaseBackendConfig::postgres("postgresql://user:pass@localhost/test".to_string());

        assert_eq!(config.database_type, DatabaseType::PostgreSQL);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_sqlite_config() {
        let config = DatabaseBackendConfig::sqlite("sqlite:./test.db".to_string());

        assert_eq!(config.database_type, DatabaseType::SQLite);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_memory_config() {
        let config = DatabaseBackendConfig::memory_sqlite();

        assert!(config.is_memory_database());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_table_name_generation() {
        let config = DatabaseBackendConfig::default();
        assert_eq!(config.table_name("users", 1), "t1_users");
        assert_eq!(config.table_name("groups", 2), "t2_groups");
        assert_eq!(
            config.table_name("group_memberships", 3),
            "t3_group_memberships"
        );
    }

    #[test]
    fn test_config_validation() {
        let mut config = DatabaseBackendConfig::postgres("".to_string());
        assert!(config.validate().is_err());

        config.connection_url = "invalid://url".to_string();
        assert!(config.validate().is_err());

        config.connection_url = "postgresql://valid".to_string();
        assert!(config.validate().is_ok());
    }
}
