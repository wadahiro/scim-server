use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use crate::error::{AppError, AppResult};
use crate::models::User;

/// Prepared user data for database insertion
/// Contains all processed and normalized data ready for database insertion
#[derive(Debug, Clone)]
pub struct PreparedUserData {
    pub user: User,
    pub id: String,
    pub external_id: Option<String>,
    pub username: String,
    pub data_orig: Value,
    pub data_norm: Value,
    pub timestamp: DateTime<Utc>,
}

/// Database-specific adapter for user INSERT operations
#[async_trait]
pub trait UserInserter: Send + Sync {
    /// Execute user insert and return the created user
    async fn execute_user_insert(&self, tenant_id: u32, data: PreparedUserData) -> AppResult<User>;
}

/// Shared business logic for user INSERT operations
pub struct UserInsertProcessor;

impl UserInsertProcessor {
    /// Prepare user data for database insertion
    ///
    /// This handles all common processing:
    /// - ID generation (always server-generated per SCIM 2.0)
    /// - Password hashing
    /// - Username normalization
    /// - Metadata generation
    /// - Data serialization and normalization
    pub fn prepare_user_for_insert(user: &User) -> AppResult<PreparedUserData> {
        let mut user = user.clone();

        // Always generate a new ID (SCIM 2.0 doesn't allow client-specified IDs in POST)
        let id = Uuid::new_v4().to_string();
        *user.id_mut() = Some(id.clone());

        // Process password if present
        Self::process_password_for_storage(&mut user)?;

        // Extract and process data
        let external_id = user.external_id.clone();
        let username = user.base.user_name.to_lowercase();

        // Set metadata timestamps
        let timestamp = Utc::now();
        Self::set_user_metadata(&mut user, &timestamp);

        // Serialize user data
        let data_orig = serde_json::to_value(&user).map_err(AppError::Serialization)?;
        let normalized_data = crate::schema::normalization::normalize_scim_data(
            &data_orig,
            crate::parser::ResourceType::User,
        );
        let data_norm = serde_json::to_value(&normalized_data).map_err(AppError::Serialization)?;

        Ok(PreparedUserData {
            user,
            id,
            external_id,
            username,
            data_orig,
            data_norm,
            timestamp,
        })
    }

    /// Finalize user after database insertion
    ///
    /// This handles common post-processing:
    /// - Password removal from response
    /// - Version setting for new users
    pub fn finalize_user_response(mut user: User) -> User {
        // Remove password from response for SCIM 2.0 compliance
        *user.password_mut() = None;

        // Set version for newly created user (always version 1)
        if let Some(ref mut meta) = user.meta_mut() {
            meta.version = Some("W/\"1\"".to_string());
        }

        user
    }

    /// Hash password if present and not already hashed
    fn process_password_for_storage(user: &mut User) -> AppResult<()> {
        if let Some(ref password) = user.password() {
            let password_manager = crate::password::PasswordManager::default();
            if !password_manager.is_hashed_password(password) {
                let hashed = password_manager.hash_password(password)?;
                *user.password_mut() = Some(hashed);
            }
        }
        Ok(())
    }

    /// Set user metadata with timestamps
    fn set_user_metadata(user: &mut User, timestamp: &DateTime<Utc>) {
        let formatted_time = crate::utils::format_scim_datetime(*timestamp);
        let meta = scim_v2::models::scim_schema::Meta {
            resource_type: Some("User".to_string()),
            created: Some(formatted_time.clone()),
            last_modified: Some(formatted_time),
            location: None,
            version: None,
        };
        *user.meta_mut() = Some(meta);
    }
}

/// Unified user INSERT operations using the adapter pattern
pub struct UnifiedUserInsertOps<T: UserInserter> {
    inserter: T,
}

impl<T: UserInserter> UnifiedUserInsertOps<T> {
    pub fn new(inserter: T) -> Self {
        Self { inserter }
    }

    /// Create a new user using shared logic and database-specific execution
    pub async fn create_user(&self, tenant_id: u32, user: &User) -> AppResult<User> {
        // Prepare data using shared business logic
        let prepared_data = UserInsertProcessor::prepare_user_for_insert(user)?;

        // Execute database-specific insertion
        let created_user = self
            .inserter
            .execute_user_insert(tenant_id, prepared_data)
            .await?;

        // Apply shared post-processing
        let finalized_user = UserInsertProcessor::finalize_user_response(created_user);

        Ok(finalized_user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prepare_user_for_insert() {
        // Create a test user directly using our models
        let mut user = User::default();
        user.base.user_name = "TestUser".to_string();
        *user.id_mut() = Some("test-id".to_string());

        let result = UserInsertProcessor::prepare_user_for_insert(&user);
        assert!(result.is_ok());

        let prepared = result.unwrap();
        assert_eq!(prepared.username, "testuser"); // Should be lowercase
        assert!(prepared.timestamp > Utc::now() - chrono::Duration::seconds(1));
    }
}
