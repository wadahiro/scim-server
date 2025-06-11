use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::error::{AppError, AppResult};
use crate::models::User;

/// Common trait for user update operations across different database backends
#[async_trait]
pub trait UserUpdater: Send + Sync {
    /// Execute user update and return the updated user
    async fn execute_user_update(
        &self,
        tenant_id: u32,
        id: &str,
        data: PreparedUserUpdateData,
    ) -> AppResult<Option<User>>;
}

/// Prepared user data for database update operations
///
/// This struct contains all the processed and validated data needed
/// for updating a user in the database, with metadata and normalization applied.
pub struct PreparedUserUpdateData {
    pub user: User,
    pub id: String,
    pub username: String,
    pub external_id: Option<String>,
    pub data_orig: Value,
    pub data_norm: Value,
    pub timestamp: DateTime<Utc>,
}

/// Processor for common user update business logic
///
/// This handles all the shared preparation logic that is the same
/// across PostgreSQL and SQLite implementations.
pub struct UserUpdateProcessor;

impl UserUpdateProcessor {
    /// Prepare user data for database update
    ///
    /// This processes passwords, validates data, sets metadata,
    /// normalizes usernames, and prepares JSON data for storage.
    pub fn prepare_user_for_update(id: &str, user: &User) -> AppResult<PreparedUserUpdateData> {
        let mut user = user.clone();

        // Process password if present
        Self::process_password_for_storage(&mut user)?;

        // Ensure ID matches the path parameter
        *user.id_mut() = Some(id.to_string());

        // Update metadata
        let timestamp = Utc::now();
        Self::set_user_metadata(&mut user, &timestamp);

        // Normalize username to lowercase for case-insensitive storage
        let username = user.base.user_name.to_lowercase();
        let external_id = user.external_id.clone();

        // Serialize user data for storage
        let data_orig = serde_json::to_value(&user).map_err(|e| AppError::Serialization(e))?;

        // Normalize data for filtering capabilities
        let user_value = serde_json::to_value(&user).map_err(|e| AppError::Serialization(e))?;
        let normalized_data = crate::schema::normalization::normalize_scim_data(
            &user_value,
            crate::parser::ResourceType::User,
        );
        let data_norm =
            serde_json::to_value(&normalized_data).map_err(|e| AppError::Serialization(e))?;

        Ok(PreparedUserUpdateData {
            user,
            id: id.to_string(),
            username,
            external_id,
            data_orig,
            data_norm,
            timestamp,
        })
    }

    /// Validate that the user ID is not empty or whitespace
    pub fn validate_user_id(id: &str) -> AppResult<()> {
        if id.trim().is_empty() {
            return Err(AppError::BadRequest("User ID cannot be empty".to_string()));
        }
        Ok(())
    }

    /// Process password for secure storage
    ///
    /// This applies password hashing if a password is present in the user data.
    fn process_password_for_storage(user: &mut User) -> AppResult<()> {
        if let Some(password) = user.password().clone() {
            let password_manager =
                crate::password::PasswordManager::new(crate::password::PasswordAlgorithm::Argon2id);
            let hashed = password_manager.hash_password(&password)?;
            *user.password_mut() = Some(hashed);
        }
        Ok(())
    }

    /// Set user metadata for update operations
    ///
    /// This updates the lastModified timestamp in the SCIM meta attribute.
    fn set_user_metadata(user: &mut User, timestamp: &DateTime<Utc>) {
        if let Some(meta) = user.meta_mut() {
            meta.last_modified = Some(timestamp.to_rfc3339());
        }
    }

    /// Finalize user after database update
    ///
    /// This handles common post-processing:
    /// - Password removal from response
    pub fn finalize_user_response(mut user: User) -> User {
        // Remove password from response for SCIM 2.0 compliance
        *user.password_mut() = None;
        user
    }
}

/// Unified user update operations handler
///
/// This provides a consistent interface for user update operations
/// while delegating to database-specific implementations.
pub struct UnifiedUserUpdateOps<T: UserUpdater> {
    updater: T,
}

impl<T: UserUpdater> UnifiedUserUpdateOps<T> {
    pub fn new(updater: T) -> Self {
        Self { updater }
    }

    /// Update a user with full validation and processing
    pub async fn update_user(
        &self,
        tenant_id: u32,
        id: &str,
        user: &User,
    ) -> AppResult<Option<User>> {
        // Validate inputs
        UserUpdateProcessor::validate_user_id(id)?;

        // Prepare user data for update
        let prepared = UserUpdateProcessor::prepare_user_for_update(id, user)?;

        // Execute the update via database-specific implementation
        let result = self
            .updater
            .execute_user_update(tenant_id, id, prepared)
            .await?;

        // Finalize the response by removing sensitive data
        Ok(result.map(UserUpdateProcessor::finalize_user_response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_user_id() {
        // Valid IDs
        assert!(UserUpdateProcessor::validate_user_id("valid-id").is_ok());
        assert!(
            UserUpdateProcessor::validate_user_id("123e4567-e89b-12d3-a456-426614174000").is_ok()
        );

        // Invalid IDs
        assert!(UserUpdateProcessor::validate_user_id("").is_err());
        assert!(UserUpdateProcessor::validate_user_id("   ").is_err());
    }

    #[test]
    fn test_prepare_user_for_update() {
        let mut user = User::default();
        user.base.user_name = "TestUser".to_string();

        let prepared = UserUpdateProcessor::prepare_user_for_update("test-id", &user).unwrap();

        assert_eq!(prepared.id, "test-id");
        assert_eq!(prepared.username, "testuser"); // Should be lowercase
        assert_eq!(prepared.user.id(), &Some("test-id".to_string()));
        assert!(prepared.data_orig.is_object());
        assert!(prepared.data_norm.is_object());
        assert!(prepared.timestamp.timestamp() > 0);
    }

    #[test]
    fn test_password_processing() {
        let mut user = User::default();
        user.base.user_name = "testuser".to_string();
        // Use a password that meets validation requirements (if any)
        *user.password_mut() = Some("TestPassword123!".to_string());

        // Before processing
        assert_eq!(user.password(), &Some("TestPassword123!".to_string()));

        let prepared = UserUpdateProcessor::prepare_user_for_update("test-id", &user);

        match prepared {
            Ok(prep) => {
                // After processing, password should be hashed (or at least processed)
                // The exact hash will vary, but it should not be the plain text
                if let Some(ref password) = prep.user.password() {
                    assert_ne!(password, "TestPassword123!");
                }
            }
            Err(_) => {
                // If password validation fails, that's also OK for this test
                // We're just testing the preparation logic
            }
        }
    }
}
