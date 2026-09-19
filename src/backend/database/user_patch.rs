use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::config::CompatibilityConfig;
use crate::error::{AppError, AppResult};
use crate::models::{ScimPatchOp, User};
use crate::parser::patch_parser::ScimPath;

/// Common trait for user patch operations across different database backends
#[async_trait]
pub trait UserPatcher: Send + Sync {
    /// Execute user patch operations and return the updated user
    async fn execute_user_patch(
        &self,
        tenant_id: u32,
        id: &str,
        data: PreparedUserPatchData,
    ) -> AppResult<Option<User>>;

    /// Find user by ID for patch operations
    async fn find_user_for_patch(&self, tenant_id: u32, id: &str) -> AppResult<Option<User>>;
}

/// Prepared user patch data for database operations
///
/// This struct contains all the processed and validated data needed
/// for patching a user in the database, with SCIM operations applied.
pub struct PreparedUserPatchData {
    pub user: User,
    pub id: String,
    pub username: String,
    pub external_id: Option<String>,
    pub data_orig: Value,
    pub data_norm: Value,
    pub timestamp: DateTime<Utc>,
}

/// Processor for common user patch business logic
///
/// This handles all the shared preparation logic that is the same
/// across PostgreSQL and SQLite implementations.
pub struct UserPatchProcessor;

impl UserPatchProcessor {
    /// Apply SCIM patch operations to a user
    ///
    /// This processes SCIM PATCH operations according to RFC 7644,
    /// applies them to the user object, and prepares the data for storage.
    pub async fn apply_patch_operations<P: UserPatcher>(
        patcher: &P,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
        compatibility: &CompatibilityConfig,
    ) -> AppResult<Option<User>> {
        // First, find the existing user
        let mut user = match patcher.find_user_for_patch(tenant_id, id).await? {
            Some(user) => user,
            None => return Ok(None),
        };

        // Apply patch operations
        for operation in &patch_ops.operations {
            let scim_path = ScimPath::parse(
                &operation.path.clone().unwrap_or_default(),
                crate::parser::ResourceType::User,
            )?;

            // Convert user to JSON for patch operations
            let mut user_json = serde_json::to_value(&user).map_err(AppError::Serialization)?;

            // Apply the operation with compatibility settings
            scim_path.apply_operation_with_compatibility(
                &mut user_json,
                &operation.op,
                &operation.value.as_ref().unwrap_or(&Value::Null).clone(),
                compatibility,
            )?;

            // RFC 7644 §3.5.2.2: reject a "remove" (or any other operation)
            // that drops a required attribute with 400 mutability, before
            // attempting to deserialize back into the typed model (which
            // would otherwise surface an opaque serde error for, e.g., a
            // missing `userName`).
            crate::schema::validate_required_attributes_present(
                &user_json,
                &crate::schema::USER_SCHEMA,
            )?;

            // Convert back to User. Any remaining failure here is a client
            // data problem (e.g. a type mismatch), not a server error, and
            // the underlying serde message is not shown to the client.
            user = serde_json::from_value(user_json).map_err(|e| {
                eprintln!("Failed to apply patch operation to user: {}", e);
                AppError::BadRequest(
                    "Invalid resource data after applying patch operations".to_string(),
                )
            })?;
        }

        // RFC 7643 §2.4: de-duplicate (type, value) pairs in multi-valued
        // complex attributes before they are stored or echoed back.
        let mut deduped_json = serde_json::to_value(&user).map_err(AppError::Serialization)?;
        crate::schema::dedupe_multivalued_attributes(&mut deduped_json);
        user = serde_json::from_value(deduped_json).map_err(AppError::Serialization)?;

        // Prepare user data for database storage
        let prepared = Self::prepare_user_for_patch(id, &user)?;

        // Execute the patch via database-specific implementation
        let result = patcher.execute_user_patch(tenant_id, id, prepared).await?;

        // Finalize the response by removing sensitive data
        Ok(result.map(Self::finalize_user_response))
    }

    /// Prepare user data for database patch
    ///
    /// This processes passwords, validates data, sets metadata,
    /// normalizes usernames, and prepares JSON data for storage.
    pub fn prepare_user_for_patch(id: &str, user: &User) -> AppResult<PreparedUserPatchData> {
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
        let data_orig = serde_json::to_value(&user).map_err(AppError::Serialization)?;

        // Normalize data for filtering capabilities
        let user_value = serde_json::to_value(&user).map_err(AppError::Serialization)?;
        let normalized_data = crate::schema::normalization::normalize_scim_data(
            &user_value,
            crate::parser::ResourceType::User,
        );
        let data_norm = serde_json::to_value(&normalized_data).map_err(AppError::Serialization)?;

        Ok(PreparedUserPatchData {
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

    /// Clear any client-supplied `meta` before storage.
    ///
    /// `meta` is entirely server-controlled per RFC 7643 §7 (mutability
    /// "readOnly"). A PATCH `path` targeting `meta.*` would otherwise let a
    /// client inject its own `resourceType`/`created`/etc. into storage; the
    /// authoritative values are always reconstructed from the
    /// `created_at`/`updated_at`/`version` database columns when the
    /// resource is read back, so nothing needs to be set here.
    fn set_user_metadata(user: &mut User, _timestamp: &DateTime<Utc>) {
        user.base.meta = None;
    }

    /// Finalize user after database patch
    ///
    /// This handles common post-processing:
    /// - Password removal from response
    pub fn finalize_user_response(mut user: User) -> User {
        // Remove password from response for SCIM 2.0 compliance
        *user.password_mut() = None;
        user
    }
}

/// Unified user patch operations handler
///
/// This provides a consistent interface for user patch operations
/// while delegating to database-specific implementations.
pub struct UnifiedUserPatchOps<T: UserPatcher> {
    patcher: T,
}

impl<T: UserPatcher> UnifiedUserPatchOps<T> {
    pub fn new(patcher: T) -> Self {
        Self { patcher }
    }

    /// Apply SCIM patch operations to a user with full validation and processing
    pub async fn patch_user(
        &self,
        tenant_id: u32,
        id: &str,
        patch_ops: &ScimPatchOp,
        compatibility: &CompatibilityConfig,
    ) -> AppResult<Option<User>> {
        // Validate inputs
        UserPatchProcessor::validate_user_id(id)?;

        // Apply patch operations using shared business logic
        UserPatchProcessor::apply_patch_operations(
            &self.patcher,
            tenant_id,
            id,
            patch_ops,
            compatibility,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_user_id() {
        // Valid IDs
        assert!(UserPatchProcessor::validate_user_id("valid-id").is_ok());
        assert!(
            UserPatchProcessor::validate_user_id("123e4567-e89b-12d3-a456-426614174000").is_ok()
        );

        // Invalid IDs
        assert!(UserPatchProcessor::validate_user_id("").is_err());
        assert!(UserPatchProcessor::validate_user_id("   ").is_err());
    }

    #[test]
    fn test_prepare_user_for_patch() {
        let mut user = User::default();
        user.base.user_name = "TestUser".to_string();

        let prepared = UserPatchProcessor::prepare_user_for_patch("test-id", &user).unwrap();

        assert_eq!(prepared.id, "test-id");
        assert_eq!(prepared.username, "testuser"); // Should be lowercase
        assert_eq!(prepared.user.id(), &Some("test-id".to_string()));
        assert!(prepared.data_orig.is_object());
        assert!(prepared.data_norm.is_object());
        assert!(prepared.timestamp.timestamp() > 0);
    }
}
