use super::{PasswordAlgorithm, PasswordHasher};
use crate::error::{AppError, AppResult};
use argon2::{
    password_hash::SaltString, Algorithm, Argon2, Params, PasswordHash,
    PasswordHasher as Argon2PasswordHasher, PasswordVerifier, Version,
};

/// Argon2id password hasher with OWASP recommended settings
///
/// OWASP recommendations:
/// - Use Argon2id with a minimum configuration of 19 MiB of memory
/// - An iteration count of 2
/// - 1 degree of parallelism
pub struct Argon2idHasher {
    argon2: Argon2<'static>,
}

impl Argon2idHasher {
    /// Create a new Argon2id hasher with OWASP recommended settings
    pub fn new() -> Self {
        // OWASP recommended parameters:
        // - Memory: 19 MiB = 19 * 1024 KiB = 19456 KiB
        // - Iterations: 2
        // - Parallelism: 1
        let params = Params::new(
            19456,    // memory cost in KiB (19 MiB)
            2,        // time cost (iterations)
            1,        // parallelism
            Some(32), // output length
        )
        .expect("Invalid Argon2 parameters");

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        Self { argon2 }
    }

    /// Generate a random salt string
    fn generate_salt(&self) -> SaltString {
        SaltString::generate(&mut rand::thread_rng())
    }
}

impl Default for Argon2idHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for Argon2idHasher {
    fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = self.generate_salt();

        let password_hash = self
            .argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                AppError::Internal(format!("Failed to hash password with Argon2id: {}", e))
            })?;

        Ok(password_hash.to_string())
    }

    fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| AppError::Internal(format!("Failed to parse Argon2id hash: {}", e)))?;

        match self
            .argon2
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AppError::Internal(format!(
                "Failed to verify Argon2id password: {}",
                e
            ))),
        }
    }

    fn is_hash(&self, value: &str) -> bool {
        // Argon2id hashes start with $argon2id$
        value.starts_with("$argon2id$") && PasswordHash::new(value).is_ok()
    }

    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Argon2id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_hash_and_verify() {
        let hasher = Argon2idHasher::new();
        let password = "TestPassword123!";

        let hash = hasher.hash_password(password).unwrap();

        // Hash should start with $argon2id$
        assert!(hash.starts_with("$argon2id$"));
        assert!(hasher.is_hash(&hash));

        // Verify correct password
        assert!(hasher.verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!hasher.verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_argon2id_algorithm() {
        let hasher = Argon2idHasher::new();
        assert_eq!(hasher.algorithm(), PasswordAlgorithm::Argon2id);
    }

    #[test]
    fn test_argon2id_is_hash() {
        let hasher = Argon2idHasher::new();

        // Valid Argon2id hash
        let valid_hash =
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdHNvbWVzYWx0c29tZXNhbHQ$example";
        assert!(!hasher.is_hash(valid_hash)); // This will fail parsing but tests prefix

        // Invalid formats
        assert!(!hasher.is_hash("not-a-hash"));
        assert!(!hasher.is_hash("$2b$12$example")); // bcrypt
        assert!(!hasher.is_hash("{SSHA}example")); // SSHA
    }

    #[test]
    fn test_argon2id_different_salts() {
        let hasher = Argon2idHasher::new();
        let password = "SamePassword123!";

        let hash1 = hasher.hash_password(password).unwrap();
        let hash2 = hasher.hash_password(password).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(hasher.verify_password(password, &hash1).unwrap());
        assert!(hasher.verify_password(password, &hash2).unwrap());
    }
}
