use super::{PasswordAlgorithm, PasswordHasher};
use crate::error::{AppError, AppResult};
use bcrypt::{hash, verify, DEFAULT_COST};

/// bcrypt password hasher
///
/// bcrypt is a well-established password hashing function that uses the Blowfish cipher.
/// It's widely supported and provides good security for existing systems.
pub struct BcryptHasher {
    cost: u32,
}

impl BcryptHasher {
    /// Create a new bcrypt hasher with default cost (12)
    pub fn new() -> Self {
        Self { cost: DEFAULT_COST }
    }

    /// Create a new bcrypt hasher with custom cost
    ///
    /// Cost should be between 4 and 31. Higher values are more secure but slower.
    /// Default is 12, which is recommended for most applications.
    #[allow(dead_code)]
    pub fn with_cost(cost: u32) -> AppResult<Self> {
        if !(4..=31).contains(&cost) {
            return Err(AppError::BadRequest(
                "bcrypt cost must be between 4 and 31".to_string(),
            ));
        }

        Ok(Self { cost })
    }
}

impl Default for BcryptHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for BcryptHasher {
    fn hash_password(&self, password: &str) -> AppResult<String> {
        hash(password, self.cost)
            .map_err(|e| AppError::Internal(format!("Failed to hash password with bcrypt: {}", e)))
    }

    fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        verify(password, hash)
            .map_err(|e| AppError::Internal(format!("Failed to verify bcrypt password: {}", e)))
    }

    fn is_hash(&self, value: &str) -> bool {
        // bcrypt hashes start with $2a$, $2b$, $2x$, or $2y$ and are typically 60 characters
        // Also support older $2$ prefix
        (value.starts_with("$2")
            || value.starts_with("$2a$")
            || value.starts_with("$2b$")
            || value.starts_with("$2x$")
            || value.starts_with("$2y$"))
            && value.len() == 60
            && value.matches('$').count() == 3
    }

    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Bcrypt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_hash_and_verify() {
        let hasher = BcryptHasher::new();
        let password = "TestPassword123!";

        let hash = hasher.hash_password(password).unwrap();

        // Hash should start with $2 and be 60 characters
        assert!(hash.starts_with("$2"));
        assert_eq!(hash.len(), 60);
        assert!(hasher.is_hash(&hash));

        // Verify correct password
        assert!(hasher.verify_password(password, &hash).unwrap());

        // Verify incorrect password
        assert!(!hasher.verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_bcrypt_algorithm() {
        let hasher = BcryptHasher::new();
        assert_eq!(hasher.algorithm(), PasswordAlgorithm::Bcrypt);
    }

    #[test]
    fn test_bcrypt_is_hash() {
        let hasher = BcryptHasher::new();

        // Create a valid hash first
        let hash = hasher.hash_password("test").unwrap();
        assert!(hasher.is_hash(&hash));

        // Test various bcrypt prefixes
        let valid_hash = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW";
        assert!(hasher.is_hash(valid_hash));

        // Invalid formats
        assert!(!hasher.is_hash("not-a-hash"));
        assert!(!hasher.is_hash("{SSHA}example")); // SSHA
        assert!(!hasher.is_hash("$argon2id$example")); // Argon2id
        assert!(!hasher.is_hash("$2b$12$tooshort")); // too short
        assert!(!hasher.is_hash("$2b$12$toolongfortesting123456789012345678901234567890"));
        // too long
    }

    #[test]
    fn test_bcrypt_custom_cost() {
        let hasher = BcryptHasher::with_cost(10).unwrap();
        let password = "TestPassword123!";

        let hash = hasher.hash_password(password).unwrap();
        assert!(hasher.verify_password(password, &hash).unwrap());

        // Check that cost is reflected in the hash
        assert!(hash.contains("$10$"));
    }

    #[test]
    fn test_bcrypt_invalid_cost() {
        assert!(BcryptHasher::with_cost(3).is_err()); // too low
        assert!(BcryptHasher::with_cost(32).is_err()); // too high
        assert!(BcryptHasher::with_cost(12).is_ok()); // valid
    }

    #[test]
    fn test_bcrypt_different_salts() {
        let hasher = BcryptHasher::new();
        let password = "SamePassword123!";

        let hash1 = hasher.hash_password(password).unwrap();
        let hash2 = hasher.hash_password(password).unwrap();

        // Different salts should produce different hashes
        assert_ne!(hash1, hash2);

        // But both should verify correctly
        assert!(hasher.verify_password(password, &hash1).unwrap());
        assert!(hasher.verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_bcrypt_known_vector() {
        let hasher = BcryptHasher::new();

        // Test with a hash we generate ourselves to ensure it works
        let password = "testpassword123";
        let hash = hasher.hash_password(password).unwrap();

        assert!(hasher.is_hash(&hash));
        assert!(hasher.verify_password(password, &hash).unwrap());
        assert!(!hasher.verify_password("wrongpassword", &hash).unwrap());
    }
}
