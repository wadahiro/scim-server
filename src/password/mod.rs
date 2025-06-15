use crate::error::{AppError, AppResult};

/// Password hashing algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordAlgorithm {
    /// bcrypt algorithm (current default for backward compatibility)
    Bcrypt,
    /// SSHA (Salted SHA-1) algorithm for LDAP compatibility
    Ssha,
    /// Argon2id algorithm (OWASP recommended for new passwords)
    Argon2id,
}

impl Default for PasswordAlgorithm {
    fn default() -> Self {
        // Default to Argon2id as OWASP recommended
        Self::Argon2id
    }
}

impl std::fmt::Display for PasswordAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bcrypt => write!(f, "bcrypt"),
            Self::Ssha => write!(f, "SSHA"),
            Self::Argon2id => write!(f, "Argon2id"),
        }
    }
}

/// Abstract trait for password hashing algorithms
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password
    fn hash_password(&self, password: &str) -> AppResult<String>;

    /// Verify a plaintext password against a hash
    #[allow(dead_code)]
    fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool>;

    /// Check if a string is a hash created by this algorithm
    fn is_hash(&self, value: &str) -> bool;

    /// Get the algorithm identifier
    fn algorithm(&self) -> PasswordAlgorithm;
}

pub mod argon2_hasher;
pub mod bcrypt_hasher;
pub mod ssha_hasher;

pub use argon2_hasher::Argon2idHasher;
pub use bcrypt_hasher::BcryptHasher;
pub use ssha_hasher::SshaHasher;

/// Password manager with support for multiple algorithms
pub struct PasswordManager {
    /// Current algorithm for new passwords
    current_algorithm: PasswordAlgorithm,
    /// Available hashers
    hashers: Vec<Box<dyn PasswordHasher>>,
}

impl Default for PasswordManager {
    fn default() -> Self {
        Self::new(PasswordAlgorithm::default())
    }
}

impl PasswordManager {
    /// Create a new PasswordManager with specified default algorithm
    pub fn new(default_algorithm: PasswordAlgorithm) -> Self {
        let hashers: Vec<Box<dyn PasswordHasher>> = vec![
            Box::new(BcryptHasher::new()),
            Box::new(SshaHasher::new()),
            Box::new(Argon2idHasher::new()),
        ];

        Self {
            current_algorithm: default_algorithm,
            hashers,
        }
    }

    /// Hash a plaintext password using the current algorithm
    pub fn hash_password(&self, password: &str) -> AppResult<String> {
        // Validate password is not empty
        if password.is_empty() {
            return Err(AppError::BadRequest("Password cannot be empty".to_string()));
        }

        // Validate password strength
        self.validate_password_strength(password)?;

        // Find the hasher for current algorithm
        let hasher = self
            .hashers
            .iter()
            .find(|h| h.algorithm() == self.current_algorithm)
            .ok_or_else(|| {
                AppError::Internal(format!(
                    "Hasher not found for algorithm: {}",
                    self.current_algorithm
                ))
            })?;

        hasher.hash_password(password)
    }

    /// Verify a plaintext password against any supported hash format
    #[allow(dead_code)]
    pub fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        // Try each hasher until one can handle this hash format
        for hasher in &self.hashers {
            if hasher.is_hash(hash) {
                return hasher.verify_password(password, hash);
            }
        }

        Err(AppError::BadRequest("Unsupported hash format".to_string()))
    }

    /// Check if a string is a password hash (any supported format)
    pub fn is_hashed_password(&self, value: &str) -> bool {
        self.hashers.iter().any(|hasher| hasher.is_hash(value))
    }

    /// Detect the algorithm used for a given hash
    #[allow(dead_code)]
    pub fn detect_algorithm(&self, hash: &str) -> Option<PasswordAlgorithm> {
        self.hashers
            .iter()
            .find(|hasher| hasher.is_hash(hash))
            .map(|hasher| hasher.algorithm())
    }

    /// Validate password strength according to SCIM security requirements
    pub fn validate_password_strength(&self, password: &str) -> AppResult<()> {
        // Minimum length requirement
        if password.len() < 8 {
            return Err(AppError::BadRequest(
                "Password must be at least 8 characters long".to_string(),
            ));
        }

        // Maximum length to prevent DoS attacks
        if password.len() > 128 {
            return Err(AppError::BadRequest(
                "Password must be no more than 128 characters long".to_string(),
            ));
        }

        // Check for at least one lowercase letter
        if !password.chars().any(|c| c.is_lowercase()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one lowercase letter".to_string(),
            ));
        }

        // Check for at least one uppercase letter
        if !password.chars().any(|c| c.is_uppercase()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one uppercase letter".to_string(),
            ));
        }

        // Check for at least one digit
        if !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AppError::BadRequest(
                "Password must contain at least one digit".to_string(),
            ));
        }

        // Check for at least one special character
        if !password
            .chars()
            .any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c))
        {
            return Err(AppError::BadRequest(
                "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?)"
                    .to_string(),
            ));
        }

        Ok(())
    }

    /// Get the current default algorithm
    #[allow(dead_code)]
    pub fn current_algorithm(&self) -> PasswordAlgorithm {
        self.current_algorithm
    }

    /// Set the current default algorithm for new passwords
    #[allow(dead_code)]
    pub fn set_current_algorithm(&mut self, algorithm: PasswordAlgorithm) {
        self.current_algorithm = algorithm;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_manager_default() {
        let pm = PasswordManager::default();
        assert_eq!(pm.current_algorithm(), PasswordAlgorithm::Argon2id);
    }

    #[test]
    fn test_password_strength_validation() {
        let pm = PasswordManager::default();

        // Valid password
        assert!(pm.validate_password_strength("TestPassword123!").is_ok());

        // Too short
        assert!(pm.validate_password_strength("Test1!").is_err());

        // No uppercase
        assert!(pm.validate_password_strength("testpassword123!").is_err());

        // No lowercase
        assert!(pm.validate_password_strength("TESTPASSWORD123!").is_err());

        // No digit
        assert!(pm.validate_password_strength("TestPassword!").is_err());

        // No special character
        assert!(pm.validate_password_strength("TestPassword123").is_err());
    }

    #[test]
    fn test_algorithm_display() {
        assert_eq!(PasswordAlgorithm::Bcrypt.to_string(), "bcrypt");
        assert_eq!(PasswordAlgorithm::Ssha.to_string(), "SSHA");
        assert_eq!(PasswordAlgorithm::Argon2id.to_string(), "Argon2id");
    }
}
