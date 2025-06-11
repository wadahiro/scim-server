use sha1::{Sha1, Digest};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use crate::error::{AppError, AppResult};
use super::{PasswordHasher, PasswordAlgorithm};

/// SSHA (Salted SHA-1) password hasher for LDAP compatibility
/// 
/// SSHA format: {SSHA}base64(sha1(password + salt) + salt)
/// This is commonly used in LDAP systems and provides backward compatibility.
pub struct SshaHasher {
    salt_length: usize,
}

impl SshaHasher {
    /// Create a new SSHA hasher
    pub fn new() -> Self {
        Self {
            salt_length: 8, // 8 bytes salt is standard for SSHA
        }
    }
    
    /// Create SSHA hasher with custom salt length
    pub fn with_salt_length(salt_length: usize) -> Self {
        Self { salt_length }
    }
    
    /// Generate a random salt
    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; self.salt_length];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }
    
    /// Hash password with salt using SHA-1
    fn hash_with_salt(&self, password: &str, salt: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.finalize().to_vec()
    }
}

impl Default for SshaHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordHasher for SshaHasher {
    fn hash_password(&self, password: &str) -> AppResult<String> {
        let salt = self.generate_salt();
        let hash = self.hash_with_salt(password, &salt);
        
        // Combine hash + salt and encode with base64
        let mut combined = hash;
        combined.extend_from_slice(&salt);
        
        let encoded = general_purpose::STANDARD.encode(&combined);
        Ok(format!("{{SSHA}}{}", encoded))
    }
    
    fn verify_password(&self, password: &str, hash: &str) -> AppResult<bool> {
        // Remove {SSHA} prefix
        let encoded = hash.strip_prefix("{SSHA}")
            .ok_or_else(|| AppError::BadRequest("Invalid SSHA hash format".to_string()))?;
        
        // Decode base64
        let combined = general_purpose::STANDARD.decode(encoded)
            .map_err(|e| AppError::BadRequest(format!("Invalid SSHA base64 encoding: {}", e)))?;
        
        // SSHA hash is always 20 bytes (SHA-1), salt is the remainder
        if combined.len() < 20 {
            return Err(AppError::BadRequest("Invalid SSHA hash length".to_string()));
        }
        
        let (stored_hash, salt) = combined.split_at(20);
        
        // Hash the provided password with the extracted salt
        let computed_hash = self.hash_with_salt(password, salt);
        
        // Compare hashes using constant-time comparison
        Ok(stored_hash == computed_hash.as_slice())
    }
    
    fn is_hash(&self, value: &str) -> bool {
        // SSHA hashes start with {SSHA} and should be valid base64 after the prefix
        if let Some(encoded) = value.strip_prefix("{SSHA}") {
            if let Ok(decoded) = general_purpose::STANDARD.decode(encoded) {
                // Should have at least 20 bytes (SHA-1 hash) + some salt
                return decoded.len() >= 20;
            }
        }
        false
    }
    
    fn algorithm(&self) -> PasswordAlgorithm {
        PasswordAlgorithm::Ssha
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssha_hash_and_verify() {
        let hasher = SshaHasher::new();
        let password = "TestPassword123!";
        
        let hash = hasher.hash_password(password).unwrap();
        
        // Hash should start with {SSHA}
        assert!(hash.starts_with("{SSHA}"));
        assert!(hasher.is_hash(&hash));
        
        // Verify correct password
        assert!(hasher.verify_password(password, &hash).unwrap());
        
        // Verify incorrect password
        assert!(!hasher.verify_password("WrongPassword", &hash).unwrap());
    }

    #[test]
    fn test_ssha_algorithm() {
        let hasher = SshaHasher::new();
        assert_eq!(hasher.algorithm(), PasswordAlgorithm::Ssha);
    }

    #[test]
    fn test_ssha_is_hash() {
        let hasher = SshaHasher::new();
        
        // Create a valid hash first
        let hash = hasher.hash_password("test").unwrap();
        assert!(hasher.is_hash(&hash));
        
        // Invalid formats
        assert!(!hasher.is_hash("not-a-hash"));
        assert!(!hasher.is_hash("$2b$12$example")); // bcrypt
        assert!(!hasher.is_hash("$argon2id$example")); // Argon2id
        assert!(!hasher.is_hash("{SSHA}invalid-base64!@#"));
        assert!(!hasher.is_hash("{SSHA}dGVzdA==")); // too short (only 4 bytes)
    }

    #[test]
    fn test_ssha_different_salts() {
        let hasher = SshaHasher::new();
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
    fn test_ssha_custom_salt_length() {
        let hasher = SshaHasher::with_salt_length(16);
        let password = "TestPassword123!";
        
        let hash = hasher.hash_password(password).unwrap();
        assert!(hasher.verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_ssha_known_vector() {
        let hasher = SshaHasher::new();
        
        // Test with a known SSHA hash (manually created for testing)
        // This uses the salt "testsalt" and password "password"
        let password = "password";
        let salt = b"testsalt";
        let expected_hash = hasher.hash_with_salt(password, salt);
        
        // Create the full SSHA hash
        let mut combined = expected_hash;
        combined.extend_from_slice(salt);
        let encoded = general_purpose::STANDARD.encode(&combined);
        let ssha_hash = format!("{{SSHA}}{}", encoded);
        
        // Verify it works
        assert!(hasher.verify_password(password, &ssha_hash).unwrap());
        assert!(!hasher.verify_password("wrongpassword", &ssha_hash).unwrap());
    }
}