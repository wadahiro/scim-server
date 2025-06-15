use crate::error::{AppError, AppResult};
use chrono_tz::Tz;
use email_address::EmailAddress;
use fluent_uri::UriRef;
use langtag::LangTag;
use regex::Regex;
use scim_v2::models::user::User;
use serde_json::Value;
use std::str::FromStr;

/// Validates that at most one element in a multi-valued attribute has primary=true
pub fn validate_primary_constraint(multi_value_attr: &[Value]) -> AppResult<()> {
    let mut primary_count = 0;

    for item in multi_value_attr {
        if let Value::Object(obj) = item {
            if let Some(primary_value) = obj.get("primary") {
                if primary_value == &Value::Bool(true) {
                    primary_count += 1;
                }
            }
        }
    }

    if primary_count > 1 {
        return Err(AppError::BadRequest(
            "At most one element can have primary=true in multi-valued attribute".to_string(),
        ));
    }

    Ok(())
}

/// Validates primary constraint for all multi-valued attributes in a User
pub fn validate_user_primary_constraints(user_json: &Value) -> AppResult<()> {
    if let Value::Object(user_obj) = user_json {
        // Check emails
        if let Some(emails) = user_obj.get("emails") {
            if let Value::Array(emails_arr) = emails {
                validate_primary_constraint(emails_arr)?;
            }
        }

        // Check phoneNumbers
        if let Some(phones) = user_obj.get("phoneNumbers") {
            if let Value::Array(phones_arr) = phones {
                validate_primary_constraint(phones_arr)?;
            }
        }

        // Check addresses
        if let Some(addresses) = user_obj.get("addresses") {
            if let Value::Array(addresses_arr) = addresses {
                validate_primary_constraint(addresses_arr)?;
            }
        }

        // Check photos
        if let Some(photos) = user_obj.get("photos") {
            if let Value::Array(photos_arr) = photos {
                validate_primary_constraint(photos_arr)?;
            }
        }

        // Check ims
        if let Some(ims) = user_obj.get("ims") {
            if let Value::Array(ims_arr) = ims {
                validate_primary_constraint(ims_arr)?;
            }
        }

        // Check entitlements
        if let Some(entitlements) = user_obj.get("entitlements") {
            if let Value::Array(entitlements_arr) = entitlements {
                validate_primary_constraint(entitlements_arr)?;
            }
        }

        // Check roles
        if let Some(roles) = user_obj.get("roles") {
            if let Value::Array(roles_arr) = roles {
                validate_primary_constraint(roles_arr)?;
            }
        }

        // Check x509Certificates
        if let Some(certs) = user_obj.get("x509Certificates") {
            if let Value::Array(certs_arr) = certs {
                validate_primary_constraint(certs_arr)?;
            }
        }
    }

    Ok(())
}

/// Ensures at most one primary value when adding/replacing multi-valued attributes
pub fn enforce_single_primary(multi_value_attr: &mut [Value]) -> AppResult<()> {
    let mut primary_indices = Vec::new();

    // Find all elements with primary=true
    for (index, item) in multi_value_attr.iter().enumerate() {
        if let Value::Object(obj) = item {
            if let Some(primary_value) = obj.get("primary") {
                if primary_value == &Value::Bool(true) {
                    primary_indices.push(index);
                }
            }
        }
    }

    // If multiple primaries found, keep only the first one
    if primary_indices.len() > 1 {
        for &index in &primary_indices[1..] {
            if let Value::Object(obj) = &mut multi_value_attr[index] {
                obj.remove("primary");
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_single_primary_valid() {
        let emails = vec![
            json!({"value": "primary@example.com", "primary": true}),
            json!({"value": "secondary@example.com", "primary": false}),
            json!({"value": "tertiary@example.com"}), // default primary=false
        ];

        assert!(validate_primary_constraint(&emails).is_ok());
    }

    #[test]
    fn test_no_primary_valid() {
        let emails = vec![
            json!({"value": "email1@example.com", "primary": false}),
            json!({"value": "email2@example.com"}), // default primary=false
        ];

        assert!(validate_primary_constraint(&emails).is_ok());
    }

    #[test]
    fn test_multiple_primary_invalid() {
        let emails = vec![
            json!({"value": "primary1@example.com", "primary": true}),
            json!({"value": "primary2@example.com", "primary": true}), // INVALID
        ];

        assert!(validate_primary_constraint(&emails).is_err());
    }

    #[test]
    fn test_enforce_single_primary() {
        let mut emails = vec![
            json!({"value": "primary1@example.com", "primary": true}),
            json!({"value": "primary2@example.com", "primary": true}),
            json!({"value": "regular@example.com"}),
        ];

        assert!(enforce_single_primary(&mut emails).is_ok());

        // Should have only one primary=true (the first one)
        let primary_count = emails
            .iter()
            .filter(|email| email.get("primary") == Some(&Value::Bool(true)))
            .count();
        assert_eq!(primary_count, 1);
        assert_eq!(emails[0]["primary"], true);
        assert!(emails[1]["primary"].is_null());
    }

    #[test]
    fn test_user_primary_constraints() {
        let user = json!({
            "emails": [
                {"value": "email1@example.com", "primary": true},
                {"value": "email2@example.com", "primary": true} // INVALID
            ],
            "phoneNumbers": [
                {"value": "+1234567890", "primary": false}
            ]
        });

        assert!(validate_user_primary_constraints(&user).is_err());
    }
}

/// Validates email format according to RFC 5322
pub fn validate_email(email: &str) -> bool {
    // Use the email_address crate for proper RFC 5322 validation
    EmailAddress::is_valid(email)
}

/// Validates URI format per SCIM specification (reference type)
/// SCIM uses URIs for references which can be absolute or relative
/// Uses RFC 3986 compliant parsing with additional SCIM-specific restrictions
pub fn validate_url(uri: &str) -> bool {
    // Reject empty strings
    if uri.is_empty() {
        return false;
    }

    // Parse as URI reference (handles both absolute URIs and relative references)
    let parsed_ref = match UriRef::parse(uri) {
        Ok(uri_ref) => uri_ref,
        Err(_) => return false,
    };

    // Accept absolute URIs with schemes (e.g., "https://example.com/path")
    if parsed_ref.has_scheme() {
        return true;
    }

    // For relative URIs, require them to start with:
    // - "/" (absolute path)
    // - "./" or "../" (relative path with explicit prefix)
    // Reject simple names without context like "not-a-url"
    if uri.starts_with('/') || uri.starts_with("./") || uri.starts_with("../") {
        return true;
    }

    false
}

/// Validates X.509 certificate format (Base64 encoded)
pub fn validate_x509_certificate(cert: &str) -> bool {
    // Check if it's valid base64 with reasonable length for a certificate
    let base64_regex = Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").unwrap();
    base64_regex.is_match(cert) && cert.len() >= 100
}

/// Validates timezone format using IANA timezone database (Olson TZ)
/// Per RFC 6557 and SCIM specification
pub fn validate_timezone(timezone: &str) -> bool {
    // Try to parse as IANA timezone
    if Tz::from_str(timezone).is_ok() {
        return true;
    }

    // Also accept common UTC offset formats
    // e.g., "UTC", "GMT", "+08:00", "-05:00"
    if timezone == "UTC" || timezone == "GMT" {
        return true;
    }

    // Check for UTC offset format: ±HH:MM
    let offset_regex = Regex::new(r"^[+-]\d{2}:\d{2}$").unwrap();
    offset_regex.is_match(timezone)
}

/// Validates locale format according to RFC 5646 (BCP 47)
/// Language tags like "en", "en-US", "zh-Hans-CN", etc.
/// This validation is stricter than pure BCP 47 syntax validation - it requires
/// the language subtag to be a known ISO 639 language code, with the exception
/// of private use tags starting with "x-".
pub fn validate_locale(locale: &str) -> bool {
    // First check if it's a well-formed BCP 47 language tag
    let tag = match LangTag::new(locale) {
        Ok(tag) => tag,
        Err(_) => return false,
    };

    // Allow private use tags (starting with "x-")
    if locale.starts_with("x-") || locale.starts_with("X-") {
        return true;
    }

    // Get the language subtag (this is required in BCP 47)
    let language = match tag.language() {
        Some(lang) => lang.to_string(),
        None => return false,
    };

    // Check if the language subtag is a known ISO 639 language code
    // This prevents nonsensical language codes like "invalid"
    is_valid_language_code(&language)
}

/// Checks if a language code is a valid ISO 639 language code
/// This is a subset of commonly used language codes for SCIM validation
fn is_valid_language_code(lang: &str) -> bool {
    // Common ISO 639-1 and ISO 639-2 language codes
    // This list can be expanded as needed
    const VALID_LANGUAGES: &[&str] = &[
        // ISO 639-1 codes (2 letter)
        "aa", "ab", "ae", "af", "ak", "am", "an", "ar", "as", "av", "ay", "az", "ba", "be", "bg",
        "bh", "bi", "bm", "bn", "bo", "br", "bs", "ca", "ce", "ch", "co", "cr", "cs", "cu", "cv",
        "cy", "da", "de", "dv", "dz", "ee", "el", "en", "eo", "es", "et", "eu", "fa", "ff", "fi",
        "fj", "fo", "fr", "fy", "ga", "gd", "gl", "gn", "gu", "gv", "ha", "he", "hi", "ho", "hr",
        "ht", "hu", "hy", "hz", "ia", "id", "ie", "ig", "ii", "ik", "io", "is", "it", "iu", "ja",
        "jv", "ka", "kg", "ki", "kj", "kk", "kl", "km", "kn", "ko", "kr", "ks", "ku", "kv", "kw",
        "ky", "la", "lb", "lg", "li", "ln", "lo", "lt", "lu", "lv", "mg", "mh", "mi", "mk", "ml",
        "mn", "mr", "ms", "mt", "my", "na", "nb", "nd", "ne", "ng", "nl", "nn", "no", "nr", "nv",
        "ny", "oc", "oj", "om", "or", "os", "pa", "pi", "pl", "ps", "pt", "qu", "rm", "rn", "ro",
        "ru", "rw", "sa", "sc", "sd", "se", "sg", "si", "sk", "sl", "sm", "sn", "so", "sq", "sr",
        "ss", "st", "su", "sv", "sw", "ta", "te", "tg", "th", "ti", "tk", "tl", "tn", "to", "tr",
        "ts", "tt", "tw", "ty", "ug", "uk", "ur", "uz", "ve", "vi", "vo", "wa", "wo", "xh", "yi",
        "yo", "za", "zh", "zu", // Some common ISO 639-2 codes (3 letter)
        "chi", "zho", // Chinese variants
        "ger", "deu", // German variants
        "fre", "fra", // French variants
        "dut", "nld", // Dutch variants
        "gre", "ell", // Greek variants
        "per", "fas", // Persian variants
        "ice", "isl", // Icelandic variants
        "mac", "mkd", // Macedonian variants
        "may", "msa", // Malay variants
        "rum", "ron", // Romanian variants
        "slo", "slk", // Slovak variants
        "wel", "cym", // Welsh variants
        "baq", "eus", // Basque variants
        "cze", "ces", // Czech variants
        "alb", "sqi", // Albanian variants
        "arm", "hye", // Armenian variants
        "bur", "mya", // Burmese variants
        "tib", "bod", // Tibetan variants
    ];

    VALID_LANGUAGES.contains(&lang)
}

/// Validates User resource with comprehensive checks
pub fn validate_user(user: &User) -> AppResult<()> {
    // Core validation
    if user.user_name.is_empty() {
        return Err(AppError::BadRequest("userName is required".to_string()));
    }

    // Convert user to JSON for primary validation
    let user_json = serde_json::to_value(user)
        .map_err(|e| AppError::BadRequest(format!("Failed to serialize user: {}", e)))?;

    // Validate primary constraints
    validate_user_primary_constraints(&user_json)?;

    // Validate emails
    if let Some(emails) = &user.emails {
        for email in emails {
            if let Some(value) = &email.value {
                if !validate_email(value) {
                    return Err(AppError::BadRequest(format!(
                        "Invalid email format: {}",
                        value
                    )));
                }
            }
        }
    }

    // Phone numbers: No validation per SCIM 2.0 specification
    // SCIM allows any string format for phone numbers

    // Validate URLs (profileUrl, photos)
    if let Some(profile_url) = &user.profile_url {
        if !validate_url(profile_url) {
            return Err(AppError::BadRequest(format!(
                "Invalid profile URL format: {}",
                profile_url
            )));
        }
    }

    if let Some(photos) = &user.photos {
        for photo in photos {
            if let Some(value) = &photo.value {
                if !validate_url(value) {
                    return Err(AppError::BadRequest(format!(
                        "Invalid photo URL format: {}",
                        value
                    )));
                }
            }
        }
    }

    // Validate timezone
    if let Some(timezone) = &user.timezone {
        if !validate_timezone(timezone) {
            return Err(AppError::BadRequest(format!(
                "Invalid timezone format: {}",
                timezone
            )));
        }
    }

    // Validate locale
    if let Some(locale) = &user.locale {
        if !validate_locale(locale) {
            return Err(AppError::BadRequest(format!(
                "Invalid locale format: {}",
                locale
            )));
        }
    }

    // Validate X.509 certificates
    if let Some(certs) = &user.x509_certificates {
        for cert in certs {
            if let Some(value) = &cert.value {
                if !validate_x509_certificate(value) {
                    return Err(AppError::BadRequest(
                        "Invalid X.509 certificate format".to_string(),
                    ));
                }
            }
        }
    }

    // Validate Enterprise User extension
    if let Some(enterprise) = &user.enterprise_user {
        validate_enterprise_user(enterprise)?;
    }

    Ok(())
}

/// Validates Enterprise User extension
pub fn validate_enterprise_user(
    enterprise: &scim_v2::models::enterprise_user::EnterpriseUser,
) -> AppResult<()> {
    // Validate manager reference if present
    if let Some(manager) = &enterprise.manager {
        if let Some(value) = &manager.value {
            // Manager value should be a valid user ID (UUID format or similar)
            if value.is_empty() {
                return Err(AppError::BadRequest(
                    "Manager value cannot be empty".to_string(),
                ));
            }
        }
    }

    // Additional business logic validation can be added here
    // For example: validate employee number format, cost center codes, etc.

    Ok(())
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn test_email_validation() {
        assert!(validate_email("user@example.com"));
        assert!(validate_email("user.name+tag@example.co.uk"));
        assert!(!validate_email("invalid.email"));
        assert!(!validate_email("@example.com"));
        assert!(!validate_email("user@"));
    }

    #[test]
    fn test_url_validation() {
        // Absolute URIs
        assert!(validate_url("https://example.com"));
        assert!(validate_url("http://example.com/path?query=value"));
        assert!(validate_url("ftp://example.com")); // Any scheme is valid for URIs
        assert!(validate_url("mailto:user@example.com"));

        // Relative URIs (valid per SCIM spec)
        assert!(validate_url("/Users/123"));
        assert!(validate_url("../Groups/456"));
        assert!(validate_url("./subfolder/resource"));

        // Invalid URIs
        assert!(!validate_url("not-a-url"));
        assert!(!validate_url(""));
        assert!(!validate_url("relative-without-prefix"));
    }

    #[test]
    fn test_timezone_validation() {
        // Valid IANA timezone identifiers
        assert!(validate_timezone("America/New_York"));
        assert!(validate_timezone("Europe/London"));
        assert!(validate_timezone("Asia/Tokyo"));
        assert!(validate_timezone("UTC"));
        assert!(validate_timezone("GMT"));

        // Valid UTC offset formats
        assert!(validate_timezone("+08:00"));
        assert!(validate_timezone("-05:00"));
        assert!(validate_timezone("+00:00"));

        // Invalid timezone identifiers
        assert!(!validate_timezone("Invalid/Timezone"));
        assert!(!validate_timezone("NonExistent/Zone"));
        assert!(!validate_timezone("GMT+8")); // Wrong format (should be +08:00)
        assert!(!validate_timezone(""));
        assert!(!validate_timezone("PST9PDT")); // Obsolete format not in IANA
    }

    #[test]
    fn test_locale_validation() {
        // Valid language tags according to RFC 5646 (BCP 47)
        assert!(validate_locale("en"));
        assert!(validate_locale("en-US"));
        assert!(validate_locale("fr-FR"));
        assert!(validate_locale("zh-Hans"));
        assert!(validate_locale("zh-Hans-CN"));
        assert!(validate_locale("x-custom")); // Private use tags are allowed

        // Invalid language tags
        assert!(!validate_locale("en_US")); // Wrong separator
        assert!(!validate_locale(""));
        assert!(!validate_locale("123"));
        assert!(!validate_locale("toolongcode"));
        assert!(!validate_locale("invalid-locale")); // Invalid language code
    }
}
