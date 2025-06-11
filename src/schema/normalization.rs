use serde_json::{Map, Value};
use super::definitions;
use crate::parser::ResourceType;

/// Normalize SCIM data for case-insensitive searching
/// 
/// This function creates a normalized version of the SCIM data where:
/// - All attribute names are converted to lowercase
/// - All string values are converted to lowercase (except caseExact fields)
/// - caseExact fields preserve their original case per SCIM 2.0 schema definitions
/// - Structure and data types are preserved
/// 
/// # Parameters
/// - `data`: The SCIM data to normalize
/// - `resource_type`: The type of SCIM resource (User or Group) for accurate schema lookup
pub fn normalize_scim_data(data: &Value, resource_type: ResourceType) -> Value {
    normalize_value_recursive(data, "", resource_type)
}

fn normalize_value_recursive(value: &Value, path: &str, resource_type: ResourceType) -> Value {
    match value {
        Value::Object(obj) => {
            let mut normalized_obj = Map::new();
            
            for (key, val) in obj {
                let normalized_key = key.to_lowercase();
                let new_path = if path.is_empty() {
                    normalized_key.clone()
                } else {
                    format!("{}.{}", path, normalized_key)
                };
                
                // Check if this field should preserve case using schema definitions
                // Normalize path for schema lookup by removing array indices
                let schema_path = new_path.replace(|c: char| c.is_ascii_digit() || c == '[' || c == ']', "");
                let preserve_case = definitions::is_case_exact_field_for_resource(&schema_path, resource_type);
                
                let normalized_value = if preserve_case && val.is_string() {
                    // Preserve original case for caseExact fields
                    val.clone()
                } else {
                    normalize_value_recursive(val, &new_path, resource_type)
                };
                
                normalized_obj.insert(normalized_key, normalized_value);
            }
            
            Value::Object(normalized_obj)
        }
        Value::Array(arr) => {
            let normalized_array: Vec<Value> = arr
                .iter()
                .enumerate()
                .map(|(i, item)| {
                    let array_path = format!("{}[{}]", path, i);
                    normalize_value_recursive(item, &array_path, resource_type)
                })
                .collect();
            Value::Array(normalized_array)
        }
        Value::String(s) => {
            // Check if this field should preserve case using schema definitions
            // Normalize path for schema lookup by removing array indices
            let schema_path = path.replace(|c: char| c.is_ascii_digit() || c == '[' || c == ']', "");
            if definitions::is_case_exact_field_for_resource(&schema_path, resource_type) {
                value.clone()
            } else {
                Value::String(s.to_lowercase())
            }
        }
        _ => value.clone(), // Numbers, booleans, null remain unchanged
    }
}

/// Check if a field path should preserve case for a specific resource type
/// 
/// This function delegates to the schema definitions in definitions.rs
/// for consistent case-exact behavior across the codebase.
pub fn is_case_exact_field_for_resource(path: &str, resource_type: ResourceType) -> bool {
    // Normalize path for schema lookup by removing array indices
    let schema_path = path.replace(|c: char| c.is_ascii_digit() || c == '[' || c == ']', "");
    definitions::is_case_exact_field_for_resource(&schema_path, resource_type)
}


#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_normalize_user_data() {
        let user_data = json!({
            "id": "USER-123",
            "externalId": "EXT-456", 
            "userName": "John.Doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe",
                "formatted": "John Doe"
            },
            "emails": [
                {
                    "value": "John.Doe@Example.Com",
                    "primary": true
                }
            ],
            "meta": {
                "resourceType": "User",
                "version": "W/\"abc123\""
            }
        });

        let normalized = normalize_scim_data(&user_data, ResourceType::User);

        // caseExact fields should preserve case (per schema definitions)
        assert_eq!(normalized["id"], "USER-123");
        assert_eq!(normalized["externalid"], "EXT-456");  // key lowercase, value preserved
        assert_eq!(normalized["meta"]["resourcetype"], "User"); // value preserved
        // Note: meta.version is not defined in schema, so gets default behavior
        
        // Case-insensitive fields should be lowercase (per schema definitions)
        assert_eq!(normalized["username"], "john.doe");
        assert_eq!(normalized["name"]["givenname"], "john");
        assert_eq!(normalized["name"]["familyname"], "doe");
        assert_eq!(normalized["name"]["formatted"], "john doe");
        assert_eq!(normalized["emails"][0]["value"], "john.doe@example.com"); // emails.value is case-insensitive per schema
        assert_eq!(normalized["emails"][0]["primary"], true); // boolean unchanged
    }

    #[test]
    fn test_normalize_group_data() {
        let group_data = json!({
            "id": "GROUP-789",
            "externalId": "EXT-GROUP-001",
            "displayName": "Administrators",
            "members": [
                {
                    "value": "USER-123",
                    "display": "John Doe",
                    "type": "User"
                }
            ],
            "meta": {
                "resourceType": "Group"
            }
        });

        let normalized = normalize_scim_data(&group_data, ResourceType::Group);

        // caseExact fields should preserve case (per schema definitions)
        assert_eq!(normalized["id"], "GROUP-789");
        assert_eq!(normalized["externalid"], "EXT-GROUP-001");
        assert_eq!(normalized["meta"]["resourcetype"], "Group");
        
        // Case-insensitive fields should be lowercase (per schema definitions)
        assert_eq!(normalized["displayname"], "administrators");
        assert_eq!(normalized["members"][0]["value"], "USER-123"); // members.value is case-exact per schema
        assert_eq!(normalized["members"][0]["display"], "john doe"); // display is case-insensitive per schema
        assert_eq!(normalized["members"][0]["type"], "user");
    }

    #[test]
    fn test_normalize_empty_and_null_values() {
        let data = json!({
            "userName": "",
            "active": null,
            "emails": []
        });

        let normalized = normalize_scim_data(&data, ResourceType::User);

        assert_eq!(normalized["username"], "");
        assert_eq!(normalized["active"], Value::Null);
        assert_eq!(normalized["emails"], json!([]));
    }

    #[test]
    fn test_is_case_exact_field_for_resource() {
        // Case-exact fields per schema definitions for User
        assert!(is_case_exact_field_for_resource("id", ResourceType::User));
        assert!(is_case_exact_field_for_resource("externalId", ResourceType::User));
        assert!(is_case_exact_field_for_resource("meta.resourceType", ResourceType::User));
        assert!(is_case_exact_field_for_resource("groups.value", ResourceType::User)); // User groups reference
        
        // Case-exact fields per schema definitions for Group
        assert!(is_case_exact_field_for_resource("id", ResourceType::Group));
        assert!(is_case_exact_field_for_resource("members.value", ResourceType::Group)); // Group member reference
        
        // Case-insensitive fields per schema definitions  
        assert!(!is_case_exact_field_for_resource("userName", ResourceType::User));
        assert!(!is_case_exact_field_for_resource("displayName", ResourceType::Group));
        assert!(!is_case_exact_field_for_resource("name.givenName", ResourceType::User));
        assert!(!is_case_exact_field_for_resource("emails.value", ResourceType::User)); // Email addresses are case-insensitive
        
        // Custom/undefined fields default to case-insensitive (stored in normalized form)
        assert!(!is_case_exact_field_for_resource("customField", ResourceType::User));
        assert!(!is_case_exact_field_for_resource("meta.customProperty", ResourceType::Group));
    }
}