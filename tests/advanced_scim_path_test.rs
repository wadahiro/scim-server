use scim_server::parser::patch_parser::ScimPath;
use serde_json::json;

#[test]
fn test_simple_attribute_path() {
    let path = "displayName";
    let parsed = ScimPath::parse(path).expect("Should parse simple path");

    let mut user = json!({
        "userName": "test.user",
        "displayName": "Test User"
    });

    // Test replace operation
    parsed
        .apply_operation(&mut user, "replace", &json!("Updated Test User"))
        .expect("Should apply operation");
    assert_eq!(user["displayName"], "Updated Test User");
}

#[test]
fn test_nested_attribute_path() {
    let path = "name.givenName";
    let parsed = ScimPath::parse(path).expect("Should parse nested path");

    let mut user = json!({
        "userName": "john.doe",
        "name": {
            "givenName": "John",
            "familyName": "Doe"
        }
    });

    // Test replace operation
    parsed
        .apply_operation(&mut user, "replace", &json!("Jonathan"))
        .expect("Should apply operation");
    assert_eq!(user["name"]["givenName"], "Jonathan");
    assert_eq!(user["name"]["familyName"], "Doe"); // Should remain unchanged
}

#[test]
fn test_deep_nested_path() {
    let path = "name.formatted.first";
    let parsed = ScimPath::parse(path).expect("Should parse deep nested path");

    let mut user = json!({
        "userName": "test.user",
        "name": {}
    });

    // Test add operation - should create nested structure
    parsed
        .apply_operation(&mut user, "add", &json!("Test"))
        .expect("Should apply operation");
    assert_eq!(user["name"]["formatted"]["first"], "Test");
}

#[test]
fn test_value_path_with_filter() {
    let path = "emails[type eq \"work\"]";
    let parsed = ScimPath::parse(path).expect("Should parse value path");

    let mut user = json!({
        "userName": "jane.doe",
        "emails": [
            {
                "type": "work",
                "value": "jane.work@example.com"
            },
            {
                "type": "home",
                "value": "jane.home@example.com"
            }
        ]
    });

    // Test replace operation on the entire work email
    let new_email = json!({
        "type": "work",
        "value": "jane.newwork@example.com",
        "primary": true
    });

    parsed
        .apply_operation(&mut user, "replace", &new_email)
        .expect("Should apply operation");

    // Find the work email to verify it was updated
    let emails = user["emails"].as_array().unwrap();
    let work_email = emails.iter().find(|e| e["type"] == "work").unwrap();
    assert_eq!(work_email["value"], "jane.newwork@example.com");
    assert_eq!(work_email["primary"], true);

    // Verify home email was not affected
    let home_email = emails.iter().find(|e| e["type"] == "home").unwrap();
    assert_eq!(home_email["value"], "jane.home@example.com");
}

#[test]
fn test_value_path_with_sub_attribute() {
    let path = "addresses[type eq \"work\"].street";
    let parsed = ScimPath::parse(path).expect("Should parse value path with sub-attribute");

    let mut user = json!({
        "userName": "bob.smith",
        "addresses": [
            {
                "type": "work",
                "street": "123 Business Ave",
                "city": "Work City"
            },
            {
                "type": "home",
                "street": "456 Home St",
                "city": "Home City"
            }
        ]
    });

    // Test replace operation on just the street of the work address
    parsed
        .apply_operation(&mut user, "replace", &json!("789 New Business Blvd"))
        .expect("Should apply operation");

    // Find the work address to verify only street was updated
    let addresses = user["addresses"].as_array().unwrap();
    let work_address = addresses.iter().find(|a| a["type"] == "work").unwrap();
    assert_eq!(work_address["street"], "789 New Business Blvd");
    assert_eq!(work_address["city"], "Work City"); // Should remain unchanged

    // Verify home address was not affected
    let home_address = addresses.iter().find(|a| a["type"] == "home").unwrap();
    assert_eq!(home_address["street"], "456 Home St");
}

#[test]
fn test_value_path_add_operation() {
    let path = "phoneNumbers[type eq \"mobile\"]";
    let parsed = ScimPath::parse(path).expect("Should parse value path");

    let mut user = json!({
        "userName": "alice.wonder",
        "phoneNumbers": [
            {
                "type": "work",
                "value": "+1-555-123-4567"
            }
        ]
    });

    // Test add operation - should add new mobile phone
    let new_phone = json!({
        "type": "mobile",
        "value": "+1-555-987-6543",
        "primary": true
    });

    parsed
        .apply_operation(&mut user, "add", &new_phone)
        .expect("Should apply operation");

    // Verify both phones exist
    let phones = user["phoneNumbers"].as_array().unwrap();
    assert_eq!(phones.len(), 2);

    let mobile_phone = phones.iter().find(|p| p["type"] == "mobile").unwrap();
    assert_eq!(mobile_phone["value"], "+1-555-987-6543");
    assert_eq!(mobile_phone["primary"], true);
}

#[test]
fn test_value_path_remove_operation() {
    let path = "emails[type eq \"work\"]";
    let parsed = ScimPath::parse(path).expect("Should parse value path");

    let mut user = json!({
        "userName": "charlie.brown",
        "emails": [
            {
                "type": "work",
                "value": "charlie.work@example.com"
            },
            {
                "type": "home",
                "value": "charlie.home@example.com"
            }
        ]
    });

    // Test remove operation
    parsed
        .apply_operation(&mut user, "remove", &json!(null))
        .expect("Should apply operation");

    // Verify work email was removed
    let emails = user["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0]["type"], "home");
}

#[test]
fn test_value_path_remove_sub_attribute() {
    let path = "addresses[type eq \"work\"].country";
    let parsed = ScimPath::parse(path).expect("Should parse value path with sub-attribute");

    let mut user = json!({
        "userName": "david.jones",
        "addresses": [
            {
                "type": "work",
                "street": "123 Business Ave",
                "city": "Work City",
                "country": "USA"
            },
            {
                "type": "home",
                "street": "456 Home St",
                "city": "Home City",
                "country": "USA"
            }
        ]
    });

    // Test remove operation on sub-attribute
    parsed
        .apply_operation(&mut user, "remove", &json!(null))
        .expect("Should apply operation");

    // Verify country was removed from work address only
    let addresses = user["addresses"].as_array().unwrap();
    let work_address = addresses.iter().find(|a| a["type"] == "work").unwrap();
    assert!(!work_address.as_object().unwrap().contains_key("country"));
    assert_eq!(work_address["street"], "123 Business Ave"); // Other fields remain

    // Verify home address was not affected
    let home_address = addresses.iter().find(|a| a["type"] == "home").unwrap();
    assert_eq!(home_address["country"], "USA");
}

#[test]
fn test_schema_qualified_attribute() {
    let path = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department";
    let parsed = ScimPath::parse(path).expect("Should parse schema-qualified path");

    let mut user = json!({
        "userName": "enterprise.user",
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"]
    });

    // Test add operation for enterprise extension
    parsed
        .apply_operation(&mut user, "add", &json!("Engineering"))
        .expect("Should apply operation");

    println!(
        "User after operation: {}",
        serde_json::to_string_pretty(&user).unwrap()
    );

    // Verify the extension attribute was added
    assert_eq!(
        user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"],
        "Engineering"
    );
}

#[test]
fn test_error_handling_invalid_filter() {
    let path = "emails[type xyz \"work\"]"; // 'xyz' operator not supported
    let result = ScimPath::parse(path);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error
        .to_string()
        .contains("Could not parse filter"));
}

#[test]
fn test_error_handling_malformed_path() {
    let path = "emails[type eq \"work\""; // Missing closing bracket
    let result = ScimPath::parse(path);
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error.to_string().contains("missing ']'"));
}

#[test]
fn test_error_handling_non_array_value_path() {
    let path = "name[type eq \"work\"]"; // name is not an array
    let parsed = ScimPath::parse(path).expect("Should parse path");

    let mut user = json!({
        "userName": "test.user",
        "name": {
            "givenName": "Test"
        }
    });

    let result = parsed.apply_operation(&mut user, "replace", &json!({"test": "value"}));
    assert!(result.is_err());

    let error = result.unwrap_err();
    assert!(error
        .to_string()
        .contains("Value path requires multi-valued attribute"));
}
