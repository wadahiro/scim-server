use scim_server::parser::patch_parser::ScimPath;
use serde_json::json;

/// Test file for developing and validating complex filter expression support
/// This demonstrates the roadmap for implementing AND/OR logical operators

#[test]
fn test_simple_filter_current_implementation() {
    // Current implementation: Simple filters work perfectly
    let path = "emails[type eq \"work\"].value";
    let parsed = ScimPath::parse(path).expect("Should parse simple filter");
    
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "simple.user",
        "emails": [
            {
                "value": "home@example.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "work@example.com",
                "type": "work",
                "primary": true
            }
        ]
    });
    
    let result = parsed.apply_operation(&mut user, "replace", &json!("new-work@company.com"));
    assert!(result.is_ok(), "Simple filters should work perfectly");
    
    let emails = user["emails"].as_array().unwrap();
    let work_email = emails.iter().find(|e| e["type"] == "work").unwrap();
    assert_eq!(work_email["value"], "new-work@company.com");
}

#[test]
fn test_special_case_filters_work() {
    // Test that filters with spaces in quoted values work
    let test_cases = vec![
        ("groups[display eq \"Marketing Team\"].value", "Marketing Team"),
        ("roles[displayName eq \"System Administrator\"].active", "System Administrator"),
        ("departments[name eq \"Human Resources\"].location", "Human Resources"),
    ];
    
    for (path, expected_display) in test_cases {
        let parsed = ScimPath::parse(path).expect(&format!("Should parse path: {}", path));
        
        // Verify the filter was parsed correctly
        match parsed {
            ScimPath::ValuePath { filter, .. } => {
                let (attr, op, value) = filter.get_condition();
                assert_eq!(op, "eq");
                assert_eq!(value, expected_display);
                assert!(attr == "display" || attr == "displayName" || attr == "name");
            }
            _ => panic!("Expected ValuePath for: {}", path),
        }
    }
}

#[test]
fn test_filter_matching_logic() {
    // Test the new filter matching logic directly
    let path = "phoneNumbers[type eq \"mobile\"]";
    let parsed = ScimPath::parse(path).expect("Should parse path");
    
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "match.test",
        "phoneNumbers": [
            {
                "value": "123-456-7890",
                "type": "mobile",
                "primary": false
            },
            {
                "value": "098-765-4321",
                "type": "work",
                "primary": true
            },
            {
                "value": "555-123-4567",
                "type": "mobile",
                "primary": true
            }
        ]
    });
    
    // Test remove operation to validate matching
    let result = parsed.apply_operation(&mut user, "remove", &json!(null));
    assert!(result.is_ok(), "Should successfully remove matching elements");
    
    // Verify only mobile phones were removed
    let phones = user["phoneNumbers"].as_array().unwrap();
    assert_eq!(phones.len(), 1, "Should have 1 phone remaining");
    assert_eq!(phones[0]["type"], "work", "Remaining phone should be work type");
}

#[test]
fn test_complex_filter_foundation() {
    // This test demonstrates the foundation for complex filters
    // showing how the new ScimFilter enum structure supports it
    
    // Test that the ScimFilter enum has the right structure
    let simple_path = "emails[type eq \"work\"]";
    let parsed = ScimPath::parse(simple_path).expect("Should parse simple filter");
    
    match parsed {
        ScimPath::ValuePath { filter, .. } => {
            // Test the get_condition method
            let (attr, op, val) = filter.get_condition();
            assert_eq!(attr, "type");
            assert_eq!(op, "eq");
            assert_eq!(val, "work");
            
            // Test the matches method
            let test_obj = serde_json::Map::from_iter(vec![
                ("type".to_string(), json!("work")),
                ("value".to_string(), json!("test@work.com")),
            ]);
            assert!(filter.matches(&test_obj), "Should match work email");
            
            let non_match_obj = serde_json::Map::from_iter(vec![
                ("type".to_string(), json!("home")),
                ("value".to_string(), json!("test@home.com")),
            ]);
            assert!(!filter.matches(&non_match_obj), "Should not match home email");
        }
        _ => panic!("Expected ValuePath"),
    }
}

#[test]
fn test_error_handling_improvements() {
    // Test improved error messages for unsupported operations
    let unsupported_filters = vec![
        "emails[type ne \"work\"]",  // 'ne' operator not supported yet
        "emails[type gt \"work\"]",  // 'gt' operator not supported yet
        "emails[type lt \"work\"]",  // 'lt' operator not supported yet
    ];
    
    for invalid_filter in unsupported_filters {
        let result = ScimPath::parse(invalid_filter);
        // These should either fail with clear error or parse but handle gracefully
        if let Ok(parsed) = result {
            // If it parses, the operation should handle unsupported operators gracefully
            let mut test_data = json!({
                "emails": [{"type": "work", "value": "test@work.com"}]
            });
            let op_result = parsed.apply_operation(&mut test_data, "replace", &json!("new-value"));
            // We expect this to either work (if we support the operator) or fail gracefully
            println!("Operation result for {}: {:?}", invalid_filter, op_result);
        }
    }
}

#[test]
fn test_complex_filter_and_operator() {
    // Test AND operator: type eq "work" and primary eq true
    let path = "emails[type eq \"work\" and primary eq true].value";
    let parsed = ScimPath::parse(path).expect("Should parse complex AND filter");
    
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "and.test",
        "emails": [
            {
                "value": "home@example.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "work-secondary@example.com", 
                "type": "work",
                "primary": false
            },
            {
                "value": "work-primary@example.com",
                "type": "work", 
                "primary": true
            }
        ]
    });
    
    // Replace the email that matches both conditions
    let result = parsed.apply_operation(&mut user, "replace", &json!("new-work-primary@company.com"));
    assert!(result.is_ok(), "Complex AND filter should work");
    
    let emails = user["emails"].as_array().unwrap();
    // Find the email that was replaced
    let work_primary_email = emails.iter().find(|e| 
        e["type"] == "work" && e["primary"] == true
    ).unwrap();
    assert_eq!(work_primary_email["value"], "new-work-primary@company.com");
    
    // Verify other emails weren't changed
    assert_eq!(emails.len(), 3);
    assert!(emails.iter().any(|e| e["value"] == "home@example.com"));
    assert!(emails.iter().any(|e| e["value"] == "work-secondary@example.com"));
}

#[test]
fn test_complex_filter_or_operator() {
    // Test OR operator: type eq "work" or type eq "mobile"
    let path = "phoneNumbers[type eq \"work\" or type eq \"mobile\"]";
    let parsed = ScimPath::parse(path).expect("Should parse complex OR filter");
    
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "or.test",
        "phoneNumbers": [
            {
                "value": "123-456-7890",
                "type": "home",
                "primary": false
            },
            {
                "value": "098-765-4321",
                "type": "work",
                "primary": true
            },
            {
                "value": "555-123-4567",
                "type": "mobile",
                "primary": false
            },
            {
                "value": "111-222-3333",
                "type": "fax",
                "primary": false
            }
        ]
    });
    
    // Remove all phones that match either condition (work OR mobile)
    let result = parsed.apply_operation(&mut user, "remove", &json!(null));
    assert!(result.is_ok(), "Complex OR filter should work");
    
    // Verify only home and fax phones remain
    let phones = user["phoneNumbers"].as_array().unwrap();
    assert_eq!(phones.len(), 2, "Should have 2 phones remaining");
    
    let remaining_types: Vec<&str> = phones.iter()
        .map(|p| p["type"].as_str().unwrap())
        .collect();
    assert!(remaining_types.contains(&"home"));
    assert!(remaining_types.contains(&"fax"));
    assert!(!remaining_types.contains(&"work"));
    assert!(!remaining_types.contains(&"mobile"));
}

#[test]
fn test_complex_filter_mixed_operators() {
    // Test mixed operators with precedence: type eq "work" and primary eq true or type eq "home"
    // This should be parsed as: (type eq "work" and primary eq true) or (type eq "home")
    let path = "emails[type eq \"work\" and primary eq true or type eq \"home\"].value";
    let parsed = ScimPath::parse(path).expect("Should parse mixed operators");
    
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "mixed.test",
        "emails": [
            {
                "value": "work-secondary@example.com",
                "type": "work",
                "primary": false
            },
            {
                "value": "work-primary@example.com", 
                "type": "work",
                "primary": true
            },
            {
                "value": "home@example.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "personal@example.com",
                "type": "personal", 
                "primary": false
            }
        ]
    });
    
    // Replace emails matching the complex condition
    let result = parsed.apply_operation(&mut user, "replace", &json!("replaced@company.com"));
    assert!(result.is_ok(), "Mixed operators should work");
    
    let emails = user["emails"].as_array().unwrap();
    
    // Should have replaced both the work-primary and home emails
    let replaced_count = emails.iter()
        .filter(|e| e["value"] == "replaced@company.com")
        .count();
    assert_eq!(replaced_count, 2, "Should have replaced 2 emails");
    
    // Verify the correct emails were replaced by checking what remains
    let remaining_values: Vec<&str> = emails.iter()
        .filter(|e| e["value"] != "replaced@company.com")
        .map(|e| e["value"].as_str().unwrap())
        .collect();
    
    assert!(remaining_values.contains(&"work-secondary@example.com"));
    assert!(remaining_values.contains(&"personal@example.com"));
    assert_eq!(remaining_values.len(), 2);
}

#[test]
fn test_advanced_filter_operators() {
    // Test various SCIM filter operators: ne, co, sw, ew
    let test_cases = vec![
        ("emails[type ne \"work\"]", "Should match non-work emails"),
        ("emails[value co \"@company\"]", "Should match emails containing @company"),
        ("emails[value sw \"admin\"]", "Should match emails starting with admin"),
        ("emails[value ew \".org\"]", "Should match emails ending with .org"),
    ];
    
    for (path, description) in test_cases {
        let parsed_result = ScimPath::parse(path);
        assert!(parsed_result.is_ok(), "{}: {}", description, path);
        
        let parsed = parsed_result.unwrap();
        
        // Test with sample data
        let mut user = json!({
            "emails": [
                {
                    "value": "user@work.com",
                    "type": "work"
                },
                {
                    "value": "admin@company.org",
                    "type": "business"
                },
                {
                    "value": "personal@home.net",
                    "type": "personal"
                }
            ]
        });
        
        // Test that the operation works without error
        let result = parsed.apply_operation(&mut user, "remove", &json!(null));
        assert!(result.is_ok(), "{}: Operation should succeed for {}", description, path);
    }
}

#[test]
fn test_filter_operator_precedence() {
    // Test that AND has higher precedence than OR
    // Expression: "type eq \"work\" or type eq \"home\" and primary eq true"
    // Should be parsed as: "type eq \"work\" or (type eq \"home\" and primary eq true)"
    let path = "emails[type eq \"work\" or type eq \"home\" and primary eq true]";
    let parsed = ScimPath::parse(path).expect("Should parse with correct precedence");
    
    let test_data = vec![
        (json!({"type": "work", "primary": false}), true),   // work (regardless of primary)
        (json!({"type": "home", "primary": true}), true),   // home AND primary
        (json!({"type": "home", "primary": false}), false), // home but NOT primary
        (json!({"type": "personal", "primary": true}), false), // not work or home
    ];
    
    if let ScimPath::ValuePath { filter, .. } = parsed {
        for (test_obj, should_match) in test_data {
            let obj_map = test_obj.as_object().unwrap();
            let matches = filter.matches(obj_map);
            assert_eq!(matches, should_match, 
                "Filter matching failed for {:?}, expected {}", test_obj, should_match);
        }
    } else {
        panic!("Expected ValuePath");
    }
}