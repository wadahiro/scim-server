//! Simple test to verify the PATCH fix works
use scim_server::parser::patch_parser::ScimPath;
use serde_json::json;

#[test]
fn test_patch_remove_emails_simple() {
    // Create a simple JSON object with emails
    let mut user_json = json!({
        "emails": [
            {
                "value": "primary@example.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "secondary@example.com",
                "type": "personal",
                "primary": false
            }
        ]
    });

    // Apply PATCH remove with path="emails" and value array
    let path = ScimPath::parse("emails").unwrap();
    let remove_value = json!([
        {
            "value": "primary@example.com"
        }
    ]);

    let result = path.apply_operation(&mut user_json, "remove", &remove_value);

    println!("Result: {:?}", result);
    println!(
        "After PATCH: {}",
        serde_json::to_string_pretty(&user_json).unwrap()
    );

    // Check if the fix worked
    if let Some(emails) = user_json.get("emails") {
        if let Some(emails_array) = emails.as_array() {
            println!("✅ Fix worked: {} emails remain", emails_array.len());
            assert_eq!(emails_array.len(), 1, "Should have 1 email remaining");

            // Verify secondary email is still there
            let remaining_email = &emails_array[0];
            assert_eq!(remaining_email["value"], "secondary@example.com");
            assert_eq!(remaining_email["type"], "personal");
        } else {
            panic!("emails should be an array");
        }
    } else {
        panic!("emails field should still exist with 1 email");
    }
}

#[test]
fn test_patch_remove_phone_numbers_simple() {
    let mut user_json = json!({
        "phoneNumbers": [
            {
                "value": "+1-555-0100",
                "type": "work"
            },
            {
                "value": "+1-555-0200",
                "type": "mobile"
            }
        ]
    });

    let path = ScimPath::parse("phoneNumbers").unwrap();
    let remove_value = json!([
        {
            "value": "+1-555-0100"
        }
    ]);

    let result = path.apply_operation(&mut user_json, "remove", &remove_value);
    assert!(result.is_ok(), "PATCH operation should succeed");

    if let Some(phones) = user_json.get("phoneNumbers") {
        let phones_array = phones.as_array().unwrap();
        assert_eq!(
            phones_array.len(),
            1,
            "Should have 1 phone number remaining"
        );
        assert_eq!(phones_array[0]["value"], "+1-555-0200");
    } else {
        panic!("phoneNumbers field should still exist");
    }
}

#[test]
fn test_patch_remove_members_simple() {
    let mut group_json = json!({
        "members": [
            {
                "value": "user-1",
                "type": "User",
                "display": "User One"
            },
            {
                "value": "user-2",
                "type": "User",
                "display": "User Two"
            }
        ]
    });

    let path = ScimPath::parse("members").unwrap();
    let remove_value = json!([
        {
            "value": "user-1"
        }
    ]);

    let result = path.apply_operation(&mut group_json, "remove", &remove_value);
    assert!(result.is_ok(), "PATCH operation should succeed");

    if let Some(members) = group_json.get("members") {
        let members_array = members.as_array().unwrap();
        assert_eq!(members_array.len(), 1, "Should have 1 member remaining");
        assert_eq!(members_array[0]["value"], "user-2");
    } else {
        panic!("members field should still exist");
    }
}
