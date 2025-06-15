//! Test to verify PATCH remove bug affects all multi-value attributes
//!
//! This test checks if the same bug that affected "members" also affects
//! other multi-value attributes like "emails", "phoneNumbers", etc.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

/// Test PATCH remove bug for emails multi-value attribute
#[tokio::test]
async fn test_patch_remove_emails_bug() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with multiple emails
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
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
        ],
        "active": true
    });

    let user_response = server.post("/scim/v2/Users").json(&user_data).await;
    user_response.assert_status(StatusCode::CREATED);
    let user: Value = user_response.json();
    let user_id = user["id"].as_str().unwrap();

    println!("Created user: {}", user_id);

    // Verify initial state - user has 2 emails
    let get_initial = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    get_initial.assert_status(StatusCode::OK);
    let initial_user: Value = get_initial.json();
    let initial_emails = initial_user["emails"].as_array().unwrap();
    assert_eq!(
        initial_emails.len(),
        2,
        "User should have 2 emails initially"
    );

    println!("✓ Initial state: User has {} emails", initial_emails.len());

    // Now apply PATCH to remove one specific email using path="emails" + value array
    let patch_remove_email = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "emails",
                "value": [
                    {
                        "value": "primary@example.com"
                    }
                ]
            }
        ]
    });

    println!("Applying PATCH to remove primary email:");
    println!(
        "{}",
        serde_json::to_string_pretty(&patch_remove_email).unwrap()
    );

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_remove_email)
        .await;

    if patch_response.status_code() != StatusCode::OK {
        println!("PATCH failed with status: {}", patch_response.status_code());
        println!("Response: {}", patch_response.text());
        panic!("PATCH operation failed");
    }

    // Check the result
    let get_after_patch = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    get_after_patch.assert_status(StatusCode::OK);
    let patched_user: Value = get_after_patch.json();

    println!(
        "User after PATCH: {}",
        serde_json::to_string_pretty(&patched_user).unwrap()
    );

    if let Some(emails_value) = patched_user.get("emails") {
        if let Some(emails_array) = emails_value.as_array() {
            println!("After PATCH: User has {} emails", emails_array.len());

            if emails_array.is_empty() {
                println!("🐛 BUG REPRODUCED: All emails were removed!");
                println!("Expected: secondary@example.com should remain (1 email)");
                println!("Actual: No emails remain (0 emails)");
                panic!("BUG: PATCH with path=\"emails\" removed all emails instead of just the specified one");
            } else if emails_array.len() == 1 {
                println!(
                    "✅ PATCH worked correctly: {} emails remain",
                    emails_array.len()
                );

                // Verify secondary email is still there and primary is removed
                let remaining_emails: Vec<&str> = emails_array
                    .iter()
                    .filter_map(|email| email.get("value").and_then(|v| v.as_str()))
                    .collect();

                assert!(
                    remaining_emails.contains(&"secondary@example.com"),
                    "secondary email should still exist"
                );
                assert!(
                    !remaining_emails.contains(&"primary@example.com"),
                    "primary email should be removed"
                );
            } else {
                println!("❓ Unexpected result: {} emails remain", emails_array.len());
                panic!(
                    "Unexpected number of emails: expected 0 (bug) or 1 (correct), got {}",
                    emails_array.len()
                );
            }
        } else {
            println!("🐛 BUG: emails field is not an array after PATCH");
            panic!("emails field should be an array");
        }
    } else {
        println!("🐛 BUG REPRODUCED: emails field was completely removed!");
        println!("Expected: secondary@example.com should remain");
        println!("Actual: emails field doesn't exist");
        panic!("BUG: PATCH with path=\"emails\" removed entire emails field instead of just the specified email");
    }
}

/// Test PATCH remove bug for phoneNumbers multi-value attribute
#[tokio::test]
async fn test_patch_remove_phone_numbers_bug() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with multiple phone numbers
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "phone-test-user",
        "name": {
            "givenName": "Phone",
            "familyName": "Test"
        },
        "phoneNumbers": [
            {
                "value": "+1-555-0100",
                "type": "work"
            },
            {
                "value": "+1-555-0200",
                "type": "mobile"
            }
        ],
        "active": true
    });

    let user_response = server.post("/scim/v2/Users").json(&user_data).await;
    user_response.assert_status(StatusCode::CREATED);
    let user: Value = user_response.json();
    let user_id = user["id"].as_str().unwrap();

    println!("Created user with phone numbers: {}", user_id);

    // Apply PATCH to remove one phone number using path="phoneNumbers" + value array
    let patch_remove_phone = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "phoneNumbers",
                "value": [
                    {
                        "value": "+1-555-0100"
                    }
                ]
            }
        ]
    });

    println!("Applying PATCH to remove work phone:");
    println!(
        "{}",
        serde_json::to_string_pretty(&patch_remove_phone).unwrap()
    );

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_remove_phone)
        .await;

    patch_response.assert_status(StatusCode::OK);

    // Check the result
    let get_after_patch = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let patched_user: Value = get_after_patch.json();

    if let Some(phones_value) = patched_user.get("phoneNumbers") {
        if let Some(phones_array) = phones_value.as_array() {
            println!("After PATCH: User has {} phone numbers", phones_array.len());

            if phones_array.is_empty() {
                println!("🐛 BUG REPRODUCED: All phone numbers were removed!");
                panic!("BUG: PATCH with path=\"phoneNumbers\" removed all phone numbers");
            } else if phones_array.len() == 1 {
                println!("✅ PATCH worked correctly for phoneNumbers");

                let remaining_phones: Vec<&str> = phones_array
                    .iter()
                    .filter_map(|phone| phone.get("value").and_then(|v| v.as_str()))
                    .collect();

                assert!(
                    remaining_phones.contains(&"+1-555-0200"),
                    "mobile phone should still exist"
                );
                assert!(
                    !remaining_phones.contains(&"+1-555-0100"),
                    "work phone should be removed"
                );
            }
        }
    } else {
        println!("🐛 BUG REPRODUCED: phoneNumbers field was completely removed!");
        panic!("BUG: PATCH with path=\"phoneNumbers\" removed entire field");
    }
}

/// Test PATCH remove bug for addresses multi-value attribute  
#[tokio::test]
async fn test_patch_remove_addresses_bug() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with multiple addresses
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "address-test-user",
        "name": {
            "givenName": "Address",
            "familyName": "Test"
        },
        "addresses": [
            {
                "type": "work",
                "streetAddress": "123 Work St",
                "locality": "Work City",
                "region": "Work State",
                "postalCode": "12345",
                "country": "US"
            },
            {
                "type": "home",
                "streetAddress": "456 Home Ave",
                "locality": "Home City",
                "region": "Home State",
                "postalCode": "67890",
                "country": "US"
            }
        ],
        "active": true
    });

    let user_response = server.post("/scim/v2/Users").json(&user_data).await;
    user_response.assert_status(StatusCode::CREATED);
    let user: Value = user_response.json();
    let user_id = user["id"].as_str().unwrap();

    // Apply PATCH to remove work address using path="addresses" + value array
    let patch_remove_address = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "addresses",
                "value": [
                    {
                        "type": "work"
                    }
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_remove_address)
        .await;

    patch_response.assert_status(StatusCode::OK);

    // Check the result
    let get_after_patch = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let patched_user: Value = get_after_patch.json();

    if let Some(addresses_value) = patched_user.get("addresses") {
        if let Some(addresses_array) = addresses_value.as_array() {
            if addresses_array.is_empty() {
                println!("🐛 BUG REPRODUCED: All addresses were removed!");
                panic!("BUG: PATCH with path=\"addresses\" removed all addresses");
            } else if addresses_array.len() == 1 {
                println!("✅ PATCH worked correctly for addresses");

                let remaining_types: Vec<&str> = addresses_array
                    .iter()
                    .filter_map(|addr| addr.get("type").and_then(|v| v.as_str()))
                    .collect();

                assert!(
                    remaining_types.contains(&"home"),
                    "home address should still exist"
                );
                assert!(
                    !remaining_types.contains(&"work"),
                    "work address should be removed"
                );
            }
        }
    } else {
        println!("🐛 BUG REPRODUCED: addresses field was completely removed!");
        panic!("BUG: PATCH with path=\"addresses\" removed entire field");
    }
}
