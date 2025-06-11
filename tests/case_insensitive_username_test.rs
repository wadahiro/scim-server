use axum_test::TestServer;
use serde_json::{json, Value};
use http::StatusCode;

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_case_insensitive_username_storage() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create user with mixed case userName
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "TestUser@Example.COM",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();

    // Verify the userName is stored as provided in the response
    assert_eq!(created_user["userName"].as_str().unwrap(), "TestUser@Example.COM");

    // Try to create another user with the same userName but different case
    let duplicate_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser@example.com",
        "name": {
            "givenName": "Another",
            "familyName": "User"
        }
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&duplicate_user_data)
        .await;
    
    // Should fail with conflict since userName is case-insensitive
    response.assert_status(StatusCode::BAD_REQUEST);
    let error_response: Value = response.json();
    let message = error_response["error"].as_str()
        .or_else(|| error_response["message"].as_str())
        .or_else(|| error_response.as_str())
        .unwrap_or("Unknown error");
    assert!(message.contains("User already exists"));
}

#[tokio::test]
async fn test_case_insensitive_username_variations() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    let test_cases = vec![
        "user@domain.com",
        "USER@DOMAIN.COM", 
        "User@Domain.Com",
        "uSeR@dOmAiN.cOm"
    ];

    // Create the first user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": test_cases[0],
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);

    // Try to create users with the same userName in different cases
    for (i, username) in test_cases.iter().enumerate().skip(1) {
        let duplicate_user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": username,
            "name": {
                "givenName": format!("User{}", i),
                "familyName": "Test"
            }
        });

        let response = server
            .post(&format!("/scim/v2/Users"))
            .content_type("application/scim+json")
            .json(&duplicate_user_data)
            .await;
        
        // All should fail due to case-insensitive duplicate detection
        response.assert_status(StatusCode::BAD_REQUEST);
        let error_response: Value = response.json();
        let message = error_response["error"].as_str()
            .or_else(|| error_response["message"].as_str())
            .or_else(|| error_response.as_str())
            .unwrap_or("Unknown error");
        assert!(message.contains("User already exists"),
               "Failed for username: {}, got message: {}", username, message);
    }
}

#[tokio::test]
async fn test_case_insensitive_username_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create user with mixed case userName
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "SearchUser@Test.COM",
        "name": {
            "givenName": "Search",
            "familyName": "User"
        }
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test searching with various case combinations
    let search_cases = vec![
        "searchuser@test.com",
        "SEARCHUSER@TEST.COM",
        "SearchUser@Test.COM",
        "sEaRcHuSeR@tEsT.cOm"
    ];

    for search_username in search_cases {
        // Note: This test assumes we have a way to search by username
        // Since the current SCIM implementation doesn't expose username search directly,
        // we'll verify the internal consistency through duplicate detection
        let duplicate_user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": search_username,
            "name": {
                "givenName": "Duplicate",
                "familyName": "User"
            }
        });

        let response = server
            .post(&format!("/scim/v2/Users"))
            .content_type("application/scim+json")
            .json(&duplicate_user_data)
            .await;
        
        // Should fail because case-insensitive search finds the existing user
        response.assert_status(StatusCode::BAD_REQUEST);
        let error_response: Value = response.json();
        let message = error_response["error"].as_str()
            .or_else(|| error_response["message"].as_str())
            .or_else(|| error_response.as_str())
            .unwrap_or("Unknown error");
        assert!(message.contains("User already exists"),
               "Failed for search username: {}, got message: {}", search_username, message);
    }

    // Verify the original user still exists with correct ID
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;
    response.assert_status(StatusCode::OK);
    let user: Value = response.json();
    assert_eq!(user["userName"].as_str().unwrap(), "SearchUser@Test.COM");
}