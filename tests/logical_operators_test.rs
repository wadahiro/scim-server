use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::{json, Value};

mod common;

/// Test basic AND/OR logical operators in SCIM filters
/// This test validates the fundamental logical operations before implementing complex scenarios

#[tokio::test]
async fn test_simple_and_operator_with_columns() {
    // Test AND with both conditions using dedicated columns
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create test users
    let users = vec![
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "john.doe",
            "displayName": "John Doe",
            "active": true
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "jane.smith",
            "displayName": "Jane Smith",
            "active": false
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bob.wilson",
            "displayName": "Bob Wilson",
            "active": true
        }),
    ];

    let mut user_ids = Vec::new();
    for user_data in users {
        let response = server
            .post(&format!("/scim/v2/Users"))
            .add_header("content-type", "application/scim+json")
            .json(&user_data)
            .await;
        response.assert_status(StatusCode::CREATED);
        let user: Value = response.json();
        user_ids.push(user["id"].as_str().unwrap().to_string());
    }

    // First, let's verify that john.doe was created correctly
    let verify_response = server
        .get(&format!("/scim/v2/Users/{}", &user_ids[0]))
        .add_header("accept", "application/scim+json")
        .await;

    verify_response.assert_status(StatusCode::OK);
    let john_user: Value = verify_response.json();
    println!(
        "DEBUG: john.doe user data: {}",
        serde_json::to_string_pretty(&john_user).unwrap()
    );

    // First test just the active filter
    let active_response = server
        .get(&format!("/scim/v2/Users?filter=active%20eq%20true"))
        .add_header("accept", "application/scim+json")
        .await;

    active_response.assert_status(StatusCode::OK);
    let active_result: Value = active_response.json();
    println!(
        "DEBUG: Active filter result count: {}",
        active_result["totalResults"]
    );

    // Then test just the userName filter
    let username_response = server
        .get(&format!("/scim/v2/Users?filter=userName%20co%20%22john%22"))
        .add_header("accept", "application/scim+json")
        .await;

    username_response.assert_status(StatusCode::OK);
    let username_result: Value = username_response.json();
    println!(
        "DEBUG: Username filter result count: {}",
        username_result["totalResults"]
    );

    // Test 1: userName contains "john" AND active eq true
    // This should match only john.doe
    let response = server
        .get(&format!(
            "/scim/v2/Users?filter=userName%20co%20%22john%22%20and%20active%20eq%20true"
        ))
        .add_header("accept", "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let result: Value = response.json();

    println!(
        "DEBUG: Combined filter result: {}",
        serde_json::to_string_pretty(&result).unwrap()
    );

    // Should find exactly 1 user (john.doe who is active)
    assert_eq!(result["totalResults"], 1);
    let resources = result["Resources"].as_array().unwrap();
    assert_eq!(resources[0]["userName"], "john.doe");
    assert_eq!(resources[0]["active"], true);

    println!("✅ Simple AND with columns test passed");
}

#[tokio::test]
async fn test_simple_or_operator_with_columns() {
    // Test OR with both conditions using dedicated columns
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create test users
    let users = vec![
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "admin.user",
            "displayName": "Admin User"
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "regular.user",
            "displayName": "Manager Role"
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "guest.user",
            "displayName": "Guest User"
        }),
    ];

    let mut user_ids = Vec::new();
    for user_data in users {
        let response = server
            .post(&format!("/scim/v2/Users"))
            .add_header("content-type", "application/scim+json")
            .json(&user_data)
            .await;
        response.assert_status(StatusCode::CREATED);
        let user: Value = response.json();
        user_ids.push(user["id"].as_str().unwrap().to_string());
    }

    // Test 1: userName contains "admin" OR displayName contains "Manager"
    // This should match admin.user and regular.user
    let response = server
        .get(&format!("/scim/v2/Users?filter=userName%20co%20%22admin%22%20or%20displayName%20co%20%22Manager%22"))
        .add_header("accept", "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let result: Value = response.json();

    // Should find exactly 2 users
    assert_eq!(result["totalResults"], 2);
    let resources = result["Resources"].as_array().unwrap();

    let usernames: Vec<&str> = resources
        .iter()
        .map(|r| r["userName"].as_str().unwrap())
        .collect();

    assert!(usernames.contains(&"admin.user"));
    assert!(usernames.contains(&"regular.user"));
    assert!(!usernames.contains(&"guest.user"));

    println!("✅ Simple OR with columns test passed");
}

#[tokio::test]
async fn test_mixed_column_and_json_conditions() {
    // Test mixing dedicated column conditions with JSON field conditions
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create test users with custom attributes
    let users = vec![
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "developer.one",
            "name": {
                "givenName": "John",
                "familyName": "Developer"
            },
            "title": "Senior Developer"
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "developer.two",
            "name": {
                "givenName": "Jane",
                "familyName": "Developer"
            },
            "title": "Junior Developer"
        }),
        json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "manager.one",
            "name": {
                "givenName": "Bob",
                "familyName": "Manager"
            },
            "title": "Team Manager"
        }),
    ];

    let mut user_ids = Vec::new();
    for user_data in users {
        let response = server
            .post(&format!("/scim/v2/Users"))
            .add_header("content-type", "application/scim+json")
            .json(&user_data)
            .await;
        response.assert_status(StatusCode::CREATED);
        let user: Value = response.json();
        user_ids.push(user["id"].as_str().unwrap().to_string());
    }

    // Test: userName contains "developer" AND name.givenName eq "John"
    // This mixes a dedicated column (userName) with JSON field (name.givenName)
    let response = server
        .get(&format!("/scim/v2/Users?filter=userName%20co%20%22developer%22%20and%20name.givenName%20eq%20%22John%22"))
        .add_header("accept", "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let result: Value = response.json();

    // Should find exactly 1 user (developer.one with givenName John)
    assert_eq!(result["totalResults"], 1);
    let resources = result["Resources"].as_array().unwrap();
    assert_eq!(resources[0]["userName"], "developer.one");
    assert_eq!(resources[0]["name"]["givenName"], "John");

    println!("✅ Mixed column and JSON conditions test passed");
}

// This test will initially fail - it's our target for implementation
#[tokio::test]
async fn test_complex_logical_expressions() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Test: (userName co "admin" OR userName co "manager") AND active eq true
    // This tests precedence and grouping
    let response = server
        .get(&format!("/scim/v2/Users?filter=(userName%20co%20%22admin%22%20or%20userName%20co%20%22manager%22)%20and%20active%20eq%20true"))
        .add_header("accept", "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    println!("✅ Complex logical expressions test passed");
}
