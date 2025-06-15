use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

mod common;
use common::{create_test_app_config, setup_test_app};

#[tokio::test]
async fn test_user_with_empty_emails_array_gets_removed() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with empty emails array
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "test@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User"
            },
            "emails": []  // Empty array should be removed
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_user: serde_json::Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Get the user
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let user: serde_json::Value = response.json();

    // Debug: print the actual response
    println!(
        "User response: {}",
        serde_json::to_string_pretty(&user).unwrap()
    );

    // emails array should NOT exist (empty arrays get removed for normal fields)
    assert!(
        user.get("emails").is_none(),
        "emails field should not exist when empty"
    );

    // But groups field should exist as empty array when show_empty_groups_members=true
    assert!(user.get("groups").is_some(), "groups field should exist");
    let groups = user["groups"].as_array().unwrap();
    assert!(groups.is_empty(), "groups should be empty array");
}

#[tokio::test]
async fn test_user_with_empty_phone_numbers_array_gets_removed() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with empty phoneNumbers array
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "phone.test@example.com",
            "name": {
                "givenName": "Phone",
                "familyName": "Test"
            },
            "phoneNumbers": []  // Empty array should be removed
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_user: serde_json::Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Get the user
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let user: serde_json::Value = response.json();

    // phoneNumbers array should NOT exist (empty arrays get removed for normal fields)
    assert!(
        user.get("phoneNumbers").is_none(),
        "phoneNumbers field should not exist when empty"
    );

    // But groups field should exist as empty array
    assert!(user.get("groups").is_some(), "groups field should exist");
    let groups = user["groups"].as_array().unwrap();
    assert!(groups.is_empty(), "groups should be empty array");
}

#[tokio::test]
async fn test_group_with_empty_members_preserved() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group with empty members array
    let response = server
        .post("/scim/v2/Groups")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Empty Group"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_group: serde_json::Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Get the group
    let response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let group: serde_json::Value = response.json();

    // Debug: print the actual response
    println!(
        "Group response: {}",
        serde_json::to_string_pretty(&group).unwrap()
    );

    // members array should exist as empty array (special handling for groups/members)
    assert!(group.get("members").is_some(), "members field should exist");
    let members = group["members"].as_array().unwrap();
    assert!(members.is_empty(), "members should be empty array");
}

#[tokio::test]
async fn test_group_with_empty_members_removed_when_false() {
    // Test that Group members are removed when show_empty_groups_members: false
    let mut app_config = create_test_app_config();
    app_config.compatibility.show_empty_groups_members = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group
    let response = server
        .post("/scim/v2/Groups")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Empty Group False"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_group: serde_json::Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Get the group
    let response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let group: serde_json::Value = response.json();

    // Debug: print the actual response
    println!(
        "Group response (false setting): {}",
        serde_json::to_string_pretty(&group).unwrap()
    );

    // members array should NOT exist when show_empty_groups_members: false
    assert!(
        group.get("members").is_none(),
        "members field should not exist when show_empty_groups_members is false"
    );
}
