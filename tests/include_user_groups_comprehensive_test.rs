use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

mod common;
use common::{create_test_app_config, setup_test_app};
use scim_server::config::CompatibilityConfig;

#[tokio::test]
async fn test_include_user_groups_true_show_empty_groups_true() {
    // Test: include_user_groups: true + show_empty_groups_members: true
    // Expected: groups field exists as empty array []
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = true;
    app_config.compatibility.show_empty_groups_members = true;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "test.user1@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User1"
            }
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
        "User response (include_user_groups: true, show_empty_groups_members: true): {}",
        serde_json::to_string_pretty(&user).unwrap()
    );

    // Should have groups field as empty array
    assert!(
        user.get("groups").is_some(),
        "groups field should exist when include_user_groups: true"
    );
    let groups = user["groups"].as_array().unwrap();
    assert!(
        groups.is_empty(),
        "groups should be empty array when show_empty_groups_members: true"
    );
}

#[tokio::test]
async fn test_include_user_groups_true_show_empty_groups_false() {
    // Test: include_user_groups: true + show_empty_groups_members: false
    // Expected: groups field is removed entirely (項目ごと削除)
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = true;
    app_config.compatibility.show_empty_groups_members = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "test.user2@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User2"
            }
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
        "User response (include_user_groups: true, show_empty_groups_members: false): {}",
        serde_json::to_string_pretty(&user).unwrap()
    );

    // Should NOT have groups field when empty and show_empty_groups_members: false
    assert!(user.get("groups").is_none(), 
            "groups field should not exist when include_user_groups: true but show_empty_groups_members: false");
}

#[tokio::test]
async fn test_include_user_groups_true_show_empty_groups_false_with_actual_groups() {
    // Test: include_user_groups: true + show_empty_groups_members: false + user has actual groups
    // Expected: groups field exists with actual group data (not empty)
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = true;
    app_config.compatibility.show_empty_groups_members = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group first
    let group_response = server
        .post("/scim/v2/Groups")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test Group for User"
        }))
        .await;

    assert_eq!(group_response.status_code(), StatusCode::CREATED);
    let created_group: serde_json::Value = group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Create a user
    let user_response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "test.user3@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User3"
            }
        }))
        .await;

    assert_eq!(user_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Add user to group by updating the group
    let update_response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test Group for User",
            "members": [{
                "value": user_id,
                "type": "User"
            }]
        }))
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);

    // Get the user - should have groups field with actual group data
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let user: serde_json::Value = response.json();

    // Debug: print the actual response
    println!("User response (include_user_groups: true, show_empty_groups_members: false, with actual groups): {}", 
             serde_json::to_string_pretty(&user).unwrap());

    // Should have groups field with actual group data
    assert!(
        user.get("groups").is_some(),
        "groups field should exist when user has actual group memberships"
    );
    let groups = user["groups"].as_array().unwrap();
    assert!(
        !groups.is_empty(),
        "groups should not be empty when user has actual group memberships"
    );
    assert_eq!(
        groups.len(),
        1,
        "user should be member of exactly one group"
    );

    // Verify the group data
    let group = &groups[0];
    assert_eq!(group["value"].as_str().unwrap(), group_id);
    assert_eq!(group["display"].as_str().unwrap(), "Test Group for User");
}

#[tokio::test]
async fn test_include_user_groups_false_no_db_fetch() {
    // Test: include_user_groups: false
    // Expected: No DB fetch for groups, groups field does not exist
    // This test verifies that even with actual group memberships, no groups are returned
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = false;
    // show_empty_groups_members setting should not matter when include_user_groups is false
    app_config.compatibility.show_empty_groups_members = true;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group first
    let group_response = server
        .post("/scim/v2/Groups")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test Group No Fetch"
        }))
        .await;

    assert_eq!(group_response.status_code(), StatusCode::CREATED);
    let created_group: serde_json::Value = group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Create a user
    let user_response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "test.user4@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User4"
            }
        }))
        .await;

    assert_eq!(user_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Add user to group by updating the group
    let update_response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test Group No Fetch",
            "members": [{
                "value": user_id,
                "type": "User"
            }]
        }))
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);

    // Get the user - should NOT have groups field regardless of actual memberships
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let user: serde_json::Value = response.json();

    // Debug: print the actual response
    println!(
        "User response (include_user_groups: false, with actual groups but no DB fetch): {}",
        serde_json::to_string_pretty(&user).unwrap()
    );

    // Should NOT have groups field when include_user_groups: false, even with actual memberships
    assert!(user.get("groups").is_none(), 
            "groups field should not exist when include_user_groups: false, regardless of actual memberships");
}

#[tokio::test]
async fn test_list_users_with_different_group_settings() {
    // Test that user list endpoint respects include_user_groups setting
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "list.test@example.com",
            "name": {
                "givenName": "List",
                "familyName": "Test"
            }
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Get users list
    let response = server.get("/scim/v2/Users").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let users_list: serde_json::Value = response.json();

    // Debug: print the actual response
    println!(
        "Users list response (include_user_groups: false): {}",
        serde_json::to_string_pretty(&users_list).unwrap()
    );

    // Verify that users in the list don't have groups field
    let resources = users_list["Resources"].as_array().unwrap();
    assert!(!resources.is_empty(), "should have at least one user");

    for user in resources {
        assert!(
            user.get("groups").is_none(),
            "no user in the list should have groups field when include_user_groups: false"
        );
    }
}
