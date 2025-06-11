use axum_test::TestServer;
use serde_json::{json, Value};
use http::StatusCode;

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_users_by_group_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create two users
    let user1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user1@example.com",
        "name": {
            "givenName": "User",
            "familyName": "One"
        }
    });

    let user2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user2@example.com",
        "name": {
            "givenName": "User",
            "familyName": "Two"
        }
    });

    let response1 = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user1_data)
        .await;
    response1.assert_status(StatusCode::CREATED);
    let user1: Value = response1.json();
    let user1_id = user1["id"].as_str().unwrap();

    let response2 = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user2_data)
        .await;
    response2.assert_status(StatusCode::CREATED);
    let user2: Value = response2.json();
    let user2_id = user2["id"].as_str().unwrap();

    // Create a group with both users as members
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group",
        "members": [
            {
                "value": user1_id,
                "type": "User"
            },
            {
                "value": user2_id,
                "type": "User"
            }
        ]
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let group: Value = response.json();
    let group_id = group["id"].as_str().unwrap();

    // Test getting users by group using SCIM filter
    let filter = format!("groups[value eq \"{}\"]", group_id);
    let encoded_filter = filter.replace(" ", "%20").replace("[", "%5B").replace("]", "%5D").replace("\"", "%22");
    let response = server
        .get(&format!("/scim/v2/Users?filter={}", encoded_filter))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let list_response: Value = response.json();
    let users = list_response["Resources"].as_array().unwrap();
    
    // Should return both users
    assert_eq!(users.len(), 2);
    
    // Verify user IDs are in the result
    let returned_user_ids: Vec<&str> = users
        .iter()
        .map(|u| u["id"].as_str().unwrap())
        .collect();
    assert!(returned_user_ids.contains(&user1_id));
    assert!(returned_user_ids.contains(&user2_id));
}

#[tokio::test]
async fn test_groups_by_user_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser@example.com",
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
    let user: Value = response.json();
    let user_id = user["id"].as_str().unwrap();

    // Create two groups with the user as member
    let group1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group 1",
        "members": [
            {
                "value": user_id,
                "type": "User"
            }
        ]
    });

    let group2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group 2",
        "members": [
            {
                "value": user_id,
                "type": "User"
            }
        ]
    });

    let response1 = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group1_data)
        .await;
    response1.assert_status(StatusCode::CREATED);
    let group1: Value = response1.json();
    let group1_id = group1["id"].as_str().unwrap();

    let response2 = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group2_data)
        .await;
    response2.assert_status(StatusCode::CREATED);
    let group2: Value = response2.json();
    let group2_id = group2["id"].as_str().unwrap();

    // Test getting groups by user using SCIM filter
    let filter = format!("members[value eq \"{}\"]", user_id);
    let encoded_filter = filter.replace(" ", "%20").replace("[", "%5B").replace("]", "%5D").replace("\"", "%22");
    let response = server
        .get(&format!("/scim/v2/Groups?filter={}", encoded_filter))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let list_response: Value = response.json();
    let groups = list_response["Resources"].as_array().unwrap();
    
    // Should return both groups
    assert_eq!(groups.len(), 2);
    
    // Verify group IDs are in the result
    let returned_group_ids: Vec<&str> = groups
        .iter()
        .map(|g| g["id"].as_str().unwrap())
        .collect();
    assert!(returned_group_ids.contains(&group1_id));
    assert!(returned_group_ids.contains(&group2_id));
    
    // Verify display names
    let display_names: Vec<&str> = groups
        .iter()
        .map(|g| g["displayName"].as_str().unwrap())
        .collect();
    assert!(display_names.contains(&"Test Group 1"));
    assert!(display_names.contains(&"Test Group 2"));
}

#[tokio::test]
async fn test_empty_group_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a group with no members
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Empty Group"
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let group: Value = response.json();
    let group_id = group["id"].as_str().unwrap();

    // Test getting users by empty group using SCIM filter
    let filter = format!("groups[value eq \"{}\"]", group_id);
    let encoded_filter = filter.replace(" ", "%20").replace("[", "%5B").replace("]", "%5D").replace("\"", "%22");
    let response = server
        .get(&format!("/scim/v2/Users?filter={}", encoded_filter))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let list_response: Value = response.json();
    let users = list_response["Resources"].as_array().unwrap();
    
    // Should return empty array
    assert_eq!(users.len(), 0);
}

#[tokio::test]
async fn test_user_not_in_any_group() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "loneuser@example.com",
        "name": {
            "givenName": "Lone",
            "familyName": "User"
        }
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let user: Value = response.json();
    let user_id = user["id"].as_str().unwrap();

    // Test getting groups by user who is not in any group using SCIM filter
    let filter = format!("members[value eq \"{}\"]", user_id);
    let encoded_filter = filter.replace(" ", "%20").replace("[", "%5B").replace("]", "%5D").replace("\"", "%22");
    let response = server
        .get(&format!("/scim/v2/Groups?filter={}", encoded_filter))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let list_response: Value = response.json();
    let groups = list_response["Resources"].as_array().unwrap();
    
    // Should return empty array
    assert_eq!(groups.len(), 0);
}