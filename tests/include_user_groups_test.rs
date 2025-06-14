use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

mod common;
use common::{create_test_app_config, setup_test_app};
use scim_server::config::CompatibilityConfig;

#[tokio::test]
async fn test_include_user_groups_true() {
    // Test default behavior (include_user_groups: true)
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "include.test@example.com",
            "name": {
                "givenName": "Include",
                "familyName": "Test"
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
    println!("User response (include_user_groups: true): {}", serde_json::to_string_pretty(&user).unwrap());

    // Should have groups field (empty array) when include_user_groups: true
    assert!(user.get("groups").is_some(), "groups field should exist when include_user_groups: true");
    let groups = user["groups"].as_array().unwrap();
    assert!(groups.is_empty(), "groups should be empty array");
}

#[tokio::test]
async fn test_include_user_groups_false() {
    // Test with include_user_groups: false
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
            "userName": "exclude.test@example.com",
            "name": {
                "givenName": "Exclude",
                "familyName": "Test"
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
    println!("User response (include_user_groups: false): {}", serde_json::to_string_pretty(&user).unwrap());

    // Should NOT have groups field when include_user_groups: false
    assert!(user.get("groups").is_none(), "groups field should not exist when include_user_groups: false");
}

#[tokio::test]
async fn test_include_user_groups_false_with_actual_groups() {
    // Test include_user_groups: false even when user has actual group memberships
    let mut app_config = create_test_app_config();
    app_config.compatibility.include_user_groups = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group first
    let group_response = server
        .post("/scim/v2/Groups")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "Test Group"
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
            "userName": "member.test@example.com",
            "name": {
                "givenName": "Member",
                "familyName": "Test"
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
            "displayName": "Test Group",
            "members": [{
                "value": user_id,
                "type": "User"
            }]
        }))
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);

    // Get the user - should NOT have groups field even though they're a member
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let user: serde_json::Value = response.json();
    
    // Debug: print the actual response
    println!("User response (include_user_groups: false, but has groups): {}", serde_json::to_string_pretty(&user).unwrap());

    // Should NOT have groups field when include_user_groups: false, even with real group memberships
    assert!(user.get("groups").is_none(), "groups field should not exist when include_user_groups: false, even with group memberships");
}

#[tokio::test]
async fn test_include_user_groups_tenant_override() {
    // Test per-tenant override of include_user_groups
    let mut app_config = create_test_app_config();
    
    // Global setting: true
    app_config.compatibility.include_user_groups = true;
    
    // Override for specific tenant: false
    if let Some(tenant) = app_config.tenants.get_mut(2) {
        // tenant with id: 3 (index 2) 
        tenant.compatibility = Some(CompatibilityConfig {
            include_user_groups: false,
            ..Default::default()
        });
    }

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user (should use tenant override: false)
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "tenant.override@example.com",
            "name": {
                "givenName": "Tenant",
                "familyName": "Override"
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

    // Should NOT have groups field due to tenant override
    assert!(user.get("groups").is_none(), "groups field should not exist due to tenant override");
}