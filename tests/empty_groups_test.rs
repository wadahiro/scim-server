use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::json;

mod common;
use common::{create_test_app_config, setup_test_app};
use scim_server::config::{CompatibilityConfig, TenantConfig};

#[tokio::test]
async fn test_show_empty_groups_true() {
    // Create config with show_empty_groups_members: true (default)
    let app_config = create_test_app_config();

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "testuser@example.com",
            "name": {
                "givenName": "Test",
                "familyName": "User"
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

    // Should have empty groups array
    assert!(user.get("groups").is_some(), "groups field should exist");
    let groups = user["groups"].as_array().unwrap();
    assert!(
        groups.is_empty(),
        "groups array should be empty but present"
    );
}

#[tokio::test]
async fn test_show_empty_groups_false() {
    // Create config with show_empty_groups_members: false
    let mut app_config = create_test_app_config();
    app_config.compatibility.show_empty_groups_members = false;

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let response = server
        .post("/scim/v2/Users")
        .add_header("Content-Type", "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "testuser2@example.com",
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

    // Should NOT have groups field
    assert!(
        user.get("groups").is_none(),
        "groups field should not exist when empty and show_empty_groups_members is false"
    );
}

#[tokio::test]
async fn test_show_empty_groups_with_tenant_override() {
    // Create config with global show_empty_groups_members: true but tenant override: false
    let mut app_config = create_test_app_config();
    app_config.compatibility.show_empty_groups_members = true;

    // Override for the specific tenant
    if let Some(tenant) = app_config.tenants.get_mut(2) {
        // tenant with id: 3 (index 2)
        tenant.compatibility = Some(CompatibilityConfig {
            show_empty_groups_members: false,
            ..Default::default()
        });
    }

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user (using the default tenant which should show empty groups)
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

    // Should NOT have groups field (using tenant override: false)
    // Note: This test uses the default tenant which has override to false
    assert!(
        user.get("groups").is_none(),
        "groups field should not exist due to tenant override"
    );
}

#[tokio::test]
async fn test_show_empty_members_group_true() {
    // Test for Group members as well (using default true)
    let app_config = create_test_app_config();

    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group
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

    // Should have empty members array
    assert!(group.get("members").is_some(), "members field should exist");
    let members = group["members"].as_array().unwrap();
    assert!(
        members.is_empty(),
        "members array should be empty but present"
    );
}

#[tokio::test]
async fn test_show_empty_members_group_false() {
    // Test for Group members with false setting
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
            "displayName": "Empty Group 2"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_group: serde_json::Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Get the group
    let response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;

    assert_eq!(response.status_code(), StatusCode::OK);

    let group: serde_json::Value = response.json();

    // Should NOT have members field
    assert!(
        group.get("members").is_none(),
        "members field should not exist when empty and show_empty_groups_members is false"
    );
}
