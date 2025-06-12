use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_user_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a test user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "name": {
            "givenName": "Test",
            "familyName": "User",
            "formatted": "Test User"
        },
        "emails": [{
            "value": "test@example.com",
            "primary": true
        }],
        "phoneNumbers": [{
            "value": "555-1234",
            "type": "work"
        }],
        "active": true
    });

    // Create the user
    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test attributes parameter - request only userName and emails
    let response = server
        .get(&format!(
            "/tenant-a/scim/v2/Users/{}?attributes=userName,emails",
            user_id
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let filtered_user: Value = response.json();

    // Should include requested attributes
    assert!(filtered_user.get("userName").is_some());
    assert!(filtered_user.get("emails").is_some());
    assert!(filtered_user.get("id").is_some()); // Always returned

    // Should not include unrequested attributes
    assert!(filtered_user.get("name").is_none());
    assert!(filtered_user.get("phoneNumbers").is_none());
}

#[tokio::test]
async fn test_user_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a test user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser2",
        "name": {
            "givenName": "Test",
            "familyName": "User2"
        },
        "emails": [{
            "value": "test2@example.com",
            "primary": true
        }],
        "phoneNumbers": [{
            "value": "555-5678",
            "type": "work"
        }],
        "active": true
    });

    // Create the user
    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test excludedAttributes parameter - exclude emails and phoneNumbers
    let response = server
        .get(&format!(
            "/tenant-a/scim/v2/Users/{}?excludedAttributes=emails,phoneNumbers",
            user_id
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let filtered_user: Value = response.json();

    // Should include default attributes except excluded ones
    assert!(filtered_user.get("userName").is_some());
    assert!(filtered_user.get("name").is_some());
    assert!(filtered_user.get("id").is_some()); // Always returned

    // Should exclude the specified attributes
    assert!(filtered_user.get("emails").is_none());
    assert!(filtered_user.get("phoneNumbers").is_none());
}

#[tokio::test]
async fn test_group_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a test group
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group"
    });

    // Create the group
    let response = server
        .post("/tenant-a/scim/v2/Groups")
        .json(&group_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Test attributes parameter - request only displayName
    let response = server
        .get(&format!(
            "/tenant-a/scim/v2/Groups/{}?attributes=displayName",
            group_id
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let filtered_group: Value = response.json();

    // Should include requested attributes
    assert!(filtered_group.get("displayName").is_some());
    assert!(filtered_group.get("id").is_some()); // Always returned

    // Should not include unrequested attributes
    assert!(filtered_group.get("members").is_none());
}

#[tokio::test]
async fn test_user_list_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create test users
    for i in 1..=3 {
        let user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("listuser{}", i),
            "name": {
                "givenName": format!("User{}", i)
            },
            "emails": [{
                "value": format!("user{}@example.com", i)
            }],
            "active": true
        });

        let response = server
            .post("/tenant-a/scim/v2/Users")
            .json(&user_data)
            .await;

        assert_eq!(response.status_code(), StatusCode::CREATED);
    }

    // Test attributes parameter in user list
    let response = server
        .get("/tenant-a/scim/v2/Users?attributes=userName")
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let list_response: Value = response.json();

    let resources = list_response["Resources"].as_array().unwrap();
    assert!(resources.len() >= 3);

    // Check that all users in the list only have requested attributes
    for user in resources {
        assert!(user.get("userName").is_some());
        assert!(user.get("id").is_some()); // Always returned
        assert!(user.get("name").is_none()); // Not requested
        assert!(user.get("emails").is_none()); // Not requested
    }
}

#[tokio::test]
async fn test_complex_attribute_filtering() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a test user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "complexuser",
        "name": {
            "givenName": "Complex",
            "familyName": "User",
            "formatted": "Complex User"
        },
        "emails": [{
            "value": "complex@example.com",
            "type": "work",
            "primary": true
        }],
        "active": true
    });

    // Create the user
    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test complex attribute filtering - request only name.givenName
    let response = server
        .get(&format!(
            "/tenant-a/scim/v2/Users/{}?attributes=name.givenName",
            user_id
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let filtered_user: Value = response.json();

    // Should include the name object with only givenName
    assert!(filtered_user.get("name").is_some());
    assert!(filtered_user.get("id").is_some()); // Always returned

    let name_obj = filtered_user["name"].as_object().unwrap();
    assert!(name_obj.get("givenName").is_some());
    assert!(name_obj.get("familyName").is_none()); // Not requested
    assert!(name_obj.get("formatted").is_none()); // Not requested

    // Should not include unrequested top-level attributes
    assert!(filtered_user.get("userName").is_none());
    assert!(filtered_user.get("emails").is_none());
}
