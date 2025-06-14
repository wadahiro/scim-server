use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_create_group_with_non_existent_user_should_fail() {
    // Use default configuration (equivalent to running without -c flag)
    let app_config = scim_server::config::AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Attempt to create a group with a non-existent user
    let group_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "TestGroup",
        "members": [{
            "value": "non-existent-user-id",
            "type": "User"
        }]
    });

    let response = server.post("/scim/v2/Groups").json(&group_payload).await;
    
    // Should return 400 Bad Request
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let error_response: Value = response.json();
    
    // Should be SCIM error format
    assert_eq!(error_response["schemas"], json!(["urn:ietf:params:scim:api:messages:2.0:Error"]));
    assert_eq!(error_response["scimType"], "invalidValue");
    assert_eq!(error_response["status"], "400");
    assert!(error_response["detail"].as_str().unwrap().contains("User with id 'non-existent-user-id' does not exist"));
}

#[tokio::test]
async fn test_create_group_with_existing_user_should_succeed() {
    // Use default configuration
    let app_config = scim_server::config::AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // First create a user
    let user_payload = common::create_test_user_json("testuser", "Test", "User");
    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap().to_string();

    // Create a group with the existing user
    let group_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "TestGroup",
        "members": [{
            "value": user_id,
            "type": "User"
        }]
    });

    let response = server.post("/scim/v2/Groups").json(&group_payload).await;
    
    // Should succeed
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let group_response: Value = response.json();
    
    assert_eq!(group_response["displayName"], "TestGroup");
    assert_eq!(group_response["members"][0]["value"], user_id);
}

