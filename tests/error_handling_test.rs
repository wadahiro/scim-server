use axum_test::TestServer;
use http::StatusCode;
use serde_json::json;

mod common;

#[tokio::test]
async fn test_user_not_found() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test getting non-existent user
    let response = server.get("/tenant-a/scim/v2/Users/non-existent-id").await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    let json: serde_json::Value = response.json();
    assert!(json["message"].as_str().unwrap().contains("User not found"));

    // Test updating non-existent user
    let update_payload = common::create_test_user_json("test", "Test", "User");
    let update_response = server
        .put("/tenant-a/scim/v2/Users/non-existent-id")
        .json(&update_payload)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::NOT_FOUND);

    // Test deleting non-existent user
    let delete_response = server.delete("/tenant-a/scim/v2/Users/non-existent-id").await;

    assert_eq!(delete_response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_empty_tenant_list() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test empty user list for each tenant
    let response_a = server.get("/tenant-a/scim/v2/Users").await;
    assert_eq!(response_a.status_code(), StatusCode::OK);
    let list_result_a: serde_json::Value = response_a.json();
    let users_a = list_result_a["Resources"].as_array().unwrap();
    assert_eq!(users_a.len(), 0);

    let response_b = server.get("/tenant-b/scim/v2/Users").await;
    assert_eq!(response_b.status_code(), StatusCode::OK);
    let list_result_b: serde_json::Value = response_b.json();
    let users_b = list_result_b["Resources"].as_array().unwrap();
    assert_eq!(users_b.len(), 0);

    let response_scim = server.get("/scim/v2/Users").await;
    assert_eq!(response_scim.status_code(), StatusCode::OK);
    let list_result_scim: serde_json::Value = response_scim.json();
    let users_scim = list_result_scim["Resources"].as_array().unwrap();
    assert_eq!(users_scim.len(), 0);

    // This test verifies that the unified routing system works
    // All requests now go through the /:tenant_id/v2/Users pattern
}

#[tokio::test]
async fn test_invalid_user_data() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test creating user with missing required fields
    let invalid_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        // Missing userName field
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&invalid_payload)
        .await;

    // Should return a 400 Bad Request for invalid data
    assert!(
        response.status_code() == StatusCode::BAD_REQUEST
            || response.status_code() == StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn test_malformed_json() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with malformed JSON
    let response = server
        .post("/tenant-a/scim/v2/Users")
        .add_header("content-type", "application/json")
        .text("{invalid json}")
        .await;

    // Accept either 400 (Bad Request) or 415 (Unsupported Media Type) for malformed JSON
    assert!(
        response.status_code() == StatusCode::BAD_REQUEST
            || response.status_code() == StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}
