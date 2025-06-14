use axum::http::{header, StatusCode};
use axum_test::TestServer;
use serde_json::json;

mod common;
use common::{create_test_app_config, setup_test_app};

#[tokio::test]
async fn test_create_user_with_scim_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with application/scim+json content type
    let response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice.scim",
            "name": {
                "givenName": "Alice",
                "familyName": "SCIM"
            },
            "emails": [{
                "value": "alice.scim@example.com",
                "primary": true
            }]
        }))
        .await;

    // Should succeed with 201 Created
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    assert_eq!(body["userName"], "alice.scim");
    assert_eq!(body["name"]["givenName"], "Alice");
    assert_eq!(body["name"]["familyName"], "SCIM");
}

#[tokio::test]
async fn test_create_user_with_json_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with regular application/json content type
    let response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "application/json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "bob.json",
            "name": {
                "givenName": "Bob",
                "familyName": "JSON"
            },
            "emails": [{
                "value": "bob.json@example.com",
                "primary": true
            }]
        }))
        .await;

    // Should also succeed with 201 Created
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    assert_eq!(body["userName"], "bob.json");
}

#[tokio::test]
async fn test_create_user_with_scim_json_charset() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with charset parameter
    let response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "application/scim+json; charset=utf-8")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "charlie.charset",
            "name": {
                "givenName": "Charlie",
                "familyName": "Charset"
            },
            "emails": [{
                "value": "charlie@example.com",
                "primary": true
            }]
        }))
        .await;

    // Should succeed with 201 Created
    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    assert_eq!(body["userName"], "charlie.charset");
}

#[tokio::test]
async fn test_create_user_with_invalid_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with invalid content type
    let response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "text/plain")
        .text(r#"{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"invalid"}"#)
        .await;

    // Should fail with 400 Bad Request
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = response.json();
    assert!(body["detail"].as_str().unwrap().contains("Content-Type"));
}

#[tokio::test]
async fn test_update_user_with_scim_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // First create a user
    let create_response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "update.test",
            "name": {
                "givenName": "Update",
                "familyName": "Test"
            }
        }))
        .await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Update with application/scim+json
    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .add_header(header::CONTENT_TYPE, "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "update.test",
            "name": {
                "givenName": "Updated",
                "familyName": "Test"
            }
        }))
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);

    let body: serde_json::Value = update_response.json();
    assert_eq!(body["name"]["givenName"], "Updated");
}

#[tokio::test]
async fn test_create_group_with_scim_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test group creation with application/scim+json
    let response = server
        .post("/scim/v2/Groups")
        .add_header(header::CONTENT_TYPE, "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": "SCIM Test Group"
        }))
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let body: serde_json::Value = response.json();
    assert_eq!(body["displayName"], "SCIM Test Group");
}

#[tokio::test]
async fn test_patch_operations_with_scim_content_type() {
    let app_config = create_test_app_config();
    let app = setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // First create a user
    let create_response = server
        .post("/scim/v2/Users")
        .add_header(header::CONTENT_TYPE, "application/json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "patch.test",
            "name": {
                "givenName": "Patch",
                "familyName": "Test"
            }
        }))
        .await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Patch with application/scim+json
    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .add_header(header::CONTENT_TYPE, "application/scim+json")
        .json(&json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{
                "op": "replace",
                "path": "name.givenName",
                "value": "Patched"
            }]
        }))
        .await;

    assert_eq!(patch_response.status_code(), StatusCode::OK);

    let body: serde_json::Value = patch_response.json();
    assert_eq!(body["name"]["givenName"], "Patched");
}
