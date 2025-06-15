/// SCIM 2.0 ETag/Version implementation tests
///
/// This test suite covers the complete ETag/Version functionality:
/// - Phase 1: meta.version in responses
/// - Phase 2: ETag response headers  
/// - Phase 3: Conditional requests (If-Match, If-None-Match)
///
/// Tests follow RFC 7644 SCIM 2.0 specification
use axum_test::TestServer;
use http::StatusCode;
use serde_json::json;

mod common;

// Test helper to extract ETag from response headers
fn extract_etag(response: &axum_test::TestResponse) -> Option<String> {
    response
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[tokio::test]
async fn test_phase1_user_create_has_version() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let response = server.post("/scim/v2/Users").json(&user_payload).await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    let created_user: serde_json::Value = response.json();

    // Phase 1: Check meta.version is present and correctly formatted
    assert!(created_user["meta"]["version"].is_string());
    let version = created_user["meta"]["version"].as_str().unwrap();
    assert!(version.starts_with("W/\""));
    assert!(version.ends_with("\""));
    assert_eq!(version, "W/\"1\""); // First version should be 1
}

#[tokio::test]
async fn test_phase1_user_get_has_version() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user first
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Get user
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;

    assert_eq!(get_response.status_code(), StatusCode::OK);

    let user: serde_json::Value = get_response.json();

    // Phase 1: Check meta.version is present
    assert_eq!(user["meta"]["version"], "W/\"1\"");
}

#[tokio::test]
async fn test_phase2_user_create_has_etag_header() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let response = server.post("/scim/v2/Users").json(&user_payload).await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Phase 2: Check ETag header is present
    let etag = extract_etag(&response);
    assert!(etag.is_some());
    assert_eq!(etag.unwrap(), "W/\"1\"");
}

#[tokio::test]
async fn test_phase2_user_get_has_etag_header() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user first
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Get user
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;

    assert_eq!(get_response.status_code(), StatusCode::OK);

    // Phase 2: Check ETag header is present
    let etag = extract_etag(&get_response);
    assert!(etag.is_some());
    assert_eq!(etag.unwrap(), "W/\"1\"");
}

#[tokio::test]
async fn test_phase3_user_update_with_matching_if_match_succeeds() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let initial_etag = extract_etag(&create_response).unwrap();

    // Update user with correct If-Match header
    let update_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "updated@example.com", "type": "work", "primary": true}]
    });

    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", initial_etag)
        .json(&update_payload)
        .await;

    // Phase 3: Update should succeed with matching If-Match
    assert_eq!(update_response.status_code(), StatusCode::OK);

    // Version should be incremented
    let new_etag = extract_etag(&update_response).unwrap();
    assert_eq!(new_etag, "W/\"2\"");

    let updated_user: serde_json::Value = update_response.json();
    assert_eq!(updated_user["meta"]["version"], "W/\"2\"");
}

#[tokio::test]
async fn test_phase3_user_update_with_mismatched_if_match_fails_412() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Update user with incorrect If-Match header
    let update_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "updated@example.com", "type": "work", "primary": true}]
    });

    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", "W/\"999\"") // Wrong version
        .json(&update_payload)
        .await;

    // Phase 3: Should return 412 Precondition Failed
    assert_eq!(
        update_response.status_code(),
        StatusCode::PRECONDITION_FAILED
    );

    let error_response: serde_json::Value = update_response.json();

    // Check SCIM error format
    assert_eq!(
        error_response["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(error_response["status"], "412");
    assert_eq!(error_response["scimType"], "preconditionFailed");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("version mismatch"));
}

#[tokio::test]
async fn test_phase3_user_get_with_matching_if_none_match_returns_304() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let etag = extract_etag(&create_response).unwrap();

    // Get user with If-None-Match header (same version)
    let get_response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-none-match", etag)
        .await;

    // Phase 3: Should return 304 Not Modified
    assert_eq!(get_response.status_code(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn test_phase3_user_get_with_different_if_none_match_returns_200() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Get user with If-None-Match header (different version)
    let get_response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-none-match", "W/\"999\"") // Different version
        .await;

    // Phase 3: Should return 200 OK with content
    assert_eq!(get_response.status_code(), StatusCode::OK);

    let etag = extract_etag(&get_response).unwrap();
    assert_eq!(etag, "W/\"1\"");
}

#[tokio::test]
async fn test_phase3_user_delete_with_matching_if_match_succeeds() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let etag = extract_etag(&create_response).unwrap();

    // Delete user with correct If-Match header
    let delete_response = server
        .delete(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", etag)
        .await;

    // Phase 3: Delete should succeed
    assert_eq!(delete_response.status_code(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_phase3_user_patch_with_if_match() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let etag = extract_etag(&create_response).unwrap();

    // PATCH user with If-Match header
    let patch_payload = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails[type eq \"work\"].value",
                "value": "patched@example.com"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", etag)
        .json(&patch_payload)
        .await;

    // Phase 3: PATCH should succeed and increment version
    assert_eq!(patch_response.status_code(), StatusCode::OK);

    let new_etag = extract_etag(&patch_response).unwrap();
    assert_eq!(new_etag, "W/\"2\"");
}

#[tokio::test]
async fn test_concurrent_update_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "test@example.com", "type": "work", "primary": true}]
    });

    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let initial_etag = extract_etag(&create_response).unwrap();

    // First update succeeds
    let update1_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "update1@example.com", "type": "work", "primary": true}]
    });

    let update1_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", &initial_etag)
        .json(&update1_payload)
        .await;

    assert_eq!(update1_response.status_code(), StatusCode::OK);

    // Second update with same old ETag should fail
    let update2_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "emails": [{"value": "update2@example.com", "type": "work", "primary": true}]
    });

    let update2_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .add_header("if-match", &initial_etag) // Same old ETag - should fail
        .json(&update2_payload)
        .await;

    assert_eq!(
        update2_response.status_code(),
        StatusCode::PRECONDITION_FAILED
    );
}

// Group tests (similar pattern)
#[tokio::test]
async fn test_group_version_functionality() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create group
    let group_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group"
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_payload).await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);

    // Check version and ETag
    let etag = extract_etag(&create_response).unwrap();
    assert_eq!(etag, "W/\"1\"");

    let created_group: serde_json::Value = create_response.json();
    assert_eq!(created_group["meta"]["version"], "W/\"1\"");
}
