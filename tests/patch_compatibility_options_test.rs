use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};
use scim_server::config::CompatibilityConfig;

mod common;

#[tokio::test]
async fn test_patch_replace_empty_array_allowed_by_default() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with empty array (should work by default)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Should succeed by default
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();
    
    // Emails should be removed
    assert!(patched_user.get("emails").is_none());
}

#[tokio::test]
async fn test_patch_replace_empty_array_disabled() {
    // Create config with empty array support disabled
    let mut tenant_config = common::create_test_app_config();
    tenant_config.tenants[2].compatibility = Some(CompatibilityConfig {
        support_patch_replace_empty_array: false,
        ..Default::default()
    });
    
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with empty array (should be rejected)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Should be rejected with 400
    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let error_response: Value = patch_response.json();
    
    // Verify SCIM-compliant error response
    assert_eq!(error_response["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error");
    assert_eq!(error_response["scimType"], "unsupported");
    assert_eq!(error_response["status"], "400");
    assert!(error_response["detail"].as_str().unwrap().contains("empty array is not supported"));
}

#[tokio::test]
async fn test_patch_replace_empty_value_disabled_by_default() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with empty value pattern (should be rejected by default)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": [{"value": ""}]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Should be rejected with 400 by default
    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let error_response: Value = patch_response.json();
    
    // Verify SCIM-compliant error response
    assert_eq!(error_response["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:Error");
    assert_eq!(error_response["scimType"], "unsupported");
    assert_eq!(error_response["status"], "400");
    assert!(error_response["detail"].as_str().unwrap().contains("empty value pattern is not supported"));
}

#[tokio::test]
async fn test_patch_replace_empty_value_enabled() {
    // Create config with empty value pattern support enabled
    let mut tenant_config = common::create_test_app_config();
    tenant_config.tenants[2].compatibility = Some(CompatibilityConfig {
        support_patch_replace_empty_value: true,
        ..Default::default()
    });
    
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with empty value pattern (should work when enabled)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": [{"value": ""}]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Should succeed when enabled
    // Note: The actual clearing is handled by the patch parser when the compatibility option is enabled
    patch_response.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn test_patch_replace_normal_values_always_allowed() {
    // Create config with empty array support disabled
    let mut tenant_config = common::create_test_app_config();
    tenant_config.tenants[2].compatibility = Some(CompatibilityConfig {
        support_patch_replace_empty_array: false,
        support_patch_replace_empty_value: false,
        ..Default::default()
    });
    
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "old@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with normal values (should always work)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": [
                    {"value": "new@example.com", "type": "work", "primary": true}
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Should always succeed with normal values
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();
    
    // Should have the new email
    let emails = patched_user["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0]["value"], "new@example.com");
}

#[tokio::test]
async fn test_patch_remove_operations_not_affected() {
    // Create config with empty array support disabled
    let mut tenant_config = common::create_test_app_config();
    tenant_config.tenants[2].compatibility = Some(CompatibilityConfig {
        support_patch_replace_empty_array: false,
        support_patch_replace_empty_value: false,
        ..Default::default()
    });
    
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with remove operation (should not be affected by compatibility settings)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "emails"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    
    // Remove operations should not be affected by these compatibility settings
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();
    
    // Emails should be removed
    assert!(patched_user.get("emails").is_none());
}