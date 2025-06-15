use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_replace_operation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";

    // Create a user first
    let user = common::create_test_user_json("john.doe", "John", "Doe");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Patch the user with replace operation
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "John Updated Doe"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    if patch_response.status_code() != StatusCode::OK {
        let response_text = patch_response.text();
        println!("Patch response status: {}", patch_response.status_code());
        println!("Patch response body: {}", response_text);
    }
    patch_response.assert_status_ok();
    let patched_user: Value = patch_response.json();
    assert_eq!(patched_user["displayName"], "John Updated Doe");
}

#[tokio::test]
async fn test_patch_add_operation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";

    // Create a user first
    let user = common::create_test_user_json("jane.doe", "Jane", "Doe");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Patch the user with add operation
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "nickName",
            "value": "Janie"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status_ok();
    let patched_user: Value = patch_response.json();
    assert_eq!(patched_user["nickName"], "Janie");
}

#[tokio::test]
async fn test_patch_remove_operation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";

    // Create a user with a nickname first
    let mut user = common::create_test_user_json("bob.smith", "Bob", "Smith");
    user["nickName"] = json!("Bobby");

    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify nickname exists
    assert_eq!(created_user["nickName"], "Bobby");

    // Patch the user with remove operation
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "nickName"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status_ok();
    let patched_user: Value = patch_response.json();
    assert!(
        patched_user["nickName"].is_null()
            || !patched_user.as_object().unwrap().contains_key("nickName")
    );
}

#[tokio::test]
async fn test_patch_multiple_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";

    // Create a user first
    let user = common::create_test_user_json("alice.wonder", "Alice", "Wonder");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Patch the user with multiple operations
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "displayName",
                "value": "Alice in Wonderland"
            },
            {
                "op": "add",
                "path": "nickName",
                "value": "Wonder Girl"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status_ok();
    let patched_user: Value = patch_response.json();
    assert_eq!(patched_user["displayName"], "Alice in Wonderland");
    assert_eq!(patched_user["nickName"], "Wonder Girl");
}

#[tokio::test]
async fn test_patch_nonexistent_user() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";
    let fake_user_id = "00000000-0000-0000-0000-000000000000";

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "Should Not Work"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", fake_user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_patch_invalid_operation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "1";

    // Create a user first
    let user = common::create_test_user_json("invalid.test", "Invalid", "Test");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Try to patch with invalid operation
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "invalid_operation",
            "path": "displayName",
            "value": "Should Not Work"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_patch_cross_tenant_isolation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant1 = "tenant-a";
    let tenant2 = "tenant-b";

    // Create a user in tenant1
    let user = common::create_test_user_json("cross.tenant", "Cross", "Tenant");
    let create_response = server
        .post(&format!("/{}/scim/v2/Users", tenant1))
        .json(&user)
        .await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Try to patch the user from tenant2 (should fail)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "Should Not Work"
        }]
    });

    let patch_response = server
        .patch(&format!("/{}/scim/v2/Users/{}", tenant2, user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::NOT_FOUND);
}
