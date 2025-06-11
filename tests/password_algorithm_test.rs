use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_password_algorithm_integration() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Test creating user with password (should be hashed with Argon2id by default)
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "password": "ComplexPassword123!",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
        "emails": [{
            "value": "testuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // Verify password is NOT returned in response (SCIM 2.0 compliance)
    assert!(
        created_user["password"].is_null(),
        "Password should not be returned in API response"
    );

    // Verify user has expected properties
    assert_eq!(created_user["userName"], "testuser");
    assert!(created_user["meta"]["created"].is_string());
    assert!(created_user["meta"]["lastModified"].is_string());
    assert_eq!(created_user["meta"]["resourceType"], "User");

    // Test retrieving user (should also not contain password)
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let retrieved_user: Value = response.json();
    assert!(
        retrieved_user["password"].is_null(),
        "Password should not be returned in GET response"
    );

    // Test updating user with new password (should be hashed)
    let updated_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser",
        "password": "NewComplexPassword456!",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
        "emails": [{
            "value": "testuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&updated_data)
        .await;

    response.assert_status(StatusCode::OK);
    let updated_user: Value = response.json();
    assert!(
        updated_user["password"].is_null(),
        "Password should not be returned in PUT response"
    );

    // Test PATCH password change
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "password",
            "value": "PatchedPassword789!"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_user: Value = response.json();
    assert!(
        patched_user["password"].is_null(),
        "Password should not be returned in PATCH response"
    );

    // Test password validation - weak password should fail
    let weak_password_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "weakuser",
        "password": "weak", // Too short, no uppercase, no numbers, no special chars
        "name": {
            "givenName": "Weak",
            "familyName": "User"
        },
        "emails": [{
            "value": "weakuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&weak_password_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);

    // Test PATCH with weak password should also fail
    let weak_patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "password",
            "value": "weak"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&weak_patch_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_password_algorithms_compatibility() {
    // Test that the default PasswordManager works correctly
    // This test focuses on the public API that is actually used
    let password = "TestPassword123!";

    // Create default PasswordManager (uses Argon2id by default)
    let pm = scim_server::password::PasswordManager::default();

    // Test hashing and validation work
    let hash = pm.hash_password(password).unwrap();
    assert!(
        hash.starts_with("$argon2id$"),
        "Default should use Argon2id algorithm"
    );

    // Test that password validation is working
    assert!(pm.is_hashed_password(&hash), "Should recognize hash format");

    // Test password strength validation is called
    let weak_password_result = pm.hash_password("weak");
    assert!(
        weak_password_result.is_err(),
        "Weak password should be rejected"
    );
}

#[tokio::test]
async fn test_service_provider_config_password_support() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Test ServiceProviderConfig shows password change support
    let response = server
        .get(&format!("/scim/v2/ServiceProviderConfig"))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let config: Value = response.json();

    // Verify password change is supported
    assert_eq!(config["changePassword"]["supported"], true);

    // Verify PATCH is supported (required for password changes)
    assert_eq!(config["patch"]["supported"], true);
}
