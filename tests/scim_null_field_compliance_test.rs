///
/// SCIM 2.0 RFC 7644 Compliance Test for Null Field Handling
///
/// This test ensures that the SCIM server correctly omits unset attributes
/// from JSON responses instead of returning them as null values, as required
/// by RFC 7644 Section 3.4.1.2.
///
use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_user_creation_no_null_fields_regression() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with minimal required fields (only userName)
    // This scenario should NOT include optional fields like name.formatted as null
    let new_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "regression.test.user"
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&new_user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let user_response: Value = response.json();

    // Essential regression test: verify NO null fields exist anywhere
    verify_no_null_fields_recursive(&user_response, "root");

    // Verify required fields are present
    assert!(user_response["id"].is_string());
    assert_eq!(user_response["userName"], "regression.test.user");
    assert!(user_response["schemas"].is_array());

    // Critical check: name object should either be absent OR present without null fields
    if let Some(name_obj) = user_response.get("name") {
        verify_no_null_fields_recursive(name_obj, "name");
        // Specifically verify name.formatted is NOT present with null value
        assert!(
            name_obj.get("formatted").is_none(),
            "name.formatted should be completely absent, not null"
        );
    }
}

#[tokio::test]
async fn test_user_update_partial_name_no_null_fields() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user first
    let new_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "partial.name.user"
    });

    let create_response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&new_user_data)
        .await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Update with partial name data (deliberately omitting formatted, middleName, etc.)
    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": "partial.name.user",
        "name": {
            "givenName": "Partial",
            "familyName": "User"
            // NOTE: deliberately NOT setting formatted, middleName, honorificPrefix, etc.
        }
    });

    let update_response = server
        .put(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .json(&update_data)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);
    let updated_user: Value = update_response.json();

    // Critical regression test
    verify_no_null_fields_recursive(&updated_user, "root");

    // Verify the name object structure
    let name_obj = updated_user["name"].as_object().unwrap();
    assert_eq!(name_obj["givenName"], "Partial");
    assert_eq!(name_obj["familyName"], "User");

    // These fields should be completely absent (not null)
    assert!(name_obj.get("formatted").is_none());
    assert!(name_obj.get("middleName").is_none());
    assert!(name_obj.get("honorificPrefix").is_none());
    assert!(name_obj.get("honorificSuffix").is_none());
}

#[tokio::test]
async fn test_group_creation_no_null_fields_regression() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a minimal group
    let new_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Regression Test Group"
    });

    let response = server
        .post("/tenant-a/scim/v2/Groups")
        .json(&new_group_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let group_response: Value = response.json();

    // Critical regression test
    verify_no_null_fields_recursive(&group_response, "root");

    // Verify required fields
    assert!(group_response["id"].is_string());
    assert_eq!(group_response["displayName"], "Regression Test Group");
    assert!(group_response["schemas"].is_array());
}

#[tokio::test]
async fn test_user_with_empty_arrays_no_null_elements() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with some array fields that might contain null elements
    let new_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "array.test.user",
        "emails": [
            {
                "value": "test@example.com",
                "primary": true
            }
        ]
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&new_user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let user_response: Value = response.json();

    // Verify no null fields anywhere, including in arrays
    verify_no_null_fields_recursive(&user_response, "root");

    // Verify email array structure
    if let Some(emails) = user_response.get("emails") {
        let emails_array = emails.as_array().unwrap();
        for (index, email) in emails_array.iter().enumerate() {
            verify_no_null_fields_recursive(email, &format!("emails[{}]", index));
        }
    }
}

#[tokio::test]
async fn test_patch_operation_no_null_fields() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user first
    let new_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "patch.test.user"
    });

    let create_response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&new_user_data)
        .await;

    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Apply a PATCH operation that adds name information
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "name.givenName",
                "value": "Patch"
            },
            {
                "op": "add",
                "path": "name.familyName",
                "value": "User"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .json(&patch_data)
        .await;

    assert_eq!(patch_response.status_code(), StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Critical: PATCH response should also have no null fields
    verify_no_null_fields_recursive(&patched_user, "root");

    // Verify the patched name structure
    let name_obj = patched_user["name"].as_object().unwrap();
    assert_eq!(name_obj["givenName"], "Patch");
    assert_eq!(name_obj["familyName"], "User");

    // Formatted should still be absent (not null)
    assert!(name_obj.get("formatted").is_none());
}

/// Recursively verify that a JSON value contains absolutely no null fields
/// This is the core regression test function to prevent future null field issues
fn verify_no_null_fields_recursive(value: &Value, path: &str) {
    match value {
        Value::Null => {
            panic!(
                "❌ REGRESSION: Found null value at path '{}' - this violates SCIM 2.0 RFC 7644",
                path
            );
        }
        Value::Object(obj) => {
            for (key, val) in obj {
                let current_path = if path == "root" {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };

                if val.is_null() {
                    panic!("❌ REGRESSION: Found null field '{}' - SCIM requires omitting unset attributes", current_path);
                }
                verify_no_null_fields_recursive(val, &current_path);
            }
        }
        Value::Array(arr) => {
            for (index, item) in arr.iter().enumerate() {
                let current_path = format!("{}[{}]", path, index);
                if item.is_null() {
                    panic!(
                        "❌ REGRESSION: Found null array element at '{}' - this should not happen",
                        current_path
                    );
                }
                verify_no_null_fields_recursive(item, &current_path);
            }
        }
        _ => {
            // String, Number, Boolean are valid
        }
    }
}
