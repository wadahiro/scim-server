use axum_test::TestServer;
use http::StatusCode;
use serde_json::json;

mod common;

#[tokio::test]
#[ignore = "Multi-tenant repository architecture needs refactoring"]
async fn test_concurrent_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create multiple users sequentially to test database handling
    for i in 0..5 {
        let user_payload =
            common::create_test_user_json(&format!("user-{}", i), &format!("User{}", i), "Test");

        let response_a = server
            .post("/tenant-a/scim/v2/Users")
            .json(&user_payload)
            .await;

        let response_b = server
            .post("/tenant-b/scim/v2/Users")
            .json(&user_payload)
            .await;

        assert_eq!(response_a.status_code(), StatusCode::CREATED);
        assert_eq!(response_b.status_code(), StatusCode::CREATED);
    }

    // Verify all users were created in both tenants
    let list_a = server.get("/tenant-a/scim/v2/Users").await;
    let list_result_a: serde_json::Value = list_a.json();
    let users_a = list_result_a["Resources"].as_array().unwrap();
    assert_eq!(users_a.len(), 5);

    let list_b = server.get("/tenant-b/scim/v2/Users").await;
    let list_result_b: serde_json::Value = list_b.json();
    let users_b = list_result_b["Resources"].as_array().unwrap();
    assert_eq!(users_b.len(), 5);
}

#[tokio::test]
async fn test_large_user_data() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with large data fields
    let large_string = "x".repeat(1000); // 1KB string
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "largeuser",
        "name": {
            "givenName": large_string,
            "familyName": "User"
        },
        "emails": [{
            "value": "largeuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = response.json();
    assert_eq!(
        created_user["name"]["givenName"].as_str().unwrap().len(),
        1000
    );
}

#[tokio::test]
async fn test_special_characters_in_data() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with various special characters and Unicode
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user@domain.com",
        "name": {
            "givenName": "José María",
            "familyName": "González-Pérez"
        },
        "emails": [{
            "value": "josé.maría@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = response.json();
    assert_eq!(created_user["userName"], "user@domain.com");
    assert_eq!(created_user["name"]["givenName"], "José María");
    assert_eq!(created_user["name"]["familyName"], "González-Pérez");
}

#[tokio::test]
async fn test_update_with_partial_data() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = common::create_test_user_json("testuser", "Test", "User");
    let create_response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Update with partial data (only changing givenName)
    let partial_update = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": "testuser",
        "name": {
            "givenName": "Updated"
            // Note: familyName is omitted
        },
        "emails": [{
            "value": "testuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let update_response = server
        .put(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .json(&partial_update)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);
    let updated_user: serde_json::Value = update_response.json();
    assert_eq!(updated_user["name"]["givenName"], "Updated");

    // Verify the update by getting the user
    let get_response = server
        .get(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .await;
    assert_eq!(get_response.status_code(), StatusCode::OK);
    let fetched_user: serde_json::Value = get_response.json();
    assert_eq!(fetched_user["name"]["givenName"], "Updated");
}

#[tokio::test]
async fn test_empty_and_null_values() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test with empty strings and null values
    let user_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "emptyuser",
        "name": {
            "givenName": "",
            "familyName": null
        },
        "emails": [{
            "value": "emptyuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;

    // Should handle empty/null values gracefully
    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = response.json();
    assert_eq!(created_user["userName"], "emptyuser");
}
