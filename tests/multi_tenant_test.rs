use axum_test::TestServer;
use http::StatusCode;
use serde_json::json;

mod common;

#[tokio::test]
async fn test_tenant_validation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test invalid tenant
    let user_payload = common::create_test_user_json("testuser", "Test", "User");
    let response = server
        .post("/invalid-tenant/v2/Users")
        .json(&user_payload)
        .await;

    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
    // With dynamic routing, invalid tenant paths result in Axum's default 404 response
    // which may not be JSON, so we only check the status code
}

#[tokio::test]
async fn test_multi_tenant_user_isolation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user in tenant-a
    let user_a_payload = common::create_test_user_json("user-a", "Alice", "Smith");
    let response_a = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_a_payload)
        .await;

    assert_eq!(response_a.status_code(), StatusCode::CREATED);
    let user_a: serde_json::Value = response_a.json();
    let user_a_id = user_a["id"].as_str().unwrap();

    // Create user in tenant-b
    let user_b_payload = common::create_test_user_json("user-b", "Bob", "Jones");
    let response_b = server
        .post("/tenant-b/scim/v2/Users")
        .json(&user_b_payload)
        .await;

    assert_eq!(response_b.status_code(), StatusCode::CREATED);
    let user_b: serde_json::Value = response_b.json();
    let user_b_id = user_b["id"].as_str().unwrap();

    // Verify tenant-a can access its own user
    let response = server
        .get(&format!("/tenant-a/scim/v2/Users/{}", user_a_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let fetched_user: serde_json::Value = response.json();
    assert_eq!(fetched_user["userName"], "user-a");

    // Verify tenant-b can access its own user
    let response = server
        .get(&format!("/tenant-b/scim/v2/Users/{}", user_b_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let fetched_user: serde_json::Value = response.json();
    assert_eq!(fetched_user["userName"], "user-b");

    // Verify tenant-a cannot access tenant-b's user
    let response = server
        .get(&format!("/tenant-a/scim/v2/Users/{}", user_b_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Verify tenant-b cannot access tenant-a's user
    let response = server
        .get(&format!("/tenant-b/scim/v2/Users/{}", user_a_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Verify users list for each tenant shows only their users
    let response_a_list = server.get("/tenant-a/scim/v2/Users").await;
    assert_eq!(response_a_list.status_code(), StatusCode::OK);
    let list_result_a: serde_json::Value = response_a_list.json();
    let users_a = list_result_a["Resources"].as_array().unwrap();
    assert_eq!(users_a.len(), 1);
    assert_eq!(users_a[0]["userName"], "user-a");

    let response_b_list = server.get("/tenant-b/scim/v2/Users").await;
    assert_eq!(response_b_list.status_code(), StatusCode::OK);
    let list_result_b: serde_json::Value = response_b_list.json();
    let users_b = list_result_b["Resources"].as_array().unwrap();
    assert_eq!(users_b.len(), 1);
    assert_eq!(users_b[0]["userName"], "user-b");
}

#[tokio::test]
async fn test_multiple_tenants_independence() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create users with same username in different tenants
    let user_payload = common::create_test_user_json("sameuser", "Same", "User");

    // Create in tenant-a
    let response_a = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;
    assert_eq!(response_a.status_code(), StatusCode::CREATED);
    let user_a: serde_json::Value = response_a.json();
    let user_a_id = user_a["id"].as_str().unwrap();

    // Create in tenant-b with same username - should succeed
    let response_b = server
        .post("/tenant-b/scim/v2/Users")
        .json(&user_payload)
        .await;
    assert_eq!(response_b.status_code(), StatusCode::CREATED);
    let user_b: serde_json::Value = response_b.json();
    let user_b_id = user_b["id"].as_str().unwrap();

    // Verify they have different IDs
    assert_ne!(user_a_id, user_b_id);

    // Update user in tenant-a
    let update_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "sameuser",
        "name": {
            "givenName": "Updated",
            "familyName": "UserA"
        },
        "emails": [{
            "value": "sameuser@example.com",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .put(&format!("/tenant-a/scim/v2/Users/{}", user_a_id))
        .json(&update_payload)
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify user in tenant-b is unchanged
    let response = server
        .get(&format!("/tenant-b/scim/v2/Users/{}", user_b_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let user_b_unchanged: serde_json::Value = response.json();
    assert_eq!(user_b_unchanged["name"]["givenName"], "Same");
    assert_eq!(user_b_unchanged["name"]["familyName"], "User");

    // Verify user in tenant-a is updated
    let response = server
        .get(&format!("/tenant-a/scim/v2/Users/{}", user_a_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let user_a_updated: serde_json::Value = response.json();
    assert_eq!(user_a_updated["name"]["givenName"], "Updated");
    assert_eq!(user_a_updated["name"]["familyName"], "UserA");

    // Delete user from tenant-a
    let response = server
        .delete(&format!("/tenant-a/scim/v2/Users/{}", user_a_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::NO_CONTENT);

    // Verify user in tenant-b still exists
    let response = server
        .get(&format!("/tenant-b/scim/v2/Users/{}", user_b_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    // Verify user in tenant-a is gone
    let response = server
        .get(&format!("/tenant-a/scim/v2/Users/{}", user_a_id))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_tenant_case_sensitivity() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_payload = common::create_test_user_json("testuser", "Test", "User");

    // Test case sensitivity - should fail for different cases
    let response = server.post("/TENANT-A/v2/Users").json(&user_payload).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let response = server.post("/Tenant-A/v2/Users").json(&user_payload).await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    // Should work with exact case
    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&user_payload)
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);
}
