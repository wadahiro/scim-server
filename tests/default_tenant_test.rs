use axum_test::TestServer;
use http::StatusCode;

mod common;

/// Test the default tenant functionality where "scim" is used as the default tenant.
/// All requests to /scim/v2/* use the "scim" tenant in the unified routing system.
#[tokio::test]
async fn test_default_tenant_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test default tenant operations - using "scim" tenant via /scim/v2/* routes
    let user_payload = common::create_test_user_json("default-user", "Default", "User");
    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test creating another user in the same scim tenant
    let user_payload_2 = common::create_test_user_json("unified-user-2", "Unified2", "User2");
    let create_response_2 = server.post("/scim/v2/Users").json(&user_payload_2).await;

    assert_eq!(create_response_2.status_code(), StatusCode::CREATED);
    let created_user_2: serde_json::Value = create_response_2.json();
    let user_id_2 = created_user_2["id"].as_str().unwrap();

    // Verify both users exist in scim tenant
    let list_response = server.get("/scim/v2/Users").await;
    assert_eq!(list_response.status_code(), StatusCode::OK);
    let list_result: serde_json::Value = list_response.json();
    let users = list_result["Resources"].as_array().unwrap();
    assert_eq!(users.len(), 2);

    // Test CRUD operations
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(get_response.status_code(), StatusCode::OK);

    let get_response_2 = server.get(&format!("/scim/v2/Users/{}", user_id_2)).await;
    assert_eq!(get_response_2.status_code(), StatusCode::OK);

    // Delete one user
    let delete_response = server
        .delete(&format!("/scim/v2/Users/{}", user_id_2))
        .await;
    assert_eq!(delete_response.status_code(), StatusCode::NO_CONTENT);

    // Verify deletion
    let final_list_response = server.get("/scim/v2/Users").await;
    assert_eq!(final_list_response.status_code(), StatusCode::OK);
    let final_list_result: serde_json::Value = final_list_response.json();
    let final_users = final_list_result["Resources"].as_array().unwrap();
    assert_eq!(final_users.len(), 1);
    assert_eq!(final_users[0]["userName"], "default-user");
}
