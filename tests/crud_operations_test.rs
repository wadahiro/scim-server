use axum_test::TestServer;
use http::StatusCode;
use serde_json::json;

mod common;

#[tokio::test]
async fn test_tenant_crud_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user
    let user_payload = common::create_test_user_json("testuser", "Test", "User");
    let create_response = server.post("/tenant-a/scim/v2/Users").json(&user_payload).await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    assert_eq!(created_user["userName"], "testuser");
    assert_eq!(created_user["name"]["givenName"], "Test");
    assert_eq!(created_user["name"]["familyName"], "User");

    // Read user
    let get_response = server.get(&format!("/tenant-a/scim/v2/Users/{}", user_id)).await;

    assert_eq!(get_response.status_code(), StatusCode::OK);
    let fetched_user: serde_json::Value = get_response.json();
    assert_eq!(fetched_user["id"], user_id);
    assert_eq!(fetched_user["userName"], "testuser");

    // Update user
    let update_payload = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": "updateduser",
        "name": {
            "givenName": "Updated",
            "familyName": "User"
        },
        "emails": [{
            "value": "updated@example.com",
            "primary": true
        }],
        "active": true
    });

    let update_response = server
        .put(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .json(&update_payload)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);
    let updated_user: serde_json::Value = update_response.json();
    assert_eq!(updated_user["userName"], "updateduser");
    assert_eq!(updated_user["name"]["givenName"], "Updated");

    // List users
    let list_response = server.get("/tenant-a/scim/v2/Users").await;
    assert_eq!(list_response.status_code(), StatusCode::OK);
    let list_result: serde_json::Value = list_response.json();
    
    // Verify SCIM list response structure
    assert_eq!(list_result["totalResults"], 1);
    assert_eq!(list_result["startIndex"], 1);
    assert_eq!(list_result["itemsPerPage"], 1);
    assert!(list_result["Resources"].is_array());
    
    let users = list_result["Resources"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["userName"], "updateduser");

    // Delete user
    let delete_response = server
        .delete(&format!("/tenant-a/scim/v2/Users/{}", user_id))
        .await;

    assert_eq!(delete_response.status_code(), StatusCode::NO_CONTENT);

    // Verify user is deleted
    let get_deleted_response = server.get(&format!("/tenant-a/scim/v2/Users/{}", user_id)).await;

    assert_eq!(get_deleted_response.status_code(), StatusCode::NOT_FOUND);

    // Verify empty user list
    let final_list_response = server.get("/tenant-a/scim/v2/Users").await;
    assert_eq!(final_list_response.status_code(), StatusCode::OK);
    let final_list_result: serde_json::Value = final_list_response.json();
    
    // Verify SCIM list response structure for empty list
    assert_eq!(final_list_result["totalResults"], 0);
    assert_eq!(final_list_result["startIndex"], 1);
    assert_eq!(final_list_result["itemsPerPage"], 0);
    assert!(final_list_result["Resources"].is_array());
    
    let final_users = final_list_result["Resources"].as_array().unwrap();
    assert_eq!(final_users.len(), 0);
}
