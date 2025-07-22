use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_group_search_by_displayname_should_not_return_409() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group first
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineering Team"
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Test 1: Search for groups with filter (should work normally)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%20Team%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with search results, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();

    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 1);
    assert_eq!(
        search_results["Resources"][0]["displayName"]
            .as_str()
            .unwrap(),
        "Engineering Team"
    );

    // Test 2: Search with case-insensitive filter (should work normally)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22engineering%20team%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with search results, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();

    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 1);

    // Test 3: Get specific group by ID (should work normally)
    let response = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with the group, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let group: Value = response.json();
    assert_eq!(group["displayName"].as_str().unwrap(), "Engineering Team");

    // Test 4: List all groups (should work normally)
    let response = server
        .get("/scim/v2/Groups")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with group list, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let groups: Value = response.json();
    assert!(groups["totalResults"].as_u64().unwrap() >= 1);

    // Test 5: NOW try to create a duplicate group (THIS should return 409)
    let duplicate_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "ENGINEERING TEAM" // Different case
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&duplicate_group_data)
        .await;

    // Only POST operations should return 409 for duplicates
    response.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response.json();
    assert_eq!(error_response["status"].as_str().unwrap(), "409");
    assert_eq!(error_response["scimType"].as_str().unwrap(), "uniqueness");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("Group with this displayName already exists"));
}

#[tokio::test]
async fn test_user_search_by_username_should_not_return_409() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user first
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser@example.com",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test 1: Search for users with filter (should work normally)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22testuser@example.com%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with search results, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();

    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 1);

    // Test 2: Search with case-insensitive filter (should work normally)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22TESTUSER@EXAMPLE.COM%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with search results, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();

    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 1);

    // Test 3: Get specific user by ID (should work normally)
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with the user, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let user: Value = response.json();
    assert_eq!(user["userName"].as_str().unwrap(), "testuser@example.com");

    // Test 4: List all users (should work normally)
    let response = server
        .get("/scim/v2/Users")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    // This should return 200 OK with user list, NOT 409 Conflict
    response.assert_status(StatusCode::OK);
    let users: Value = response.json();
    assert!(users["totalResults"].as_u64().unwrap() >= 1);

    // Test 5: NOW try to create a duplicate user (THIS should return 409)
    let duplicate_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "TESTUSER@EXAMPLE.COM", // Different case
        "name": {
            "givenName": "Another",
            "familyName": "User"
        }
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&duplicate_user_data)
        .await;

    // Only POST operations should return 409 for duplicates
    response.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response.json();
    assert_eq!(error_response["status"].as_str().unwrap(), "409");
    assert_eq!(error_response["scimType"].as_str().unwrap(), "uniqueness");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("User with this userName already exists"));
}

#[tokio::test]
async fn test_search_non_existent_resources_should_return_empty_results() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test 1: Search for non-existent group (should return empty results, not 409)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22NonExistentGroup%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();
    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 0);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 0);

    // Test 2: Search for non-existent user (should return empty results, not 409)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22nonexistent@example.com%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_results: Value = response.json();
    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 0);
    assert_eq!(search_results["Resources"].as_array().unwrap().len(), 0);

    // Test 3: Get non-existent group by ID (should return 404, not 409)
    let response = server
        .get("/scim/v2/Groups/00000000-0000-0000-0000-000000000000")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::NOT_FOUND);

    // Test 4: Get non-existent user by ID (should return 404, not 409)
    let response = server
        .get("/scim/v2/Users/00000000-0000-0000-0000-000000000000")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}
