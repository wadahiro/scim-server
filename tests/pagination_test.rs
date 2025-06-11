use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_pagination_basic() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create multiple users for pagination testing
    let users_data = vec![
        ("alice.smith", "Alice", "Smith"),
        ("bob.jones", "Bob", "Jones"),
        ("charlie.brown", "Charlie", "Brown"),
        ("diana.prince", "Diana", "Prince"),
        ("edward.norton", "Edward", "Norton"),
        ("fiona.green", "Fiona", "Green"),
        ("george.white", "George", "White"),
        ("helen.black", "Helen", "Black"),
    ];

    // Create all users
    for (username, given_name, family_name) in &users_data {
        let user = common::create_test_user_json(username, given_name, family_name);
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test basic pagination with count=3
    let response = server
        .get(&format!("/scim/v2/Users?count=3"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 8);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 3);
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 1);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_pagination_start_index() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 5 users
    let users_data = vec![
        ("user1", "User", "One"),
        ("user2", "User", "Two"),
        ("user3", "User", "Three"),
        ("user4", "User", "Four"),
        ("user5", "User", "Five"),
    ];

    for (username, given_name, family_name) in &users_data {
        let user = common::create_test_user_json(username, given_name, family_name);
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test pagination starting from index 3, count=2
    let response = server
        .get(&format!("/scim/v2/Users?startIndex=3&count=2"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 5);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 2);
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 3);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_pagination_last_page() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 7 users
    for i in 1..=7 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("Number{}", i)
        );
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test last page: startIndex=6, count=3 (should return only 2 items)
    let response = server
        .get(&format!("/scim/v2/Users?startIndex=6&count=3"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 7);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 2); // Only 2 items available
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 6);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_pagination_out_of_bounds() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 3 users
    for i in 1..=3 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("Number{}", i)
        );
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test startIndex beyond available users
    let response = server
        .get(&format!("/scim/v2/Users?startIndex=10&count=2"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 3);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 0);
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 10);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_pagination_default_values() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 5 users
    for i in 1..=5 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("Number{}", i)
        );
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test default pagination (no parameters)
    let response = server
        .get(&format!("/scim/v2/Users"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 5);
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 1);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 5);
    
    // itemsPerPage should equal the number of returned items when no count is specified
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 5);
}

#[tokio::test]
async fn test_pagination_zero_count() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 3 users
    for i in 1..=3 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("Number{}", i)
        );
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test count=0 (should return no items but correct metadata)
    let response = server
        .get(&format!("/scim/v2/Users?count=0"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 3);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 0);
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 1);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_pagination_large_count() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create 3 users
    for i in 1..=3 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("Number{}", i)
        );
        let response = server
            .post(&format!("/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test count=100 (larger than available users)
    let response = server
        .get(&format!("/scim/v2/Users?count=100"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    assert_eq!(list_response["totalResults"].as_i64().unwrap(), 3);
    assert_eq!(list_response["itemsPerPage"].as_i64().unwrap(), 3); // Only 3 items available
    assert_eq!(list_response["startIndex"].as_i64().unwrap(), 1);
    assert_eq!(list_response["Resources"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_pagination_multi_tenant_isolation() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create users in tenant-a
    for i in 1..=5 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("NumberA{}", i)
        );
        let response = server
            .post(&format!("/tenant-a/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Create users in tenant-b
    for i in 1..=3 {
        let user = common::create_test_user_json(
            &format!("user{}", i),
            "User",
            &format!("NumberB{}", i)
        );
        let response = server
            .post(&format!("/tenant-b/scim/v2/Users"))
            .json(&user)
            .await;
        response.assert_status(StatusCode::CREATED);
    }

    // Test pagination for tenant-a
    let response = server
        .get("/tenant-a/scim/v2/Users?count=2")
        .await;
    response.assert_status_ok();
    
    let list_response_a: Value = response.json();
    assert_eq!(list_response_a["totalResults"].as_i64().unwrap(), 5);
    assert_eq!(list_response_a["itemsPerPage"].as_i64().unwrap(), 2);

    // Test pagination for tenant-b
    let response = server
        .get("/tenant-b/scim/v2/Users?count=2")
        .await;
    response.assert_status_ok();
    
    let list_response_b: Value = response.json();
    assert_eq!(list_response_b["totalResults"].as_i64().unwrap(), 3);
    assert_eq!(list_response_b["itemsPerPage"].as_i64().unwrap(), 2);

    // Verify tenant isolation - each tenant should only see their own users
    assert_ne!(
        list_response_a["totalResults"], 
        list_response_b["totalResults"]
    );
}

#[tokio::test]
async fn test_pagination_response_schema() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "1";

    // Create a user
    let user = common::create_test_user_json("testuser", "Test", "User");
    let response = server
        .post(&format!("/scim/v2/Users"))
        .json(&user)
        .await;
    response.assert_status(StatusCode::CREATED);

    // Test pagination response structure
    let response = server
        .get(&format!("/scim/v2/Users?count=1"))
        .await;
    response.assert_status_ok();
    
    let list_response: Value = response.json();
    
    // Verify required SCIM ListResponse fields
    assert!(list_response.get("schemas").is_some());
    assert!(list_response.get("totalResults").is_some());
    assert!(list_response.get("startIndex").is_some());
    assert!(list_response.get("itemsPerPage").is_some());
    assert!(list_response.get("Resources").is_some());
    
    // Verify schema
    let schemas = list_response["schemas"].as_array().unwrap();
    assert!(schemas.contains(&json!("urn:ietf:params:scim:api:messages:2.0:ListResponse")));
    
    // Verify Resources is an array
    assert!(list_response["Resources"].is_array());
}
