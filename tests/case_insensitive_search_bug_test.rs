use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_group_displayname_case_insensitive_search_bug() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group with specific case
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

    println!(
        "Created group: {}",
        serde_json::to_string_pretty(&created_group).unwrap()
    );

    // Test 1: Search with exact case (should work)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%20Team%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for exact case: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for exact case: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    response.assert_status(StatusCode::OK);
    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);

    // Test 2: Search with different case (this might be failing)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22engineering%20team%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for lowercase: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for lowercase: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // This should work if case-insensitive search is implemented correctly
    response.assert_status(StatusCode::OK);
    assert_eq!(
        search_results["totalResults"].as_u64().unwrap(),
        1,
        "Case-insensitive search should find the group created with different case"
    );

    // Test 3: Search with UPPERCASE (this might be failing)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22ENGINEERING%20TEAM%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for uppercase: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for uppercase: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // This should work if case-insensitive search is implemented correctly
    response.assert_status(StatusCode::OK);
    assert_eq!(
        search_results["totalResults"].as_u64().unwrap(),
        1,
        "Case-insensitive search should find the group created with different case"
    );

    // Test 4: Search with mixed case (this might be failing)
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22Engineering%20TEAM%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for mixed case: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for mixed case: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // This should work if case-insensitive search is implemented correctly
    response.assert_status(StatusCode::OK);
    assert_eq!(
        search_results["totalResults"].as_u64().unwrap(),
        1,
        "Case-insensitive search should find the group created with different case"
    );
}

#[tokio::test]
async fn test_user_username_case_insensitive_search_bug() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user with specific case
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "TestUser@Example.COM",
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

    println!(
        "Created user: {}",
        serde_json::to_string_pretty(&created_user).unwrap()
    );

    // Test 1: Search with exact case (should work)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22TestUser@Example.COM%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for exact case: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for exact case: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    response.assert_status(StatusCode::OK);
    assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);

    // Test 2: Search with different case (this might be failing)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22testuser@example.com%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for lowercase: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for lowercase: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // This should work if case-insensitive search is implemented correctly
    response.assert_status(StatusCode::OK);
    assert_eq!(
        search_results["totalResults"].as_u64().unwrap(),
        1,
        "Case-insensitive search should find the user created with different case"
    );

    // Test 3: Search with UPPERCASE (this might be failing)
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22TESTUSER@EXAMPLE.COM%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Response status for uppercase: {}", response.status_code());
    let search_results: Value = response.json();
    println!(
        "Search results for uppercase: {}",
        serde_json::to_string_pretty(&search_results).unwrap()
    );

    // This should work if case-insensitive search is implemented correctly
    response.assert_status(StatusCode::OK);
    assert_eq!(
        search_results["totalResults"].as_u64().unwrap(),
        1,
        "Case-insensitive search should find the user created with different case"
    );
}

#[tokio::test]
async fn test_list_all_resources_to_verify_existence() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group
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

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "TestUser@Example.COM",
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

    // List all groups to verify they exist
    let response = server
        .get("/scim/v2/Groups")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let groups: Value = response.json();
    println!(
        "All groups: {}",
        serde_json::to_string_pretty(&groups).unwrap()
    );

    assert!(groups["totalResults"].as_u64().unwrap() >= 1);

    // List all users to verify they exist
    let response = server
        .get("/scim/v2/Users")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let users: Value = response.json();
    println!(
        "All users: {}",
        serde_json::to_string_pretty(&users).unwrap()
    );

    assert!(users["totalResults"].as_u64().unwrap() >= 1);
}
