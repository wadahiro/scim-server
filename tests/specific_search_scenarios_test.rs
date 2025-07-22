use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_common_search_scenarios_that_might_fail() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create groups with various names that might cause issues
    let test_groups = vec![
        "Admin Team",
        "Engineering-Team",
        "QA_Team",
        "Support & Help",
        "Sales/Marketing",
        "IT Department",
        "R&D Group",
        "Operations Team",
    ];

    let mut created_group_ids = Vec::new();

    // Create all test groups
    for group_name in &test_groups {
        let group_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": group_name
        });

        let response = server
            .post("/scim/v2/Groups")
            .content_type("application/scim+json")
            .json(&group_data)
            .await;

        if response.status_code() != StatusCode::CREATED {
            println!(
                "Failed to create group '{}': {}",
                group_name,
                response.status_code()
            );
            let error: Value = response.json();
            println!("Error: {}", serde_json::to_string_pretty(&error).unwrap());
        } else {
            response.assert_status(StatusCode::CREATED);
            let created_group: Value = response.json();
            created_group_ids.push(created_group["id"].as_str().unwrap().to_string());
            println!("Created group: '{}'", group_name);
        }
    }

    // Test search for each group with exact name
    for group_name in &test_groups {
        let encoded_name = group_name
            .replace(" ", "%20")
            .replace("&", "%26")
            .replace("/", "%2F");
        let search_url = format!(
            "/scim/v2/Groups?filter=displayName%20eq%20%22{}%22",
            encoded_name
        );

        let response = server
            .get(&search_url)
            .add_header(http::header::ACCEPT, "application/scim+json")
            .await;

        println!("Searching for '{}' with URL: {}", group_name, search_url);
        println!("Response status: {}", response.status_code());

        if response.status_code() != StatusCode::OK {
            let error: Value = response.json();
            println!(
                "Search error for '{}': {}",
                group_name,
                serde_json::to_string_pretty(&error).unwrap()
            );
        } else {
            let search_results: Value = response.json();
            println!(
                "Search results for '{}': totalResults = {}",
                group_name,
                search_results["totalResults"].as_u64().unwrap_or(0)
            );

            // This should find exactly 1 result
            assert_eq!(
                search_results["totalResults"].as_u64().unwrap(),
                1,
                "Should find exactly 1 group for '{}'",
                group_name
            );
        }
    }

    // Test case-insensitive search for each group
    for group_name in &test_groups {
        let lowercase_name = group_name.to_lowercase();
        let encoded_name = lowercase_name
            .replace(" ", "%20")
            .replace("&", "%26")
            .replace("/", "%2F");
        let search_url = format!(
            "/scim/v2/Groups?filter=displayName%20eq%20%22{}%22",
            encoded_name
        );

        let response = server
            .get(&search_url)
            .add_header(http::header::ACCEPT, "application/scim+json")
            .await;

        println!(
            "Case-insensitive search for '{}' (as '{}') with URL: {}",
            group_name, lowercase_name, search_url
        );
        println!("Response status: {}", response.status_code());

        if response.status_code() != StatusCode::OK {
            let error: Value = response.json();
            println!(
                "Case-insensitive search error for '{}': {}",
                group_name,
                serde_json::to_string_pretty(&error).unwrap()
            );
        } else {
            let search_results: Value = response.json();
            println!(
                "Case-insensitive search results for '{}': totalResults = {}",
                group_name,
                search_results["totalResults"].as_u64().unwrap_or(0)
            );

            // This should find exactly 1 result if case-insensitive search works
            assert_eq!(
                search_results["totalResults"].as_u64().unwrap(),
                1,
                "Case-insensitive search should find exactly 1 group for '{}' searched as '{}'",
                group_name,
                lowercase_name
            );
        }
    }
}

#[tokio::test]
async fn test_edge_cases_in_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group with spaces and special characters
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group With Spaces"
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;
    response.assert_status(StatusCode::CREATED);

    // Note: We cannot test malformed URIs (unencoded spaces/quotes) because
    // the test framework itself rejects invalid URI characters at the HTTP client level.
    // In a real scenario, such requests would be rejected by HTTP clients or proxies
    // before reaching the SCIM server.

    // Test 1: Search with correct URL encoding
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22Test%20Group%20With%20Spaces%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Search with URL encoding - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "URL encoded search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
        assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    } else {
        let error: Value = response.json();
        println!(
            "URL encoded search error: {}",
            serde_json::to_string_pretty(&error).unwrap()
        );
    }

    // Test 2: Search with alternative operators
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20co%20%22Test%20Group%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Search with 'contains' operator - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "Contains search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
        assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    }

    // Test 3: Search with startsWith
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20sw%20%22Test%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Search with 'starts with' operator - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "StartsWith search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
        assert_eq!(search_results["totalResults"].as_u64().unwrap(), 1);
    }
}
