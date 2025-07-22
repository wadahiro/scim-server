use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_hyphen_displayname_search_exact_case() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a group with hyphenated displayName exactly like the user's case
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "GITHUB-test001-users"
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    println!("Create group response status: {}", response.status_code());

    if response.status_code() != StatusCode::CREATED {
        let error: Value = response.json();
        println!(
            "Create error: {}",
            serde_json::to_string_pretty(&error).unwrap()
        );
        panic!("Failed to create group");
    }

    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    println!(
        "Created group: {}",
        serde_json::to_string_pretty(&created_group).unwrap()
    );

    // Test 1: Search with exact case and exact displayName
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22GITHUB-test001-users%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Search exact case - Status: {}", response.status_code());

    if response.status_code() != StatusCode::OK {
        let error: Value = response.json();
        println!(
            "Search error (exact case): {}",
            serde_json::to_string_pretty(&error).unwrap()
        );
    } else {
        let search_results: Value = response.json();
        println!(
            "Search results (exact case): {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );

        assert_eq!(
            search_results["totalResults"].as_u64().unwrap(),
            1,
            "Should find exactly 1 group for exact case search"
        );
    }

    // Test 2: Search with lowercase
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22github-test001-users%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Search lowercase - Status: {}", response.status_code());

    if response.status_code() != StatusCode::OK {
        let error: Value = response.json();
        println!(
            "Search error (lowercase): {}",
            serde_json::to_string_pretty(&error).unwrap()
        );
    } else {
        let search_results: Value = response.json();
        println!(
            "Search results (lowercase): {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );

        assert_eq!(
            search_results["totalResults"].as_u64().unwrap(),
            1,
            "Should find exactly 1 group for case-insensitive search"
        );
    }

    // Test 3: Search with mixed case
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22GitHub-Test001-Users%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!("Search mixed case - Status: {}", response.status_code());

    if response.status_code() != StatusCode::OK {
        let error: Value = response.json();
        println!(
            "Search error (mixed case): {}",
            serde_json::to_string_pretty(&error).unwrap()
        );
    } else {
        let search_results: Value = response.json();
        println!(
            "Search results (mixed case): {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );

        assert_eq!(
            search_results["totalResults"].as_u64().unwrap(),
            1,
            "Should find exactly 1 group for mixed case search"
        );
    }
}

#[tokio::test]
async fn test_multiple_hyphen_groups_search() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create multiple groups with hyphenated names
    let test_groups = vec![
        "GITHUB-test001-users",
        "GITHUB-test002-users",
        "GITLAB-prod-admins",
        "AWS-dev-team",
        "K8S-staging-operators",
        "CI-CD-pipeline-users",
    ];

    // Create all groups
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
            println!("Created group: '{}'", group_name);
        }
    }

    // List all groups to verify they exist
    let response = server
        .get("/scim/v2/Groups")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let all_groups: Value = response.json();
    println!(
        "All groups: {}",
        serde_json::to_string_pretty(&all_groups).unwrap()
    );

    // Test search for each group with exact case
    for group_name in &test_groups {
        let search_url = format!(
            "/scim/v2/Groups?filter=displayName%20eq%20%22{}%22",
            group_name
        );

        let response = server
            .get(&search_url)
            .add_header(http::header::ACCEPT, "application/scim+json")
            .await;

        println!(
            "Searching for '{}' - Status: {}",
            group_name,
            response.status_code()
        );

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
        let search_url = format!(
            "/scim/v2/Groups?filter=displayName%20eq%20%22{}%22",
            lowercase_name
        );

        let response = server
            .get(&search_url)
            .add_header(http::header::ACCEPT, "application/scim+json")
            .await;

        println!(
            "Case-insensitive search for '{}' (as '{}') - Status: {}",
            group_name,
            lowercase_name,
            response.status_code()
        );

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
async fn test_partial_search_with_hyphens() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create the specific group the user mentioned
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "GITHUB-test001-users"
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;
    response.assert_status(StatusCode::CREATED);

    // Test different search operators that might work better

    // Test 1: Contains search
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20co%20%22GITHUB%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Contains search for 'GITHUB' - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "Contains search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
    }

    // Test 2: Starts with search
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20sw%20%22GITHUB%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Starts with search for 'GITHUB' - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "Starts with search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
    }

    // Test 3: Ends with search
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20ew%20%22users%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Ends with search for 'users' - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "Ends with search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
    }

    // Test 4: Search for part with hyphens
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20co%20%22test001%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    println!(
        "Contains search for 'test001' - Status: {}",
        response.status_code()
    );

    if response.status_code() == StatusCode::OK {
        let search_results: Value = response.json();
        println!(
            "Contains 'test001' search results: {}",
            serde_json::to_string_pretty(&search_results).unwrap()
        );
    }
}
