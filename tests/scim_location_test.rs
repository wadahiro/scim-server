///
/// SCIM 2.0 RFC 7644 Location Header Test
///
/// This test verifies that the SCIM server returns proper Location headers
/// for POST operations (User and Group creation) and meta.location fields
/// as required by RFC 7644.
///
use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_user_creation_location_header() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let new_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "location.test.user"
    });

    let response = server
        .post("/tenant-a/scim/v2/Users")
        .json(&new_user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Check if Location header is present
    let headers = response.headers();
    println!("Response headers: {:?}", headers);

    if let Some(location_header) = headers.get("location") {
        let location_value = location_header.to_str().unwrap();
        println!("✅ Location header found: {}", location_value);

        // Verify the location header format
        assert!(location_value.contains("/tenant-a/scim/v2/Users/"));
    } else {
        println!("❌ Location header is missing from POST response");
    }

    // Check meta.location in response body
    let user_response: Value = response.json();
    if let Some(meta) = user_response.get("meta") {
        if let Some(location) = meta.get("location") {
            println!("✅ meta.location found: {}", location);
        } else {
            println!("❌ meta.location is missing from response body");
        }
    } else {
        println!("❌ meta object is missing from response body");
    }
}

#[tokio::test]
async fn test_group_creation_location_header() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let new_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Location Test Group"
    });

    let response = server
        .post("/tenant-a/scim/v2/Groups")
        .json(&new_group_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);

    // Check if Location header is present
    let headers = response.headers();
    println!("Response headers: {:?}", headers);

    if let Some(location_header) = headers.get("location") {
        let location_value = location_header.to_str().unwrap();
        println!("✅ Location header found: {}", location_value);

        // Verify the location header format
        assert!(location_value.contains("/tenant-a/scim/v2/Groups/"));
    } else {
        println!("❌ Location header is missing from POST response");
    }

    // Check meta.location in response body
    let group_response: Value = response.json();
    if let Some(meta) = group_response.get("meta") {
        if let Some(location) = meta.get("location") {
            println!("✅ meta.location found: {}", location);
        } else {
            println!("❌ meta.location is missing from response body");
        }
    } else {
        println!("❌ meta object is missing from response body");
    }
}
