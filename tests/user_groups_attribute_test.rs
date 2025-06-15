use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_user_groups_attribute() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test.user@example.com",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
        "displayName": "Test User"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let user: Value = response.json();
    let user_id = user["id"].as_str().unwrap();

    // Initially, user should have no groups
    assert!(user["groups"].is_null() || user["groups"].as_array().is_none_or(|g| g.is_empty()));

    // Create two groups
    let group1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Engineering Team"
    });

    let group2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Product Team"
    });

    let response1 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group1_data)
        .await;
    response1.assert_status(StatusCode::CREATED);
    let group1: Value = response1.json();
    let group1_id = group1["id"].as_str().unwrap();

    let response2 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group2_data)
        .await;
    response2.assert_status(StatusCode::CREATED);
    let group2: Value = response2.json();
    let group2_id = group2["id"].as_str().unwrap();

    // Add user to both groups
    let patch_data1 = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": user_id,
                        "type": "User"
                    }
                ]
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group1_id))
        .content_type("application/scim+json")
        .json(&patch_data1)
        .await;
    response.assert_status(StatusCode::OK);

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group2_id))
        .content_type("application/scim+json")
        .json(&patch_data1)
        .await;
    response.assert_status(StatusCode::OK);

    // Get user by ID - should now have groups populated
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let user: Value = response.json();

    // Verify groups attribute is populated
    assert!(user["groups"].is_array());
    let groups = user["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);

    // Verify group structure
    for group in groups {
        assert!(group["value"].is_string());
        assert!(group["$ref"].is_string());
        assert!(group["display"].is_string());
        assert_eq!(group["type_"], "direct");

        let group_id = group["value"].as_str().unwrap();
        assert!(group_id == group1_id || group_id == group2_id);

        let display = group["display"].as_str().unwrap();
        assert!(display == "Engineering Team" || display == "Product Team");

        // Verify $ref format
        let ref_url = group["$ref"].as_str().unwrap();
        assert!(ref_url.ends_with(&format!("/Groups/{}", group_id)));
    }

    // Test listing all users - groups should be populated
    let response = server
        .get("/scim/v2/Users")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let list_response: Value = response.json();
    let users = list_response["Resources"].as_array().unwrap();

    assert_eq!(users.len(), 1);
    let listed_user = &users[0];

    // Verify groups are populated in list response
    assert!(listed_user["groups"].is_array());
    assert_eq!(listed_user["groups"].as_array().unwrap().len(), 2);

    // Test searching by username - groups should be populated
    let filter = format!("userName eq \"{}\"", "test.user@example.com");
    let encoded_filter = filter.replace(" ", "%20").replace("\"", "%22");
    let response = server
        .get(&format!("/scim/v2/Users?filter={}", encoded_filter))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_response: Value = response.json();
    let found_users = search_response["Resources"].as_array().unwrap();

    assert_eq!(found_users.len(), 1);
    let found_user = &found_users[0];

    // Verify groups are populated in search response
    assert!(found_user["groups"].is_array());
    assert_eq!(found_user["groups"].as_array().unwrap().len(), 2);

    // Test updating user - groups should remain populated
    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "id": user_id,
        "userName": "test.user@example.com",
        "name": {
            "givenName": "Test Updated",
            "familyName": "User"
        },
        "displayName": "Test User Updated"
    });

    let response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&update_data)
        .await;

    response.assert_status(StatusCode::OK);
    let updated_user: Value = response.json();

    // Verify groups are still populated after update
    assert!(updated_user["groups"].is_array());
    assert_eq!(updated_user["groups"].as_array().unwrap().len(), 2);
    assert_eq!(updated_user["name"]["givenName"], "Test Updated");
}

#[tokio::test]
async fn test_user_with_no_groups() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "lonely.user@example.com",
        "name": {
            "givenName": "Lonely",
            "familyName": "User"
        }
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);
    let user: Value = response.json();
    let user_id = user["id"].as_str().unwrap();

    // Verify groups attribute is not present or empty
    assert!(user["groups"].is_null() || user["groups"].as_array().is_none_or(|g| g.is_empty()));

    // Get user by ID
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let fetched_user: Value = response.json();

    // Verify groups attribute is still not present or empty
    assert!(
        fetched_user["groups"].is_null()
            || fetched_user["groups"]
                .as_array()
                .is_none_or(|g| g.is_empty())
    );
}
