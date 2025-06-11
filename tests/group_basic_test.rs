use axum_test::TestServer;
use serde_json::{json, Value};
use http::StatusCode;

mod common;

#[tokio::test]
async fn test_group_create_and_get() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Test POST - Create a group
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group"
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    if response.status_code() != StatusCode::CREATED {
        eprintln!("Create group failed with status: {}", response.status_code());
        eprintln!("Response body: {}", response.text());
        panic!("Group creation failed");
    }
    
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().expect("Group should have an ID");

    // Verify the created group has the expected properties
    assert_eq!(created_group["displayName"], "Test Group");
    assert!(created_group["meta"]["created"].is_string());
    assert!(created_group["meta"]["lastModified"].is_string());
    assert_eq!(created_group["meta"]["resourceType"], "Group");

    // Test GET - Read the group
    let response = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);

    let retrieved_group: Value = response.json();
    assert_eq!(retrieved_group["id"], group_id);
    assert_eq!(retrieved_group["displayName"], "Test Group");
}

#[tokio::test]
async fn test_group_list() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a group first
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "List Test Group"
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);

    // Test GET all groups
    let response = server
        .get(&format!("/scim/v2/Groups"))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);

    let groups_response: Value = response.json();
    assert_eq!(groups_response["schemas"][0], "urn:ietf:params:scim:api:messages:2.0:ListResponse");
    assert!(groups_response["totalResults"].as_i64().unwrap() >= 1);

    let resources = groups_response["Resources"].as_array().unwrap();
    assert!(!resources.is_empty());
}

#[tokio::test]
async fn test_group_update_and_delete() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a group first
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Update Test Group"
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Test PUT - Update the group
    let updated_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Updated Group Name"
    });

    let response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&updated_data)
        .await;

    response.assert_status(StatusCode::OK);
    let updated_group: Value = response.json();
    assert_eq!(updated_group["displayName"], "Updated Group Name");
    assert_eq!(updated_group["id"], group_id);

    // Test DELETE - Delete the group
    let response = server
        .delete(&format!("/scim/v2/Groups/{}", group_id))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);

    // Verify the group is deleted
    let response = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_group_patch_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a user first for testing membership
    let user_data = common::create_test_user_json("test-user", "Test", "User");
    let user_response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    
    user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Create a group
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Patch Test Group"
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Test PATCH - Replace displayName
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "displayName",
                "value": "Patched Group Name"
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert_eq!(patched_group["displayName"], "Patched Group Name");
    assert_eq!(patched_group["id"], group_id);

    // Test PATCH - Add members
    let patch_add_members = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": user_id,
                        "display": "Test User"
                    }
                ]
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_add_members)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert!(patched_group["members"].is_array());
    assert_eq!(patched_group["members"][0]["value"], user_id);
    assert_eq!(patched_group["members"][0]["type"], "User");
    
    // Test PATCH - Remove members
    let patch_remove_members = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": format!("members[value eq \"{}\"]", user_id)
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_remove_members)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert!(patched_group["members"].is_null() || 
            (patched_group["members"].is_array() && patched_group["members"].as_array().unwrap().is_empty()));
}

#[tokio::test]
async fn test_user_groups_attribute() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create a user
    let user_data = common::create_test_user_json("group-test-user", "Group", "Test");
    let user_response = server
        .post(&format!("/scim/v2/Users"))
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    
    user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Create a group with the user as member
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "User Groups Test Group",
        "members": [
            {
                "value": user_id,
                "display": "Group Test User"
            }
        ]
    });

    let group_response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Get the group to verify it has the member (since create might not return members)
    let group_get_response = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .await;

    group_get_response.assert_status(StatusCode::OK);
    let group_with_members: Value = group_get_response.json();
    
    
    // Verify group has the member
    assert!(group_with_members["members"].is_array());
    assert_eq!(group_with_members["members"][0]["value"], user_id);
    assert_eq!(group_with_members["members"][0]["type"], "User");

    // Get the user and verify it has groups attribute
    let user_get_response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .await;

    user_get_response.assert_status(StatusCode::OK);
    let user_with_groups: Value = user_get_response.json();
    
    // Verify user has groups attribute
    assert!(user_with_groups["groups"].is_array());
    assert_eq!(user_with_groups["groups"][0]["value"], group_id);
    assert_eq!(user_with_groups["groups"][0]["display"], "User Groups Test Group");
    
    // Verify $ref contains full URL with numeric tenant ID 3 (which "scim" resolves to)
    let expected_group_ref = format!("http://localhost:3000/scim/v2/Groups/{}", group_id);
    assert_eq!(user_with_groups["groups"][0]["$ref"], expected_group_ref);
}

#[tokio::test]
async fn test_group_error_scenarios() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";
    let invalid_tenant_id = "invalid-tenant";

    // Test creating group with invalid tenant
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group"
    });

    let response = server
        .post(&format!("/{}/v2/Groups", invalid_tenant_id))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);

    // Test creating group with missing displayName
    let invalid_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    });

    let response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&invalid_group_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);

    // Test getting non-existent group
    let fake_group_id = "00000000-0000-0000-0000-000000000000";
    let response = server
        .get(&format!("/scim/v2/Groups/{}", fake_group_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_group_to_group_membership() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let tenant_id = "3";

    // Create parent group
    let parent_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Parent Group"
    });

    let parent_response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&parent_group_data)
        .await;

    parent_response.assert_status(StatusCode::CREATED);
    let parent_group: Value = parent_response.json();
    let parent_group_id = parent_group["id"].as_str().unwrap();

    // Create child group
    let child_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Child Group"
    });

    let child_response = server
        .post(&format!("/scim/v2/Groups"))
        .content_type("application/scim+json")
        .json(&child_group_data)
        .await;

    child_response.assert_status(StatusCode::CREATED);
    let child_group: Value = child_response.json();
    let child_group_id = child_group["id"].as_str().unwrap();

    // Add child group as member of parent group
    let patch_add_group_member = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": child_group_id,
                        "type": "Group",
                        "display": "Child Group"
                    }
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", parent_group_id))
        .content_type("application/scim+json")
        .json(&patch_add_group_member)
        .await;

    patch_response.assert_status(StatusCode::OK);
    let patched_parent: Value = patch_response.json();

    // Verify the parent group has the child group as member
    assert!(patched_parent["members"].is_array());
    assert_eq!(patched_parent["members"][0]["value"], child_group_id);
    assert_eq!(patched_parent["members"][0]["type"], "Group");
    assert_eq!(patched_parent["members"][0]["display"], "Child Group");

    // Verify the $ref is correctly set for Group type with full URL with numeric tenant ID 3
    let expected_ref = format!("http://localhost:3000/scim/v2/Groups/{}", child_group_id);
    assert_eq!(patched_parent["members"][0]["$ref"], expected_ref);
}