use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_replace_with_empty_array_clears_emails() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with multiple emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user",
        "emails": [
            {
                "value": "work@example.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "home@example.com",
                "type": "home"
            }
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify user has emails
    assert_eq!(created_user["emails"].as_array().unwrap().len(), 2);

    // PATCH to replace emails with empty array
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify emails field is removed (not present as empty array)
    assert!(patched_user.get("emails").is_none());
}

#[tokio::test]
async fn test_patch_remove_without_value_clears_emails() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with multiple emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user2",
        "emails": [
            {
                "value": "work@example.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "home@example.com",
                "type": "home"
            }
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify user has emails
    assert_eq!(created_user["emails"].as_array().unwrap().len(), 2);

    // PATCH to remove emails attribute entirely (no value field)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "emails"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify emails field is removed
    assert!(patched_user.get("emails").is_none());
}

#[tokio::test]
async fn test_patch_replace_with_empty_array_clears_phone_numbers() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with multiple phone numbers
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user3",
        "phoneNumbers": [
            {
                "value": "555-1234",
                "type": "work"
            },
            {
                "value": "555-5678",
                "type": "mobile"
            }
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify user has phone numbers
    assert_eq!(created_user["phoneNumbers"].as_array().unwrap().len(), 2);

    // PATCH to replace phoneNumbers with empty array
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "phoneNumbers",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify phoneNumbers field is removed
    assert!(patched_user.get("phoneNumbers").is_none());
}

#[tokio::test]
async fn test_patch_remove_without_value_clears_addresses() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with multiple addresses
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user4",
        "addresses": [
            {
                "streetAddress": "100 Universal Way",
                "locality": "Hollywood",
                "region": "CA",
                "postalCode": "91608",
                "country": "USA",
                "type": "work"
            },
            {
                "streetAddress": "456 Home Ave",
                "locality": "Los Angeles",
                "region": "CA",
                "postalCode": "90001",
                "country": "USA",
                "type": "home"
            }
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify user has addresses
    assert_eq!(created_user["addresses"].as_array().unwrap().len(), 2);

    // PATCH to remove addresses attribute entirely
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "addresses"
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify addresses field is removed
    assert!(patched_user.get("addresses").is_none());
}

#[tokio::test]
async fn test_patch_multiple_clear_operations() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with multiple multi-valued attributes
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user5",
        "emails": [
            {"value": "work@example.com", "type": "work"}
        ],
        "phoneNumbers": [
            {"value": "555-1234", "type": "work"}
        ],
        "addresses": [
            {
                "streetAddress": "100 Universal Way",
                "locality": "Hollywood",
                "type": "work"
            }
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with multiple operations to clear different attributes
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": []
            },
            {
                "op": "remove",
                "path": "phoneNumbers"
            },
            {
                "op": "replace",
                "path": "addresses",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify all multi-valued fields are removed
    assert!(patched_user.get("emails").is_none());
    assert!(patched_user.get("phoneNumbers").is_none());
    assert!(patched_user.get("addresses").is_none());
}

#[tokio::test]
async fn test_patch_clear_then_add_new_values() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user6",
        "emails": [
            {"value": "old1@example.com", "type": "work"},
            {"value": "old2@example.com", "type": "home"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH to clear and then add new emails
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "emails",
                "value": []
            },
            {
                "op": "add",
                "path": "emails",
                "value": [
                    {"value": "new@example.com", "type": "work", "primary": true}
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Verify only new email exists
    let emails = patched_user["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
    assert_eq!(emails[0]["value"], "new@example.com");
    assert_eq!(emails[0]["primary"], true);
}

#[tokio::test]
async fn test_patch_remove_group_members_with_empty_array() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create users first
    let user1_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "member1"
    });
    let user2_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "member2"
    });

    let user1_response = server.post("/scim/v2/Users").json(&user1_body).await;
    user1_response.assert_status(StatusCode::CREATED);
    let user1: Value = user1_response.json();
    let user1_id = user1["id"].as_str().unwrap();

    let user2_response = server.post("/scim/v2/Users").json(&user2_body).await;
    user2_response.assert_status(StatusCode::CREATED);
    let user2: Value = user2_response.json();
    let user2_id = user2["id"].as_str().unwrap();

    // Create group with members
    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group",
        "members": [
            {
                "value": user1_id,
                "$ref": format!("https://example.com/scim/v2/Users/{}", user1_id),
                "type": "User"
            },
            {
                "value": user2_id,
                "$ref": format!("https://example.com/scim/v2/Users/{}", user2_id),
                "type": "User"
            }
        ]
    });

    let group_response = server.post("/scim/v2/Groups").json(&group_body).await;
    group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Verify group has members
    assert_eq!(created_group["members"].as_array().unwrap().len(), 2);

    // PATCH to replace members with empty array
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "members",
                "value": []
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_group: Value = patch_response.json();

    // Verify members field behavior (may be empty array or removed based on config)
    // The default config shows empty arrays for groups
    let members = patched_group.get("members");
    if let Some(members_value) = members {
        assert_eq!(members_value.as_array().unwrap().len(), 0);
    }
}

#[tokio::test]
async fn test_patch_remove_with_value_field_as_null() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with emails
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user7",
        "emails": [
            {"value": "test@example.com", "type": "work"}
        ]
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH with explicit null value (this is not the correct way per RFC)
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": "emails",
                "value": null
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    // The implementation should accept this and treat it as remove without value
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();
    
    // Emails should be removed
    assert!(patched_user.get("emails").is_none());
}

#[tokio::test]
async fn test_patch_replace_single_valued_with_empty_string() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with various single-valued attributes
    let create_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test_user8",
        "displayName": "Test User 8",
        "title": "Engineer",
        "userType": "Employee"
    });

    let create_response = server.post("/scim/v2/Users").json(&create_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // PATCH to clear single-valued attributes with empty string
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "displayName",
                "value": ""
            },
            {
                "op": "replace",
                "path": "title",
                "value": ""
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    // Check if empty strings are stored as empty strings or removed
    // The implementation might store empty strings rather than removing them
    if let Some(display_name) = patched_user.get("displayName") {
        assert_eq!(display_name, "");
    }
    if let Some(title) = patched_user.get("title") {
        assert_eq!(title, "");
    }
    // userName and userType should still exist
    assert_eq!(patched_user["userName"], "test_user8");
    assert_eq!(patched_user["userType"], "Employee");
}