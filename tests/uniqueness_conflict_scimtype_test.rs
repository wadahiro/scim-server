// RFC 7644 §3.12 Table 9's "uniqueness" row states: "One or more of the
// attribute values are already in use or are reserved", and lists it as
// applicable to POST (Create - Section 3.3), PUT (Section 3.5.1), and
// PATCH (Section 3.5.2) alike.
//
// RFC 7643 §7 ("uniqueness" characteristic) says a server MAY reject an
// invalid value based on uniqueness by returning HTTP 400 -- so returning
// 400 for a uniqueness violation would also be RFC-compliant. This server
// returns 409 for all three operations (POST, PUT, PATCH) for consistency:
// the create path already used 409 + scimType "uniqueness" before this
// fix, and PUT/PATCH previously (incorrectly) returned 400 + scimType
// "invalidValue" for the same underlying condition. These tests assert the
// scimType is "uniqueness" and the status is 409 in every case, matching
// the create path.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

// ---------------------------------------------------------------------
// User - userName
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_post_user_duplicate_username_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-post-user"
    });
    let create_a = server.post("/scim/v2/Users").json(&user_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    // Attempt to create a second user with the same userName.
    let user_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-post-user"
    });
    let create_b = server.post("/scim/v2/Users").json(&user_b).await;

    assert_eq!(create_b.status_code(), StatusCode::CONFLICT);
    let body: Value = create_b.json();
    assert_eq!(body["scimType"], "uniqueness");
}

#[tokio::test]
async fn test_put_user_duplicate_username_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-put-user-a"
    });
    let create_a = server.post("/scim/v2/Users").json(&user_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    let user_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-put-user-b"
    });
    let create_b = server.post("/scim/v2/Users").json(&user_b).await;
    assert_eq!(create_b.status_code(), StatusCode::CREATED);
    let created_b: Value = create_b.json();
    let user_b_id = created_b["id"].as_str().unwrap();

    // PUT user B, giving it user A's userName.
    let update_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-put-user-a"
    });
    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_b_id))
        .json(&update_b)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::CONFLICT);
    let body: Value = update_response.json();
    assert_eq!(body["scimType"], "uniqueness");
}

#[tokio::test]
async fn test_patch_user_duplicate_username_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-patch-user-a"
    });
    let create_a = server.post("/scim/v2/Users").json(&user_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    let user_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dup-patch-user-b"
    });
    let create_b = server.post("/scim/v2/Users").json(&user_b).await;
    assert_eq!(create_b.status_code(), StatusCode::CREATED);
    let created_b: Value = create_b.json();
    let user_b_id = created_b["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "userName",
            "value": "dup-patch-user-a"
        }]
    });
    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_b_id))
        .json(&patch_body)
        .await;

    assert_eq!(patch_response.status_code(), StatusCode::CONFLICT);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "uniqueness");
}

// ---------------------------------------------------------------------
// Group - displayName
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_post_group_duplicate_displayname_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-post-group"
    });
    let create_a = server.post("/scim/v2/Groups").json(&group_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    let group_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-post-group"
    });
    let create_b = server.post("/scim/v2/Groups").json(&group_b).await;

    assert_eq!(create_b.status_code(), StatusCode::CONFLICT);
    let body: Value = create_b.json();
    assert_eq!(body["scimType"], "uniqueness");
}

#[tokio::test]
async fn test_put_group_duplicate_displayname_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-put-group-a"
    });
    let create_a = server.post("/scim/v2/Groups").json(&group_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    let group_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-put-group-b"
    });
    let create_b = server.post("/scim/v2/Groups").json(&group_b).await;
    assert_eq!(create_b.status_code(), StatusCode::CREATED);
    let created_b: Value = create_b.json();
    let group_b_id = created_b["id"].as_str().unwrap();

    let update_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-put-group-a"
    });
    let update_response = server
        .put(&format!("/scim/v2/Groups/{}", group_b_id))
        .json(&update_b)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::CONFLICT);
    let body: Value = update_response.json();
    assert_eq!(body["scimType"], "uniqueness");
}

#[tokio::test]
async fn test_patch_group_duplicate_displayname_is_uniqueness_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_a = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-patch-group-a"
    });
    let create_a = server.post("/scim/v2/Groups").json(&group_a).await;
    assert_eq!(create_a.status_code(), StatusCode::CREATED);

    let group_b = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "dup-patch-group-b"
    });
    let create_b = server.post("/scim/v2/Groups").json(&group_b).await;
    assert_eq!(create_b.status_code(), StatusCode::CREATED);
    let created_b: Value = create_b.json();
    let group_b_id = created_b["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "dup-patch-group-a"
        }]
    });
    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", group_b_id))
        .json(&patch_body)
        .await;

    assert_eq!(patch_response.status_code(), StatusCode::CONFLICT);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "uniqueness");
}
