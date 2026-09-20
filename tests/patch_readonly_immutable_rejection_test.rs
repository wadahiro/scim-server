//! RFC 7644 §3.5.2 (raw `rfc7644.txt:1886-1894`): "Each operation against
//! an attribute MUST be compatible with the attribute's mutability ... a
//! client MUST NOT modify an attribute that has mutability 'readOnly' or
//! 'immutable' ... An operation that is not compatible with an attribute's
//! mutability ... SHALL return the appropriate HTTP response status code"
//! -- 400 with `scimType: "mutability"` per Table 9 (§3.12). This is a
//! PATCH-specific rule: unlike POST/PUT, where a readOnly value in the
//! request body is silently ignored (§3.3, §3.5.1 raw
//! `rfc7644.txt:1665`), a PATCH that targets a readOnly/immutable
//! attribute must be rejected outright, not silently ignored with a 200.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_replace_readonly_user_id_returns_400_mutability() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("readonly.id.patch.user", "Read", "Only");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "id",
            "value": "forged-id"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "mutability");

    // The `id` must be genuinely unchanged, not merely rejected in the
    // response while silently applied.
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let fetched_user: Value = get_response.json();
    assert_eq!(fetched_user["id"], user_id);
}

#[tokio::test]
async fn test_patch_replace_readonly_group_id_returns_400_mutability() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Readonly Id Patch Group"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "id",
            "value": "forged-group-id"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "mutability");
}

#[tokio::test]
async fn test_patch_replace_readonly_meta_subattribute_returns_400_mutability() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("readonly.meta.patch.user", "Meta", "Patch");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "meta.resourceType",
            "value": "Forged"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "mutability");
}

#[tokio::test]
async fn test_patch_replace_immutable_group_member_type_with_different_value_returns_400() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("immutable.member.type.user", "Immutable", "Member");
    let create_user_response = server.post("/scim/v2/Users").json(&user).await;
    create_user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Immutable Member Type Group",
        "members": [{"value": user_id, "type": "User"}]
    });
    let create_group_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // `members[].type` is declared `mutability: immutable`: it already has
    // a value ("User"), so replacing it with a different value must be
    // rejected.
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": format!("members[value eq \"{}\"].type", user_id),
            "value": "Group"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "mutability");
}

#[tokio::test]
async fn test_patch_replace_immutable_group_member_type_with_same_value_succeeds() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("immutable.same.value.user", "Same", "Value");
    let create_user_response = server.post("/scim/v2/Users").json(&user).await;
    create_user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Immutable Same Value Group",
        "members": [{"value": user_id, "type": "User"}]
    });
    let create_group_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Resubmitting the same value an immutable attribute already has is
    // not a modification (RFC 7644 §3.5.1: "the input value(s) MUST
    // match" is satisfied) and must still succeed.
    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": format!("members[value eq \"{}\"].type", user_id),
            "value": "User"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::OK);
}
