//! RFC 7644 §3.5.2.2: a PATCH "remove" of a required attribute must be
//! rejected with HTTP 400 and `scimType: "mutability"`, and the response
//! must never leak an internal (e.g. serialization) error message.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_remove_required_user_attribute_returns_400_mutability() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("required.attr.user", "Req", "User");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "userName"
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    patch_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = patch_response.json();
    assert_eq!(body["scimType"], "mutability");

    // The detail must never contain a raw serde/internal message such as
    // the literal missing-field text that would come from deserializing a
    // struct with a non-optional `userName` field.
    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        !detail.contains("missing field"),
        "detail leaked an internal message: {}",
        detail
    );
}

#[tokio::test]
async fn test_patch_remove_required_group_attribute_returns_400_mutability() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Required Attr Group"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "displayName"
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
