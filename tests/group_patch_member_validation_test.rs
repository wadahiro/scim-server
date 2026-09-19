//! RFC 7643 §4.2 restricts Group `members[].type` to the values the schema
//! (and the underlying storage model) actually support. `POST /Groups`
//! already rejects an invalid member type with 400 `invalidValue`; a PATCH
//! that introduces the same invalid data must be rejected identically,
//! rather than reaching storage and failing there. RFC 7644 §3.12 also
//! requires that no internal (e.g. database driver) error text ever reaches
//! the client.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_add_member_with_invalid_type_returns_400_not_500() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Member Type Validation Group"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "members",
            "value": [{"value": "11111111-1111-1111-1111-111111111111", "type": "SomeRandomType"}]
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidValue");

    let detail = body["detail"].as_str().unwrap_or_default();
    assert!(
        !detail.to_lowercase().contains("constraint")
            && !detail.to_lowercase().contains("database")
            && !detail.to_lowercase().contains("sqlite")
            && !detail.to_lowercase().contains("code:"),
        "detail leaked an internal database message: {}",
        detail
    );
}
