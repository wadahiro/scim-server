//! RFC 7643 §4.2 (rfc7643.txt:1409-1411): "displayName A human-readable
//! name for the Group. REQUIRED." `create_group` already enforces this
//! (missing `displayName` on POST returns 400), but `update_group` had no
//! equivalent check: a PUT with no `displayName` fell through to
//! `Group::default()`'s placeholder `"default_display_name"` and returned
//! 200 instead of being rejected.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_put_group_missing_display_name_returns_400() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Original Group Name"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // A PUT with no `displayName` at all must be rejected, not silently
    // fall back to a server-generated placeholder value.
    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    });

    let put_response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .json(&put_body)
        .await;

    put_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = put_response.json();
    assert_eq!(body["scimType"], "invalidValue");

    // The group's stored displayName must be unaffected by the rejected PUT.
    let get_response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    get_response.assert_status(StatusCode::OK);
    let fetched_group: Value = get_response.json();
    assert_eq!(fetched_group["displayName"], "Original Group Name");
}
