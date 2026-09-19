//! RFC 7644 §3.5.2.3: a PATCH "replace" whose value-path filter matches no
//! element must fail with `scimType: "noTarget"`, not "invalidValue".

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_replace_unmatched_value_path_returns_no_target() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("no.target.user", "No", "Target");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "emails[type eq \"nonexistent\"].value",
            "value": "new@example.com"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "noTarget");
}
