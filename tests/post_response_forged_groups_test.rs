//! RFC 7644 §3.3 (rfc7644.txt:583-584): "In the request body, attributes
//! whose mutability is 'readOnly' ... SHALL be ignored." `User.groups` is
//! declared `mutability: readOnly` in `/Schemas` -- it is entirely
//! server-computed from group memberships and can never legitimately be
//! set by a client. `GET /Users/{id}` already gets this right (it always
//! recomputes `groups` from the membership table via `find_user_by_id`,
//! never trusting stored/submitted JSON), but `POST /Users` echoed back
//! whatever `groups` array the client submitted in the 201 response, even
//! though nothing was actually persisted.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_post_does_not_echo_forged_groups() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "forged.groups.user@example.com",
        "groups": [{
            "value": "forged-group-id",
            "display": "FORGED GROUP"
        }]
    });

    let response = server.post("/scim/v2/Users").json(&user_data).await;
    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();

    // The forged group membership must not be echoed back in the create
    // response, matching GET semantics -- either omitted entirely or an
    // empty array, but never the client-submitted value.
    if !created_user["groups"].is_null() {
        assert_eq!(created_user["groups"], json!([]));
    }

    // Nothing was actually persisted either.
    let user_id = created_user["id"].as_str().unwrap();
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    get_response.assert_status(StatusCode::OK);
    let fetched_user: Value = get_response.json();
    if !fetched_user["groups"].is_null() {
        assert_eq!(fetched_user["groups"], json!([]));
    }
}
