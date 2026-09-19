//! RFC 7644 §3.4.3: `POST /{Resource}/.search` must be accepted as an
//! alternative to `GET /{Resource}?...` for queries too large to comfortably
//! fit in a URL, and must return the same `ListResponse` shape.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_post_users_search_returns_same_shape_as_get() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    for name in ["search.alice", "search.bob"] {
        let user = common::create_test_user_json(name, "Search", "User");
        server.post("/scim/v2/Users").json(&user).await;
    }

    let search_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        "filter": "userName eq \"search.alice\"",
        "attributes": ["userName"],
    });

    let response = server
        .post("/scim/v2/Users/.search")
        .json(&search_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["userName"], "search.alice");
}

#[tokio::test]
async fn test_post_users_search_rejects_missing_schema() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let search_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "filter": "userName eq \"nobody\""
    });

    let response = server
        .post("/scim/v2/Users/.search")
        .json(&search_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_post_groups_search_returns_same_shape_as_get() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Search Group"
    });
    server.post("/scim/v2/Groups").json(&group_body).await;

    let search_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        "filter": "displayName eq \"Search Group\""
    });

    let response = server
        .post("/scim/v2/Groups/.search")
        .json(&search_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["totalResults"], 1);
    assert_eq!(body["Resources"][0]["displayName"], "Search Group");
}
