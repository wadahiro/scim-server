//! RFC 7644 §3.4.2.2 states verbatim: "Boolean and Binary attributes SHALL
//! cause a failed response (HTTP status code 400) with 'scimType' of
//! 'invalidFilter'." when used with a relational operator (`gt`, `ge`,
//! `lt`, `le`).

use axum_test::TestServer;
use http::StatusCode;
use serde_json::Value;

mod common;

#[tokio::test]
async fn test_relational_operator_on_boolean_attribute_returns_400_invalid_filter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("bool.filter.user", "Bool", "Filter");
    server.post("/scim/v2/Users").json(&user).await;

    for op in ["gt", "ge", "lt", "le"] {
        let response = server
            .get(&format!("/scim/v2/Users?filter=active%20{}%20true", op))
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let body: Value = response.json();
        assert_eq!(
            body["scimType"], "invalidFilter",
            "operator {} should be rejected on a Boolean attribute",
            op
        );
    }
}

#[tokio::test]
async fn test_equality_operator_on_boolean_attribute_still_works() {
    // Only relational operators are restricted; `eq`/`ne` on Boolean
    // attributes remain valid.
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("bool.filter.eq.user", "Bool", "Eq");
    server.post("/scim/v2/Users").json(&user).await;

    let response = server.get("/scim/v2/Users?filter=active%20eq%20true").await;
    response.assert_status(StatusCode::OK);
}
