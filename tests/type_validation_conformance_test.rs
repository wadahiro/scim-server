//! RFC 7643 §2.3 (rfc7643.txt:438): "Attribute Data Types". A wrong-typed
//! attribute value (e.g. a JSON number where the schema declares a String)
//! must be rejected with 400, matching the behavior already correct for
//! typed fields such as `name.givenName` and `emails.value`. Several
//! attributes bypassed that discipline instead of enforcing it:
//! `User.addresses.*` (deserialized as raw JSON), `Group.externalId`, and
//! `Group.members[].*`.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_post_user_rejects_wrong_typed_address_formatted() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "addr.type.user@example.com",
        "addresses": [{
            "formatted": 123,
            "primary": "yes"
        }]
    });

    let response = server.post("/scim/v2/Users").json(&user_data).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_post_user_rejects_wrong_typed_address_primary() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "addr.primary.type.user@example.com",
        "addresses": [{
            "streetAddress": "1 Infinite Loop",
            "primary": "yes"
        }]
    });

    let response = server.post("/scim/v2/Users").json(&user_data).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_put_user_rejects_wrong_typed_address_field() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "addr.put.user@example.com"
    });
    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "addr.put.user@example.com",
        "addresses": [{
            "locality": true
        }]
    });

    let put_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .json(&put_body)
        .await;
    put_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = put_response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_post_group_rejects_wrong_typed_external_id() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "External Id Type Group",
        "externalId": 12345
    });

    let response = server.post("/scim/v2/Groups").json(&group_body).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_put_group_rejects_wrong_typed_external_id() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "External Id Type Group Put"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "External Id Type Group Put",
        "externalId": {"nested": "object"}
    });

    let put_response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .json(&put_body)
        .await;
    put_response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = put_response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_post_group_rejects_wrong_typed_member_value() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Member Type Group",
        "members": [{
            "value": 42
        }]
    });

    let response = server.post("/scim/v2/Groups").json(&group_body).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_post_group_rejects_wrong_typed_member_ref() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a real user so a type-valid member value would otherwise pass
    // member-existence validation.
    let user_data = common::create_test_user_json("member.ref.type.user", "Ref", "User");
    let create_user_response = server.post("/scim/v2/Users").json(&user_data).await;
    create_user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Member Ref Type Group",
        "members": [{
            "value": user_id,
            "$ref": 999
        }]
    });

    let response = server.post("/scim/v2/Groups").json(&group_body).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}

#[tokio::test]
async fn test_put_group_rejects_wrong_typed_member_type() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = common::create_test_user_json("member.type.put.user", "Type", "User");
    let create_user_response = server.post("/scim/v2/Users").json(&user_data).await;
    create_user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Member Type Put Group"
    });
    let create_group_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Member Type Put Group",
        "members": [{
            "value": user_id,
            "type": true
        }]
    });

    let response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .json(&put_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["scimType"], "invalidSyntax");
}
