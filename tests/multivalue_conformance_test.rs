//! RFC 7643 §2.4: "a service provider SHOULD NOT return the same value more
//! than once within a multi-valued attribute" -- duplicate `(type, value)`
//! pairs must be de-duplicated on write.
//!
//! RFC 7643 §4.1.2 also defines a `primary` sub-attribute for `addresses`,
//! matching `emails`/`phoneNumbers`; client-supplied `primary` values on
//! addresses must be preserved, not silently discarded.
//!
//! RFC 7643 §2.4 further requires that at most one element of a
//! multi-valued attribute have `primary: true`; this must hold for
//! `addresses` exactly as it does for `emails`/`phoneNumbers`.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_duplicate_email_type_value_pairs_are_deduplicated_on_create() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dedup.user",
        "emails": [
            {"type": "work", "value": "dup@example.test"},
            {"type": "work", "value": "dup@example.test"}
        ]
    });

    let response = server.post("/scim/v2/Users").json(&user).await;
    response.assert_status(StatusCode::CREATED);
    let body: Value = response.json();
    let emails = body["emails"].as_array().unwrap();
    assert_eq!(
        emails.len(),
        1,
        "duplicate (type, value) pairs should be de-duplicated: {:?}",
        emails
    );
}

#[tokio::test]
async fn test_duplicate_email_type_value_pairs_are_deduplicated_on_patch_add() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dedup.patch.user",
        "emails": [{"type": "work", "value": "existing@example.test"}]
    });
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "emails",
            "value": [{"type": "work", "value": "existing@example.test"}]
        }]
    });
    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();
    let emails = patched_user["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 1);
}

#[tokio::test]
async fn test_address_primary_is_preserved_not_dropped() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "address.primary.user",
        "addresses": [{
            "streetAddress": "1 Infinite Loop",
            "type": "work",
            "primary": true
        }]
    });

    let response = server.post("/scim/v2/Users").json(&user).await;
    response.assert_status(StatusCode::CREATED);
    let body: Value = response.json();
    assert_eq!(body["addresses"][0]["primary"], true);

    let user_id = body["id"].as_str().unwrap();
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let fetched: Value = get_response.json();
    assert_eq!(
        fetched["addresses"][0]["primary"], true,
        "primary must survive a round trip through storage"
    );
}

#[tokio::test]
async fn test_two_primary_addresses_are_rejected_on_create() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dual.primary.address.create",
        "addresses": [
            {"type": "work", "streetAddress": "1 Main", "primary": true},
            {"type": "home", "streetAddress": "2 Side", "primary": true}
        ]
    });

    let response = server.post("/scim/v2/Users").json(&user).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(
        error["detail"]
            .as_str()
            .unwrap()
            .contains("At most one element can have primary=true"),
        "unexpected error body: {:?}",
        error
    );
}

#[tokio::test]
async fn test_two_primary_addresses_are_rejected_on_update() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dual.primary.address.update",
        "addresses": [{"type": "work", "streetAddress": "1 Main", "primary": true}]
    });
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let updated_user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "dual.primary.address.update",
        "addresses": [
            {"type": "work", "streetAddress": "1 Main", "primary": true},
            {"type": "home", "streetAddress": "2 Side", "primary": true}
        ]
    });
    let response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .json(&updated_user)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(
        error["detail"]
            .as_str()
            .unwrap()
            .contains("At most one element can have primary=true"),
        "unexpected error body: {:?}",
        error
    );
}
