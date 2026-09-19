//! RFC 7643 §7 declares `meta` (and its sub-attributes `resourceType`,
//! `created`, `lastModified`, `location`, `version`) mutability "readOnly".
//! RFC 7644 §3.5.1 therefore requires a service provider to ignore any
//! client-supplied value for it on PUT, rather than let it leak into the
//! stored/returned resource, and `created` must survive updates unchanged.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_put_ignores_client_supplied_meta_and_preserves_created() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("meta.readonly.user", "Meta", "User");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    let original_created = created_user["meta"]["created"].clone();
    assert!(!original_created.is_null());

    // A client attempting to overwrite readOnly meta sub-attributes on PUT.
    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "meta.readonly.user",
        "meta": {
            "resourceType": "Invalid",
            "created": "2000-01-01T00:00:00Z",
            "version": "W/\"999\""
        }
    });

    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .json(&put_body)
        .await;
    update_response.assert_status(StatusCode::OK);
    let updated_user: Value = update_response.json();

    // The client-supplied resourceType must not be echoed back.
    assert_eq!(updated_user["meta"]["resourceType"], "User");
    // `created` must be preserved across the update, not dropped or
    // replaced by the client-supplied value.
    assert_eq!(updated_user["meta"]["created"], original_created);
    // The bogus client-supplied version must not be echoed back either.
    assert_ne!(updated_user["meta"]["version"], "W/\"999\"");

    // Re-fetch to confirm the readOnly override wasn't merely a response
    // artifact but was never persisted either.
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let fetched_user: Value = get_response.json();
    assert_eq!(fetched_user["meta"]["resourceType"], "User");
    assert_eq!(fetched_user["meta"]["created"], original_created);
}

#[tokio::test]
async fn test_group_put_ignores_client_supplied_meta_and_preserves_created() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Meta Readonly Group"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group_body).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();
    let original_created = created_group["meta"]["created"].clone();
    assert!(!original_created.is_null());

    let put_body = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Meta Readonly Group",
        "meta": {
            "resourceType": "Invalid",
            "created": "2000-01-01T00:00:00Z"
        }
    });

    let update_response = server
        .put(&format!("/scim/v2/Groups/{}", group_id))
        .json(&put_body)
        .await;
    update_response.assert_status(StatusCode::OK);
    let updated_group: Value = update_response.json();

    assert_eq!(updated_group["meta"]["resourceType"], "Group");
    assert_eq!(updated_group["meta"]["created"], original_created);
}

#[tokio::test]
async fn test_schemas_endpoint_declares_meta_version_sub_attribute() {
    // RFC 7643 §3.1 defines `version` as part of the common `meta`
    // attribute, and real responses include `meta.version`; the schema
    // representation must advertise it too.
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/Schemas").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let user_schema = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        .expect("User schema present");

    let meta_attr = user_schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "meta")
        .expect("meta attribute present");

    let sub_attr_names: Vec<&str> = meta_attr["subAttributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["name"].as_str().unwrap())
        .collect();

    assert!(
        sub_attr_names.contains(&"version"),
        "meta subAttributes should include 'version', got {:?}",
        sub_attr_names
    );
}
