//! RFC 7644 §3.3 (raw `rfc7644.txt:583-584`): "In the request body,
//! attributes whose mutability is 'readOnly' ... SHALL be ignored."
//! `/Schemas` declares the Enterprise User extension's `manager.$ref` and
//! `manager.displayName` sub-attributes `mutability: readOnly` (only
//! `manager.value` is client-settable). A client-forged `$ref`/`displayName`
//! must never be echoed back on POST, PUT, or PATCH.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

const ENTERPRISE_SCHEMA: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

#[tokio::test]
async fn test_post_ignores_forged_manager_readonly_subattributes() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            ENTERPRISE_SCHEMA
        ],
        "userName": "readonly.manager.post@example.com",
        ENTERPRISE_SCHEMA: {
            "manager": {
                "value": "boss-id",
                "$ref": "http://forged.example.com/Users/boss-id",
                "displayName": "FORGED NAME"
            }
        }
    });

    let response = server.post("/scim/v2/Users").json(&user_data).await;
    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();

    let manager = &created_user[ENTERPRISE_SCHEMA]["manager"];
    // `value` is readWrite and must round-trip.
    assert_eq!(manager["value"], "boss-id");
    // `$ref` and `displayName` are readOnly and must be ignored.
    assert!(manager["$ref"].is_null());
    assert!(manager["displayName"].is_null());

    // Confirm it wasn't merely a response artifact.
    let user_id = created_user["id"].as_str().unwrap();
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    let fetched_user: Value = get_response.json();
    let manager = &fetched_user[ENTERPRISE_SCHEMA]["manager"];
    assert!(manager["$ref"].is_null());
    assert!(manager["displayName"].is_null());
}

#[tokio::test]
async fn test_put_ignores_forged_manager_readonly_subattributes() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "readonly.manager.put@example.com"
    });
    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let put_body = json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            ENTERPRISE_SCHEMA
        ],
        "userName": "readonly.manager.put@example.com",
        ENTERPRISE_SCHEMA: {
            "manager": {
                "value": "boss-id",
                "$ref": "http://forged.example.com/Users/boss-id",
                "displayName": "FORGED NAME"
            }
        }
    });

    let put_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .json(&put_body)
        .await;
    put_response.assert_status(StatusCode::OK);
    let updated_user: Value = put_response.json();

    let manager = &updated_user[ENTERPRISE_SCHEMA]["manager"];
    assert_eq!(manager["value"], "boss-id");
    assert!(manager["$ref"].is_null());
    assert!(manager["displayName"].is_null());
}

#[tokio::test]
async fn test_patch_ignores_forged_manager_readonly_subattributes() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "readonly.manager.patch@example.com"
    });
    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": format!("{}:manager", ENTERPRISE_SCHEMA),
            "value": {
                "value": "boss-id",
                "$ref": "http://forged.example.com/Users/boss-id",
                "displayName": "FORGED NAME"
            }
        }]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    patch_response.assert_status(StatusCode::OK);
    let patched_user: Value = patch_response.json();

    let manager = &patched_user[ENTERPRISE_SCHEMA]["manager"];
    assert_eq!(manager["value"], "boss-id");
    assert!(manager["$ref"].is_null());
    assert!(manager["displayName"].is_null());
}
