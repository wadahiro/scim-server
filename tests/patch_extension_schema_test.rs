//! RFC 7644 §3.5.2 (example 3) allows a PATCH `path` to be a bare extension
//! schema URN, e.g.
//! `"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`,
//! with an object `value` merged into that extension. RFC 7643 §3 requires
//! `schemas` to list every schema describing the resource's content, so
//! introducing extension data this way must add the extension URN to
//! `schemas` too.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

#[tokio::test]
async fn test_patch_add_bare_extension_urn_sets_extension_data_and_schemas() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("extension.urn.user", "Ext", "User");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User",
            "value": {"employeeNumber": "12345"}
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let extension_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    assert_eq!(body[extension_key]["employeeNumber"], "12345");

    let schemas: Vec<&str> = body["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(
        schemas.contains(&extension_key),
        "schemas should list the extension URN, got {:?}",
        schemas
    );

    // Must not have mis-parsed the URN and split off "User" as a fake
    // attribute name under a truncated "...:2.0" key.
    assert!(body
        .get("urn:ietf:params:scim:schemas:extension:enterprise:2.0")
        .is_none());
}

#[tokio::test]
async fn test_patch_add_extension_attribute_path_also_updates_schemas() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("extension.attr.user", "Ext", "Attr");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
            "value": "Engineering"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let extension_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    assert_eq!(body[extension_key]["department"], "Engineering");

    let schemas: Vec<&str> = body["schemas"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert!(schemas.contains(&extension_key));
}
