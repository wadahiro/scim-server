//! RFC 7644 §3.5.2 (example 3) allows a PATCH `path` to be a bare extension
//! schema URN, e.g.
//! `"path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"`,
//! with an object `value` merged into that extension. RFC 7643 §3 requires
//! `schemas` to list every schema describing the resource's content, so
//! introducing extension data this way must add the extension URN to
//! `schemas` too.
//!
//! RFC 7643 §3 also requires that core-schema attributes live at the top
//! level of a resource -- they are not namespaced into a container the way
//! extension attributes are. So a core-schema-qualified `path`, e.g.
//! `"urn:ietf:params:scim:schemas:core:2.0:User:userName"`, must resolve to
//! the plain attribute (`userName`) rather than creating a container keyed
//! by the core schema URN.

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

#[tokio::test]
async fn test_patch_replace_core_schema_qualified_path_updates_plain_attribute() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("core.urn.user", "Core", "User");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "urn:ietf:params:scim:schemas:core:2.0:User:userName",
            "value": "core.urn.user.renamed"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    // A core-schema-qualified path must behave exactly like the plain
    // attribute path: it updates `userName` directly...
    assert_eq!(body["userName"], "core.urn.user.renamed");

    // ...and must NOT create a bogus top-level key named after the core
    // schema URN (unlike an extension URN, which does get a container).
    assert!(body
        .as_object()
        .unwrap()
        .keys()
        .all(|k| !k.starts_with("urn:ietf:params:scim:schemas:core")));
}

#[tokio::test]
async fn test_patch_remove_core_schema_qualified_path() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let mut user = common::create_test_user_json("core.urn.remove.user", "Core", "Remove");
    user["nickName"] = json!("Coreo");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();
    assert_eq!(created_user["nickName"], "Coreo");

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "remove",
            "path": "urn:ietf:params:scim:schemas:core:2.0:User:nickName"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert!(body.get("nickName").is_none());
    assert!(body
        .as_object()
        .unwrap()
        .keys()
        .all(|k| !k.starts_with("urn:ietf:params:scim:schemas:core")));
}

#[tokio::test]
async fn test_patch_add_extension_attribute_employee_number_still_works() {
    // Regression guard: fixing core-schema-qualified paths must not disturb
    // extension-schema-qualified attribute paths.
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("employee.number.user", "Emp", "Number");
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber",
            "value": "E-42"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let extension_key = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
    assert_eq!(body[extension_key]["employeeNumber"], "E-42");
}
