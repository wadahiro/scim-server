// RFC 7644 §3.9: "Clients MAY request a partial resource representation on
// any operation that returns a resource within the response by specifying
// either of the mutually exclusive URL query parameters 'attributes' or
// 'excludedAttributes'". This applies to every operation that returns a
// resource, not only GET -- including POST (create), PUT (replace), and
// PATCH, per the explicit cross-reference in §3.5.2 ("a 200 OK response
// code and the entire resource within the response body, subject to the
// 'attributes' query parameter (see Section 3.9)") and §3.5.1's "a
// successful PUT operation returns ... the entire resource".
//
// These tests cover all 12 combinations that were previously ignored:
// {POST, PUT, PATCH} x {User, Group} x {attributes, excludedAttributes}.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

// ---------------------------------------------------------------------
// User - POST
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_post_user_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "post-attr-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post("/scim/v2/Users?attributes=userName")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created: Value = response.json();

    assert!(created.get("userName").is_some());
    assert!(created.get("id").is_some());
    assert!(created.get("schemas").is_some());
    assert!(created.get("meta").is_some());
    assert!(created.get("name").is_none());
}

#[tokio::test]
async fn test_post_user_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "post-excl-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let response = server
        .post("/scim/v2/Users?excludedAttributes=name")
        .json(&user_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created: Value = response.json();

    assert!(created.get("name").is_none());
    assert!(created.get("userName").is_some());
    assert!(created.get("id").is_some());
}

// ---------------------------------------------------------------------
// User - PUT
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_put_user_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "put-attr-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let user_id = created["id"].as_str().unwrap();

    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "put-attr-user",
        "name": {
            "givenName": "Updated",
            "familyName": "User"
        }
    });

    let response = server
        .put(&format!("/scim/v2/Users/{}?attributes=userName", user_id))
        .json(&update_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let updated: Value = response.json();

    assert!(updated.get("userName").is_some());
    assert!(updated.get("id").is_some());
    assert!(updated.get("schemas").is_some());
    assert!(updated.get("meta").is_some());
    assert!(updated.get("name").is_none());
}

#[tokio::test]
async fn test_put_user_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "put-excl-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let user_id = created["id"].as_str().unwrap();

    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "put-excl-user",
        "name": {
            "givenName": "Updated",
            "familyName": "User"
        }
    });

    let response = server
        .put(&format!(
            "/scim/v2/Users/{}?excludedAttributes=name",
            user_id
        ))
        .json(&update_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let updated: Value = response.json();

    assert!(updated.get("name").is_none());
    assert!(updated.get("userName").is_some());
}

// ---------------------------------------------------------------------
// User - PATCH
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_patch_user_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "patch-attr-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "name.givenName",
            "value": "Patched"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}?attributes=userName", user_id))
        .json(&patch_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let patched: Value = response.json();

    assert!(patched.get("userName").is_some());
    assert!(patched.get("id").is_some());
    assert!(patched.get("schemas").is_some());
    assert!(patched.get("meta").is_some());
    assert!(patched.get("name").is_none());
}

#[tokio::test]
async fn test_patch_user_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "patch-excl-user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });

    let create_response = server.post("/scim/v2/Users").json(&user_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "name.givenName",
            "value": "Patched"
        }]
    });

    let response = server
        .patch(&format!(
            "/scim/v2/Users/{}?excludedAttributes=name",
            user_id
        ))
        .json(&patch_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let patched: Value = response.json();

    assert!(patched.get("name").is_none());
    assert!(patched.get("userName").is_some());
}

// ---------------------------------------------------------------------
// Group - POST
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_post_group_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "post-attr-group",
        "externalId": "ext-post-attr-group"
    });

    let response = server
        .post("/scim/v2/Groups?attributes=displayName")
        .json(&group_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created: Value = response.json();

    assert!(created.get("displayName").is_some());
    assert!(created.get("id").is_some());
    assert!(created.get("schemas").is_some());
    assert!(created.get("meta").is_some());
    assert!(created.get("externalId").is_none());
}

#[tokio::test]
async fn test_post_group_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "post-excl-group",
        "externalId": "ext-post-excl-group"
    });

    let response = server
        .post("/scim/v2/Groups?excludedAttributes=externalId")
        .json(&group_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::CREATED);
    let created: Value = response.json();

    assert!(created.get("externalId").is_none());
    assert!(created.get("displayName").is_some());
}

// ---------------------------------------------------------------------
// Group - PUT
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_put_group_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "put-attr-group",
        "externalId": "ext-put-attr-group"
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let group_id = created["id"].as_str().unwrap();

    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "put-attr-group-renamed",
        "externalId": "ext-put-attr-group"
    });

    let response = server
        .put(&format!(
            "/scim/v2/Groups/{}?attributes=displayName",
            group_id
        ))
        .json(&update_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let updated: Value = response.json();

    assert!(updated.get("displayName").is_some());
    assert!(updated.get("id").is_some());
    assert!(updated.get("schemas").is_some());
    assert!(updated.get("meta").is_some());
    assert!(updated.get("externalId").is_none());
}

#[tokio::test]
async fn test_put_group_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "put-excl-group",
        "externalId": "ext-put-excl-group"
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let group_id = created["id"].as_str().unwrap();

    let update_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "put-excl-group-renamed",
        "externalId": "ext-put-excl-group"
    });

    let response = server
        .put(&format!(
            "/scim/v2/Groups/{}?excludedAttributes=externalId",
            group_id
        ))
        .json(&update_data)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let updated: Value = response.json();

    assert!(updated.get("externalId").is_none());
    assert!(updated.get("displayName").is_some());
}

// ---------------------------------------------------------------------
// Group - PATCH
// ---------------------------------------------------------------------

#[tokio::test]
async fn test_patch_group_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "patch-attr-group",
        "externalId": "ext-patch-attr-group"
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let group_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "patch-attr-group-renamed"
        }]
    });

    let response = server
        .patch(&format!(
            "/scim/v2/Groups/{}?attributes=displayName",
            group_id
        ))
        .json(&patch_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let patched: Value = response.json();

    assert!(patched.get("displayName").is_some());
    assert!(patched.get("id").is_some());
    assert!(patched.get("schemas").is_some());
    assert!(patched.get("meta").is_some());
    assert!(patched.get("externalId").is_none());
}

#[tokio::test]
async fn test_patch_group_excluded_attributes_parameter() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "patch-excl-group",
        "externalId": "ext-patch-excl-group"
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_data).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created: Value = create_response.json();
    let group_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "displayName",
            "value": "patch-excl-group-renamed"
        }]
    });

    let response = server
        .patch(&format!(
            "/scim/v2/Groups/{}?excludedAttributes=externalId",
            group_id
        ))
        .json(&patch_body)
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let patched: Value = response.json();

    assert!(patched.get("externalId").is_none());
    assert!(patched.get("displayName").is_some());
}
