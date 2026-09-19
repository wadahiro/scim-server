//! RFC 7644 §3.10 ("Attribute Notation") states "All operations share a
//! common scheme for referencing simple and complex attributes" and ends
//! "All facets (URN, attribute, and sub-attribute name) of the fully encoded
//! attribute name are case insensitive." RFC 7643 §2.1 says the same of
//! attribute names generally.
//!
//! The contexts covered by this file are bound to that notation explicitly:
//! `attributes` and `excludedAttributes` -- "Attribute names MUST be in
//! standard attribute notation (Section 3.10) form" (§3.4.2.5, and §3.4.3
//! for POST /.search); `sortBy` -- the same MUST in §3.4.3; the PATCH `path`
//! -- "The attribute notation rules described in Section 3.10 apply for
//! describing attribute paths" (§3.5.2). Filters already resolved case
//! correctly before this change (§3.4.2.2 restates it for them) and are
//! re-verified here only as a regression guard.
//!
//! Separately, RFC 7644 §3.12 defines `invalidPath` for "The 'path'
//! attribute was invalid or malformed". A PATCH `path` that names no
//! attribute this server can actually persist must not return 200 with no
//! effect. This server's `User` model has an open `additional_fields` map
//! that lets a PATCH create genuinely new, arbitrary top-level attributes --
//! a deliberate custom-attribute feature -- so an unrecognized top-level
//! attribute name on a bare User path is accepted and stored. Everywhere
//! else -- Group (whose model has no such catch-all), a sub-attribute of a
//! known complex attribute, or an attribute inside a registered
//! schema-extension container such as the enterprise-user extension (whose
//! Rust types likewise have no catch-all) -- an unresolved path has nowhere
//! to land: it would silently be dropped on the JSON round trip while still
//! reporting success, so it is rejected with `invalidPath` instead.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_get_attributes_param_case_insensitive() {
    // RFC 7644 §3.4.2.5 requires `attributes` to be in standard attribute
    // notation (§3.10), which is case insensitive: `attributes=USERNAME`
    // must resolve to `userName`.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("attr.case.user", "Attr", "Case");
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let response = server
        .get(&format!("/scim/v2/Users/{}?attributes=USERNAME", user_id))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert_eq!(body["userName"], "attr.case.user");
    assert!(body.get("name").is_none(), "name was not requested");
}

#[tokio::test]
async fn test_get_excluded_attributes_param_case_insensitive() {
    // Same §2.1-by-interpretation rule as `attributes`, applied to
    // `excludedAttributes`.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("excl.case.user", "Excl", "Case");
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let response = server
        .get(&format!(
            "/scim/v2/Users/{}?excludedAttributes=USERNAME",
            user_id
        ))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert!(body.get("userName").is_none(), "userName was excluded");
    assert_eq!(body["name"]["givenName"], "Excl");
}

#[tokio::test]
async fn test_filter_case_insensitive_still_works() {
    // Regression guard: RFC 7644 §3.4.2.2 states filter attribute-name case
    // insensitivity explicitly, and this already worked before this change.
    // It must keep working unchanged.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("filter.case.user", "Filter", "Case");
    server.post("/scim/v2/Users").json(&user).await;

    for filter in [
        "filter=USERNAME%20eq%20%22filter.case.user%22",
        "filter=username%20eq%20%22filter.case.user%22",
    ] {
        let response = server.get(&format!("/scim/v2/Users?{}", filter)).await;
        response.assert_status(StatusCode::OK);
        let body: Value = response.json();
        assert_eq!(
            body["totalResults"], 1,
            "filter '{}' should match exactly one user",
            filter
        );
    }
}

#[tokio::test]
async fn test_sort_by_case_insensitive_matches_lowercase_sort() {
    // RFC 7644 §3.4.3 requires `sortBy` to be in standard attribute
    // notation (§3.10), which is case insensitive: `sortBy=USERNAME` must
    // sort the same way as `sortBy=userName`.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    for username in ["sort.case.bravo", "sort.case.alpha", "sort.case.charlie"] {
        let user = common::create_test_user_json(username, "Sort", "Case");
        server.post("/scim/v2/Users").json(&user).await;
    }

    let lower: Value = server
        .get("/scim/v2/Users?sortBy=userName&sortOrder=ascending")
        .await
        .json();
    let upper: Value = server
        .get("/scim/v2/Users?sortBy=USERNAME&sortOrder=ascending")
        .await
        .json();

    let lower_names: Vec<&str> = lower["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["userName"].as_str().unwrap())
        .collect();
    let upper_names: Vec<&str> = upper["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["userName"].as_str().unwrap())
        .collect();

    assert_eq!(lower_names, upper_names);
    assert!(lower_names.contains(&"sort.case.alpha"));
    // Ascending order: alpha < bravo < charlie among our seeded users.
    let alpha_idx = lower_names
        .iter()
        .position(|n| *n == "sort.case.alpha")
        .unwrap();
    let bravo_idx = lower_names
        .iter()
        .position(|n| *n == "sort.case.bravo")
        .unwrap();
    assert!(alpha_idx < bravo_idx);
}

#[tokio::test]
async fn test_patch_top_level_attribute_case_insensitive() {
    // RFC 7644 §3.5.2 applies the §3.10 attribute-notation rules to PATCH
    // paths, and §3.10 makes every facet case insensitive: upper, lower and
    // mixed case must all resolve to `nickName`, not silently no-op or
    // create a distinct pseudo-attribute.
    for (case_label, path) in [
        ("upper", "NICKNAME"),
        ("lower", "nickname"),
        ("mixed", "NickName"),
    ] {
        let app = common::setup_test_app(create_test_app_config())
            .await
            .unwrap();
        let server = TestServer::new(app).unwrap();

        let mut user = common::create_test_user_json(
            &format!("patch.case.{}.user", case_label),
            "Patch",
            "Case",
        );
        user["nickName"] = json!("Original");
        let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
        let user_id = created["id"].as_str().unwrap();

        let patch_body = json!({
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": path, "value": "Updated"}]
        });

        let response = server
            .patch(&format!("/scim/v2/Users/{}", user_id))
            .json(&patch_body)
            .await;
        response.assert_status(StatusCode::OK);
        let body: Value = response.json();

        assert_eq!(
            body["nickName"], "Updated",
            "case '{}' (path '{}') should update nickName",
            case_label, path
        );
        // No stray pseudo-attribute named after the client's literal casing.
        assert!(
            body.get(path).is_none(),
            "case '{}' must not create a separate '{}' key",
            case_label,
            path
        );
    }
}

#[tokio::test]
async fn test_patch_sub_attribute_case_insensitive() {
    // Sub-attributes resolve segment by segment (RFC 7643 §2.1, by
    // interpretation as above).
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("patch.subattr.user", "Original", "Case");
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "NAME.GIVENNAME", "value": "Updated"}]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert_eq!(body["name"]["givenName"], "Updated");
    assert!(body.get("NAME").is_none());
}

#[tokio::test]
async fn test_patch_value_path_case_insensitive() {
    // The attribute portion of a value path (and its trailing sub-attribute)
    // resolve the same way as a plain attrPath (RFC 7643 §2.1, by
    // interpretation as above). The filter's own condition ("type eq
    // \"work\"") is unaffected -- filter case insensitivity is RFC
    // 7644 §3.4.2.2 explicit text and untouched by this change.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let mut user = common::create_test_user_json("patch.valuepath.user", "Value", "Path");
    user["emails"] = json!([
        {"value": "old-work@example.com", "type": "work", "primary": true}
    ]);
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "EMAILS[type eq \"work\"].VALUE",
            "value": "new-work@example.com"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let emails = body["emails"].as_array().unwrap();
    assert_eq!(emails[0]["value"], "new-work@example.com");
    assert_eq!(emails[0]["type"], "work");
}

#[tokio::test]
async fn test_patch_group_unknown_attribute_returns_invalid_path() {
    // RFC 7644 §3.12 `invalidPath`. Group's model has no catch-all for
    // unrecognized fields (unlike User's `additional_fields`), so an
    // unknown attribute would otherwise be silently dropped on the JSON
    // round trip while still reporting 200 -- rejected instead.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Invalid Path Group"
    });
    let created: Value = server.post("/scim/v2/Groups").json(&group).await.json();
    let group_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "totallyBogusAttr", "value": "foo"}]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidPath");

    // The operation must have had no effect.
    let after: Value = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .await
        .json();
    assert!(after.get("totallyBogusAttr").is_none());
    assert_eq!(after["displayName"], "Invalid Path Group");
}

#[tokio::test]
async fn test_patch_user_unknown_top_level_attribute_is_stored_as_custom_attribute() {
    // Decision for RFC 7644 §3.12 `invalidPath`, User case: this server's
    // `User` model has an open `additional_fields` map (a deliberate
    // custom-attribute feature -- see `models::User`), so an unrecognized
    // *top-level* attribute name on a bare (non-schema-qualified) User path
    // genuinely persists and is not rejected.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("custom.attr.user", "Custom", "Attr");
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{"op": "replace", "path": "totallyBogusAttr", "value": "foo"}]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["totallyBogusAttr"], "foo");

    // And it round-trips on a plain GET too, confirming it was actually
    // persisted rather than only echoed in the PATCH response.
    let after: Value = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .await
        .json();
    assert_eq!(after["totallyBogusAttr"], "foo");
}

#[tokio::test]
async fn test_patch_enterprise_extension_unknown_sub_attribute_returns_invalid_path() {
    // RFC 7644 §3.12 `invalidPath`, extension case: the enterprise-user
    // extension is a registered schema with a fixed, typed Rust
    // representation (no catch-all), so an unknown sub-attribute inside its
    // schema-URN container would otherwise be silently dropped -- rejected
    // instead.
    let app = common::setup_test_app(create_test_app_config())
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();

    let user = common::create_test_user_json("enterprise.unknown.user", "Ent", "Unknown");
    let created: Value = server.post("/scim/v2/Users").json(&user).await.json();
    let user_id = created["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:bogusEnterpriseField",
            "value": "foo"
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidPath");
}
