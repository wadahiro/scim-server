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
//!
//! RFC 7643 §2.4 also forbids more than one `primary: true` within a single
//! multi-valued attribute's array, and RFC 7644 §3.5.2 says that a PATCH
//! setting one value's `primary` to `true` SHALL clear it from every other
//! value already present. Neither RFC says what should happen when a
//! *single* PATCH operation's own `value` supplies more than one
//! `primary: true` at once -- that request is internally contradictory and
//! unspecified by either RFC. The tests below verify that this
//! self-contradictory case is rejected (400 `invalidValue`), while every
//! sequentially coherent case -- an existing primary superseded by a new
//! one, two separate operations, operations on different attributes, and
//! attributes with no `primary` sub-attribute at all -- keeps working
//! exactly as before.

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

async fn create_bare_user(server: &TestServer, username: &str) -> String {
    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": username
    });
    let response = server.post("/scim/v2/Users").json(&user).await;
    response.assert_status(StatusCode::CREATED);
    let created: Value = response.json();
    created["id"].as_str().unwrap().to_string()
}

/// A single "add" operation whose own `value` array sets `primary: true` on
/// two elements at once is internally contradictory (RFC 7643 §2.4) and
/// must be rejected, not resolved by picking a winner.
#[tokio::test]
async fn test_patch_add_with_two_primaries_in_one_operation_is_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "conflicting.primary.add").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "emails",
            "value": [
                {"type": "work", "value": "a@example.test", "primary": true},
                {"type": "home", "value": "b@example.test", "primary": true}
            ]
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidValue");

    // Nothing should have been persisted.
    let fetched: Value = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .await
        .json();
    assert!(
        fetched.get("emails").is_none(),
        "rejected operation must not be persisted: {:?}",
        fetched
    );
}

/// Same contradiction, expressed via "replace" instead of "add", and on a
/// different attribute (`phoneNumbers`) to confirm the check is not
/// `emails`-specific.
#[tokio::test]
async fn test_patch_replace_with_two_primaries_in_one_operation_is_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "conflicting.primary.replace",
        "phoneNumbers": [{"value": "+1000", "type": "work"}]
    });
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "phoneNumbers",
            "value": [
                {"value": "+1000", "type": "work", "primary": true},
                {"value": "+2000", "type": "home", "primary": true}
            ]
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidValue");
}

/// Same contradiction on `addresses`, whose `primary` is carried on a
/// custom JSON wrapper field rather than the typed `scim_v2::User` model
/// (see `validate_addresses_primary_constraint`); confirms the PATCH-time
/// check covers it identically.
#[tokio::test]
async fn test_patch_add_with_two_primary_addresses_in_one_operation_is_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "conflicting.primary.address").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "addresses",
            "value": [
                {"type": "work", "streetAddress": "1 Main", "primary": true},
                {"type": "home", "streetAddress": "2 Side", "primary": true}
            ]
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidValue");
}

/// The value-path spelling of the same contradiction: a `replace` whose
/// filter matches more than one element and sets `primary` to `true` on
/// all of them is exactly as contradictory as an explicit two-element
/// array, just expressed differently.
#[tokio::test]
async fn test_patch_replace_value_path_primary_matching_multiple_is_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "conflicting.primary.valuepath",
        "emails": [
            {"value": "a@example.test", "type": "work"},
            {"value": "b@example.test", "type": "work"}
        ]
    });
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "emails[type eq \"work\"].primary",
            "value": true
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidValue");
}

/// RFC 7644 §3.5.2's SHALL: an existing `primary` must be superseded by a
/// newly PATCHed one. This is the legitimate, sequentially coherent case
/// that must keep working exactly as before -- it is not the contradiction
/// being rejected above.
#[tokio::test]
async fn test_new_primary_email_supersedes_existing_primary() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "supersede.primary",
        "emails": [{"value": "a@example.test", "type": "work", "primary": true}]
    });
    let create_response = server.post("/scim/v2/Users").json(&user).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_user: Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "emails",
            "value": [{"value": "b@example.test", "type": "home", "primary": true}]
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let patched: Value = response.json();
    let emails = patched["emails"].as_array().unwrap();
    assert_eq!(emails.len(), 2);
    let a = emails
        .iter()
        .find(|e| e["value"] == "a@example.test")
        .unwrap();
    let b = emails
        .iter()
        .find(|e| e["value"] == "b@example.test")
        .unwrap();
    assert!(
        a.get("primary").is_none() || a["primary"] == false,
        "old primary must be cleared: {:?}",
        a
    );
    assert_eq!(b["primary"], true, "new value must become primary: {:?}", b);
}

/// Two *separate* operations, each setting a different value's `primary`
/// to `true`, are sequentially coherent (RFC 7644 §3.5.2): the later
/// operation wins, and this must not be rejected as a contradiction --
/// only a single operation's own `value` array is checked.
#[tokio::test]
async fn test_two_separate_patch_operations_each_setting_primary_is_not_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "sequential.primary.ops").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": "a@example.test", "type": "work", "primary": true}]},
            {"op": "add", "path": "emails", "value": [{"value": "b@example.test", "type": "home", "primary": true}]}
        ]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let patched: Value = response.json();
    let emails = patched["emails"].as_array().unwrap();
    let primaries: Vec<_> = emails.iter().filter(|e| e["primary"] == true).collect();
    assert_eq!(
        primaries.len(),
        1,
        "exactly one primary expected: {:?}",
        emails
    );
    assert_eq!(
        primaries[0]["value"], "b@example.test",
        "later operation must win"
    );
}

/// The same "second wins" sequencing must hold even with an unrelated
/// operation on a *different* attribute in between -- `primary` is scoped
/// per multi-valued attribute (RFC 7643 §2.4), and the contradiction check
/// must never aggregate `primary: true` counts across separate operations,
/// even when they target the same attribute and are not adjacent.
#[tokio::test]
async fn test_interleaved_operations_on_same_attribute_are_not_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "interleaved.primary.ops").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": "e1@e.test", "type": "work", "primary": true}]},
            {"op": "add", "path": "phoneNumbers", "value": [{"value": "+15555550111", "type": "work", "primary": true}]},
            {"op": "add", "path": "emails", "value": [{"value": "e3@e.test", "type": "other", "primary": true}]}
        ]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let patched: Value = response.json();

    let emails = patched["emails"].as_array().unwrap();
    let e1 = emails.iter().find(|e| e["value"] == "e1@e.test").unwrap();
    let e3 = emails.iter().find(|e| e["value"] == "e3@e.test").unwrap();
    assert!(e1.get("primary").is_none() || e1["primary"] == false);
    assert_eq!(e3["primary"], true, "last operation on emails must win");

    let phones = patched["phoneNumbers"].as_array().unwrap();
    assert_eq!(
        phones[0]["primary"], true,
        "unrelated attribute's primary must be unaffected: {:?}",
        phones
    );
}

/// Two operations on two *different* attributes, each setting their own
/// primary, are entirely independent -- `primary` is scoped per
/// multi-valued attribute -- and neither should be rejected nor affect the
/// other.
#[tokio::test]
async fn test_operations_on_different_attributes_each_keep_own_primary() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "independent.primary.attrs").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": "a@example.test", "primary": true}]},
            {"op": "add", "path": "phoneNumbers", "value": [{"value": "+1000", "primary": true}]}
        ]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let patched: Value = response.json();
    assert_eq!(patched["emails"][0]["primary"], true);
    assert_eq!(patched["phoneNumbers"][0]["primary"], true);
}

/// RFC 7644 §3.5.2 requires PATCH to apply its operations in order and, on
/// failure, leave the resource as if the request had never been received.
/// A request mixing one valid operation with one internally contradictory
/// one must be rejected as a whole, and the valid operation must not have
/// been persisted.
#[tokio::test]
async fn test_mixed_valid_and_contradictory_operations_rejects_whole_request_atomically() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let user_id = create_bare_user(&server, "atomic.mixed.ops").await;

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {"op": "add", "path": "emails", "value": [{"value": "a@example.test", "primary": true}]},
            {"op": "add", "path": "phoneNumbers", "value": [
                {"value": "+1000", "primary": true},
                {"value": "+2000", "primary": true}
            ]}
        ]
    });
    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert_eq!(error["scimType"], "invalidValue");

    let fetched: Value = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .await
        .json();
    assert!(
        fetched.get("emails").is_none(),
        "the earlier, individually-valid operation must not have been persisted: {:?}",
        fetched
    );
    assert!(fetched.get("phoneNumbers").is_none());
}

/// A multi-valued attribute with no `primary` sub-attribute at all (Group
/// `members`) must never trigger the new rejection, even if a client
/// happens to send a field literally named "primary" on more than one
/// member -- this is the false-positive guard for resource types that
/// don't carry the concept.
#[tokio::test]
async fn test_group_members_with_no_primary_subattribute_is_never_rejected() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let member1 = create_bare_user(&server, "group.member.one").await;
    let member2 = create_bare_user(&server, "group.member.two").await;

    let group = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "No Primary Sub-Attribute Group"
    });
    let create_response = server.post("/scim/v2/Groups").json(&group).await;
    create_response.assert_status(StatusCode::CREATED);
    let created_group: Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    let patch_body = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "members",
            "value": [
                {"value": member1, "primary": true},
                {"value": member2, "primary": true}
            ]
        }]
    });
    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .json(&patch_body)
        .await;
    response.assert_status(StatusCode::OK);
    let patched: Value = response.json();
    assert_eq!(patched["members"].as_array().unwrap().len(), 2);
}
