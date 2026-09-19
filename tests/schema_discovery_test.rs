//! RFC 7644 §4: `/Schemas/{id}` and `/ResourceTypes/{id}` must be
//! implemented alongside their collection forms; RFC 7643 §7: attributes
//! with a restricted set of values must advertise `canonicalValues`; and
//! every member of `authenticationSchemes[]` must be a valid `AuthenticationScheme`
//! (in particular, `specUri` -- an optional reference -- must never be an
//! empty string, which is not a valid URI).

use axum_test::TestServer;
use http::StatusCode;
use serde_json::Value;

mod common;

/// Look up the `attributes[].name == name` entry of a `/Schemas` resource.
fn find_attribute<'a>(schema: &'a Value, name: &str) -> &'a Value {
    schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name)
        .unwrap_or_else(|| panic!("attribute '{}' present", name))
}

#[tokio::test]
async fn test_get_schema_by_id_returns_the_matching_schema() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["id"], "urn:ietf:params:scim:schemas:core:2.0:User");
    assert_eq!(body["name"], "User");
}

#[tokio::test]
async fn test_schema_meta_location_is_an_absolute_url_not_a_bare_urn() {
    // RFC 7643 §3.1 defines `meta.location` as "The URI of the resource
    // being returned" -- an absolute URL consistent with the tenant's base
    // URL, not the schema's own `id` URN (a schema is not located at its
    // own identifying URN).
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let location = body["meta"]["location"].as_str().unwrap();
    assert!(location.starts_with("http://"));
    assert!(location.ends_with("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"));
}

#[tokio::test]
async fn test_resource_type_meta_location_is_an_absolute_url_not_a_bare_urn() {
    // RFC 7643 §3.1: same requirement as schemas, for the sibling
    // /ResourceTypes/{id} endpoint.
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/ResourceTypes/User").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let location = body["meta"]["location"].as_str().unwrap();
    assert!(location.starts_with("http://"));
    assert!(location.ends_with("/scim/v2/ResourceTypes/User"));
    assert!(
        !location.contains("urn:ietf:params:scim:schemas"),
        "ResourceTypes location must be a URL, not a schema URN: {}",
        location
    );
}

#[tokio::test]
async fn test_get_schema_by_unknown_id_returns_scim_404() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:NoSuchSchema")
        .await;
    response.assert_status(StatusCode::NOT_FOUND);
    let body: Value = response.json();
    assert_eq!(
        body["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
}

#[tokio::test]
async fn test_get_resource_type_by_id_returns_the_matching_resource_type() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/ResourceTypes/User").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["id"], "User");
    assert_eq!(body["endpoint"], "/Users");
}

#[tokio::test]
async fn test_get_resource_type_by_unknown_id_returns_scim_404() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/ResourceTypes/NoSuchType").await;
    response.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_group_members_type_advertises_canonical_values() {
    // RFC 7643 §7: canonicalValues must come from real schema data, not be
    // reconstructed by pattern-matching a human-readable description --
    // Group.members.type's description ("A label indicating the type of
    // resource") doesn't mention "member" at all, which is exactly why a
    // description-based heuristic would miss it.
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/Schemas").await;
    let body: Value = response.json();

    let group_schema = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group")
        .expect("Group schema present");

    let members_attr = group_schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "members")
        .expect("members attribute present");

    let type_attr = members_attr["subAttributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "type")
        .expect("members.type sub-attribute present");

    let canonical: Vec<&str> = type_attr["canonicalValues"]
        .as_array()
        .expect("members.type should advertise canonicalValues")
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(canonical, vec!["User", "Group"]);
}

#[tokio::test]
async fn test_emails_type_advertises_canonical_values() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/Schemas").await;
    let body: Value = response.json();

    let user_schema = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        .expect("User schema present");

    let emails_attr = user_schema["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "emails")
        .expect("emails attribute present");

    let type_attr = emails_attr["subAttributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "type")
        .expect("emails.type sub-attribute present");

    assert!(type_attr["canonicalValues"].is_array());
}

#[tokio::test]
async fn test_service_provider_config_never_advertises_empty_spec_uri() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/ServiceProviderConfig").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    for scheme in body["authenticationSchemes"].as_array().unwrap() {
        if let Some(spec_uri) = scheme.get("specUri") {
            assert_ne!(
                spec_uri.as_str(),
                Some(""),
                "specUri must not be an empty string: {:?}",
                scheme
            );
        }
    }
}

// RFC 7643 §7 defines the "returned" attribute characteristic: "default"
// means the attribute is returned by default, "never" means it is never
// returned. When a tenant is configured with `include_user_groups: false`,
// `GET /Users/{id}` structurally never includes `groups` (even for a user
// that has groups), so advertising `"returned": "default"` for it in
// `/Schemas` would be a mismatch between the advertised schema and actual
// behavior. `/Schemas` must instead advertise `"returned": "never"` for
// `User.groups` in that case.

#[tokio::test]
async fn test_schemas_advertises_user_groups_as_never_when_include_user_groups_disabled() {
    let mut app_config = common::create_test_app_config();
    app_config.compatibility.include_user_groups = false;
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

    let groups_attr = find_attribute(user_schema, "groups");
    assert_eq!(
        groups_attr["returned"], "never",
        "User.groups must be advertised as 'never' when include_user_groups is false"
    );
}

#[tokio::test]
async fn test_schema_by_id_advertises_user_groups_as_never_when_include_user_groups_disabled() {
    let mut app_config = common::create_test_app_config();
    app_config.compatibility.include_user_groups = false;
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let groups_attr = find_attribute(&body, "groups");
    assert_eq!(
        groups_attr["returned"], "never",
        "User.groups must be advertised as 'never' when include_user_groups is false"
    );
}

#[tokio::test]
async fn test_schemas_advertises_user_groups_as_default_when_include_user_groups_enabled() {
    // Default configuration (include_user_groups: true, the default) --
    // User.groups is actually returned, so "default" remains correct.
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

    let groups_attr = find_attribute(user_schema, "groups");
    assert_eq!(groups_attr["returned"], "default");

    let response = server
        .get("/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let groups_attr = find_attribute(&body, "groups");
    assert_eq!(groups_attr["returned"], "default");
}

#[tokio::test]
async fn test_group_members_stays_default_when_show_empty_groups_members_disabled() {
    // Unchanged case: `show_empty_groups_members: false` only omits
    // Group.members / User.groups when the value is an *empty* array.
    // RFC 7643 §2.5: "Unassigned attributes, the null value, or an empty
    // array (in the case of a multi-valued attribute) SHALL be considered
    // to be equivalent in 'state'" and "When a resource is expressed in
    // JSON format, unassigned attributes, although they are defined in
    // schema, MAY be omitted for compactness." Omitting an empty
    // multi-valued attribute is therefore explicitly permitted and stays
    // consistent with "returned": "default" -- this must NOT be changed
    // to "never".
    let mut app_config = common::create_test_app_config();
    app_config.compatibility.show_empty_groups_members = false;
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let response = server.get("/scim/v2/Schemas").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    let group_schema = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:Group")
        .expect("Group schema present");

    let members_attr = find_attribute(group_schema, "members");
    assert_eq!(
        members_attr["returned"], "default",
        "Group.members must remain 'default' under show_empty_groups_members: false (RFC 7643 §2.5)"
    );

    let user_schema = body["Resources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        .expect("User schema present");
    let groups_attr = find_attribute(user_schema, "groups");
    assert_eq!(
        groups_attr["returned"], "default",
        "User.groups must remain 'default' under show_empty_groups_members: false (RFC 7643 §2.5)"
    );
}
