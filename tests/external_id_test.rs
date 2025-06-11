use serde_json::json;
use scim_server::models::{User, Group};
use scim_v2::models::{user::User as ScimUser, group::Group as ScimGroup};

#[test]
fn test_user_with_external_id_serialization() {
    let mut scim_user = ScimUser::default();
    scim_user.user_name = "testuser@example.com".to_string();
    
    let user_with_external = User::with_external_id(scim_user, Some("ext-123".to_string()));
    let user_json = serde_json::to_value(&user_with_external).unwrap();
    
    // Check that externalId is serialized
    assert_eq!(user_json["externalId"], "ext-123");
    assert_eq!(user_json["userName"], "testuser@example.com");
    
    // Check schemas are preserved
    let schemas = user_json["schemas"].as_array().unwrap();
    assert!(schemas.contains(&json!("urn:ietf:params:scim:schemas:core:2.0:User")));
}

#[test]
fn test_user_without_external_id_serialization() {
    let mut scim_user = ScimUser::default();
    scim_user.user_name = "testuser@example.com".to_string();
    
    let user_without_external = User::from_scim_user(scim_user);
    let user_json = serde_json::to_value(&user_without_external).unwrap();
    
    // Check that externalId is not serialized when None
    assert!(user_json.get("externalId").is_none());
    assert_eq!(user_json["userName"], "testuser@example.com");
}

#[test]
fn test_group_with_external_id_serialization() {
    let mut scim_group = ScimGroup::default();
    scim_group.display_name = "Test Group".to_string();
    
    let group_with_external = Group::with_external_id(scim_group, Some("ext-grp-456".to_string()));
    let group_json = serde_json::to_value(&group_with_external).unwrap();
    
    // Check that externalId is serialized
    assert_eq!(group_json["externalId"], "ext-grp-456");
    assert_eq!(group_json["displayName"], "Test Group");
    
    // Check schemas are preserved
    let schemas = group_json["schemas"].as_array().unwrap();
    assert!(schemas.contains(&json!("urn:ietf:params:scim:schemas:core:2.0:Group")));
}

#[test]
fn test_group_without_external_id_serialization() {
    let mut scim_group = ScimGroup::default();
    scim_group.display_name = "Test Group".to_string();
    
    let group_without_external = Group::from_scim_group(scim_group);
    let group_json = serde_json::to_value(&group_without_external).unwrap();
    
    // Check that externalId is not serialized when None
    assert!(group_json.get("externalId").is_none());
    assert_eq!(group_json["displayName"], "Test Group");
}

#[test]
fn test_user_deserialization_with_external_id() {
    let user_json = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser@example.com",
        "externalId": "ext-123",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });
    
    let user: User = serde_json::from_value(user_json).unwrap();
    assert_eq!(user.external_id, Some("ext-123".to_string()));
    assert_eq!(user.base.user_name, "testuser@example.com");
}

#[test]
fn test_user_deserialization_without_external_id() {
    let user_json = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "testuser@example.com",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        }
    });
    
    let user: User = serde_json::from_value(user_json).unwrap();
    assert_eq!(user.external_id, None);
    assert_eq!(user.base.user_name, "testuser@example.com");
}

#[test]
fn test_group_deserialization_with_external_id() {
    let group_json = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": "test-group-id",
        "displayName": "Test Group",
        "externalId": "ext-grp-456"
    });
    
    let group: Group = serde_json::from_value(group_json).unwrap();
    assert_eq!(group.external_id, Some("ext-grp-456".to_string()));
    assert_eq!(group.base.display_name, "Test Group");
}

#[test]
fn test_group_deserialization_without_external_id() {
    let group_json = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "id": "test-group-id",
        "displayName": "Test Group"
    });
    
    let group: Group = serde_json::from_value(group_json).unwrap();
    assert_eq!(group.external_id, None);
    assert_eq!(group.base.display_name, "Test Group");
}