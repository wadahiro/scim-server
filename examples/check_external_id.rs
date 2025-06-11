use scim_server::models::{Group, User};
use scim_v2::models::{group::Group as ScimGroup, user::User as ScimUser};
use serde_json;

fn main() {
    // Create a default User and Group to inspect their structure
    let user = User::default();
    let group = Group::default();

    println!("Extended User model structure:");
    let user_json = serde_json::to_value(&user).unwrap();
    let user_pretty = serde_json::to_string_pretty(&user_json).unwrap();
    println!("{}", user_pretty);

    println!("\nExtended Group model structure:");
    let group_json = serde_json::to_value(&group).unwrap();
    let group_pretty = serde_json::to_string_pretty(&group_json).unwrap();
    println!("{}", group_pretty);

    // Test creating User/Group with externalId
    println!("\n=== Testing User with externalId ===");
    let mut scim_user = ScimUser::default();
    scim_user.user_name = "testuser@example.com".to_string();

    let user_with_external = User::with_external_id(scim_user, Some("ext-123".to_string()));
    let user_external_json = serde_json::to_value(&user_with_external).unwrap();
    let user_external_pretty = serde_json::to_string_pretty(&user_external_json).unwrap();
    println!("{}", user_external_pretty);

    println!("\n=== Testing Group with externalId ===");
    let mut scim_group = ScimGroup::default();
    scim_group.display_name = "Test Group".to_string();

    let group_with_external = Group::with_external_id(scim_group, Some("ext-grp-456".to_string()));
    let group_external_json = serde_json::to_value(&group_with_external).unwrap();
    let group_external_pretty = serde_json::to_string_pretty(&group_external_json).unwrap();
    println!("{}", group_external_pretty);

    // Check if externalId field exists by trying to access it
    println!("\n=== Checking for externalId field ===");

    // For User
    match user_external_json.get("externalId") {
        Some(val) => println!("User externalId field exists: {:?}", val),
        None => println!("User externalId field does NOT exist"),
    }

    // For Group
    match group_external_json.get("externalId") {
        Some(val) => println!("Group externalId field exists: {:?}", val),
        None => println!("Group externalId field does NOT exist"),
    }
}
