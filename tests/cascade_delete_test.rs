//! Test cascade delete behavior for users and groups
//!
//! This test verifies that membership relationships are properly cleaned up
//! when users or groups are deleted.

use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

/// Test that deleting a user automatically removes them from all groups
#[tokio::test]
async fn test_user_delete_removes_from_groups() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create two users
    let user1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "cascade-test-user1",
        "name": {
            "givenName": "User",
            "familyName": "One"
        },
        "active": true
    });

    let user2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "cascade-test-user2",
        "name": {
            "givenName": "User",
            "familyName": "Two"
        },
        "active": true
    });

    let user1_response = server.post("/scim/v2/Users").json(&user1_data).await;
    user1_response.assert_status(StatusCode::CREATED);
    let user1: Value = user1_response.json();
    let user1_id = user1["id"].as_str().unwrap();

    let user2_response = server.post("/scim/v2/Users").json(&user2_data).await;
    user2_response.assert_status(StatusCode::CREATED);
    let user2: Value = user2_response.json();
    let user2_id = user2["id"].as_str().unwrap();

    println!("Created users: {} and {}", user1_id, user2_id);

    // Create a group with both users
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Cascade Test Group",
        "members": [
            {
                "value": user1_id,
                "type": "User",
                "display": "User One"
            },
            {
                "value": user2_id,
                "type": "User",
                "display": "User Two"
            }
        ]
    });

    let group_response = server.post("/scim/v2/Groups").json(&group_data).await;
    group_response.assert_status(StatusCode::CREATED);
    let group: Value = group_response.json();
    let group_id = group["id"].as_str().unwrap();

    println!("Created group: {} with 2 members", group_id);

    // Verify initial state - group has 2 members
    let get_group = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    get_group.assert_status(StatusCode::OK);
    let initial_group: Value = get_group.json();
    let initial_members = initial_group["members"].as_array().unwrap();
    assert_eq!(
        initial_members.len(),
        2,
        "Group should have 2 members initially"
    );

    // Now delete user1
    println!("Deleting user1: {}", user1_id);
    let delete_response = server.delete(&format!("/scim/v2/Users/{}", user1_id)).await;
    delete_response.assert_status(StatusCode::NO_CONTENT);

    // Verify user1 is deleted
    let get_deleted_user = server.get(&format!("/scim/v2/Users/{}", user1_id)).await;
    get_deleted_user.assert_status(StatusCode::NOT_FOUND);

    // Check the group - it should now have only 1 member (user2)
    let get_group_after = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    get_group_after.assert_status(StatusCode::OK);
    let group_after: Value = get_group_after.json();

    if let Some(members_value) = group_after.get("members") {
        if let Some(members_array) = members_value.as_array() {
            println!(
                "After user deletion: Group has {} members",
                members_array.len()
            );

            assert_eq!(
                members_array.len(),
                1,
                "Group should have 1 member after deleting user1"
            );

            // Verify remaining member is user2
            assert_eq!(
                members_array[0]["value"], user2_id,
                "Remaining member should be user2"
            );

            println!("✅ User deletion correctly removed user from group membership");
        } else {
            panic!("members should be an array");
        }
    } else {
        // Some implementations might remove empty members array
        panic!("Group should still have members field with 1 member");
    }
}

/// Test that deleting a group automatically removes it from all user's groups attribute
#[tokio::test]
async fn test_group_delete_removes_from_user_groups() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "multi-group-user",
        "name": {
            "givenName": "Multi",
            "familyName": "Group"
        },
        "active": true
    });

    let user_response = server.post("/scim/v2/Users").json(&user_data).await;
    user_response.assert_status(StatusCode::CREATED);
    let user: Value = user_response.json();
    let user_id = user["id"].as_str().unwrap();

    println!("Created user: {}", user_id);

    // Create two groups with the user as member
    let group1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Group One",
        "members": [
            {
                "value": user_id,
                "type": "User",
                "display": "Multi Group"
            }
        ]
    });

    let group2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Group Two",
        "members": [
            {
                "value": user_id,
                "type": "User",
                "display": "Multi Group"
            }
        ]
    });

    let group1_response = server.post("/scim/v2/Groups").json(&group1_data).await;
    group1_response.assert_status(StatusCode::CREATED);
    let group1: Value = group1_response.json();
    let group1_id = group1["id"].as_str().unwrap();

    let group2_response = server.post("/scim/v2/Groups").json(&group2_data).await;
    group2_response.assert_status(StatusCode::CREATED);
    let group2: Value = group2_response.json();
    let group2_id = group2["id"].as_str().unwrap();

    println!("Created groups: {} and {}", group1_id, group2_id);

    // Verify initial state - user is member of 2 groups
    let get_user = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    get_user.assert_status(StatusCode::OK);
    let initial_user: Value = get_user.json();

    if let Some(groups_value) = initial_user.get("groups") {
        if let Some(groups_array) = groups_value.as_array() {
            assert_eq!(
                groups_array.len(),
                2,
                "User should be member of 2 groups initially"
            );
            println!(
                "✓ Initial state: User is member of {} groups",
                groups_array.len()
            );
        }
    }

    // Now delete group1
    println!("Deleting group1: {}", group1_id);
    let delete_response = server
        .delete(&format!("/scim/v2/Groups/{}", group1_id))
        .await;
    delete_response.assert_status(StatusCode::NO_CONTENT);

    // Verify group1 is deleted
    let get_deleted_group = server.get(&format!("/scim/v2/Groups/{}", group1_id)).await;
    get_deleted_group.assert_status(StatusCode::NOT_FOUND);

    // Check the user - they should now be member of only 1 group (group2)
    let get_user_after = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    get_user_after.assert_status(StatusCode::OK);
    let user_after: Value = get_user_after.json();

    if let Some(groups_value) = user_after.get("groups") {
        if let Some(groups_array) = groups_value.as_array() {
            println!(
                "After group deletion: User is member of {} groups",
                groups_array.len()
            );

            assert_eq!(
                groups_array.len(),
                1,
                "User should be member of 1 group after deleting group1"
            );

            // Verify remaining group is group2
            assert_eq!(
                groups_array[0]["value"], group2_id,
                "Remaining group should be group2"
            );
            assert_eq!(
                groups_array[0]["display"], "Group Two",
                "Remaining group display should be 'Group Two'"
            );

            println!("✅ Group deletion correctly removed group from user's groups attribute");
        } else {
            panic!("groups should be an array");
        }
    } else {
        // Check if compatibility mode might be hiding empty groups
        panic!("User should still have groups field with 1 group");
    }
}

/// Test that deleting a parent group removes it from child group's groups attribute
#[tokio::test]
async fn test_parent_group_delete_removes_from_child_groups() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create two groups: parent and child
    let parent_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Parent Group"
    });

    let child_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Child Group"
    });

    let parent_response = server
        .post("/scim/v2/Groups")
        .json(&parent_group_data)
        .await;
    parent_response.assert_status(StatusCode::CREATED);
    let parent_group: Value = parent_response.json();
    let parent_group_id = parent_group["id"].as_str().unwrap();

    let child_response = server.post("/scim/v2/Groups").json(&child_group_data).await;
    child_response.assert_status(StatusCode::CREATED);
    let child_group: Value = child_response.json();
    let child_group_id = child_group["id"].as_str().unwrap();

    println!("Created parent group: {}", parent_group_id);
    println!("Created child group: {}", child_group_id);

    // Add child group as member of parent group
    let patch_add_child = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": child_group_id,
                        "type": "Group",
                        "display": "Child Group"
                    }
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", parent_group_id))
        .json(&patch_add_child)
        .await;
    patch_response.assert_status(StatusCode::OK);

    // Verify initial state - parent has child as member
    let get_parent = server
        .get(&format!("/scim/v2/Groups/{}", parent_group_id))
        .await;
    get_parent.assert_status(StatusCode::OK);
    let initial_parent: Value = get_parent.json();
    let parent_members = initial_parent["members"].as_array().unwrap();
    assert_eq!(
        parent_members.len(),
        1,
        "Parent should have 1 member (child group)"
    );
    assert_eq!(parent_members[0]["value"], child_group_id);
    assert_eq!(parent_members[0]["type"], "Group");

    // Verify child has parent in groups attribute (if implemented)
    let get_child = server
        .get(&format!("/scim/v2/Groups/{}", child_group_id))
        .await;
    get_child.assert_status(StatusCode::OK);
    let initial_child: Value = get_child.json();

    // Note: SCIM groups don't typically have a "groups" attribute like users do
    // But if implemented, we would check it here
    if let Some(groups_value) = initial_child.get("groups") {
        if let Some(groups_array) = groups_value.as_array() {
            println!(
                "Child group is member of {} parent groups",
                groups_array.len()
            );
        }
    }

    // Now delete the parent group
    println!("Deleting parent group: {}", parent_group_id);
    let delete_response = server
        .delete(&format!("/scim/v2/Groups/{}", parent_group_id))
        .await;
    delete_response.assert_status(StatusCode::NO_CONTENT);

    // Verify parent group is deleted
    let get_deleted_parent = server
        .get(&format!("/scim/v2/Groups/{}", parent_group_id))
        .await;
    get_deleted_parent.assert_status(StatusCode::NOT_FOUND);

    // Verify child group still exists (should not be cascade deleted)
    let get_child_after = server
        .get(&format!("/scim/v2/Groups/{}", child_group_id))
        .await;
    get_child_after.assert_status(StatusCode::OK);
    let child_after: Value = get_child_after.json();

    println!("✅ Parent group deletion: Child group still exists as expected");

    // If child groups had a "groups" attribute, we would verify the parent is removed from it
    if let Some(groups_value) = child_after.get("groups") {
        if let Some(groups_array) = groups_value.as_array() {
            assert!(
                !groups_array.iter().any(|g| g["value"] == parent_group_id),
                "Parent group should be removed from child's groups attribute"
            );
            println!("✅ Parent group correctly removed from child's groups attribute");
        }
    }
}

/// Test that deleting a child group removes it from parent group's members
#[tokio::test]
async fn test_child_group_delete_removes_from_parent_members() {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) =
        common::setup_test_app_with_db(tenant_config, common::TestDatabaseType::Sqlite)
            .await
            .unwrap();
    let server = TestServer::new(app).unwrap();

    // Create parent group and two child groups
    let parent_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Parent Group with Multiple Children"
    });

    let child1_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Child Group 1"
    });

    let child2_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Child Group 2"
    });

    let parent_response = server
        .post("/scim/v2/Groups")
        .json(&parent_group_data)
        .await;
    parent_response.assert_status(StatusCode::CREATED);
    let parent_group: Value = parent_response.json();
    let parent_group_id = parent_group["id"].as_str().unwrap();

    let child1_response = server.post("/scim/v2/Groups").json(&child1_data).await;
    child1_response.assert_status(StatusCode::CREATED);
    let child1_group: Value = child1_response.json();
    let child1_group_id = child1_group["id"].as_str().unwrap();

    let child2_response = server.post("/scim/v2/Groups").json(&child2_data).await;
    child2_response.assert_status(StatusCode::CREATED);
    let child2_group: Value = child2_response.json();
    let child2_group_id = child2_group["id"].as_str().unwrap();

    println!(
        "Created parent: {} and children: {}, {}",
        parent_group_id, child1_group_id, child2_group_id
    );

    // Add both child groups as members of parent group
    let patch_add_children = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": child1_group_id,
                        "type": "Group",
                        "display": "Child Group 1"
                    },
                    {
                        "value": child2_group_id,
                        "type": "Group",
                        "display": "Child Group 2"
                    }
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", parent_group_id))
        .json(&patch_add_children)
        .await;
    patch_response.assert_status(StatusCode::OK);

    // Verify initial state - parent has 2 child groups as members
    let get_parent = server
        .get(&format!("/scim/v2/Groups/{}", parent_group_id))
        .await;
    get_parent.assert_status(StatusCode::OK);
    let initial_parent: Value = get_parent.json();
    let initial_members = initial_parent["members"].as_array().unwrap();
    assert_eq!(
        initial_members.len(),
        2,
        "Parent should have 2 child group members"
    );

    let member_ids: Vec<&str> = initial_members
        .iter()
        .map(|m| m["value"].as_str().unwrap())
        .collect();
    assert!(member_ids.contains(&child1_group_id));
    assert!(member_ids.contains(&child2_group_id));

    println!(
        "✓ Initial state: Parent has {} child group members",
        initial_members.len()
    );

    // Now delete child1 group
    println!("Deleting child1 group: {}", child1_group_id);
    let delete_response = server
        .delete(&format!("/scim/v2/Groups/{}", child1_group_id))
        .await;
    delete_response.assert_status(StatusCode::NO_CONTENT);

    // Verify child1 group is deleted
    let get_deleted_child = server
        .get(&format!("/scim/v2/Groups/{}", child1_group_id))
        .await;
    get_deleted_child.assert_status(StatusCode::NOT_FOUND);

    // Verify parent group now has only 1 member (child2)
    let get_parent_after = server
        .get(&format!("/scim/v2/Groups/{}", parent_group_id))
        .await;
    get_parent_after.assert_status(StatusCode::OK);
    let parent_after: Value = get_parent_after.json();

    if let Some(members_value) = parent_after.get("members") {
        if let Some(members_array) = members_value.as_array() {
            println!(
                "After child1 deletion: Parent has {} members",
                members_array.len()
            );

            assert_eq!(
                members_array.len(),
                1,
                "Parent should have 1 member after deleting child1"
            );

            // Verify remaining member is child2
            assert_eq!(
                members_array[0]["value"], child2_group_id,
                "Remaining member should be child2"
            );
            assert_eq!(
                members_array[0]["type"], "Group",
                "Remaining member should be of type Group"
            );

            println!("✅ Child group deletion correctly removed group from parent's members");
        } else {
            panic!("members should be an array");
        }
    } else {
        panic!("Parent should still have members field with 1 group");
    }

    // Verify child2 still exists
    let get_child2_after = server
        .get(&format!("/scim/v2/Groups/{}", child2_group_id))
        .await;
    get_child2_after.assert_status(StatusCode::OK);
    println!("✅ Child2 group still exists as expected");
}

/// Test cascade delete with PostgreSQL database
#[tokio::test]
#[cfg(feature = "postgresql")]
async fn test_cascade_delete_postgres() {
    let app_config = common::create_test_app_config();
    let (app, _postgres_container) = common::setup_postgres_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create a user
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "postgres-cascade-user",
        "name": {
            "givenName": "Postgres",
            "familyName": "User"
        }
    });

    let user_response = server.post("/scim/v2/Users").json(&user_data).await;
    user_response.assert_status(StatusCode::CREATED);
    let user: Value = user_response.json();
    let user_id = user["id"].as_str().unwrap();

    // Create a group with the user
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Postgres Cascade Group",
        "members": [
            {
                "value": user_id,
                "type": "User"
            }
        ]
    });

    let group_response = server.post("/scim/v2/Groups").json(&group_data).await;
    group_response.assert_status(StatusCode::CREATED);
    let group: Value = group_response.json();
    let group_id = group["id"].as_str().unwrap();

    // Delete the user
    let delete_response = server.delete(&format!("/scim/v2/Users/{}", user_id)).await;
    delete_response.assert_status(StatusCode::NO_CONTENT);

    // Verify group now has no members
    let get_group = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    get_group.assert_status(StatusCode::OK);
    let group_after: Value = get_group.json();

    if let Some(members) = group_after.get("members") {
        if let Some(members_array) = members.as_array() {
            assert!(
                members_array.is_empty(),
                "Group should have no members after user deletion"
            );
            println!("✅ PostgreSQL: User deletion correctly cascaded to group membership");
        }
    }
}
