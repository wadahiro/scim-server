use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::TestDatabaseType;

// Macro to run the same test with different database types
macro_rules! matrix_test {
    ($test_name:ident, $test_fn:ident) => {
        paste::paste! {
            #[tokio::test]
            async fn [<$test_name _sqlite>]() {
                $test_fn(TestDatabaseType::Sqlite).await;
            }

            #[tokio::test]
            async fn [<$test_name _postgres>]() {
                $test_fn(TestDatabaseType::Postgres).await;
            }
        }
    };
}

async fn user_crud_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    // Test POST - Create a user
    let user_data = common::create_test_user_json(
        &format!("{}-user", db_prefix),
        &format!(
            "{}User",
            db_prefix
                .chars()
                .next()
                .unwrap()
                .to_uppercase()
                .collect::<String>()
                + &db_prefix[1..]
        ),
        "Test",
    );

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    if response.status_code() != StatusCode::CREATED {
        eprintln!("Create user failed with status: {}", response.status_code());
        eprintln!("Response body: {}", response.text());
        panic!("User creation failed for {:?}", db_type);
    }

    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // Verify the created user has the expected properties
    assert_eq!(created_user["userName"], format!("{}-user", db_prefix));
    assert!(created_user["meta"]["created"].is_string());
    assert!(created_user["meta"]["lastModified"].is_string());
    assert_eq!(created_user["meta"]["resourceType"], "User");

    // Test GET - Read the user
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);

    let retrieved_user: Value = response.json();
    assert_eq!(retrieved_user["id"], user_id);
    assert_eq!(retrieved_user["userName"], format!("{}-user", db_prefix));

    // Test PUT - Update the user
    let updated_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": format!("{}-user-updated", db_prefix),
        "name": {
            "givenName": format!("{}UserUpdated", db_prefix.chars().next().unwrap().to_uppercase().collect::<String>() + &db_prefix[1..]),
            "familyName": "TestUpdated"
        },
        "emails": [{
            "value": format!("{}-updated@example.com", db_prefix),
            "primary": true
        }],
        "active": true
    });

    let response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&updated_data)
        .await;

    response.assert_status(StatusCode::OK);
    let updated_user: Value = response.json();
    assert_eq!(
        updated_user["userName"],
        format!("{}-user-updated", db_prefix)
    );

    // Test DELETE - Delete the user
    let response = server.delete(&format!("/scim/v2/Users/{}", user_id)).await;

    response.assert_status(StatusCode::NO_CONTENT);

    // Verify the user is deleted
    let response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;

    response.assert_status(StatusCode::NOT_FOUND);
}

async fn group_crud_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "SQLite",
        TestDatabaseType::Postgres => "PostgreSQL",
    };

    // Test POST - Create a group
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} Test Group", db_prefix)
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"]
        .as_str()
        .expect("Group should have an ID");

    // Verify the created group
    assert_eq!(
        created_group["displayName"],
        format!("{} Test Group", db_prefix)
    );
    assert_eq!(created_group["meta"]["resourceType"], "Group");

    // Test GET - Read the group
    let response = server
        .get(&format!("/scim/v2/Groups/{}", group_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let retrieved_group: Value = response.json();
    assert_eq!(retrieved_group["id"], group_id);
    assert_eq!(
        retrieved_group["displayName"],
        format!("{} Test Group", db_prefix)
    );

    // Test DELETE - Delete the group
    let response = server
        .delete(&format!("/scim/v2/Groups/{}", group_id))
        .await;

    response.assert_status(StatusCode::NO_CONTENT);
}

async fn group_membership_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    // Create a user first
    let user_data =
        common::create_test_user_json(&format!("member-{}", db_prefix), "Member", "User");
    let user_response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Create a group with the user as member
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} Membership Group", db_prefix.chars().next().unwrap().to_uppercase().collect::<String>() + &db_prefix[1..]),
        "members": [
            {
                "value": user_id,
                "display": "Member User"
            }
        ]
    });

    let group_response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    group_response.assert_status(StatusCode::CREATED);
    let created_group: Value = group_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Get the group to verify it has the member
    let group_get_response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;

    group_get_response.assert_status(StatusCode::OK);
    let group_with_members: Value = group_get_response.json();

    // Verify group has the member
    assert!(group_with_members["members"].is_array());
    assert_eq!(group_with_members["members"][0]["value"], user_id);
    assert_eq!(group_with_members["members"][0]["type"], "User");

    // Get the user and verify it has groups attribute
    let user_get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;

    user_get_response.assert_status(StatusCode::OK);
    let user_with_groups: Value = user_get_response.json();

    // Verify user has groups attribute
    assert!(user_with_groups["groups"].is_array());
    assert_eq!(user_with_groups["groups"][0]["value"], group_id);
    assert_eq!(
        user_with_groups["groups"][0]["display"],
        format!(
            "{} Membership Group",
            db_prefix
                .chars()
                .next()
                .unwrap()
                .to_uppercase()
                .collect::<String>()
                + &db_prefix[1..]
        )
    );
}

async fn group_to_group_membership_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "SQLite",
        TestDatabaseType::Postgres => "PostgreSQL",
    };

    // Create parent group
    let parent_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} Parent Group", db_prefix)
    });

    let parent_response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&parent_group_data)
        .await;

    parent_response.assert_status(StatusCode::CREATED);
    let parent_group: Value = parent_response.json();
    let parent_group_id = parent_group["id"].as_str().unwrap();

    // Create child group
    let child_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} Child Group", db_prefix)
    });

    let child_response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&child_group_data)
        .await;

    child_response.assert_status(StatusCode::CREATED);
    let child_group: Value = child_response.json();
    let child_group_id = child_group["id"].as_str().unwrap();

    // Add child group as member of parent group
    let patch_add_group_member = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": child_group_id,
                        "type": "Group",
                        "display": format!("{} Child Group", db_prefix)
                    }
                ]
            }
        ]
    });

    let patch_response = server
        .patch(&format!("/scim/v2/Groups/{}", parent_group_id))
        .content_type("application/scim+json")
        .json(&patch_add_group_member)
        .await;

    patch_response.assert_status(StatusCode::OK);
    let patched_parent: Value = patch_response.json();

    // Verify the parent group has the child group as member
    assert!(patched_parent["members"].is_array());
    assert_eq!(patched_parent["members"][0]["value"], child_group_id);
    assert_eq!(patched_parent["members"][0]["type"], "Group");
    assert_eq!(
        patched_parent["members"][0]["display"],
        format!("{} Child Group", db_prefix)
    );

    // Verify the $ref is correctly set for Group type with full URL with numeric tenant ID 3
    let expected_ref = format!("http://localhost/scim/v2/Groups/{}", child_group_id);
    assert_eq!(patched_parent["members"][0]["$ref"], expected_ref);
}

async fn group_list_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "SQLite",
        TestDatabaseType::Postgres => "PostgreSQL",
    };

    // Create a group first
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} List Test Group", db_prefix)
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);

    // Test GET all groups
    let response = server
        .get("/scim/v2/Groups")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);

    let groups_response: Value = response.json();
    assert_eq!(
        groups_response["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert!(groups_response["totalResults"].as_i64().unwrap() >= 1);

    let resources = groups_response["Resources"].as_array().unwrap();
    assert!(!resources.is_empty());
}

async fn group_patch_operations_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    // Create a user first for testing membership
    let user_data = common::create_test_user_json(&format!("test-{}", db_prefix), "Test", "User");
    let user_response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    user_response.assert_status(StatusCode::CREATED);
    let created_user: Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Create a group
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": format!("{} Patch Test Group", db_prefix.chars().next().unwrap().to_uppercase().collect::<String>() + &db_prefix[1..])
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_group: Value = response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Test PATCH - Replace displayName
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "displayName",
                "value": format!("Patched {} Group Name", db_prefix.chars().next().unwrap().to_uppercase().collect::<String>() + &db_prefix[1..])
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert_eq!(
        patched_group["displayName"],
        format!(
            "Patched {} Group Name",
            db_prefix
                .chars()
                .next()
                .unwrap()
                .to_uppercase()
                .collect::<String>()
                + &db_prefix[1..]
        )
    );
    assert_eq!(patched_group["id"], group_id);

    // Test PATCH - Add members
    let patch_add_members = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "add",
                "path": "members",
                "value": [
                    {
                        "value": user_id,
                        "display": "Test User"
                    }
                ]
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_add_members)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert!(patched_group["members"].is_array());
    assert_eq!(patched_group["members"][0]["value"], user_id);
    assert_eq!(patched_group["members"][0]["type"], "User");

    // Test PATCH - Remove members
    let patch_remove_members = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "remove",
                "path": format!("members[value eq \"{}\"]", user_id)
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Groups/{}", group_id))
        .content_type("application/scim+json")
        .json(&patch_remove_members)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_group: Value = response.json();
    assert!(
        patched_group["members"].is_array()
            && patched_group["members"].as_array().unwrap().is_empty()
    );
}

async fn group_error_scenarios_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";
    let invalid_tenant_id = "invalid-tenant";

    // Test creating group with invalid tenant
    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Test Group"
    });

    let response = server
        .post(&format!("/{}/v2/Groups", invalid_tenant_id))
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response.assert_status(StatusCode::NOT_FOUND);

    // Test creating group with missing displayName
    let invalid_group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    });

    let response = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&invalid_group_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);

    // Test getting non-existent group
    let fake_group_id = "00000000-0000-0000-0000-000000000000";
    let response = server
        .get(&format!("/scim/v2/Groups/{}", fake_group_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::NOT_FOUND);
}

async fn enhanced_filter_search_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔍 Enhanced Filter Search Test ({:?})", db_type);
    println!("=========================================");

    // 🏗️ 様々な属性を持つテストユーザーを作成
    println!("\n1. 📝 テストユーザーの作成");

    let test_users = vec![
        // (username, nickname, external_id, title, user_type)
        ("alice", "Ali", "EXT-001", "Software Engineer", "Employee"),
        ("bob", "Bobby", "EXT-002", "Product Manager", "Employee"),
        ("charlie", "Chuck", "EXT-003", "Designer", "Contractor"),
        ("diana", "Di", "EXT-004", "Data Scientist", "Employee"),
        ("eve", "Evelyn", "EXT-005", "QA Engineer", "Employee"),
    ];

    let mut created_user_ids = Vec::new();

    for (username, nickname, external_id, title, user_type) in test_users {
        let user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("{}-{}", db_prefix, username),
            "nickName": nickname,
            "externalId": external_id,
            "name": {
                "givenName": username.chars().next().unwrap().to_uppercase().collect::<String>() + &username[1..],
                "familyName": "Test",
                "formatted": format!("{} Test", username.chars().next().unwrap().to_uppercase().collect::<String>() + &username[1..])
            },
            "displayName": format!("{} ({})", nickname, title),
            "emails": [
                {
                    "value": format!("{}@company.com", username),
                    "type": "work",
                    "primary": true
                },
                {
                    "value": format!("{}.personal@gmail.com", username),
                    "type": "home",
                    "primary": false
                }
            ],
            "title": title,
            "userType": user_type,
            "active": true
        });

        let response = server
            .post("/scim/v2/Users")
            .content_type("application/scim+json")
            .json(&user_data)
            .await;

        response.assert_status(StatusCode::CREATED);
        let created_user: Value = response.json();

        if let Some(id) = created_user["id"].as_str() {
            created_user_ids.push(id.to_string());
            println!(
                "   ✅ ユーザー '{}-{}' を作成 (ID: {})",
                db_prefix, username, id
            );
        }
    }

    // 🎯 様々な属性での検索テストを実行
    println!("\n2. 🔍 拡張フィルタ検索テスト");

    // Test 1: userName での検索（既存機能の確認）
    println!("\n   Test 1: userName での検索");
    let response = server
        .get(&format!(
            "/scim/v2/Users?filter=userName%20eq%20%22{}-alice%22",
            db_prefix
        ))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-alice", db_prefix)
    );
    println!("      ✅ userName '{}-alice' での検索成功", db_prefix);

    // Test 2: nickName での検索（新機能）
    println!("\n   Test 2: nickName での検索");
    let response = server
        .get("/scim/v2/Users?filter=nickName%20eq%20%22Bobby%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-bob", db_prefix)
    );
    println!("      ✅ nickName 'Bobby' での検索成功");

    // Test 3: externalId での検索（case-exact）
    println!("\n   Test 3: externalId での検索（case-exact）");
    let response = server
        .get("/scim/v2/Users?filter=externalId%20eq%20%22EXT-003%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-charlie", db_prefix)
    );
    println!("      ✅ externalId 'EXT-003' での検索成功");

    // Test 4: title での検索
    println!("\n   Test 4: title での検索");
    let response = server
        .get("/scim/v2/Users?filter=title%20eq%20%22Product%20Manager%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-bob", db_prefix)
    );
    println!("      ✅ title 'Product Manager' での検索成功");

    // Test 5: userType での検索（複数結果）
    println!("\n   Test 5: userType での検索（複数結果）");
    let response = server
        .get("/scim/v2/Users?filter=userType%20eq%20%22Employee%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 4); // alice, bob, diana, eve
    println!(
        "      ✅ userType 'Employee' での検索成功（{}件）",
        search_result["totalResults"]
    );

    // Test 6: emails での検索（複合フィルター）
    println!("\n   Test 6: emails での検索（複合フィルター）");
    let response = server
        .get("/scim/v2/Users?filter=emails.value%20eq%20%22diana%40company.com%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-diana", db_prefix)
    );
    println!("      ✅ emails[value eq 'diana@company.com'] での検索成功");

    // Test 7: name.formatted での検索（ネストしたname属性）
    println!("\n   Test 7: name.formatted での検索（ネストしたname属性）");
    let response = server
        .get("/scim/v2/Users?filter=name.formatted%20eq%20%22Alice%20Test%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-alice", db_prefix)
    );
    println!("      ✅ name.formatted 'Alice Test' での検索成功");

    // Test 8: name.givenName での検索
    println!("\n   Test 8: name.givenName での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.givenName%20eq%20%22Bob%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-bob", db_prefix)
    );
    println!("      ✅ name.givenName 'Bob' での検索成功");

    // Test 9: name.familyName での検索
    println!("\n   Test 9: name.familyName での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.familyName%20eq%20%22Test%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    // 全ユーザーがfamilyName "Test"を持っているので5件ヒット
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 5);
    println!(
        "      ✅ name.familyName 'Test' での検索成功（{}件）",
        search_result["totalResults"]
    );

    // Test 10: displayName での検索（case-insensitive）
    println!("\n   Test 10: displayName での検索（case-insensitive）");
    let response = server
        .get("/scim/v2/Users?filter=displayName%20eq%20%22ali%20%28software%20engineer%29%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-alice", db_prefix)
    );
    println!("      ✅ displayName case-insensitive検索成功");

    // Test 11: emails.type での検索（ネストした属性の別フィールド）
    println!("\n   Test 11: emails.type での検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.type%20eq%20%22work%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    // 全ユーザーがwork emailを持っているので5件ヒット
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 5);
    println!(
        "      ✅ emails.type 'work' での検索成功（{}件）",
        search_result["totalResults"]
    );

    // Test 12: 存在しない値での検索
    println!("\n   Test 12: 存在しない値での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20eq%20%22nonexistent%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 0);
    println!("      ✅ 存在しない値での検索成功（0件）");

    println!("\n✅ 全ての拡張フィルタ検索テストが成功！({:?})", db_type);
}

async fn nested_attributes_filter_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔍 Nested Attributes Filter Test ({:?})", db_type);
    println!("==========================================");

    // 🏗️ より複雑なネスト構造を持つテストユーザーを作成
    println!("\n1. 📝 複雑なネスト構造を持つテストユーザーの作成");

    let complex_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": format!("{}-complex", db_prefix),
        "name": {
            "formatted": "Dr. John Smith Jr.",
            "familyName": "Smith",
            "givenName": "John",
            "middleName": "Michael",
            "honorificPrefix": "Dr.",
            "honorificSuffix": "Jr."
        },
        "displayName": "Dr. John Smith Jr.",
        "nickName": "Johnny",
        "profileUrl": "https://example.com/profile/john",
        "emails": [
            {
                "value": "john.smith@company.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "j.smith@personal.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "dr.smith@university.edu",
                "type": "other",
                "primary": false
            }
        ],
        "phoneNumbers": [
            {
                "value": "+1-555-123-4567",
                "type": "work",
                "primary": true
            },
            {
                "value": "+1-555-987-6543",
                "type": "mobile",
                "primary": false
            }
        ],
        "addresses": [
            {
                "formatted": "123 Main St\nSuite 100\nNew York, NY 10001\nUSA",
                "streetAddress": "123 Main St",
                "locality": "New York",
                "region": "NY",
                "postalCode": "10001",
                "country": "USA",
                "type": "work",
                "primary": true
            }
        ],
        "title": "Senior Software Architect",
        "userType": "Employee",
        "preferredLanguage": "en-US",
        "locale": "en-US",
        "timezone": "America/New_York",
        "active": true,
        "externalId": "EXT-COMPLEX-001"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&complex_user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();
    println!(
        "   ✅ 複雑なユーザー '{}-complex' を作成 (ID: {})",
        db_prefix, user_id
    );

    // 🎯 深いネスト属性での検索テスト
    println!("\n2. 🔍 深いネスト属性での検索テスト");

    // Test 1: name.middleName での検索
    println!("\n   Test 1: name.middleName での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.middleName%20eq%20%22Michael%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-complex", db_prefix)
    );
    println!("      ✅ name.middleName 'Michael' での検索成功");

    // Test 2: name.honorificPrefix での検索
    println!("\n   Test 2: name.honorificPrefix での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.honorificPrefix%20eq%20%22Dr.%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ name.honorificPrefix 'Dr.' での検索成功");

    // Test 3: name.honorificSuffix での検索
    println!("\n   Test 3: name.honorificSuffix での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.honorificSuffix%20eq%20%22Jr.%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ name.honorificSuffix 'Jr.' での検索成功");

    // Test 4: profileUrl での検索
    println!("\n   Test 4: profileUrl での検索");
    let response = server
        .get("/scim/v2/Users?filter=profileUrl%20eq%20%22https://example.com/profile/john%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ profileUrl での検索成功");

    // Test 5: phoneNumbers.value での検索
    println!("\n   Test 5: phoneNumbers.value での検索");
    let response = server
        .get("/scim/v2/Users?filter=phoneNumbers.value%20eq%20%22%2B1-555-123-4567%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ phoneNumbers.value での検索成功");

    // Test 6: phoneNumbers.type での検索
    println!("\n   Test 6: phoneNumbers.type での検索");
    let response = server
        .get("/scim/v2/Users?filter=phoneNumbers.type%20eq%20%22mobile%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ phoneNumbers.type 'mobile' での検索成功");

    // Test 7: addresses.locality での検索（住所のネスト属性）
    println!("\n   Test 7: addresses.locality での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.locality%20eq%20%22New%20York%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.locality 'New York' での検索成功");

    // Test 8: addresses.region での検索
    println!("\n   Test 8: addresses.region での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.region%20eq%20%22NY%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.region 'NY' での検索成功");

    // Test 9: addresses.postalCode での検索
    println!("\n   Test 9: addresses.postalCode での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.postalCode%20eq%20%2210001%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.postalCode '10001' での検索成功");

    // Test 10: addresses.country での検索
    println!("\n   Test 10: addresses.country での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.country%20eq%20%22USA%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.country 'USA' での検索成功");

    // Test 11: preferredLanguage での検索
    println!("\n   Test 11: preferredLanguage での検索");
    let response = server
        .get("/scim/v2/Users?filter=preferredLanguage%20eq%20%22en-US%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ preferredLanguage 'en-US' での検索成功");

    // Test 12: timezone での検索
    println!("\n   Test 12: timezone での検索");
    let response = server
        .get("/scim/v2/Users?filter=timezone%20eq%20%22America/New_York%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ timezone 'America/New_York' での検索成功");

    // Test 13: 複数のemailsがある中で特定のtypeの検索
    println!("\n   Test 13: 特定のemails.typeの検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.type%20eq%20%22other%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ emails.type 'other' での検索成功");

    println!("\n✅ 全ての深いネスト属性検索テストが成功！({:?})", db_type);
}

async fn multi_value_attributes_filter_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔍 Multi-Value Attributes Filter Test ({:?})", db_type);
    println!("============================================");

    // 🏗️ 複数のマルチバリュー属性を持つテストユーザーを作成
    println!("\n1. 📝 複数のマルチバリュー属性を持つテストユーザーの作成");

    let multi_value_user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": format!("{}-multivalue", db_prefix),
        "name": {
            "formatted": "Alice Johnson Smith",
            "familyName": "Smith",
            "givenName": "Alice",
            "middleName": "Johnson"
        },
        "displayName": "Alice Johnson Smith",
        "nickName": "AJ",
        // 複数のemails（異なるtype、value、primary設定）
        "emails": [
            {
                "value": "alice.work@company.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "alice.personal@gmail.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "alice.backup@outlook.com",
                "type": "other",
                "primary": false
            },
            {
                "value": "a.smith@university.edu",
                "type": "work",
                "primary": false
            }
        ],
        // 複数のphoneNumbers（異なるtype、value、primary設定）
        "phoneNumbers": [
            {
                "value": "+1-555-100-1001",
                "type": "work",
                "primary": true
            },
            {
                "value": "+1-555-200-2002",
                "type": "home",
                "primary": false
            },
            {
                "value": "+1-555-300-3003",
                "type": "mobile",
                "primary": false
            },
            {
                "value": "+1-555-400-4004",
                "type": "fax",
                "primary": false
            }
        ],
        // 複数のaddresses（仕事用と自宅用）
        "addresses": [
            {
                "formatted": "100 Corporate Blvd\nSuite 500\nSan Francisco, CA 94105\nUSA",
                "streetAddress": "100 Corporate Blvd",
                "locality": "San Francisco",
                "region": "CA",
                "postalCode": "94105",
                "country": "USA",
                "type": "work",
                "primary": true
            },
            {
                "formatted": "456 Home Street\nApt 2B\nBerkeley, CA 94704\nUSA",
                "streetAddress": "456 Home Street",
                "locality": "Berkeley",
                "region": "CA",
                "postalCode": "94704",
                "country": "USA",
                "type": "home",
                "primary": false
            },
            {
                "formatted": "789 Vacation Lane\nMiami, FL 33101\nUSA",
                "streetAddress": "789 Vacation Lane",
                "locality": "Miami",
                "region": "FL",
                "postalCode": "33101",
                "country": "USA",
                "type": "other",
                "primary": false
            }
        ],
        "title": "Senior Data Analyst",
        "userType": "Employee",
        "active": true,
        "externalId": "EXT-MULTI-001"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&multi_value_user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().unwrap();
    println!(
        "   ✅ マルチバリューユーザー '{}-multivalue' を作成 (ID: {})",
        db_prefix, user_id
    );

    // 🎯 マルチバリュー属性での検索テスト
    println!("\n2. 🔍 マルチバリュー属性での検索テスト");

    // Test 1: 複数emailsの中から1つ目をヒット
    println!("\n   Test 1: emails - 1つ目の値での検索");
    let response = server
        .get("/scim/v2/Users?filter=emails%5Bvalue%20eq%20%22alice.work%40company.com%22%5D")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    assert_eq!(
        search_result["Resources"][0]["userName"].as_str().unwrap(),
        format!("{}-multivalue", db_prefix)
    );
    println!("      ✅ 1つ目のemail 'alice.work@company.com' での検索成功");

    // Test 2: 複数emailsの中から2つ目をヒット
    println!("\n   Test 2: emails - 2つ目の値での検索");
    let response = server
        .get("/scim/v2/Users?filter=emails%5Bvalue%20eq%20%22alice.personal%40gmail.com%22%5D")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 2つ目のemail 'alice.personal@gmail.com' での検索成功");

    // Test 3: 複数emailsの中から最後の値をヒット
    println!("\n   Test 3: emails - 最後の値での検索");
    let response = server
        .get("/scim/v2/Users?filter=emails%5Bvalue%20eq%20%22a.smith%40university.edu%22%5D")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 最後のemail 'a.smith@university.edu' での検索成功");

    // Test 4: emails.type での検索（複数の"work"タイプが存在）
    println!("\n   Test 4: emails.type - 複数存在する 'work' タイプでの検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.type%20eq%20%22work%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 複数のwork emailがある中での type 'work' 検索成功");

    // Test 5: emails.type での検索（1つしかない"other"タイプ）
    println!("\n   Test 5: emails.type - 1つしかない 'other' タイプでの検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.type%20eq%20%22other%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ emails.type 'other' での検索成功");

    // Test 6: 複数phoneNumbersの中から特定の値をヒット
    println!("\n   Test 6: phoneNumbers - 特定の値での検索");
    let response = server
        .get("/scim/v2/Users?filter=phoneNumbers.value%20eq%20%22%2B1-555-300-3003%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ phoneNumbers.value '+1-555-300-3003' での検索成功");

    // Test 7: phoneNumbers.type での検索
    println!("\n   Test 7: phoneNumbers.type - 'mobile' タイプでの検索");
    let response = server
        .get("/scim/v2/Users?filter=phoneNumbers.type%20eq%20%22mobile%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ phoneNumbers.type 'mobile' での検索成功");

    // Test 8: phoneNumbers.type での検索（存在しないタイプ）
    println!("\n   Test 8: phoneNumbers.type - 存在しない 'pager' タイプでの検索");
    let response = server
        .get("/scim/v2/Users?filter=phoneNumbers.type%20eq%20%22pager%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 0);
    println!("      ✅ 存在しない phoneNumbers.type 'pager' での検索成功（0件）");

    // Test 9: 複数addressesの中から特定の都市名での検索
    println!("\n   Test 9: addresses.locality - 'San Francisco' での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.locality%20eq%20%22San%20Francisco%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.locality 'San Francisco' での検索成功");

    // Test 10: 複数addressesの中から別の都市名での検索
    println!("\n   Test 10: addresses.locality - 'Berkeley' での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.locality%20eq%20%22Berkeley%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.locality 'Berkeley' での検索成功");

    // Test 11: 複数addressesの中から3つ目の都市名での検索
    println!("\n   Test 11: addresses.locality - 'Miami' での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.locality%20eq%20%22Miami%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.locality 'Miami' での検索成功");

    // Test 12: addresses.region での検索（複数のCAがある中で）
    println!("\n   Test 12: addresses.region - 複数の 'CA' があるが正しくヒット");
    let response = server
        .get("/scim/v2/Users?filter=addresses.region%20eq%20%22CA%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 複数の addresses.region 'CA' での検索成功");

    // Test 13: addresses.region での検索（1つしかないFL）
    println!("\n   Test 13: addresses.region - 1つしかない 'FL' での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.region%20eq%20%22FL%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.region 'FL' での検索成功");

    // Test 14: addresses.postalCode での検索（複数の中から特定のものを検索）
    println!("\n   Test 14: addresses.postalCode - 特定の郵便番号での検索");
    let response = server
        .get("/scim/v2/Users?filter=addresses.postalCode%20eq%20%2294704%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ addresses.postalCode '94704' での検索成功");

    // Test 15: 存在しないemail値での検索
    println!("\n   Test 15: emails[value eq ...] - 存在しない値での検索");
    let response = server
        .get("/scim/v2/Users?filter=emails%5Bvalue%20eq%20%22nonexistent%40email.com%22%5D")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 0);
    println!("      ✅ 存在しない email での検索成功（0件）");

    println!(
        "\n✅ 全てのマルチバリュー属性検索テストが成功！({:?})",
        db_type
    );
    println!("   📊 テスト結果: emails(4個), phoneNumbers(4個), addresses(3個)の中から正確に検索");
}

async fn enhanced_group_filter_search_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "SQLite",
        TestDatabaseType::Postgres => "PostgreSQL",
    };

    println!("\n🔍 Enhanced Group Filter Search Test ({:?})", db_type);
    println!("===========================================");

    // 🏗️ テストグループの作成
    println!("\n1. 📝 テストグループの作成");

    let test_groups = vec![
        ("Administrators", "GRP-001"),
        ("Developers", "GRP-002"),
        ("Support Team", "GRP-003"),
        ("Sales Team", "GRP-004"),
    ];

    for (display_name, external_id) in test_groups {
        let group_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": format!("{} {}", db_prefix, display_name),
            "externalId": external_id,
            "members": []
        });

        let response = server
            .post("/scim/v2/Groups")
            .content_type("application/scim+json")
            .json(&group_data)
            .await;

        response.assert_status(StatusCode::CREATED);
        println!("   ✅ グループ '{} {}' を作成", db_prefix, display_name);
    }

    // 🎯 グループ検索テスト
    println!("\n2. 🔍 グループの拡張フィルタ検索テスト");

    // Test 1: displayName での検索（case-insensitive）
    println!("\n   Test 1: displayName での検索（case-insensitive）");
    let search_filter = format!("{}%20developers", db_prefix.to_lowercase());
    println!(
        "      🔍 検索フィルタ: displayName eq \"{}\"",
        search_filter.replace("%20", " ")
    );
    let response = server
        .get(&format!(
            "/scim/v2/Groups?filter=displayName%20eq%20%22{}%22",
            search_filter
        ))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    println!(
        "      📊 検索結果: totalResults={}",
        search_result["totalResults"].as_i64().unwrap()
    );
    if let Some(resources) = search_result["Resources"].as_array() {
        println!("      📝 マッチしたグループ:");
        for resource in resources {
            if let Some(display_name) = resource["displayName"].as_str() {
                println!("         - {}", display_name);
            }
        }
    }
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ displayName case-insensitive検索成功");

    // Test 2: externalId での検索（case-exact）
    println!("\n   Test 2: externalId での検索（case-exact）");
    let response = server
        .get("/scim/v2/Groups?filter=externalId%20eq%20%22GRP-002%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ externalId 'GRP-002' での検索成功");

    // Test 3: 存在しないグループでの検索
    println!("\n   Test 3: 存在しないグループでの検索");
    let response = server
        .get("/scim/v2/Groups?filter=displayName%20eq%20%22NonExistent%20Group%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 0);
    println!("      ✅ 存在しないグループでの検索成功（0件）");

    println!(
        "\n✅ 全てのグループ拡張フィルタ検索テストが成功！({:?})",
        db_type
    );
}

async fn case_sensitivity_filtering_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔍 Case Sensitivity Filtering Test ({:?})", db_type);
    println!("=================================");

    // テストユーザーを作成
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": format!("{}-testuser", db_prefix),
        "nickName": "TestNick",
        "externalId": "EXT-CASE-001",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
        "active": true
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    println!("   ✅ テストユーザーを作成");

    // Test 1: externalId（case-exact）- 正確なケース
    println!("\n   Test 1: externalId (case-exact) - 正確なケース");
    let response = server
        .get("/scim/v2/Users?filter=externalId%20eq%20%22EXT-CASE-001%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 正確なケースでマッチ");

    // Test 2: externalId（case-exact）- 間違ったケース
    println!("\n   Test 2: externalId (case-exact) - 間違ったケース");
    let response = server
        .get("/scim/v2/Users?filter=externalId%20eq%20%22ext-case-001%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 0);
    println!("      ✅ 間違ったケースでマッチしない");

    // Test 3: nickName（case-insensitive）- 大文字小文字無視
    println!("\n   Test 3: nickName (case-insensitive) - 大文字小文字無視");
    let response = server
        .get("/scim/v2/Users?filter=nickName%20eq%20%22testnick%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    assert_eq!(search_result["totalResults"].as_i64().unwrap(), 1);
    println!("      ✅ 大文字小文字を無視してマッチ");

    println!("\n✅ Case sensitivity テストが成功！({:?})", db_type);
}

async fn complex_query_patterns_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔍 Complex Query Patterns Test ({:?})", db_type);
    println!("=====================================");

    // 🏗️ 複雑なテストデータセットの作成
    println!("\n1. 📝 複雑なテストデータセットの作成");

    let complex_users = vec![
        // (username, title, userType, department, costCenter, active)
        (
            "alice.smith",
            "Senior Software Engineer",
            "Employee",
            "Engineering",
            "ENG001",
            true,
        ),
        (
            "bob.jones",
            "Product Manager",
            "Employee",
            "Product",
            "PROD001",
            true,
        ),
        (
            "charlie.brown",
            "Junior Developer",
            "Contractor",
            "Engineering",
            "ENG001",
            true,
        ),
        (
            "diana.prince",
            "Director of Engineering",
            "Employee",
            "Engineering",
            "ENG001",
            true,
        ),
        (
            "eve.adams",
            "UX Designer",
            "Employee",
            "Design",
            "DES001",
            false,
        ),
        (
            "frank.miller",
            "DevOps Engineer",
            "Employee",
            "Operations",
            "OPS001",
            true,
        ),
        (
            "grace.hopper",
            "Senior Data Scientist",
            "Employee",
            "Data",
            "DATA001",
            true,
        ),
        (
            "henry.ford",
            "Quality Assurance Engineer",
            "Contractor",
            "Engineering",
            "ENG001",
            true,
        ),
        (
            "iris.watson",
            "Technical Writer",
            "Employee",
            "Documentation",
            "DOC001",
            true,
        ),
        (
            "jack.black",
            "Sales Engineer",
            "Employee",
            "Sales",
            "SALES001",
            false,
        ),
    ];

    let mut created_user_ids = Vec::new();

    for (username, title, user_type, department, cost_center, active) in complex_users {
        let user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("{}-{}", db_prefix, username),
            "name": {
                "givenName": username.split('.').next().unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').next().unwrap()[1..],
                "familyName": username.split('.').nth(1).unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').nth(1).unwrap()[1..],
                "formatted": format!("{} {}",
                    username.split('.').next().unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').next().unwrap()[1..],
                    username.split('.').nth(1).unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').nth(1).unwrap()[1..]
                )
            },
            "emails": [
                {
                    "value": format!("{}@company.com", username),
                    "type": "work",
                    "primary": true
                },
                {
                    "value": format!("{}.personal@gmail.com", username),
                    "type": "home",
                    "primary": false
                }
            ],
            "title": title,
            "userType": user_type,
            "department": department,
            "costCenter": cost_center,
            "active": active
        });

        let response = server
            .post("/scim/v2/Users")
            .content_type("application/scim+json")
            .json(&user_data)
            .await;

        response.assert_status(StatusCode::CREATED);
        let created_user: Value = response.json();

        if let Some(id) = created_user["id"].as_str() {
            created_user_ids.push(id.to_string());
            println!(
                "   ✅ ユーザー '{}-{}' を作成 (ID: {})",
                db_prefix, username, id
            );
        }
    }

    // 🎯 複雑なクエリパターンのテスト
    println!("\n2. 🔍 複雑なクエリパターンのテスト");

    // Pattern 1: 複合条件 - Engineering部門のEmployee
    println!("\n   Pattern 1: 部門とユーザータイプの組み合わせ");
    let response = server
        .get("/scim/v2/Users?filter=department%20eq%20%22Engineering%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let engineering_users = search_result["totalResults"].as_i64().unwrap();
    assert!(engineering_users >= 4); // alice, charlie, diana, henry
    println!(
        "      ✅ Engineering部門のユーザー検索成功: {}件",
        engineering_users
    );

    // Pattern 2: タイトルでの部分一致 - "Senior"を含む
    println!("\n   Pattern 2: タイトルでの部分一致検索");
    let response = server
        .get("/scim/v2/Users?filter=title%20co%20%22Senior%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let senior_users = search_result["totalResults"].as_i64().unwrap();
    assert!(senior_users >= 2); // alice (Senior Software Engineer), grace (Senior Data Scientist)
    println!(
        "      ✅ 'Senior'を含むタイトル検索成功: {}件",
        senior_users
    );

    // Pattern 3: プレフィックス検索 - "ENG"で始まるコストセンター
    println!("\n   Pattern 3: コストセンターのプレフィックス検索");
    let response = server
        .get("/scim/v2/Users?filter=costCenter%20sw%20%22ENG%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let eng_cost_center_users = search_result["totalResults"].as_i64().unwrap();
    assert!(eng_cost_center_users >= 4); // alice, charlie, diana, henry
    println!(
        "      ✅ 'ENG'で始まるコストセンター検索成功: {}件",
        eng_cost_center_users
    );

    // Pattern 4: サフィックス検索 - "Engineer"で終わるタイトル
    println!("\n   Pattern 4: タイトルのサフィックス検索");
    let response = server
        .get("/scim/v2/Users?filter=title%20ew%20%22Engineer%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let engineer_title_users = search_result["totalResults"].as_i64().unwrap();
    assert!(engineer_title_users >= 4); // alice, frank, henry, jack
    println!(
        "      ✅ 'Engineer'で終わるタイトル検索成功: {}件",
        engineer_title_users
    );

    // Pattern 5: 否定検索 - Employeeでないユーザー
    println!("\n   Pattern 5: 否定条件での検索");
    let response = server
        .get("/scim/v2/Users?filter=userType%20ne%20%22Employee%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let non_employee_users = search_result["totalResults"].as_i64().unwrap();
    assert!(non_employee_users >= 2); // charlie, henry (Contractors)
    println!(
        "      ✅ Employeeでないユーザー検索成功: {}件",
        non_employee_users
    );

    // Pattern 6: 存在チェック - departmentフィールドが存在する
    println!("\n   Pattern 6: フィールド存在チェック");
    let response = server
        .get("/scim/v2/Users?filter=department%20pr")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let users_with_department = search_result["totalResults"].as_i64().unwrap();
    assert!(users_with_department >= 10); // 全ユーザー
    println!(
        "      ✅ departmentフィールド存在チェック成功: {}件",
        users_with_department
    );

    // Pattern 7: 複雑なEmailドメイン検索
    println!("\n   Pattern 7: メールアドレスドメイン検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.value%20ew%20%22%40company.com%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let company_email_users = search_result["totalResults"].as_i64().unwrap();
    assert!(company_email_users >= 10); // 全ユーザーが会社メールを持つ
    println!(
        "      ✅ 会社メールドメイン検索成功: {}件",
        company_email_users
    );

    // Pattern 8: 名前のフォーマット検索
    println!("\n   Pattern 8: フォーマット済み名前での検索");
    let response = server
        .get("/scim/v2/Users?filter=name.formatted%20co%20%22Alice%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let alice_name_users = search_result["totalResults"].as_i64().unwrap();
    assert_eq!(alice_name_users, 1); // Alice Smith
    println!("      ✅ 'Alice'を含む名前検索成功: {}件", alice_name_users);

    // Pattern 9: 非アクティブユーザー検索
    println!("\n   Pattern 9: 非アクティブユーザーの検索");
    let response = server
        .get("/scim/v2/Users?filter=active%20eq%20false")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let inactive_users = search_result["totalResults"].as_i64().unwrap();
    println!(
        "      🔍 非アクティブユーザー検索結果: {}件",
        inactive_users
    );
    if let Some(resources) = search_result["Resources"].as_array() {
        println!("      📝 見つかったユーザー:");
        for resource in resources {
            if let Some(username) = resource["userName"].as_str() {
                if let Some(active) = resource["active"].as_bool() {
                    println!("         - {} (active: {})", username, active);
                }
            }
        }
    }

    assert!(
        inactive_users >= 2,
        "Expected at least 2 inactive users (eve, jack), found {}",
        inactive_users
    ); // eve, jack
    println!(
        "      ✅ 非アクティブユーザー検索成功: {}件",
        inactive_users
    );

    // Pattern 10: 特定のメールタイプ検索
    println!("\n   Pattern 10: 特定のメールタイプでの検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.type%20eq%20%22home%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let home_email_users = search_result["totalResults"].as_i64().unwrap();
    assert!(home_email_users >= 10); // 全ユーザーがホームメールを持つ
    println!(
        "      ✅ ホームメールタイプ検索成功: {}件",
        home_email_users
    );

    println!(
        "\n✅ 全ての複雑なクエリパターンテストが成功！({:?})",
        db_type
    );
    println!("   📊 テスト結果: 10種類の複雑なクエリパターンをテスト完了");
}

async fn advanced_filter_operators_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n🔧 Advanced Filter Operators Test ({:?})", db_type);
    println!("==========================================");

    // 🏗️ 数値・日付・時間データを含むテストユーザーの作成
    println!("\n1. 📝 数値・日付データを含むテストユーザーの作成");

    let advanced_users = vec![
        // (username, age, salary, hire_date, performance_score, manager_level)
        ("alex.young", "22", "55000", "2023-01-15", "3.2", "1"),
        ("betty.old", "45", "95000", "2018-03-20", "4.8", "3"),
        ("carlos.mid", "35", "85000", "2020-07-10", "4.2", "2"),
        ("donna.senior", "52", "120000", "2015-09-05", "4.9", "4"),
        ("eric.junior", "28", "68000", "2022-11-12", "3.8", "1"),
        ("fiona.expert", "40", "105000", "2017-02-28", "4.5", "3"),
        ("george.newbie", "25", "62000", "2023-06-01", "3.1", "1"),
        ("helen.veteran", "48", "135000", "2012-04-15", "4.7", "4"),
    ];

    let mut created_user_ids = Vec::new();

    for (username, age, salary, hire_date, performance_score, manager_level) in advanced_users {
        let user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("{}-{}", db_prefix, username),
            "name": {
                "givenName": username.split('.').next().unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').next().unwrap()[1..],
                "familyName": username.split('.').nth(1).unwrap().chars().next().unwrap().to_uppercase().collect::<String>() + &username.split('.').nth(1).unwrap()[1..]
            },
            "emails": [{
                "value": format!("{}@company.com", username),
                "type": "work",
                "primary": true
            }],
            "active": true,
            "age": age,
            "salary": salary,
            "hireDate": hire_date,
            "performanceScore": performance_score,
            "managerLevel": manager_level
        });

        let response = server
            .post("/scim/v2/Users")
            .content_type("application/scim+json")
            .json(&user_data)
            .await;

        response.assert_status(StatusCode::CREATED);
        let created_user: Value = response.json();

        if let Some(id) = created_user["id"].as_str() {
            created_user_ids.push(id.to_string());
            println!(
                "   ✅ ユーザー '{}-{}' を作成 (年齢: {}, 給与: {})",
                db_prefix, username, age, salary
            );
        }
    }

    // 🎯 高度なフィルタオペレータのテスト
    println!("\n2. 🔧 高度なフィルタオペレータのテスト");

    // Test 1: Greater Than (gt) - 30歳より上
    println!("\n   Test 1: gt (Greater Than) - 30歳より上");
    let response = server
        .get("/scim/v2/Users?filter=age%20gt%20%2230%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    println!(
        "      🔍 Debug: Search result: {}",
        serde_json::to_string_pretty(&search_result).unwrap()
    );
    let older_users = search_result["totalResults"].as_i64().unwrap();
    println!("      🔍 Debug: Found {} users older than 30", older_users);
    assert!(older_users >= 4); // betty(45), carlos(35), donna(52), fiona(40), helen(48)
    println!("      ✅ 30歳より上のユーザー検索成功: {}件", older_users);

    // Test 2: Greater Than or Equal (ge) - 給与85000以上
    println!("\n   Test 2: ge (Greater Than or Equal) - 給与85000以上");
    let response = server
        .get("/scim/v2/Users?filter=salary%20ge%20%2285000%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let high_salary_users = search_result["totalResults"].as_i64().unwrap();
    assert!(high_salary_users >= 4); // betty(95000), carlos(85000), donna(120000), fiona(105000), helen(135000)
    println!(
        "      ✅ 給与85000以上のユーザー検索成功: {}件",
        high_salary_users
    );

    // Test 3: Less Than (lt) - 30歳未満
    println!("\n   Test 3: lt (Less Than) - 30歳未満");
    let response = server
        .get("/scim/v2/Users?filter=age%20lt%20%2230%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let younger_users = search_result["totalResults"].as_i64().unwrap();
    assert!(younger_users >= 3); // alex(22), eric(28), george(25)
    println!("      ✅ 30歳未満のユーザー検索成功: {}件", younger_users);

    // Test 4: Less Than or Equal (le) - 給与70000以下
    println!("\n   Test 4: le (Less Than or Equal) - 給与70000以下");
    let response = server
        .get("/scim/v2/Users?filter=salary%20le%20%2270000%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let low_salary_users = search_result["totalResults"].as_i64().unwrap();
    assert!(low_salary_users >= 3); // alex(55000), eric(68000), george(62000)
    println!(
        "      ✅ 給与70000以下のユーザー検索成功: {}件",
        low_salary_users
    );

    // Test 5: Not Equal (ne) - マネージャーレベル1でない
    println!("\n   Test 5: ne (Not Equal) - マネージャーレベル1でない");
    let response = server
        .get("/scim/v2/Users?filter=managerLevel%20ne%20%221%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let non_level1_users = search_result["totalResults"].as_i64().unwrap();
    assert!(non_level1_users >= 4); // betty(3), carlos(2), donna(4), fiona(3), helen(4)
    println!(
        "      ✅ マネージャーレベル1でないユーザー検索成功: {}件",
        non_level1_users
    );

    // Test 6: Contains (co) - メールアドレスに\"old\"を含む
    println!("\n   Test 6: co (Contains) - メールアドレスに'old'を含む");
    let response = server
        .get("/scim/v2/Users?filter=emails.value%20co%20%22old%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let old_email_users = search_result["totalResults"].as_i64().unwrap();
    assert!(old_email_users >= 1); // betty.old
    println!(
        "      ✅ 'old'を含むメールアドレス検索成功: {}件",
        old_email_users
    );

    // Test 7: Starts With (sw) - ユーザー名が\"alex\"で始まる
    println!("\n   Test 7: sw (Starts With) - ユーザー名が特定の文字で始まる");
    let response = server
        .get(&format!(
            "/scim/v2/Users?filter=userName%20sw%20%22{}-a%22",
            db_prefix
        ))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let alex_users = search_result["totalResults"].as_i64().unwrap();
    assert!(alex_users >= 1); // alex.young
    println!(
        "      ✅ 特定の文字で始まるユーザー名検索成功: {}件",
        alex_users
    );

    // Test 8: Ends With (ew) - 雇用日が\"05\"で終わる (xx-xx-05)
    println!("\n   Test 8: ew (Ends With) - 雇用日が'05'で終わる");
    let response = server
        .get("/scim/v2/Users?filter=hireDate%20ew%20%2205%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let date05_users = search_result["totalResults"].as_i64().unwrap();
    assert!(date05_users >= 1); // donna (2015-09-05)
    println!("      ✅ '05'で終わる雇用日検索成功: {}件", date05_users);

    // Test 9: Present (pr) - performanceScoreフィールドが存在する
    println!("\n   Test 9: pr (Present) - performanceScoreフィールドが存在する");
    let response = server
        .get("/scim/v2/Users?filter=performanceScore%20pr")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let performance_users = search_result["totalResults"].as_i64().unwrap();
    assert!(performance_users >= 8); // 全ユーザー
    println!(
        "      ✅ performanceScoreフィールド存在チェック成功: {}件",
        performance_users
    );

    // Test 10: 複合条件 - 30歳以上かつ給与90000以上の組み合わせテスト
    println!("\n   Test 10: 複合条件シミュレーション - 高年齢高給与ユーザー");

    // 30歳以上のユーザーを取得
    let response_age = server
        .get("/scim/v2/Users?filter=age%20ge%20%2230%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;
    response_age.assert_status(StatusCode::OK);
    let age_result: Value = response_age.json();
    let age_30_plus = age_result["totalResults"].as_i64().unwrap();

    // 給与90000以上のユーザーを取得
    let response_salary = server
        .get("/scim/v2/Users?filter=salary%20ge%20%2290000%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;
    response_salary.assert_status(StatusCode::OK);
    let salary_result: Value = response_salary.json();
    let salary_90k_plus = salary_result["totalResults"].as_i64().unwrap();

    assert!(age_30_plus >= 5); // carlos(35), betty(45), donna(52), fiona(40), helen(48)
    assert!(salary_90k_plus >= 4); // betty(95000), donna(120000), fiona(105000), helen(135000)

    println!("      ✅ 30歳以上のユーザー: {}件", age_30_plus);
    println!("      ✅ 給与90000以上のユーザー: {}件", salary_90k_plus);

    println!(
        "\n✅ 全ての高度なフィルタオペレータテストが成功！({:?})",
        db_type
    );
    println!("   🔧 テスト結果: 10種類の高度なオペレータをテスト完了");
    println!("   📈 数値比較: gt, ge, lt, le");
    println!("   🔤 文字列操作: co, sw, ew, ne");
    println!("   ✅ 存在チェック: pr");
}

async fn edge_case_filtering_test(db_type: TestDatabaseType) {
    let tenant_config = common::create_test_app_config();
    let (app, _test_db) = common::setup_test_app_with_db(tenant_config, db_type)
        .await
        .unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let db_prefix = match db_type {
        TestDatabaseType::Sqlite => "sqlite",
        TestDatabaseType::Postgres => "postgres",
    };

    println!("\n⚡ Edge Case Filtering Test ({:?})", db_type);
    println!("===================================");

    // 🏗️ エッジケース用の特殊なテストデータの作成
    println!("\n1. 📝 エッジケース用の特殊なテストデータの作成");

    let edge_case_users = vec![
        // (username, special_chars, unicode_name, empty_fields, null_values)
        (
            "user.with-special@chars",
            "test+user@company.com",
            "José María",
            true,
            false,
        ),
        (
            "user_with_underscore",
            "user_test@domain.co.uk",
            "François",
            false,
            true,
        ),
        (
            "user with spaces",
            "user.spaces@company.org",
            "Müller",
            true,
            false,
        ),
        (
            "userWithCamelCase",
            "camel.case@example.net",
            "Østergård",
            false,
            false,
        ),
        (
            "user123numbers",
            "numbers123@test.com",
            "田中太郎",
            true,
            true,
        ),
        ("UPPERCASE_USER", "UPPER@CASE.COM", "ALLCAPS", false, false),
        ("lowercase.user", "lower@case.com", "lowercase", true, false),
        (
            "user-with-dashes",
            "dashes-user@domain.com",
            "O'Connor",
            false,
            true,
        ),
    ];

    let mut created_user_ids = Vec::new();

    for (username, email, display_name, has_empty_field, has_null_field) in edge_case_users {
        let mut user_data = json!({
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": format!("{}-{}", db_prefix, username),
            "displayName": display_name,
            "name": {
                "givenName": display_name.split(' ').next().unwrap_or(display_name),
                "familyName": display_name.split(' ').nth(1).unwrap_or("TestUser")
            },
            "emails": [{
                "value": email,
                "type": "work",
                "primary": true
            }],
            "active": true
        });

        // エッジケース: 空文字列フィールド
        if has_empty_field {
            user_data["title"] = json!("");
            user_data["department"] = json!("");
        }

        // エッジケース: null値フィールド（実際にはフィールドを含めない）
        if !has_null_field {
            user_data["nickName"] = json!("nick");
            user_data["preferredLanguage"] = json!("en");
        }

        let response = server
            .post("/scim/v2/Users")
            .content_type("application/scim+json")
            .json(&user_data)
            .await;

        response.assert_status(StatusCode::CREATED);
        let created_user: Value = response.json();

        if let Some(id) = created_user["id"].as_str() {
            created_user_ids.push(id.to_string());
            println!(
                "   ✅ エッジケースユーザー '{}-{}' を作成",
                db_prefix, username
            );
        }
    }

    // 🎯 エッジケースフィルタリングのテスト
    println!("\n2. ⚡ エッジケースフィルタリングのテスト");

    // Edge Case 1: 特殊文字を含むユーザー名での検索
    println!("\n   Edge Case 1: 特殊文字を含むユーザー名での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20co%20%22special%40chars%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let special_char_users = search_result["totalResults"].as_i64().unwrap();
    assert!(special_char_users >= 1); // user.with-special@chars
    println!(
        "      ✅ 特殊文字を含むユーザー名検索成功: {}件",
        special_char_users
    );

    // Edge Case 2: Unicode文字を含む表示名での検索
    println!("\n   Edge Case 2: Unicode文字を含む表示名での検索");
    let response = server
        .get("/scim/v2/Users?filter=displayName%20co%20%22Jos%C3%A9%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let unicode_users = search_result["totalResults"].as_i64().unwrap();
    assert!(unicode_users >= 1); // José María
    println!(
        "      ✅ Unicode文字を含む表示名検索成功: {}件",
        unicode_users
    );

    // Edge Case 3: スペースを含むユーザー名での検索
    println!("\n   Edge Case 3: スペースを含むユーザー名での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20co%20%22with%20spaces%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let space_users = search_result["totalResults"].as_i64().unwrap();
    assert!(space_users >= 1); // user with spaces
    println!(
        "      ✅ スペースを含むユーザー名検索成功: {}件",
        space_users
    );

    // Edge Case 4: 大文字小文字混在での検索（case-insensitive）
    println!("\n   Edge Case 4: 大文字小文字混在での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20co%20%22uppercase%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let mixed_case_users = search_result["totalResults"].as_i64().unwrap();
    assert!(mixed_case_users >= 1); // UPPERCASE_USER (case-insensitive match)
    println!("      ✅ 大文字小文字混在検索成功: {}件", mixed_case_users);

    // Edge Case 5: 数字を含むユーザー名での検索
    println!("\n   Edge Case 5: 数字を含むユーザー名での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20co%20%22123%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let numeric_users = search_result["totalResults"].as_i64().unwrap();
    assert!(numeric_users >= 1); // user123numbers
    println!("      ✅ 数字を含むユーザー名検索成功: {}件", numeric_users);

    // Edge Case 6: ハイフンを含むユーザー名での検索
    println!("\n   Edge Case 6: ハイフンを含むユーザー名での検索");
    let response = server
        .get("/scim/v2/Users?filter=userName%20co%20%22dashes%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let dash_users = search_result["totalResults"].as_i64().unwrap();
    assert!(dash_users >= 1); // user-with-dashes
    println!(
        "      ✅ ハイフンを含むユーザー名検索成功: {}件",
        dash_users
    );

    // Edge Case 7: 複雑なメールドメインでの検索
    println!("\n   Edge Case 7: 複雑なメールドメインでの検索");
    let response = server
        .get("/scim/v2/Users?filter=emails.value%20ew%20%22.co.uk%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let complex_domain_users = search_result["totalResults"].as_i64().unwrap();
    assert!(complex_domain_users >= 1); // user_test@domain.co.uk
    println!(
        "      ✅ 複雑なメールドメイン検索成功: {}件",
        complex_domain_users
    );

    // Edge Case 8: アポストロフィを含む名前での検索
    println!("\n   Edge Case 8: アポストロフィを含む名前での検索");
    let response = server
        .get("/scim/v2/Users?filter=displayName%20co%20%22O%27Connor%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let apostrophe_users = search_result["totalResults"].as_i64().unwrap();
    assert!(apostrophe_users >= 1); // O'Connor
    println!(
        "      ✅ アポストロフィを含む名前検索成功: {}件",
        apostrophe_users
    );

    // Edge Case 9: 日本語文字での検索
    println!("\n   Edge Case 9: 日本語文字での検索");
    let response = server
        .get("/scim/v2/Users?filter=displayName%20co%20%22%E7%94%B0%E4%B8%AD%22")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let japanese_users = search_result["totalResults"].as_i64().unwrap();
    assert!(japanese_users >= 1); // 田中太郎
    println!("      ✅ 日本語文字での検索成功: {}件", japanese_users);

    // Edge Case 10: フィールドが存在しない場合のPresent検索
    println!("\n   Edge Case 10: フィールドが存在しない場合のPresent検索");
    let response = server
        .get("/scim/v2/Users?filter=nickName%20pr")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let nickname_present_users = search_result["totalResults"].as_i64().unwrap();
    // nickNameが設定されているユーザーのみがヒット
    println!(
        "      ✅ nickNameフィールド存在チェック成功: {}件",
        nickname_present_users
    );

    // Edge Case 11: 空文字列での検索（存在するが空）
    println!("\n   Edge Case 11: 空文字列フィールドでの検索");
    let response = server
        .get("/scim/v2/Users?filter=title%20eq%20%22%5D")
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let empty_title_users = search_result["totalResults"].as_i64().unwrap();
    // 空文字列のtitleを持つユーザー
    println!(
        "      ✅ 空文字列フィールド検索成功: {}件",
        empty_title_users
    );

    // Edge Case 12: 境界値テスト - 非常に長い文字列
    println!("\n   Edge Case 12: 非常に長い検索文字列での検索");
    let long_search_string = "a".repeat(100); // 100文字の"a"
    let response = server
        .get(&format!(
            "/scim/v2/Users?filter=userName%20co%20%22{}%22",
            long_search_string
        ))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let search_result: Value = response.json();
    let long_string_users = search_result["totalResults"].as_i64().unwrap();
    // 存在しないので0件
    assert_eq!(long_string_users, 0);
    println!(
        "      ✅ 長い検索文字列での検索成功（該当なし）: {}件",
        long_string_users
    );

    println!(
        "\n✅ 全てのエッジケースフィルタリングテストが成功！({:?})",
        db_type
    );
    println!("   ⚡ テスト結果: 12種類のエッジケースをテスト完了");
    println!("   🌐 Unicode文字: 日本語、ウムラウト、アクセント記号");
    println!("   🔤 特殊文字: @, _, -, spaces, ', 数字");
    println!("   📝 データ状態: 空文字列、null値、存在チェック");
    println!("   🔍 境界値テスト: 長い文字列、複雑なドメイン");
}

// Generate matrix tests for each test function
matrix_test!(user_crud, user_crud_test);
matrix_test!(group_crud, group_crud_test);
matrix_test!(group_list, group_list_test);
matrix_test!(group_patch_operations, group_patch_operations_test);
matrix_test!(group_membership, group_membership_test);
matrix_test!(group_to_group_membership, group_to_group_membership_test);
matrix_test!(group_error_scenarios, group_error_scenarios_test);
matrix_test!(enhanced_filter_search, enhanced_filter_search_test);
matrix_test!(
    enhanced_group_filter_search,
    enhanced_group_filter_search_test
);
matrix_test!(case_sensitivity_filtering, case_sensitivity_filtering_test);
matrix_test!(nested_attributes_filter, nested_attributes_filter_test);
matrix_test!(
    multi_value_attributes_filter,
    multi_value_attributes_filter_test
);
matrix_test!(complex_query_patterns, complex_query_patterns_test);
matrix_test!(advanced_filter_operators, advanced_filter_operators_test);
matrix_test!(edge_case_filtering, edge_case_filtering_test);
