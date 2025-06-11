use axum_test::TestServer;
use http::StatusCode;
use scim_server::config::AppConfig;

mod common;

/// Test simple mode functionality (no config file specified)
/// This tests the default configuration that users get when running without -c flag
#[tokio::test]
async fn test_simple_mode_user_operations() {
    // Use default configuration (equivalent to running without -c flag)
    let app_config = AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test user creation - this should work without any configuration
    let user_payload = common::create_test_user_json("simple-user", "Simple", "User");
    let create_response = server.post("/scim/v2/Users").json(&user_payload).await;

    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = create_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Verify user was created correctly
    assert_eq!(created_user["userName"], "simple-user");
    assert_eq!(created_user["name"]["givenName"], "Simple");
    assert_eq!(created_user["name"]["familyName"], "User");

    // Test user retrieval
    let get_response = server.get(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(get_response.status_code(), StatusCode::OK);
    let retrieved_user: serde_json::Value = get_response.json();
    assert_eq!(retrieved_user["userName"], "simple-user");

    // Test user listing
    let list_response = server.get("/scim/v2/Users").await;
    assert_eq!(list_response.status_code(), StatusCode::OK);
    let list_result: serde_json::Value = list_response.json();
    let users = list_result["Resources"].as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["userName"], "simple-user");

    // Test user update
    let mut update_payload = created_user.clone();
    update_payload["name"]["givenName"] = serde_json::Value::String("UpdatedSimple".to_string());

    let update_response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .json(&update_payload)
        .await;

    assert_eq!(update_response.status_code(), StatusCode::OK);
    let updated_user: serde_json::Value = update_response.json();
    assert_eq!(updated_user["name"]["givenName"], "UpdatedSimple");

    // Test user deletion
    let delete_response = server.delete(&format!("/scim/v2/Users/{}", user_id)).await;
    assert_eq!(delete_response.status_code(), StatusCode::NO_CONTENT);

    // Verify deletion
    let final_list_response = server.get("/scim/v2/Users").await;
    assert_eq!(final_list_response.status_code(), StatusCode::OK);
    let final_list_result: serde_json::Value = final_list_response.json();
    let final_users = final_list_result["Resources"].as_array().unwrap();
    assert_eq!(final_users.len(), 0);
}

#[tokio::test]
async fn test_simple_mode_group_operations() {
    // Use default configuration
    let app_config = AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // First create a user to add to the group
    let user_payload = common::create_test_user_json("group-member", "Group", "Member");
    let user_response = server.post("/scim/v2/Users").json(&user_payload).await;
    assert_eq!(user_response.status_code(), StatusCode::CREATED);
    let created_user: serde_json::Value = user_response.json();
    let user_id = created_user["id"].as_str().unwrap();

    // Test group creation
    let group_payload = serde_json::json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Simple Group",
        "members": [{
            "value": user_id,
            "type": "User"
        }]
    });

    let create_response = server.post("/scim/v2/Groups").json(&group_payload).await;
    assert_eq!(create_response.status_code(), StatusCode::CREATED);
    let created_group: serde_json::Value = create_response.json();
    let group_id = created_group["id"].as_str().unwrap();

    // Verify group was created correctly
    assert_eq!(created_group["displayName"], "Simple Group");
    assert_eq!(created_group["members"][0]["value"], user_id);

    // Test group retrieval
    let get_response = server.get(&format!("/scim/v2/Groups/{}", group_id)).await;
    assert_eq!(get_response.status_code(), StatusCode::OK);
    let retrieved_group: serde_json::Value = get_response.json();
    assert_eq!(retrieved_group["displayName"], "Simple Group");

    // Test group listing
    let list_response = server.get("/scim/v2/Groups").await;
    assert_eq!(list_response.status_code(), StatusCode::OK);
    let list_result: serde_json::Value = list_response.json();
    let groups = list_result["Resources"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["displayName"], "Simple Group");

    // Test group deletion
    let delete_response = server
        .delete(&format!("/scim/v2/Groups/{}", group_id))
        .await;
    assert_eq!(delete_response.status_code(), StatusCode::NO_CONTENT);

    // Verify deletion
    let final_list_response = server.get("/scim/v2/Groups").await;
    assert_eq!(final_list_response.status_code(), StatusCode::OK);
    let final_list_result: serde_json::Value = final_list_response.json();
    let final_groups = final_list_result["Resources"].as_array().unwrap();
    assert_eq!(final_groups.len(), 0);
}

#[tokio::test]
async fn test_simple_mode_service_provider_config() {
    // Use default configuration
    let app_config = AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test ServiceProviderConfig endpoint
    let response = server.get("/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let config: serde_json::Value = response.json();

    // Verify basic structure
    assert!(config["patch"]["supported"].as_bool().unwrap());
    assert!(config["filter"]["supported"].as_bool().unwrap());
    assert!(config["sort"]["supported"].as_bool().unwrap());
    assert!(!config["bulk"]["supported"].as_bool().unwrap());

    // Verify authentication schemes for unauthenticated mode
    let auth_schemes = config["authenticationSchemes"].as_array().unwrap();
    assert_eq!(auth_schemes.len(), 1);
    assert_eq!(auth_schemes[0]["type"], "none");
    assert_eq!(auth_schemes[0]["name"], "Anonymous Access");

    // Verify that location contains absolute URL
    let location = config["meta"]["location"].as_str().unwrap();
    assert!(location.starts_with("http://"));
    assert!(location.contains("/scim/v2/ServiceProviderConfig"));
    println!("ServiceProviderConfig location: {}", location);
}

#[tokio::test]
async fn test_simple_mode_schemas_endpoint() {
    // Use default configuration
    let app_config = AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test Schemas endpoint
    let response = server.get("/scim/v2/Schemas").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let schemas: serde_json::Value = response.json();

    // Verify basic structure
    assert_eq!(
        schemas["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert!(schemas["totalResults"].as_u64().unwrap() > 0);

    let resources = schemas["Resources"].as_array().unwrap();
    assert!(!resources.is_empty());

    // Find User schema
    let user_schema = resources
        .iter()
        .find(|r| r["id"] == "urn:ietf:params:scim:schemas:core:2.0:User")
        .expect("User schema should exist");

    assert_eq!(user_schema["name"], "User");
    assert!(user_schema["attributes"].as_array().unwrap().len() > 0);
}

#[tokio::test]
async fn test_simple_mode_resource_types_endpoint() {
    // Use default configuration
    let app_config = AppConfig::default_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test ResourceTypes endpoint
    let response = server.get("/scim/v2/ResourceTypes").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let resource_types: serde_json::Value = response.json();

    // Verify basic structure
    assert_eq!(
        resource_types["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:ListResponse"
    );
    assert_eq!(resource_types["totalResults"], 2);

    let resources = resource_types["Resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);

    // Find User resource type
    let user_rt = resources
        .iter()
        .find(|r| r["id"] == "User")
        .expect("User resource type should exist");
    assert_eq!(user_rt["name"], "User");
    assert_eq!(user_rt["endpoint"], "/Users");

    // Find Group resource type
    let group_rt = resources
        .iter()
        .find(|r| r["id"] == "Group")
        .expect("Group resource type should exist");
    assert_eq!(group_rt["name"], "Group");
    assert_eq!(group_rt["endpoint"], "/Groups");
}
