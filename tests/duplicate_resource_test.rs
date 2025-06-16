use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

/// Test SCIM 2.0 compliance for duplicate resource creation
/// According to RFC 7644, duplicate resources should return 409 Conflict with scimType "uniqueness"
#[tokio::test]
async fn test_duplicate_user_creation_returns_409_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "duplicate_user",
        "name": {
            "givenName": "Test",
            "familyName": "User"
        },
        "emails": [{
            "value": "duplicate@example.com",
            "primary": true
        }]
    });

    // First creation should succeed (201 Created)
    let response1 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response1.assert_status(StatusCode::CREATED);
    let created_user: Value = response1.json();
    assert_eq!(created_user["userName"], "duplicate_user");

    // Second creation with same userName should fail (409 Conflict)
    let response2 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response2.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response2.json();

    // Verify SCIM 2.0 compliant error response
    assert_eq!(
        error_response["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(error_response["scimType"], "uniqueness");
    assert_eq!(error_response["status"], "409");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("userName"));
}

#[tokio::test]
async fn test_duplicate_group_creation_returns_409_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let group_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Duplicate Group"
    });

    // First creation should succeed (201 Created)
    let response1 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response1.assert_status(StatusCode::CREATED);
    let created_group: Value = response1.json();
    assert_eq!(created_group["displayName"], "Duplicate Group");

    // Second creation with same displayName should fail (409 Conflict)
    let response2 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data)
        .await;

    response2.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response2.json();

    // Verify SCIM 2.0 compliant error response
    assert_eq!(
        error_response["schemas"][0],
        "urn:ietf:params:scim:api:messages:2.0:Error"
    );
    assert_eq!(error_response["scimType"], "uniqueness");
    assert_eq!(error_response["status"], "409");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("displayName"));
}

#[tokio::test]
async fn test_case_insensitive_duplicate_user_detection() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with lowercase userName
    let user_data_lower = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "casetest",
        "name": {
            "givenName": "Case",
            "familyName": "Test"
        }
    });

    let response1 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data_lower)
        .await;

    response1.assert_status(StatusCode::CREATED);

    // Try to create user with uppercase userName (should fail due to case-insensitive check)
    let user_data_upper = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "CASETEST",
        "name": {
            "givenName": "Case",
            "familyName": "Test2"
        }
    });

    let response2 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data_upper)
        .await;

    response2.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response2.json();

    // Verify SCIM 2.0 compliant error response
    assert_eq!(error_response["scimType"], "uniqueness");
    assert_eq!(error_response["status"], "409");
}

#[tokio::test]
async fn test_case_insensitive_duplicate_group_detection() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create group with lowercase displayName
    let group_data_lower = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "marketing team"
    });

    let response1 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data_lower)
        .await;

    response1.assert_status(StatusCode::CREATED);

    // Try to create group with mixed case displayName (should fail due to case-insensitive check)
    let group_data_mixed = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
        "displayName": "Marketing Team"
    });

    let response2 = server
        .post("/scim/v2/Groups")
        .content_type("application/scim+json")
        .json(&group_data_mixed)
        .await;

    response2.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response2.json();

    // Verify SCIM 2.0 compliant error response
    assert_eq!(error_response["scimType"], "uniqueness");
    assert_eq!(error_response["status"], "409");
}

#[tokio::test]
async fn test_external_id_duplicate_returns_409_conflict() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Create user with externalId
    let user_data1 = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user1",
        "externalId": "EXT-001",
        "name": {
            "givenName": "Test",
            "familyName": "User1"
        }
    });

    let response1 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data1)
        .await;

    response1.assert_status(StatusCode::CREATED);

    // Try to create another user with same externalId (should fail)
    let user_data2 = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "user2",
        "externalId": "EXT-001",
        "name": {
            "givenName": "Test",
            "familyName": "User2"
        }
    });

    let response2 = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data2)
        .await;

    response2.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response2.json();

    // Verify SCIM 2.0 compliant error response
    assert_eq!(error_response["scimType"], "uniqueness");
    assert_eq!(error_response["status"], "409");
    assert!(error_response["detail"]
        .as_str()
        .unwrap()
        .contains("externalId"));
}

#[tokio::test]
async fn test_multi_tenant_duplicate_isolation() {
    let app_config = common::create_test_app_config();
    let app = common::setup_test_app(app_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "tenant_test",
        "name": {
            "givenName": "Tenant",
            "familyName": "Test"
        }
    });

    // Create user in tenant-a
    let response1 = server
        .post("/tenant-a/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response1.assert_status(StatusCode::CREATED);

    // Creating same userName in tenant-b should succeed (different tenants)
    let response2 = server
        .post("/tenant-b/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response2.assert_status(StatusCode::CREATED);

    // But creating duplicate in same tenant should fail
    let response3 = server
        .post("/tenant-a/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response3.assert_status(StatusCode::CONFLICT);
    let error_response: Value = response3.json();
    assert_eq!(error_response["scimType"], "uniqueness");
}
