use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_enterprise_user_extension_crud() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test creating user with Enterprise User extension
    let user_data = json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ],
        "userName": "enterprise.user@example.com",
        "name": {
            "givenName": "John",
            "familyName": "Doe"
        },
        "emails": [{
            "value": "john.doe@example.com",
            "type": "work",
            "primary": true
        }],
        "active": true,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": "EMP001",
            "costCenter": "CC1234",
            "organization": "Acme Corporation",
            "division": "Technology",
            "department": "Engineering",
            "manager": {
                "value": "550e8400-e29b-41d4-a716-446655440000",
                "displayName": "Jane Smith"
            }
        }
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // Verify Enterprise User extension is included
    assert_eq!(
        created_user["schemas"],
        json!([
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ])
    );

    let enterprise_data =
        &created_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(enterprise_data["employeeNumber"], "EMP001");
    assert_eq!(enterprise_data["costCenter"], "CC1234");
    assert_eq!(enterprise_data["organization"], "Acme Corporation");
    assert_eq!(enterprise_data["division"], "Technology");
    assert_eq!(enterprise_data["department"], "Engineering");
    assert_eq!(
        enterprise_data["manager"]["value"],
        "550e8400-e29b-41d4-a716-446655440000"
    );
    assert_eq!(enterprise_data["manager"]["displayName"], "Jane Smith");

    // Test retrieving user with Enterprise User extension
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let retrieved_user: Value = response.json();

    // Verify Enterprise User extension is preserved
    let enterprise_data =
        &retrieved_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(enterprise_data["employeeNumber"], "EMP001");
    assert_eq!(enterprise_data["costCenter"], "CC1234");

    // Test updating Enterprise User extension
    let update_data = json!({
        "schemas": [
            "urn:ietf:params:scim:schemas:core:2.0:User",
            "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
        ],
        "userName": "enterprise.user@example.com",
        "name": {
            "givenName": "John",
            "familyName": "Doe"
        },
        "emails": [{
            "value": "john.doe@example.com",
            "type": "work",
            "primary": true
        }],
        "active": true,
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {
            "employeeNumber": "EMP001",
            "costCenter": "CC5678", // Changed
            "organization": "Acme Corporation",
            "division": "Technology",
            "department": "Research & Development", // Changed
            "manager": {
                "value": "660e8400-e29b-41d4-a716-446655440001", // Changed
                "displayName": "Bob Johnson" // Changed
            }
        }
    });

    let response = server
        .put(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&update_data)
        .await;

    response.assert_status(StatusCode::OK);
    let updated_user: Value = response.json();

    let enterprise_data =
        &updated_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(enterprise_data["costCenter"], "CC5678");
    assert_eq!(enterprise_data["department"], "Research & Development");
    assert_eq!(
        enterprise_data["manager"]["value"],
        "660e8400-e29b-41d4-a716-446655440001"
    );
    assert_eq!(enterprise_data["manager"]["displayName"], "Bob Johnson");

    // Test PATCH operations on Enterprise User extension
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [
            {
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:costCenter",
                "value": "CC9999"
            },
            {
                "op": "replace",
                "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
                "value": {
                    "value": "770e8400-e29b-41d4-a716-446655440002",
                    "displayName": "Alice Williams"
                }
            }
        ]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_user: Value = response.json();

    let enterprise_data =
        &patched_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"];
    assert_eq!(enterprise_data["costCenter"], "CC9999");
    assert_eq!(
        enterprise_data["manager"]["value"],
        "770e8400-e29b-41d4-a716-446655440002"
    );
    assert_eq!(enterprise_data["manager"]["displayName"], "Alice Williams");
}

#[tokio::test]
async fn test_user_without_enterprise_extension() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create user without Enterprise User extension
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "regular.user@example.com",
        "name": {
            "givenName": "Regular",
            "familyName": "User"
        },
        "emails": [{
            "value": "regular.user@example.com",
            "type": "work",
            "primary": true
        }],
        "active": true
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();

    // Verify no Enterprise User extension is included
    assert_eq!(
        created_user["schemas"],
        json!(["urn:ietf:params:scim:schemas:core:2.0:User"])
    );
    assert!(created_user["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"].is_null());
}

#[tokio::test]
async fn test_email_validation() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test invalid email format
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "test.user",
        "emails": [{
            "value": "invalid-email",
            "type": "work",
            "primary": true
        }]
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("Invalid email format"));
}

#[tokio::test]
async fn test_phone_no_validation() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test that any phone number format is accepted (no validation per SCIM 2.0)
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "any.phone@example.com",
        "phoneNumbers": [
            {
                "value": "+1-234-567-8900",  // Standard format
                "type": "work"
            },
            {
                "value": "(123) 456-7890",  // US format
                "type": "mobile"
            },
            {
                "value": "not-a-phone",  // This should be accepted now
                "type": "home"
            },
            {
                "value": "123",  // Short number
                "type": "other"
            },
            {
                "value": "☎️ Call me maybe",  // Even emojis should be accepted
                "type": "pager"
            }
        ]
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();

    // All phone numbers should be accepted as-is
    assert_eq!(created_user["phoneNumbers"][0]["value"], "+1-234-567-8900");
    assert_eq!(created_user["phoneNumbers"][1]["value"], "(123) 456-7890");
    assert_eq!(created_user["phoneNumbers"][2]["value"], "not-a-phone");
    assert_eq!(created_user["phoneNumbers"][3]["value"], "123");
    assert_eq!(created_user["phoneNumbers"][4]["value"], "☎️ Call me maybe");
}

#[tokio::test]
async fn test_locale_timezone_validation() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test valid locale and timezone
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "intl.user@example.com",
        "locale": "en-US",
        "timezone": "America/New_York"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);

    // Test invalid locale
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bad.locale@example.com",
        "locale": "invalid-locale"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("Invalid locale format"));

    // Test invalid timezone
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "bad.tz@example.com",
        "timezone": "InvalidTZ"
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("Invalid timezone format"));
}
