use axum_test::TestServer;
use http::StatusCode;
use serde_json::{json, Value};

mod common;

use common::create_test_app_config;

#[tokio::test]
async fn test_multiple_emails_with_primary() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create user with multiple emails
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "multi.email@example.com",
        "emails": [
            {
                "value": "work@example.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "home@example.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "other@example.com",
                "type": "other"
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
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // Verify all emails are stored
    assert_eq!(created_user["emails"].as_array().unwrap().len(), 3);

    // Verify primary email
    let primary_email = created_user["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["primary"] == true)
        .expect("Should have a primary email");

    assert_eq!(primary_email["value"], "work@example.com");
    assert_eq!(primary_email["type"], "work");

    // Test retrieving user preserves all emails
    let response = server
        .get(&format!("/scim/v2/Users/{}", user_id))
        .add_header(http::header::ACCEPT, "application/scim+json")
        .await;

    response.assert_status(StatusCode::OK);
    let retrieved_user: Value = response.json();
    assert_eq!(retrieved_user["emails"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn test_multiple_phones_with_primary() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create user with multiple phone numbers
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "multi.phone@example.com",
        "phoneNumbers": [
            {
                "value": "+1-555-123-4567",
                "type": "work",
                "primary": true,
                "display": "Work Phone"
            },
            {
                "value": "+1-555-987-6543",
                "type": "mobile",
                "primary": false,
                "display": "Mobile Phone"
            },
            {
                "value": "(555) 555-5555",
                "type": "home"
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

    // Verify all phone numbers are stored
    assert_eq!(created_user["phoneNumbers"].as_array().unwrap().len(), 3);

    // Verify primary phone
    let primary_phone = created_user["phoneNumbers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["primary"] == true)
        .expect("Should have a primary phone");

    assert_eq!(primary_phone["value"], "+1-555-123-4567");
    assert_eq!(primary_phone["type"], "work");
    assert_eq!(primary_phone["display"], "Work Phone");
}

#[tokio::test]
async fn test_invalid_email_in_multi_value() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test with one invalid email among multiple
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "invalid.multi.email@example.com",
        "emails": [
            {
                "value": "valid@example.com",
                "type": "work"
            },
            {
                "value": "invalid-email",  // Invalid
                "type": "home"
            }
        ]
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
async fn test_multiple_addresses() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "multi.address@example.com",
        "addresses": [
            {
                "formatted": "100 Universal City Plaza\nHollywood, CA 91608 USA",
                "streetAddress": "100 Universal City Plaza",
                "locality": "Hollywood",
                "region": "CA",
                "postalCode": "91608",
                "country": "USA",
                "type": "work",
                "primary": true
            },
            {
                "formatted": "456 Hollywood Blvd\nHollywood, CA 91608 USA",
                "streetAddress": "456 Hollywood Blvd",
                "locality": "Hollywood",
                "region": "CA",
                "postalCode": "91608",
                "country": "USA",
                "type": "home"
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

    // Verify all addresses are stored
    assert_eq!(created_user["addresses"].as_array().unwrap().len(), 2);

    // Verify work address details
    let work_address = created_user["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["type"] == "work")
        .expect("Should have work address");

    assert_eq!(work_address["streetAddress"], "100 Universal City Plaza");
    assert_eq!(work_address["locality"], "Hollywood");
    assert_eq!(work_address["region"], "CA");
    assert_eq!(work_address["postalCode"], "91608");
    assert_eq!(work_address["country"], "USA");
}

#[tokio::test]
async fn test_photos_and_ims() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "photo.im@example.com",
        "photos": [
            {
                "value": "https://photos.example.com/profile.jpg",
                "type": "photo",
                "primary": true
            },
            {
                "value": "https://photos.example.com/thumbnail.jpg",
                "type": "thumbnail"
            }
        ],
        "ims": [
            {
                "value": "johndoe",
                "type": "aim",
                "primary": true
            },
            {
                "value": "john.doe@example.com",
                "type": "gtalk"
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

    // Verify photos
    assert_eq!(created_user["photos"].as_array().unwrap().len(), 2);
    let primary_photo = created_user["photos"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["primary"] == true)
        .expect("Should have primary photo");
    assert_eq!(
        primary_photo["value"],
        "https://photos.example.com/profile.jpg"
    );

    // Verify IMs
    assert_eq!(created_user["ims"].as_array().unwrap().len(), 2);
    let primary_im = created_user["ims"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["primary"] == true)
        .expect("Should have primary IM");
    assert_eq!(primary_im["value"], "johndoe");
    assert_eq!(primary_im["type"], "aim");
}

#[tokio::test]
async fn test_entitlements_and_roles() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "entitlement.role@example.com",
        "entitlements": [
            {
                "value": "Premium User",
                "display": "Premium Access",
                "type": "subscription",
                "primary": true
            },
            {
                "value": "Beta Tester",
                "display": "Beta Access",
                "type": "feature"
            }
        ],
        "roles": [
            {
                "value": "Administrator",
                "display": "System Administrator",
                "type": "system",
                "primary": true
            },
            {
                "value": "Developer",
                "display": "Software Developer",
                "type": "application"
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

    // Verify entitlements
    assert_eq!(created_user["entitlements"].as_array().unwrap().len(), 2);

    // Verify roles
    assert_eq!(created_user["roles"].as_array().unwrap().len(), 2);
    let primary_role = created_user["roles"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["primary"] == true)
        .expect("Should have primary role");
    assert_eq!(primary_role["value"], "Administrator");
}

#[tokio::test]
async fn test_patch_multi_value_attributes() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create user with initial emails
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "patch.multi@example.com",
        "emails": [{
            "value": "initial@example.com",
            "type": "work",
            "primary": true
        }]
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // PATCH to add more emails
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "emails",
            "value": [
                {
                    "value": "secondary@example.com",
                    "type": "home"
                },
                {
                    "value": "tertiary@example.com",
                    "type": "other"
                }
            ]
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_user: Value = response.json();

    // Should have 3 emails now (1 original + 2 added)
    assert_eq!(patched_user["emails"].as_array().unwrap().len(), 3);

    // PATCH to replace all emails
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "replace",
            "path": "emails",
            "value": [{
                "value": "new@example.com",
                "type": "work",
                "primary": true
            }]
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_user: Value = response.json();

    // Should have only 1 email now
    assert_eq!(patched_user["emails"].as_array().unwrap().len(), 1);
    assert_eq!(patched_user["emails"][0]["value"], "new@example.com");
}

#[tokio::test]
async fn test_x509_certificates() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Sample certificate (truncated for test)
    let cert = "MIIDQzCCAqygAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwTjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFDASBgNVBAoMC2V4YW1wbGUuY29tMRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0xMTEwMjIwNjI0MzFaFw0xMjEwMDQwNjI0MzFaMH8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRQwEgYDVQQKDAtleGFtcGxlLmNvbTEhMB8GA1UEAwwYTXMuIEJhcmJhcmEgSiBKZW5zZW4gSUlJMSIwIAYJKoZIhvcNAQkBFhNiamVuc2VuQGV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Kr+Dcds/JQ5GwejJFcBIP682X3xpjis56AK02bc1FLgzdLI8auoR+cC9/Vrh5t66HkQIOdA4unHh0AaZ4xL5PhVbXIPMB5vAPKpzz5iPSi8xO8SL7I7SDhcBVJhqVqr3HgllEG6UClDdHO7nkLuwXq8HcISKkbT5WFTVfFZzidPl8HZ7DhXkZIRtJwBweq4bvm3hM1Os7UQH05ZS6cVDgweKNwdLLrT51ikSQG3DYrl+ft781UQRIqxgwqCfXEuDiinPh0kkvIi5jivVu1Z9QiwlYEdRbLJ4zJQBmDrSGTMYn4lRc2HgHO4DqB/bnMVorHB0CC6AV1QoFK4GPe1LwIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU8pD0U0vsZIsaA16lL8En8bx0F/gwHwYDVR0jBBgwFoAUdGeKitcaF7gnzsNwDx708kqaVt0wDQYJKoZIhvcNAQEFBQADgYEAA81SsFnOdYJtNg5Tcq+/ByEDrBgnusx0jloUhByPMEVkoMZ3J7j1ZgI8rAbOkNngX8+pKfTiDz1RC4+dx8oU6Za+4NJXUjlL5CvV6BEYb1+QAEJwitTVvxB/A67g42/vzgAtoRUeDov1+GFiBZ+GNF/cAYKcMtGcrs2i97ZkJMo=";

    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "cert.user@example.com",
        "x509Certificates": [
            {
                "value": cert,
                "display": "Primary Certificate",
                "type": "signing",
                "primary": true
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

    // Verify certificate is stored
    assert_eq!(
        created_user["x509Certificates"].as_array().unwrap().len(),
        1
    );
    assert_eq!(created_user["x509Certificates"][0]["value"], cert);
}

#[tokio::test]
async fn test_multiple_primary_constraint() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Test with multiple primary emails (should be rejected per SCIM spec)
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "multi.primary@example.com",
        "emails": [
            {
                "value": "work1@example.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "work2@example.com",
                "type": "work",
                "primary": true  // Multiple primary violates SCIM spec
            }
        ]
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    // SCIM spec requires at most one primary=true
    response.assert_status(StatusCode::BAD_REQUEST);
    let error: Value = response.json();
    assert!(error["error"]
        .as_str()
        .unwrap()
        .contains("At most one element can have primary=true"));
}

#[tokio::test]
async fn test_primary_enforcement_in_patch() {
    let tenant_config = create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();
    let _tenant_id = "3";

    // Create user with one primary email
    let user_data = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "patch.primary@example.com",
        "emails": [{
            "value": "primary@example.com",
            "type": "work",
            "primary": true
        }]
    });

    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    let user_id = created_user["id"].as_str().expect("User should have an ID");

    // PATCH to add emails with primary=true (should make existing primary false)
    let patch_data = json!({
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
        "Operations": [{
            "op": "add",
            "path": "emails",
            "value": [
                {
                    "value": "secondary@example.com",
                    "type": "home",
                    "primary": true  // Should become primary, existing primary becomes false
                }
            ]
        }]
    });

    let response = server
        .patch(&format!("/scim/v2/Users/{}", user_id))
        .content_type("application/scim+json")
        .json(&patch_data)
        .await;

    response.assert_status(StatusCode::OK);
    let patched_user: Value = response.json();

    // Should have 2 emails, but only the new one should have primary=true
    assert_eq!(patched_user["emails"].as_array().unwrap().len(), 2);

    let primary_count = patched_user["emails"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|email| email["primary"] == true)
        .count();
    assert_eq!(primary_count, 1);

    // Original email should no longer have primary attribute
    let original_email = patched_user["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|email| email["value"] == "primary@example.com")
        .expect("Original email should exist");
    assert!(original_email["primary"].is_null());

    // New email should be primary
    let new_email = patched_user["emails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|email| email["value"] == "secondary@example.com")
        .expect("New email should exist");
    assert_eq!(new_email["primary"], true);
}
