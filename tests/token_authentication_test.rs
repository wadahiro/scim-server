use axum_test::TestServer;
use http::StatusCode;
use serde_json::Value;

mod common;

#[tokio::test]
async fn test_token_authentication_success() {
    let tenant_config = common::create_token_auth_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test successful authentication with token
    let user_data = common::create_test_user_json("test-user", "Test", "User");
    
    let response = server
        .post("/scim/v2/Users")
        .add_header("authorization", "token test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::CREATED);
    let created_user: Value = response.json();
    assert_eq!(created_user["userName"], "test-user");
}

#[tokio::test]
async fn test_token_authentication_invalid_token() {
    let tenant_config = common::create_token_auth_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test failed authentication with wrong token
    let user_data = common::create_test_user_json("test-user", "Test", "User");
    
    let response = server
        .post("/scim/v2/Users")
        .add_header("authorization", "token wrong-token")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_authentication_missing_token() {
    let tenant_config = common::create_token_auth_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test failed authentication without token
    let user_data = common::create_test_user_json("test-user", "Test", "User");
    
    let response = server
        .post("/scim/v2/Users")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_authentication_wrong_prefix() {
    let tenant_config = common::create_token_auth_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test failed authentication with Bearer instead of token
    let user_data = common::create_test_user_json("test-user", "Test", "User");
    
    let response = server
        .post("/scim/v2/Users")
        .add_header("authorization", "Bearer test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_token_vs_bearer_difference() {
    let token_config = common::create_token_auth_config();
    let bearer_config = common::create_bearer_auth_config();
    
    let token_app = common::setup_test_app(token_config).await.unwrap();
    let bearer_app = common::setup_test_app(bearer_config).await.unwrap();
    
    let token_server = TestServer::new(token_app).unwrap();
    let bearer_server = TestServer::new(bearer_app).unwrap();

    let user_data = common::create_test_user_json("test-user", "Test", "User");

    // Token auth server should accept "token xyz" but reject "Bearer xyz"
    let response = token_server
        .post("/scim/v2/Users")
        .add_header("authorization", "token test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);

    let response = token_server
        .post("/scim/v2/Users")
        .add_header("authorization", "Bearer test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);

    // Bearer auth server should accept "Bearer xyz" but reject "token xyz"
    let response = bearer_server
        .post("/scim/v2/Users")
        .add_header("authorization", "Bearer test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::CREATED);

    let response = bearer_server
        .post("/scim/v2/Users")
        .add_header("authorization", "token test-token-123")
        .content_type("application/scim+json")
        .json(&user_data)
        .await;
    response.assert_status(StatusCode::UNAUTHORIZED);
}