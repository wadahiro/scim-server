use axum_test::TestServer;
use http::StatusCode;

mod common;

#[tokio::test]
async fn test_service_provider_config() {
    let tenant_config = common::create_test_app_config();
    let app = common::setup_test_app(tenant_config).await.unwrap();
    let server = TestServer::new(app).unwrap();

    // Test ServiceProviderConfig for different tenants
    let response_scim = server.get("/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response_scim.status_code(), StatusCode::OK);
    let json_scim: serde_json::Value = response_scim.json();

    // Verify tenant-specific configuration
    assert!(json_scim.get("patch").is_some());
    assert!(json_scim.get("bulk").is_some());
    assert!(json_scim.get("filter").is_some());
    assert!(json_scim.get("authenticationSchemes").is_some());

    // Verify tenant-specific URLs
    let meta = json_scim.get("meta").unwrap();
    let location = meta.get("location").unwrap().as_str().unwrap();
    assert!(location.starts_with("http://"));
    assert!(location.contains("/scim/v2/ServiceProviderConfig"));

    // Test another tenant
    let response_tenant_a = server.get("/tenant-a/scim/v2/ServiceProviderConfig").await;
    assert_eq!(response_tenant_a.status_code(), StatusCode::OK);
    let json_tenant_a: serde_json::Value = response_tenant_a.json();

    let meta_tenant_a = json_tenant_a.get("meta").unwrap();
    let location_tenant_a = meta_tenant_a.get("location").unwrap().as_str().unwrap();
    assert!(location_tenant_a.starts_with("http://"));
    assert!(location_tenant_a.contains("/tenant-a/scim/v2/ServiceProviderConfig"));
}
