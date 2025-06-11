use scim_server::parser::{SortOrder, SortSpec};

#[tokio::test]
async fn test_sort_spec_creation() {
    // Test SortSpec::from_params
    let spec = SortSpec::from_params(Some("userName"), Some("descending"));
    assert!(spec.is_some());
    let spec = spec.unwrap();
    assert_eq!(spec.attribute, "userName");
    assert_eq!(spec.order, SortOrder::Descending);

    let spec = SortSpec::from_params(Some("displayName"), None);
    assert!(spec.is_some());
    let spec = spec.unwrap();
    assert_eq!(spec.attribute, "displayName");
    assert_eq!(spec.order, SortOrder::Ascending); // Default

    let spec = SortSpec::from_params(None, Some("ascending"));
    assert!(spec.is_none());
}

#[tokio::test]
async fn test_sort_order_conversion() {
    assert_eq!(SortOrder::from_str("ascending"), SortOrder::Ascending);
    assert_eq!(SortOrder::from_str("DESCENDING"), SortOrder::Descending);
    assert_eq!(SortOrder::from_str("invalid"), SortOrder::Ascending); // Default
}


// TODO: Update these integration tests to use the new storage abstraction
// #[tokio::test]
// async fn test_user_service_sort_integration() {
//     // Tests will be updated to use storage abstraction instead of repositories
// }

// #[tokio::test]
// async fn test_group_service_sort_integration() {
//     // Tests will be updated to use storage abstraction instead of repositories
// }

