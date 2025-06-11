#[derive(Debug, Clone, PartialEq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl SortOrder {
    pub fn from_str(s: &str) -> SortOrder {
        match s.to_lowercase().as_str() {
            "descending" | "desc" => SortOrder::Descending,
            _ => SortOrder::Ascending, // Default to ascending
        }
    }
}

#[derive(Debug, Clone)]
pub struct SortSpec {
    pub attribute: String,
    pub order: SortOrder,
}

impl SortSpec {
    pub fn new(attribute: String, order: SortOrder) -> Self {
        SortSpec { attribute, order }
    }

    /// Parse SCIM sortBy and sortOrder parameters
    pub fn from_params(sort_by: Option<&str>, sort_order: Option<&str>) -> Option<SortSpec> {
        sort_by.map(|attr| {
            let order = sort_order
                .map(SortOrder::from_str)
                .unwrap_or(SortOrder::Ascending);
            SortSpec::new(attr.to_string(), order)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sort_order_from_str() {
        assert_eq!(SortOrder::from_str("ascending"), SortOrder::Ascending);
        assert_eq!(SortOrder::from_str("ASCENDING"), SortOrder::Ascending);
        assert_eq!(SortOrder::from_str("descending"), SortOrder::Descending);
        assert_eq!(SortOrder::from_str("DESCENDING"), SortOrder::Descending);
        assert_eq!(SortOrder::from_str("desc"), SortOrder::Descending);
        assert_eq!(SortOrder::from_str("invalid"), SortOrder::Ascending); // Default
    }

    #[test]
    fn test_sort_spec_from_params() {
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

        let spec = SortSpec::from_params(None, Some("descending"));
        assert!(spec.is_none());
    }
}
