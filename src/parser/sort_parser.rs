#[derive(Debug, Clone, PartialEq)]
pub enum SortOrder {
    Ascending,
    Descending,
}

impl SortOrder {
    #[allow(clippy::should_implement_trait)]
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

    /// Like [`from_params`](Self::from_params), but first resolves `sort_by`
    /// to the resource schema's own attribute-name casing.
    ///
    /// RFC 7644 §3.10 defines the notation these parameters use: "All
    /// operations share a common scheme for referencing simple and complex
    /// attributes", ending "All facets (URN, attribute, and sub-attribute
    /// name) of the fully encoded attribute name are case insensitive."
    /// §3.4.3 binds `sortBy` to it: "The "sortBy" attribute MUST be in
    /// standard attribute notation (Section 3.10) form."
    /// Without this, `sortBy=USERNAME`
    /// would fail to match the `userName` column/JSON-path special-casing
    /// the database layer looks for and silently fall back to an
    /// unsorted (or meaninglessly sorted) result.
    pub fn from_params_for_resource(
        sort_by: Option<&str>,
        sort_order: Option<&str>,
        resource_type: crate::parser::ResourceType,
    ) -> Option<SortSpec> {
        let resolved_sort_by = sort_by.map(|attr| {
            let schema = match resource_type {
                crate::parser::ResourceType::User => &*crate::schema::USER_SCHEMA,
                crate::parser::ResourceType::Group => &*crate::schema::GROUP_SCHEMA,
            };
            crate::schema::resolve_attribute_path_case(schema, attr)
        });
        Self::from_params(resolved_sort_by.as_deref(), sort_order)
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

    #[test]
    fn test_sort_spec_from_params_for_resource_case_insensitive() {
        // RFC 7644 §3.4.3 requires `sortBy` to be in standard attribute
        // notation (§3.10), and §3.10 states that all facets of an attribute
        // name are case insensitive.
        let spec = SortSpec::from_params_for_resource(
            Some("USERNAME"),
            None,
            crate::parser::ResourceType::User,
        )
        .unwrap();
        assert_eq!(spec.attribute, "userName");

        let spec = SortSpec::from_params_for_resource(
            Some("DISPLAYNAME"),
            None,
            crate::parser::ResourceType::Group,
        )
        .unwrap();
        assert_eq!(spec.attribute, "displayName");
    }
}
