use crate::parser::ResourceType;
use crate::schema::definitions::{find_attribute, Returned, GROUP_SCHEMA, USER_SCHEMA};
use serde_json::{Map, Value};

/// Query parameters for SCIM attribute filtering per RFC 7644 section 3.4.2.5
#[derive(Debug, Clone)]
pub struct AttributeFilter {
    /// Comma-separated list of attributes to include (overrides default)
    pub attributes: Option<Vec<String>>,
    /// Comma-separated list of attributes to exclude from default set
    pub excluded_attributes: Option<Vec<String>>,
}

impl AttributeFilter {
    /// Parse attributes and excludedAttributes query parameters
    pub fn from_params(attributes: Option<&str>, excluded_attributes: Option<&str>) -> Self {
        let attributes = attributes.map(|attr_str| {
            attr_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });

        let excluded_attributes = excluded_attributes.map(|attr_str| {
            attr_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        });

        Self {
            attributes,
            excluded_attributes,
        }
    }

    /// Apply attribute filtering to a SCIM resource
    /// Returns filtered JSON value according to RFC 7644 specification
    pub fn apply_to_resource(&self, resource: &Value, resource_type: ResourceType) -> Value {
        // First, remove null fields to comply with SCIM specification
        let resource_no_nulls = Self::remove_null_fields(resource);

        // If no filtering specified, return resource without nulls
        if self.attributes.is_none() && self.excluded_attributes.is_none() {
            return resource_no_nulls;
        }

        let schema = match resource_type {
            ResourceType::User => &*USER_SCHEMA,
            ResourceType::Group => &*GROUP_SCHEMA,
        };

        // Get the set of attributes to include
        let included_attributes = if let Some(ref attrs) = self.attributes {
            // If attributes parameter is specified, it overrides everything else
            self.get_included_attributes_from_list(attrs, schema)
        } else {
            // Use default attributes minus excluded ones
            self.get_default_attributes_minus_excluded(schema)
        };

        // Filter the resource
        self.filter_json_object(&resource_no_nulls, &included_attributes)
    }

    /// Get attributes to include when "attributes" parameter is specified
    fn get_included_attributes_from_list(
        &self,
        attrs: &[String],
        schema: &crate::schema::definitions::SchemaDefinition,
    ) -> std::collections::HashSet<String> {
        let mut included = std::collections::HashSet::new();

        for attr in attrs {
            // Always include attributes with "returned" = "always"
            if let Some(attr_def) = find_attribute(schema, attr) {
                if matches!(attr_def.returned, Returned::Always) {
                    included.insert(attr.clone());
                    continue;
                }
            }

            // Include the requested attribute
            included.insert(attr.clone());

            // For complex attributes, include sub-attributes if needed
            self.add_sub_attributes(attr, schema, &mut included);
        }

        // Always include mandatory attributes (id, meta, etc.)
        self.add_always_returned_attributes(schema, &mut included);

        included
    }

    /// Get default attributes minus excluded ones
    fn get_default_attributes_minus_excluded(
        &self,
        schema: &crate::schema::definitions::SchemaDefinition,
    ) -> std::collections::HashSet<String> {
        let mut included = std::collections::HashSet::new();

        // Start with all default and always returned attributes
        for attr in &schema.attributes {
            match attr.returned {
                Returned::Always | Returned::Default => {
                    included.insert(attr.name.to_string());
                    // Add sub-attributes for complex types
                    self.add_sub_attributes_recursive(
                        &attr.name,
                        &attr.sub_attributes,
                        &mut included,
                    );
                }
                _ => {} // Skip Request and Never attributes in default set
            }
        }

        // Remove excluded attributes (except those with "returned" = "always")
        if let Some(ref excluded) = self.excluded_attributes {
            for excluded_attr in excluded {
                if let Some(attr_def) = find_attribute(schema, excluded_attr) {
                    // Cannot exclude attributes with "returned" = "always"
                    if !matches!(attr_def.returned, Returned::Always) {
                        included.remove(excluded_attr);
                        // Also remove sub-attributes
                        self.remove_sub_attributes(excluded_attr, &mut included);
                    }
                }
            }
        }

        included
    }

    /// Add sub-attributes for a given attribute path
    fn add_sub_attributes(
        &self,
        attr_path: &str,
        schema: &crate::schema::definitions::SchemaDefinition,
        included: &mut std::collections::HashSet<String>,
    ) {
        if let Some(attr_def) = find_attribute(schema, attr_path) {
            if !attr_def.sub_attributes.is_empty() {
                self.add_sub_attributes_recursive(attr_path, &attr_def.sub_attributes, included);
            }
        }
    }

    /// Recursively add sub-attributes
    fn add_sub_attributes_recursive(
        &self,
        parent_path: &str,
        sub_attrs: &[crate::schema::definitions::AttributeDefinition],
        included: &mut std::collections::HashSet<String>,
    ) {
        for sub_attr in sub_attrs {
            let sub_path = format!("{}.{}", parent_path, sub_attr.name);
            included.insert(sub_path.clone());

            if !sub_attr.sub_attributes.is_empty() {
                self.add_sub_attributes_recursive(&sub_path, &sub_attr.sub_attributes, included);
            }
        }
    }

    /// Remove sub-attributes for excluded attributes
    fn remove_sub_attributes(
        &self,
        attr_path: &str,
        included: &mut std::collections::HashSet<String>,
    ) {
        // Remove any attributes that start with this path
        let to_remove: Vec<String> = included
            .iter()
            .filter(|attr| attr.starts_with(&format!("{}.", attr_path)))
            .cloned()
            .collect();

        for attr in to_remove {
            included.remove(&attr);
        }
    }

    /// Add attributes that must always be returned
    fn add_always_returned_attributes(
        &self,
        schema: &crate::schema::definitions::SchemaDefinition,
        included: &mut std::collections::HashSet<String>,
    ) {
        for attr in &schema.attributes {
            if matches!(attr.returned, Returned::Always) {
                included.insert(attr.name.to_string());
                self.add_sub_attributes_recursive(&attr.name, &attr.sub_attributes, included);
            }
        }
    }

    /// Filter a JSON object based on included attributes
    fn filter_json_object(
        &self,
        value: &Value,
        included_attributes: &std::collections::HashSet<String>,
    ) -> Value {
        match value {
            Value::Object(obj) => {
                let mut filtered = Map::new();

                for (key, val) in obj {
                    // Check if this attribute should be included
                    if self.should_include_attribute(key, included_attributes) {
                        // For complex attributes, recursively filter sub-attributes
                        let filtered_value = if self.is_complex_attribute(key, val) {
                            self.filter_complex_attribute(key, val, included_attributes)
                        } else {
                            val.clone()
                        };
                        filtered.insert(key.clone(), filtered_value);
                    }
                }

                Value::Object(filtered)
            }
            _ => value.clone(),
        }
    }

    /// Check if an attribute should be included
    fn should_include_attribute(
        &self,
        attr_name: &str,
        included_attributes: &std::collections::HashSet<String>,
    ) -> bool {
        // Direct match
        if included_attributes.contains(attr_name) {
            return true;
        }

        // Check if any included attribute starts with this attribute name (for complex attributes)
        included_attributes
            .iter()
            .any(|included| included.starts_with(&format!("{}.", attr_name)))
    }

    /// Check if an attribute is complex (has sub-attributes)
    fn is_complex_attribute(&self, _attr_name: &str, value: &Value) -> bool {
        value.is_object() || value.is_array()
    }

    /// Filter complex attributes (objects and arrays)
    fn filter_complex_attribute(
        &self,
        attr_name: &str,
        value: &Value,
        included_attributes: &std::collections::HashSet<String>,
    ) -> Value {
        match value {
            Value::Object(obj) => {
                let mut filtered = Map::new();

                for (sub_key, sub_val) in obj {
                    let full_path = format!("{}.{}", attr_name, sub_key);
                    if self.should_include_sub_attribute(&full_path, included_attributes) {
                        filtered.insert(sub_key.clone(), sub_val.clone());
                    }
                }

                Value::Object(filtered)
            }
            Value::Array(arr) => {
                // For arrays, filter each element if it's an object
                let filtered_array: Vec<Value> = arr
                    .iter()
                    .map(|item| {
                        if item.is_object() {
                            self.filter_array_item(attr_name, item, included_attributes)
                        } else {
                            item.clone()
                        }
                    })
                    .collect();
                Value::Array(filtered_array)
            }
            _ => value.clone(),
        }
    }

    /// Filter array items (for multi-valued attributes)
    fn filter_array_item(
        &self,
        attr_name: &str,
        item: &Value,
        included_attributes: &std::collections::HashSet<String>,
    ) -> Value {
        if let Value::Object(obj) = item {
            let mut filtered = Map::new();

            for (sub_key, sub_val) in obj {
                let full_path = format!("{}.{}", attr_name, sub_key);
                if self.should_include_sub_attribute(&full_path, included_attributes) {
                    filtered.insert(sub_key.clone(), sub_val.clone());
                }
            }

            Value::Object(filtered)
        } else {
            item.clone()
        }
    }

    /// Check if a sub-attribute should be included
    fn should_include_sub_attribute(
        &self,
        full_path: &str,
        included_attributes: &std::collections::HashSet<String>,
    ) -> bool {
        included_attributes.contains(full_path)
    }

    /// Remove null fields from JSON to comply with SCIM specification
    /// SCIM 2.0 RFC 7644 specifies that unassigned attributes should not be included in responses
    pub fn remove_null_fields(value: &Value) -> Value {
        match value {
            Value::Object(obj) => {
                let mut filtered = Map::new();

                for (key, val) in obj {
                    match val {
                        Value::Null => {
                            // Skip null values - they should not be present in SCIM responses
                            continue;
                        }
                        Value::Object(_) => {
                            // Recursively clean nested objects
                            let cleaned = Self::remove_null_fields(val);
                            // Only include non-empty objects
                            if let Value::Object(ref inner_obj) = cleaned {
                                if !inner_obj.is_empty() {
                                    filtered.insert(key.clone(), cleaned);
                                }
                            } else {
                                filtered.insert(key.clone(), cleaned);
                            }
                        }
                        Value::Array(arr) => {
                            // Clean array elements
                            let cleaned_array: Vec<Value> = arr
                                .iter()
                                .map(|item| Self::remove_null_fields(item))
                                .filter(|item| {
                                    if item.is_null() {
                                        false // Remove null array elements
                                    } else if let Value::Object(obj) = item {
                                        !obj.is_empty() // Remove empty objects
                                    } else {
                                        true // Keep non-null, non-empty values
                                    }
                                })
                                .collect();

                            // Special case: always include empty arrays for Group members field
                            if key == "members" || !cleaned_array.is_empty() {
                                filtered.insert(key.clone(), Value::Array(cleaned_array));
                            }
                        }
                        _ => {
                            // Include other values (strings, numbers, booleans)
                            filtered.insert(key.clone(), val.clone());
                        }
                    }
                }

                Value::Object(filtered)
            }
            Value::Array(arr) => {
                // Clean array elements
                let cleaned_array: Vec<Value> = arr
                    .iter()
                    .map(|item| Self::remove_null_fields(item))
                    .filter(|item| !item.is_null())
                    .collect();
                Value::Array(cleaned_array)
            }
            _ => value.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_no_filtering() {
        let filter = AttributeFilter::from_params(None, None);
        let user = json!({
            "id": "123",
            "userName": "john.doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe"
            },
            "emails": [{"value": "john@example.com", "primary": true}]
        });

        let result = filter.apply_to_resource(&user, ResourceType::User);
        assert_eq!(result, user);
    }

    #[test]
    fn test_remove_null_fields() {
        let user_with_nulls = json!({
            "id": "123",
            "userName": "john.doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe",
                "formatted": null,
                "middleName": null
            },
            "emails": [
                {"value": "john@example.com", "primary": true},
                {"value": null, "primary": false}
            ],
            "phoneNumbers": null,
            "addresses": []
        });

        let cleaned = AttributeFilter::remove_null_fields(&user_with_nulls);

        // Check that null fields are removed
        assert_eq!(cleaned["id"], "123");
        assert_eq!(cleaned["userName"], "john.doe");

        // Name object should not have null fields
        let name_obj = &cleaned["name"];
        assert!(name_obj.get("givenName").is_some());
        assert!(name_obj.get("familyName").is_some());
        assert!(name_obj.get("formatted").is_none()); // Should be removed
        assert!(name_obj.get("middleName").is_none()); // Should be removed

        // Array should have null element removed
        let emails = cleaned["emails"].as_array().unwrap();
        // The second email object will have its null value field removed,
        // but the object itself remains with primary: false
        assert_eq!(emails.len(), 2); // Both email objects remain
        assert_eq!(emails[0]["value"], "john@example.com");
        assert_eq!(emails[1]["primary"], false);
        assert!(emails[1].get("value").is_none()); // null value was removed

        // Null top-level field should be removed
        assert!(cleaned.get("phoneNumbers").is_none());

        // Empty arrays should be removed
        assert!(cleaned.get("addresses").is_none());
    }

    #[test]
    fn test_nested_null_removal() {
        let complex_obj = json!({
            "level1": {
                "level2": {
                    "value": "keep",
                    "null_field": null
                },
                "null_object": null
            },
            "array_with_nulls": [
                {"valid": "data"},
                null,
                {"another": "value"}
            ]
        });

        let cleaned = AttributeFilter::remove_null_fields(&complex_obj);

        // Check deep nesting
        assert_eq!(cleaned["level1"]["level2"]["value"], "keep");
        assert!(cleaned["level1"]["level2"].get("null_field").is_none());
        assert!(cleaned["level1"].get("null_object").is_none());

        // Array should have nulls removed
        let arr = cleaned["array_with_nulls"].as_array().unwrap();
        assert_eq!(arr.len(), 2); // Two valid objects should remain
        assert_eq!(arr[0]["valid"], "data");
        assert_eq!(arr[1]["another"], "value");
    }

    #[test]
    fn test_attributes_parameter() {
        let filter = AttributeFilter::from_params(Some("userName,emails"), None);
        let user = json!({
            "id": "123",
            "userName": "john.doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe"
            },
            "emails": [{"value": "john@example.com", "primary": true}],
            "phoneNumbers": [{"value": "555-1234"}]
        });

        let result = filter.apply_to_resource(&user, ResourceType::User);

        // Should include userName, emails, and always-returned attributes like id
        assert!(result.get("userName").is_some());
        assert!(result.get("emails").is_some());
        assert!(result.get("id").is_some()); // Always returned
        assert!(result.get("name").is_none()); // Not requested
        assert!(result.get("phoneNumbers").is_none()); // Not requested
    }

    #[test]
    fn test_excluded_attributes_parameter() {
        let filter = AttributeFilter::from_params(None, Some("emails,phoneNumbers"));
        let user = json!({
            "id": "123",
            "userName": "john.doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe"
            },
            "emails": [{"value": "john@example.com", "primary": true}],
            "phoneNumbers": [{"value": "555-1234"}]
        });

        let result = filter.apply_to_resource(&user, ResourceType::User);

        // Should exclude emails and phoneNumbers but keep others
        assert!(result.get("userName").is_some());
        assert!(result.get("name").is_some());
        assert!(result.get("id").is_some()); // Always returned
        assert!(result.get("emails").is_none()); // Excluded
        assert!(result.get("phoneNumbers").is_none()); // Excluded
    }

    #[test]
    fn test_complex_attribute_filtering() {
        let filter = AttributeFilter::from_params(Some("name.givenName"), None);
        let user = json!({
            "id": "123",
            "userName": "john.doe",
            "name": {
                "givenName": "John",
                "familyName": "Doe",
                "formatted": "John Doe"
            }
        });

        let result = filter.apply_to_resource(&user, ResourceType::User);

        // Should include only name.givenName, id (always), and the name object structure
        assert!(result.get("id").is_some());
        assert!(result.get("name").is_some());
        assert!(result.get("userName").is_none());

        let name_obj = result.get("name").unwrap();
        assert!(name_obj.get("givenName").is_some());
        assert!(name_obj.get("familyName").is_none());
        assert!(name_obj.get("formatted").is_none());
    }

    #[test]
    fn test_emails_value_filtering() {
        let filter = AttributeFilter::from_params(Some("emails.value"), None);
        let user = json!({
            "id": "123",
            "userName": "john.doe",
            "emails": [{
                "value": "john@example.com",
                "type": "work",
                "primary": true
            }],
            "phoneNumbers": [{
                "value": "555-1234",
                "type": "work"
            }]
        });

        let result = filter.apply_to_resource(&user, ResourceType::User);

        // Should include emails with only value sub-attribute and id (always returned)
        assert!(result.get("id").is_some());
        assert!(result.get("emails").is_some());
        assert!(result.get("userName").is_none());
        assert!(result.get("phoneNumbers").is_none());

        let emails = result.get("emails").unwrap();
        let emails_array = emails.as_array().unwrap();
        let first_email = emails_array[0].as_object().unwrap();

        // The email object should only have the 'value' field
        assert!(first_email.get("value").is_some());
        assert!(first_email.get("type").is_none());
        assert!(first_email.get("primary").is_none());
        assert_eq!(first_email.len(), 1); // Only 'value' should be present
    }
}
