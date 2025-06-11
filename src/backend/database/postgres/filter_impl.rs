use super::super::filter::FilterConverter;
use crate::error::AppResult;
use crate::parser::filter_operator::FilterOperator;
use crate::parser::ResourceType;
use crate::schema::is_case_insensitive_attribute;
use serde_json::Value;

/// PostgreSQL-specific filter converter for SCIM filters
///
/// This handles conversion of SCIM filter expressions to PostgreSQL
/// JSONB queries with proper parameter binding and SQL injection prevention.
pub struct PostgresFilterConverter;

impl PostgresFilterConverter {
    pub fn new() -> Self {
        Self
    }
}

impl FilterConverter for PostgresFilterConverter {
    fn to_where_clause(
        &self,
        filter: &FilterOperator,
        resource_type: ResourceType,
    ) -> AppResult<(String, Vec<String>)> {
        let mut params = Vec::new();
        let condition = self.convert_filter_to_sql(filter, resource_type, &mut params)?;
        Ok((condition, params))
    }

    fn get_param_placeholder(&self, index: usize) -> String {
        format!("${}", index)
    }

    fn is_case_insensitive_attribute(&self, attr: &str, resource_type: ResourceType) -> bool {
        is_case_insensitive_attribute(attr, resource_type)
    }

    fn get_json_path(&self, attr: &str, resource_type: ResourceType) -> String {
        // PostgreSQL uses -> and ->> operators for JSON access
        match resource_type {
            ResourceType::User => match attr {
                "userName" => "username".to_string(),
                "externalId" => "external_id".to_string(),
                "id" => "id".to_string(),
                _ if attr.starts_with("meta.") => {
                    let sub_attr = &attr[5..];
                    format!("data_norm->'meta'->>'{}')", sub_attr)
                }
                _ => format!("data_norm->>'{}'", attr),
            },
            ResourceType::Group => match attr {
                "displayName" => "display_name".to_string(),
                "externalId" => "external_id".to_string(),
                "id" => "id".to_string(),
                _ if attr.starts_with("meta.") => {
                    let sub_attr = &attr[5..];
                    format!("data_norm->'meta'->>'{}')", sub_attr)
                }
                _ => format!("data_norm->>'{}'", attr),
            },
        }
    }
}

impl PostgresFilterConverter {
    /// Convert a filter operator to SQL condition
    fn convert_filter_to_sql(
        &self,
        filter: &FilterOperator,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        match filter {
            FilterOperator::Equal(attr, value) => {
                self.handle_equality(attr, value, resource_type, params)
            }
            FilterOperator::NotEqual(attr, value) => {
                self.handle_not_equality(attr, value, resource_type, params)
            }
            FilterOperator::Contains(attr, value) => {
                self.handle_contains(attr, value, resource_type, params)
            }
            FilterOperator::StartsWith(attr, value) => {
                self.handle_starts_with(attr, value, resource_type, params)
            }
            FilterOperator::EndsWith(attr, value) => {
                self.handle_ends_with(attr, value, resource_type, params)
            }
            FilterOperator::Present(attr) => self.handle_present(attr, resource_type),
            FilterOperator::GreaterThan(attr, value) => {
                self.handle_greater_than(attr, value, resource_type, params)
            }
            FilterOperator::GreaterThanOrEqual(attr, value) => {
                self.handle_greater_equal(attr, value, resource_type, params)
            }
            FilterOperator::LessThan(attr, value) => {
                self.handle_less_than(attr, value, resource_type, params)
            }
            FilterOperator::LessThanOrEqual(attr, value) => {
                self.handle_less_equal(attr, value, resource_type, params)
            }
            FilterOperator::And(left, right) => {
                let left_sql = self.convert_filter_to_sql(left, resource_type, params)?;
                let right_sql = self.convert_filter_to_sql(right, resource_type, params)?;
                Ok(format!("({} AND {})", left_sql, right_sql))
            }
            FilterOperator::Or(left, right) => {
                let left_sql = self.convert_filter_to_sql(left, resource_type, params)?;
                let right_sql = self.convert_filter_to_sql(right, resource_type, params)?;
                Ok(format!("({} OR {})", left_sql, right_sql))
            }
            FilterOperator::Not(inner) => {
                let inner_sql = self.convert_filter_to_sql(inner, resource_type, params)?;
                Ok(format!("NOT ({})", inner_sql))
            }
            FilterOperator::Complex(attr, inner) => {
                // For complex filters like emails[value eq "work"], we need to handle
                // multi-valued attributes by checking if any element matches
                self.handle_complex_filter(attr, inner, resource_type, params)
            }
        }
    }

    /// Handle equality comparison
    fn handle_equality(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // Check if this is a multi-valued attribute query like "emails.value"
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                return self.handle_multi_value_equality(parts[0], parts[1], value, params);
            }
        }

        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;

        // Handle Boolean values specially
        if let Value::Bool(bool_val) = value {
            // For Boolean values, we compare with the JSON boolean representation
            return Ok(format!(
                "data_norm #> '{{{}}}' = '{}'",
                json_path,
                if *bool_val { "true" } else { "false" }
            ));
        }

        // Check if this is a case-exact field
        let is_case_exact = self.is_case_exact_field(attr, resource_type);
        let data_column = if is_case_exact {
            "data_orig"
        } else {
            "data_norm"
        };

        let value_str = self.value_to_string(value);
        // For data_norm column, normalize values; for data_orig, preserve case
        let comparison_value = if is_case_exact || !value.is_string() {
            value_str
        } else {
            value_str.to_lowercase()
        };
        params.push(comparison_value);

        Ok(format!(
            "{} #>> '{{{}}}' = ${}",
            data_column, json_path, param_index
        ))
    }

    /// Handle not equality comparison
    fn handle_not_equality(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // Check if this is a multi-valued attribute query like "emails.value"
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                return self.handle_multi_value_not_equality(parts[0], parts[1], value, params);
            }
        }

        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;

        // Handle Boolean values specially
        if let Value::Bool(bool_val) = value {
            // For Boolean values, we compare with the JSON boolean representation
            return Ok(format!(
                "data_norm #> '{{{}}}' != '{}'",
                json_path,
                if *bool_val { "true" } else { "false" }
            ));
        }

        // Check if this is a case-exact field
        let is_case_exact = self.is_case_exact_field(attr, resource_type);
        let data_column = if is_case_exact {
            "data_orig"
        } else {
            "data_norm"
        };

        let value_str = self.value_to_string(value);
        // For data_norm column, normalize values; for data_orig, preserve case
        let comparison_value = if is_case_exact || !value.is_string() {
            value_str
        } else {
            value_str.to_lowercase()
        };
        params.push(comparison_value);

        Ok(format!(
            "{} #>> '{{{}}}' != ${}",
            data_column, json_path, param_index
        ))
    }

    /// Handle contains comparison
    fn handle_contains(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // Check if this is a multi-valued attribute query like \"emails.value\"
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                return self.handle_multi_value_contains(parts[0], parts[1], value, params);
            }
        }

        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("%{}%", value_str));

        Ok(format!(
            "LOWER(data_norm #>> '{{{}}}') LIKE LOWER(${})",
            json_path, param_index
        ))
    }

    /// Handle starts with comparison
    fn handle_starts_with(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // Check if this is a multi-valued attribute query like \"emails.value\"
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                return self.handle_multi_value_starts_with(parts[0], parts[1], value, params);
            }
        }

        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("{}%", value_str));

        Ok(format!(
            "LOWER(data_norm #>> '{{{}}}') LIKE LOWER(${})",
            json_path, param_index
        ))
    }

    /// Handle ends with comparison
    fn handle_ends_with(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // Check if this is a multi-valued attribute query like \"emails.value\"
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                return self.handle_multi_value_ends_with(parts[0], parts[1], value, params);
            }
        }

        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("%{}", value_str));

        Ok(format!(
            "LOWER(data_norm #>> '{{{}}}') LIKE LOWER(${})",
            json_path, param_index
        ))
    }

    /// Handle present comparison
    fn handle_present(&self, attr: &str, resource_type: ResourceType) -> AppResult<String> {
        let json_path = self.scim_path_to_json_path(attr, resource_type);
        Ok(format!(
            "data_norm #>> '{{{}}}' IS NOT NULL AND data_norm #>> '{{{}}}' != ''",
            json_path, json_path
        ))
    }

    /// Handle greater than comparison
    fn handle_greater_than(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        // For data_norm column, we need to compare with normalized values (lowercase for strings)
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        Ok(format!(
            "(data_norm #>> '{{{}}}')::numeric > ${}::numeric",
            json_path, param_index
        ))
    }

    /// Handle greater than or equal comparison
    fn handle_greater_equal(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        // For data_norm column, we need to compare with normalized values (lowercase for strings)
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        Ok(format!(
            "(data_norm #>> '{{{}}}')::numeric >= ${}::numeric",
            json_path, param_index
        ))
    }

    /// Handle less than comparison
    fn handle_less_than(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        // For data_norm column, we need to compare with normalized values (lowercase for strings)
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        Ok(format!(
            "(data_norm #>> '{{{}}}')::numeric < ${}::numeric",
            json_path, param_index
        ))
    }

    /// Handle less than or equal comparison
    fn handle_less_equal(
        &self,
        attr: &str,
        value: &Value,
        resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let json_path = self.scim_path_to_json_path(attr, resource_type);
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        // For data_norm column, we need to compare with normalized values (lowercase for strings)
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        Ok(format!(
            "(data_norm #>> '{{{}}}')::numeric <= ${}::numeric",
            json_path, param_index
        ))
    }

    /// Convert JSON Value to string for SQL parameters
    fn value_to_string(&self, value: &Value) -> String {
        match value {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Null => "null".to_string(),
            _ => value.to_string(),
        }
    }

    /// Convert SCIM attribute path to PostgreSQL JSON path
    fn scim_path_to_json_path(&self, attr: &str, resource_type: ResourceType) -> String {
        // Handle special case for userName (case-insensitive)
        if attr.eq_ignore_ascii_case("userName") {
            return "username".to_string();
        }

        // Handle special case for displayName (case-insensitive)
        if attr.eq_ignore_ascii_case("displayName") {
            return "displayname".to_string();
        }

        // Handle special case for externalId (case-exact)
        if attr.eq_ignore_ascii_case("externalId") {
            return "externalId".to_string(); // Preserve original case for case-exact field
        }

        // Handle nested attributes like name.givenName and multi-value attributes like emails.value
        if attr.contains('.') {
            let parts: Vec<&str> = attr.split('.').collect();

            // Check if this is a multi-valued attribute with sub-property
            if parts.len() == 2 && crate::schema::is_multi_valued_attribute(parts[0], resource_type)
            {
                // This is something like "emails.value" - return as is for array processing
                return format!("{},{}", parts[0].to_lowercase(), parts[1].to_lowercase());
            }

            let mut path_parts = Vec::new();

            for part in parts {
                // Convert to lowercase for data_norm column consistency
                // But preserve case for case-exact fields
                let current_path = if path_parts.is_empty() {
                    part.to_string()
                } else {
                    format!("{}.{}", path_parts.join(","), part)
                };
                if self.is_case_exact_field(&current_path, resource_type) {
                    path_parts.push(part.to_string());
                } else {
                    path_parts.push(part.to_lowercase());
                }
            }

            return path_parts.join(",");
        }

        // Handle multi-valued attributes (emails, phoneNumbers, etc.)
        if crate::schema::is_multi_valued_attribute(attr, resource_type) {
            return format!("{},0,value", attr.to_lowercase());
        }

        // For case-exact fields, preserve case; for others use lowercase
        if self.is_case_exact_field(attr, resource_type) {
            attr.to_string()
        } else {
            // Use lowercase for both standard SCIM attributes and custom attributes
            // since they are stored in lowercase in data_norm column
            attr.to_lowercase()
        }
    }

    /// Check if an attribute is case-exact (case-sensitive)
    fn is_case_exact_field(&self, attr: &str, resource_type: ResourceType) -> bool {
        crate::schema::normalization::is_case_exact_field_for_resource(attr, resource_type)
    }

    /// Handle complex filter expressions like emails[value eq "work"]
    fn handle_complex_filter(
        &self,
        attr: &str,
        inner: &FilterOperator,
        _resource_type: ResourceType,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        // For complex filters, we need to check if any element in the array matches
        // the inner condition. This is similar to multi-valued attribute handling
        // but with recursive filter processing.

        match inner {
            FilterOperator::Equal(sub_attr, value) => {
                self.handle_multi_value_equality(attr, sub_attr, value, params)
            }
            FilterOperator::NotEqual(sub_attr, value) => {
                self.handle_multi_value_not_equality(attr, sub_attr, value, params)
            }
            FilterOperator::Contains(sub_attr, value) => {
                self.handle_multi_value_contains(attr, sub_attr, value, params)
            }
            FilterOperator::StartsWith(sub_attr, value) => {
                self.handle_multi_value_starts_with(attr, sub_attr, value, params)
            }
            FilterOperator::EndsWith(sub_attr, value) => {
                self.handle_multi_value_ends_with(attr, sub_attr, value, params)
            }
            FilterOperator::Present(sub_attr) => {
                // For present check in arrays, check if any element has the sub-attribute
                Ok(format!(
                    "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE elem ? '{}')",
                    attr.to_lowercase(),
                    sub_attr.to_lowercase()
                ))
            }
            // For other operators like logical operators within complex filters,
            // we would need more sophisticated handling
            _ => Err(crate::error::AppError::FilterParse(format!(
                "Unsupported complex filter operation for {}",
                attr
            ))),
        }
    }

    /// Handle multi-valued attribute equality (e.g., emails.value)
    fn handle_multi_value_equality(
        &self,
        attr_name: &str,
        sub_attr: &str,
        value: &Value,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        // Use PostgreSQL JSONB functions to search in array
        // This creates a query like: EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{emails}') elem WHERE elem ->> 'value' = $1)
        Ok(format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE elem ->> '{}' = ${})",
            attr_name.to_lowercase(),
            sub_attr.to_lowercase(),
            param_index
        ))
    }

    /// Handle multi-valued attribute not equality (e.g., emails.value ne)
    fn handle_multi_value_not_equality(
        &self,
        attr_name: &str,
        sub_attr: &str,
        value: &Value,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        let normalized_value = if value.is_string() {
            value_str.to_lowercase()
        } else {
            value_str
        };
        params.push(normalized_value);

        // Use NOT EXISTS for not equality
        Ok(format!(
            "NOT EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE elem ->> '{}' = ${})",
            attr_name.to_lowercase(),
            sub_attr.to_lowercase(),
            param_index
        ))
    }

    /// Handle multi-valued attribute contains (e.g., emails.value co)
    fn handle_multi_value_contains(
        &self,
        attr_name: &str,
        sub_attr: &str,
        value: &Value,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("%{}%", value_str));

        // Use PostgreSQL JSONB functions to search in array with LIKE
        Ok(format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE LOWER(elem ->> '{}') LIKE LOWER(${}))",
            attr_name.to_lowercase(),
            sub_attr.to_lowercase(),
            param_index
        ))
    }

    /// Handle multi-valued attribute starts with (e.g., emails.value sw)
    fn handle_multi_value_starts_with(
        &self,
        attr_name: &str,
        sub_attr: &str,
        value: &Value,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("{}%", value_str));

        // Use PostgreSQL JSONB functions to search in array with LIKE
        Ok(format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE LOWER(elem ->> '{}') LIKE LOWER(${}))",
            attr_name.to_lowercase(),
            sub_attr.to_lowercase(),
            param_index
        ))
    }

    /// Handle multi-valued attribute ends with (e.g., emails.value ew)
    fn handle_multi_value_ends_with(
        &self,
        attr_name: &str,
        sub_attr: &str,
        value: &Value,
        params: &mut Vec<String>,
    ) -> AppResult<String> {
        let param_index = params.len() + 1;
        let value_str = self.value_to_string(value);
        params.push(format!("%{}", value_str));

        // Use PostgreSQL JSONB functions to search in array with LIKE
        Ok(format!(
            "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{{{}}}') elem WHERE LOWER(elem ->> '{}') LIKE LOWER(${}))",
            attr_name.to_lowercase(),
            sub_attr.to_lowercase(),
            param_index
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scim_path_conversion() {
        let converter = PostgresFilterConverter::new();

        // Standard attributes should be lowercase
        assert_eq!(
            converter.scim_path_to_json_path("userName", ResourceType::User),
            "username"
        );

        // Nested attributes
        assert_eq!(
            converter.scim_path_to_json_path("name.givenName", ResourceType::User),
            "name,givenname"
        );

        // Multi-valued attributes
        assert_eq!(
            converter.scim_path_to_json_path("emails", ResourceType::User),
            "emails,0,value"
        );

        // Custom attributes use lowercase (stored in data_norm column)
        assert_eq!(
            converter.scim_path_to_json_path("customAttribute", ResourceType::User),
            "customattribute"
        );
    }

    #[test]
    fn test_filter_conversion() {
        let converter = PostgresFilterConverter::new();
        let filter = FilterOperator::Equal(
            "userName".to_string(),
            serde_json::Value::String("john.doe".to_string()),
        );

        let (condition, params) = converter
            .to_where_clause(&filter, ResourceType::User)
            .unwrap();

        assert_eq!(condition, "data_norm #>> '{username}' = $1");
        assert_eq!(params, vec!["john.doe"]);
    }

    #[test]
    fn test_not_filter_conversion() {
        let converter = PostgresFilterConverter::new();
        let inner_filter =
            FilterOperator::Equal("active".to_string(), serde_json::Value::Bool(true));
        let not_filter = FilterOperator::Not(Box::new(inner_filter));

        let (condition, params) = converter
            .to_where_clause(&not_filter, ResourceType::User)
            .unwrap();

        // Boolean values use direct comparison without parameter binding
        assert_eq!(condition, "NOT (data_norm #> '{active}' = 'true')");
        assert_eq!(params, Vec::<String>::new());
    }

    #[test]
    fn test_complex_filter_conversion() {
        let converter = PostgresFilterConverter::new();
        let inner_filter = FilterOperator::Equal(
            "type".to_string(),
            serde_json::Value::String("work".to_string()),
        );
        let complex_filter = FilterOperator::Complex("emails".to_string(), Box::new(inner_filter));

        let (condition, params) = converter
            .to_where_clause(&complex_filter, ResourceType::User)
            .unwrap();

        assert_eq!(condition, "EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{emails}') elem WHERE elem ->> 'type' = $1)");
        assert_eq!(params, vec!["work"]);
    }

    #[test]
    fn test_not_with_complex_filter_conversion() {
        let converter = PostgresFilterConverter::new();
        let inner_filter = FilterOperator::Equal(
            "value".to_string(),
            serde_json::Value::String("alice@example.com".to_string()),
        );
        let complex_filter = FilterOperator::Complex("emails".to_string(), Box::new(inner_filter));
        let not_filter = FilterOperator::Not(Box::new(complex_filter));

        let (condition, params) = converter
            .to_where_clause(&not_filter, ResourceType::User)
            .unwrap();

        assert_eq!(condition, "NOT (EXISTS (SELECT 1 FROM jsonb_array_elements(data_norm #> '{emails}') elem WHERE elem ->> 'value' = $1))");
        assert_eq!(params, vec!["alice@example.com"]);
    }
}
