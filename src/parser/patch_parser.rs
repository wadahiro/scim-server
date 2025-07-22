use crate::config::CompatibilityConfig;
use crate::error::{AppError, AppResult};
use crate::parser::filter_operator::FilterOperator;
use crate::parser::filter_parser::parse_filter;
use serde_json::Value;

/// SCIM PATH parser and processor according to RFC 7644
/// Supports both attrPath and valuePath with filter expressions

#[derive(Debug, Clone)]
pub enum ScimPath {
    /// Simple attribute path: "name.givenName"
    AttrPath(Vec<String>),
    /// Value path with filter: "addresses[type eq \"work\"]"
    ValuePath {
        attr_path: Vec<String>,
        filter: ScimFilter,
        sub_attr: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct ScimFilter {
    filter_op: FilterOperator,
}

impl ScimPath {
    /// Parse a SCIM path according to RFC 7644 PATH ABNF
    pub fn parse(path: &str) -> AppResult<Self> {
        if path.contains('[') {
            // This is a valuePath with filter
            Self::parse_value_path(path)
        } else {
            // This is a simple attrPath
            Self::parse_attr_path(path)
        }
    }

    fn parse_attr_path(path: &str) -> AppResult<Self> {
        // Handle schema-qualified attributes like "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
        // or "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value"
        if path.starts_with("urn:ietf:params:scim:schemas:") {
            // Find the last colon to separate schema URN from attribute name
            if let Some(last_colon) = path.rfind(':') {
                let schema_urn = &path[..last_colon];
                let attr_path = &path[last_colon + 1..];

                if schema_urn.is_empty() || attr_path.is_empty() {
                    return Err(AppError::BadRequest(format!(
                        "Invalid schema-qualified attribute: {}",
                        path
                    )));
                }

                // Handle nested attributes after the schema URN (e.g., "manager.value")
                let mut parts = vec![schema_urn.to_string()];
                parts.extend(attr_path.split('.').map(|s| s.to_string()));

                if parts.iter().any(|p| p.is_empty()) {
                    return Err(AppError::BadRequest(format!(
                        "Invalid schema-qualified attribute path: {}",
                        path
                    )));
                }

                return Ok(ScimPath::AttrPath(parts));
            }
        }

        // Handle regular dot-separated paths like "name.givenName"
        let parts: Vec<String> = path.split('.').map(|s| s.to_string()).collect();
        if parts.is_empty() || parts.iter().any(|p| p.is_empty()) {
            return Err(AppError::BadRequest(format!(
                "Invalid attribute path: {}",
                path
            )));
        }
        Ok(ScimPath::AttrPath(parts))
    }

    fn parse_value_path(path: &str) -> AppResult<Self> {
        // Parse: "addresses[type eq \"work\"].street"
        // or: "members[value eq \"2819c223-7f76-453a-919d-413861904646\"]"

        let bracket_start = path.find('[').ok_or_else(|| {
            AppError::BadRequest(format!("Invalid value path: missing '[' in {}", path))
        })?;

        let bracket_end = path.find(']').ok_or_else(|| {
            AppError::BadRequest(format!("Invalid value path: missing ']' in {}", path))
        })?;

        if bracket_start >= bracket_end {
            return Err(AppError::BadRequest(format!(
                "Invalid value path: malformed brackets in {}",
                path
            )));
        }

        // Extract the attribute path before the filter
        let attr_part = &path[..bracket_start];
        let attr_path: Vec<String> = if attr_part.is_empty() {
            vec![]
        } else {
            attr_part.split('.').map(|s| s.to_string()).collect()
        };

        // Extract the filter expression
        let filter_expr = &path[bracket_start + 1..bracket_end];
        let filter = ScimFilter::new(parse_filter(filter_expr)?);

        // Extract sub-attribute if present
        let sub_attr = if bracket_end + 1 < path.len() {
            let remaining = &path[bracket_end + 1..];
            if let Some(stripped) = remaining.strip_prefix('.') {
                Some(stripped.to_string())
            } else {
                return Err(AppError::BadRequest(format!(
                    "Invalid value path: malformed sub-attribute in {}",
                    path
                )));
            }
        } else {
            None
        };

        Ok(ScimPath::ValuePath {
            attr_path,
            filter,
            sub_attr,
        })
    }

    /// Apply SCIM PATCH operation to JSON object
    pub fn apply_operation(&self, user_json: &mut Value, op: &str, value: &Value) -> AppResult<()> {
        // Use default compatibility config for backward compatibility
        let default_config = CompatibilityConfig::default();
        self.apply_operation_with_compatibility(user_json, op, value, &default_config)
    }

    /// Apply SCIM PATCH operation to JSON object with compatibility settings
    pub fn apply_operation_with_compatibility(
        &self,
        user_json: &mut Value,
        op: &str,
        value: &Value,
        compatibility: &CompatibilityConfig,
    ) -> AppResult<()> {
        match self {
            ScimPath::AttrPath(path) => self.apply_attr_path_operation_with_compatibility(
                user_json,
                path,
                op,
                value,
                compatibility,
            ),
            ScimPath::ValuePath {
                attr_path,
                filter,
                sub_attr,
            } => self.apply_value_path_operation_with_compatibility(
                user_json,
                attr_path,
                filter,
                sub_attr.as_deref(),
                op,
                value,
                compatibility,
            ),
        }
    }

    fn apply_attr_path_operation(
        &self,
        user_json: &mut Value,
        path: &[String],
        op: &str,
        value: &Value,
    ) -> AppResult<()> {
        // Use default compatibility config for backward compatibility
        let default_config = CompatibilityConfig::default();
        self.apply_attr_path_operation_with_compatibility(
            user_json,
            path,
            op,
            value,
            &default_config,
        )
    }

    fn apply_attr_path_operation_with_compatibility(
        &self,
        user_json: &mut Value,
        path: &[String],
        op: &str,
        value: &Value,
        compatibility: &CompatibilityConfig,
    ) -> AppResult<()> {
        if path.is_empty() {
            return Err(AppError::BadRequest("Empty attribute path".to_string()));
        }

        // Check for schema updates first
        let final_key = &path[path.len() - 1];
        let needs_schema_update = final_key.starts_with("urn:ietf:params:scim:schemas:");

        // Navigate to the parent and apply operation
        let final_key_name = final_key.clone();
        self.navigate_and_apply_with_compatibility(user_json, path, op, value, compatibility)?;

        // Handle schema updates for fully qualified names after modifying the tree
        if needs_schema_update && op != "remove" {
            self.update_schemas_attribute(user_json, &final_key_name)?;
        }

        Ok(())
    }

    fn navigate_and_apply(
        &self,
        user_json: &mut Value,
        path: &[String],
        op: &str,
        value: &Value,
    ) -> AppResult<()> {
        // Use default compatibility config for backward compatibility
        let default_config = CompatibilityConfig::default();
        self.navigate_and_apply_with_compatibility(user_json, path, op, value, &default_config)
    }

    fn navigate_and_apply_with_compatibility(
        &self,
        user_json: &mut Value,
        path: &[String],
        op: &str,
        value: &Value,
        compatibility: &CompatibilityConfig,
    ) -> AppResult<()> {
        // Navigate to the target location
        let mut current = user_json;

        // Navigate to parent
        for segment in &path[..path.len() - 1] {
            match current {
                Value::Object(obj) => {
                    current = obj
                        .entry(segment.clone())
                        .or_insert(Value::Object(serde_json::Map::new()));
                }
                _ => {
                    return Err(AppError::BadRequest(format!(
                        "Cannot navigate path: expected object at '{}'",
                        segment
                    )));
                }
            }
        }

        // Apply operation to final attribute
        let final_key = &path[path.len() - 1];
        match op {
            "add" => {
                if let Value::Object(obj) = current {
                    // For add operation, check if target is array and append to it
                    if let Some(existing) = obj.get_mut(final_key) {
                        if let (Value::Array(existing_arr), Value::Array(new_arr)) =
                            (existing, value)
                        {
                            // Clone new array elements
                            let mut new_elements = new_arr.clone();

                            // Validate and enforce primary constraints for multi-valued attributes
                            if is_multi_valued_attribute(final_key) {
                                // Enforce single primary in the new elements first
                                crate::schema::enforce_single_primary(&mut new_elements)?;

                                // Check if new elements have a primary
                                let new_has_primary = new_elements.iter().any(|item| {
                                    if let Value::Object(obj) = item {
                                        obj.get("primary") == Some(&serde_json::Value::Bool(true))
                                    } else {
                                        false
                                    }
                                });

                                // If new elements have primary, remove primary from existing elements
                                if new_has_primary {
                                    for existing_item in existing_arr.iter_mut() {
                                        if let Value::Object(obj) = existing_item {
                                            obj.remove("primary");
                                        }
                                    }
                                }
                            }

                            // Append new array elements to existing array
                            existing_arr.extend(new_elements);
                        } else {
                            // Replace non-array values
                            obj.insert(final_key.clone(), value.clone());
                        }
                    } else {
                        // Key doesn't exist, insert new value
                        let mut new_value = value.clone();

                        // Validate primary constraints for new multi-valued attributes
                        if is_multi_valued_attribute(final_key) {
                            if let Value::Array(arr) = &mut new_value {
                                crate::schema::enforce_single_primary(arr)?;
                            }
                        }

                        obj.insert(final_key.clone(), new_value);
                    }
                } else {
                    return Err(AppError::BadRequest(
                        "Cannot set value: parent is not an object".to_string(),
                    ));
                }
            }
            "replace" => {
                if let Value::Object(obj) = current {
                    let mut new_value = value.clone();

                    // Handle multi-valued attributes clearing and validation
                    if is_multi_valued_attribute(final_key) {
                        if let Value::Array(arr) = &new_value {
                            // Handle empty array clearing - remove attribute entirely
                            if arr.is_empty() {
                                obj.remove(final_key);
                                return Ok(());
                            }

                            // Handle special empty value pattern [{"value":""}] - remove attribute entirely
                            if arr.len() == 1 {
                                if let Value::Object(ref item) = arr[0] {
                                    if item.len() == 1
                                        && item.get("value") == Some(&Value::String("".to_string()))
                                    {
                                        if compatibility.support_patch_replace_empty_value {
                                            // Remove the attribute entirely for this special pattern
                                            obj.remove(final_key);
                                            return Ok(());
                                        }
                                        // If not supported, continue with normal processing (will store the empty value)
                                    }
                                }
                            }

                            // Validate primary constraints for normal arrays
                            if let Value::Array(ref mut arr_mut) = new_value {
                                crate::schema::enforce_single_primary(arr_mut)?;
                            }
                        }
                    }

                    obj.insert(final_key.clone(), new_value);
                } else {
                    return Err(AppError::BadRequest(
                        "Cannot set value: parent is not an object".to_string(),
                    ));
                }
            }
            "remove" => {
                if let Value::Object(obj) = current {
                    // Special handling for multi-value attributes with value array
                    // This handles cases like: path="emails", value=[{items to remove}]
                    if !value.is_null() && value.is_array() {
                        #[allow(clippy::collapsible_match)]
                        if let Some(current_array) = obj.get_mut(final_key) {
                            if let Value::Array(attribute_array) = current_array {
                                if let Value::Array(to_remove) = value {
                                    // Apply selective removal based on the items in the value array
                                    Self::remove_items_from_array(attribute_array, to_remove);
                                }
                            }
                        }
                    } else {
                        // Standard remove operation - remove the entire attribute
                        obj.remove(final_key);
                    }
                }
                // Remove operation is idempotent - no error if key doesn't exist
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported operation: {}",
                    op
                )));
            }
        }

        Ok(())
    }

    /// Removes items from a multi-value array based on matching criteria
    /// This method supports different matching strategies for different SCIM attributes
    fn remove_items_from_array(attribute_array: &mut Vec<Value>, to_remove: &[Value]) {
        for remove_item in to_remove {
            // Try multiple matching strategies to handle different attribute types
            attribute_array.retain(|existing_item| !Self::items_match(existing_item, remove_item));
        }
    }

    /// Determines if two items match for removal purposes
    /// Supports various matching criteria for different SCIM attribute types
    fn items_match(existing_item: &Value, remove_item: &Value) -> bool {
        // Strategy 1: Match by "value" field (emails, phoneNumbers, etc.)
        if let (Some(existing_value), Some(remove_value)) = (
            existing_item.get("value").and_then(|v| v.as_str()),
            remove_item.get("value").and_then(|v| v.as_str()),
        ) {
            return existing_value == remove_value;
        }

        // Strategy 2: Match by "type" field (addresses, emails with type, etc.)
        if let (Some(existing_type), Some(remove_type)) = (
            existing_item.get("type").and_then(|v| v.as_str()),
            remove_item.get("type").and_then(|v| v.as_str()),
        ) {
            // For type-based matching, also ensure it's the primary match criterion
            if existing_type == remove_type {
                // If remove_item only specifies type, match by type
                if remove_item.as_object().is_some_and(|obj| obj.len() == 1) {
                    return true;
                }
                // If more fields are specified, require exact match on all fields
                return Self::objects_match_partially(existing_item, remove_item);
            }
        }

        // Strategy 3: Match by multiple fields (complex objects)
        if existing_item.is_object() && remove_item.is_object() {
            return Self::objects_match_partially(existing_item, remove_item);
        }

        // Strategy 4: Exact value match (fallback)
        existing_item == remove_item
    }

    /// Checks if an object matches based on all fields specified in the match criteria
    fn objects_match_partially(existing_item: &Value, remove_item: &Value) -> bool {
        if let (Some(existing_obj), Some(remove_obj)) =
            (existing_item.as_object(), remove_item.as_object())
        {
            // All fields in remove_item must match the corresponding fields in existing_item
            for (key, remove_value) in remove_obj {
                if let Some(existing_value) = existing_obj.get(key) {
                    if existing_value != remove_value {
                        return false;
                    }
                } else {
                    // Remove item specifies a field that doesn't exist in existing item
                    return false;
                }
            }
            return true;
        }
        false
    }

    fn apply_value_path_operation(
        &self,
        user_json: &mut Value,
        attr_path: &[String],
        filter: &ScimFilter,
        sub_attr: Option<&str>,
        op: &str,
        value: &Value,
    ) -> AppResult<()> {
        // Use default compatibility config for backward compatibility
        let default_config = CompatibilityConfig::default();
        self.apply_value_path_operation_with_compatibility(
            user_json,
            attr_path,
            filter,
            sub_attr,
            op,
            value,
            &default_config,
        )
    }

    fn apply_value_path_operation_with_compatibility(
        &self,
        user_json: &mut Value,
        attr_path: &[String],
        filter: &ScimFilter,
        sub_attr: Option<&str>,
        op: &str,
        value: &Value,
        _compatibility: &CompatibilityConfig,
    ) -> AppResult<()> {
        // Navigate to the multi-valued attribute
        let mut current = user_json;
        for segment in attr_path {
            match current {
                Value::Object(obj) => {
                    current = obj.get_mut(segment).ok_or_else(|| {
                        AppError::BadRequest(format!("Attribute '{}' not found", segment))
                    })?;
                }
                _ => {
                    return Err(AppError::BadRequest(format!(
                        "Cannot navigate path: expected object at '{}'",
                        segment
                    )));
                }
            }
        }

        // Ensure we have an array for multi-valued attributes
        let array = match current {
            Value::Array(arr) => arr,
            _ => {
                return Err(AppError::BadRequest(
                    "Value path requires multi-valued attribute (array)".to_string(),
                ));
            }
        };

        // Find matching elements based on filter
        let mut matching_indices = Vec::new();
        for (index, item) in array.iter().enumerate() {
            if let Value::Object(item_obj) = item {
                if filter.matches(item_obj) {
                    matching_indices.push(index);
                }
            }
        }

        // Apply operation based on type and matches
        match op {
            "add" => {
                // For add with valuePath, add new element to array
                if let Value::Object(new_item) = value {
                    let mut item = new_item.clone();
                    // Set the filter attribute to match the filter value
                    let (attr, _, val) = filter.get_condition();
                    item.insert(attr.to_string(), Value::String(val.to_string()));
                    array.push(Value::Object(item));
                } else {
                    return Err(AppError::BadRequest(
                        "Add operation with valuePath requires object value".to_string(),
                    ));
                }
            }
            "replace" => {
                // Replace all matching elements
                for &index in &matching_indices {
                    if let Some(sub_attr) = sub_attr {
                        // Replace sub-attribute of matching element
                        if let Value::Object(item_obj) = &mut array[index] {
                            item_obj.insert(sub_attr.to_string(), value.clone());
                        }
                    } else {
                        // Replace entire matching element
                        if let Value::Object(new_item) = value {
                            let mut item = new_item.clone();
                            // Preserve the filter attribute
                            let (attr, _, val) = filter.get_condition();
                            item.insert(attr.to_string(), Value::String(val.to_string()));
                            array[index] = Value::Object(item);
                        }
                    }
                }

                if matching_indices.is_empty() {
                    let (attr, _, val) = filter.get_condition();
                    return Err(AppError::BadRequest(format!(
                        "No matching elements found for filter: {} eq {}",
                        attr, val
                    )));
                }
            }
            "remove" => {
                // Remove matching elements (in reverse order to maintain indices)
                for &index in matching_indices.iter().rev() {
                    if let Some(sub_attr) = sub_attr {
                        // Remove sub-attribute of matching element
                        if let Value::Object(item_obj) = &mut array[index] {
                            item_obj.remove(sub_attr);
                        }
                    } else {
                        // Remove entire matching element
                        array.remove(index);
                    }
                }
            }
            _ => {
                return Err(AppError::BadRequest(format!(
                    "Unsupported operation: {}",
                    op
                )));
            }
        }

        // Handle primary attribute logic for multi-valued attributes
        if let Some(sub_attr) = sub_attr {
            if sub_attr == "primary" && op != "remove" {
                if let Value::Bool(true) = value {
                    // Remove primary from all other elements
                    for (index, item) in array.iter_mut().enumerate() {
                        if !matching_indices.contains(&index) {
                            if let Value::Object(item_obj) = item {
                                item_obj.remove("primary");
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn update_schemas_attribute(
        &self,
        user_json: &mut Value,
        fully_qualified_attr: &str,
    ) -> AppResult<()> {
        // Extract schema URN from fully qualified attribute name
        // Example: "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber"
        // -> "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

        let parts: Vec<&str> = fully_qualified_attr.split(':').collect();
        if parts.len() >= 7
            && parts[0] == "urn"
            && parts[1] == "ietf"
            && parts[2] == "params"
            && parts[3] == "scim"
            && parts[4] == "schemas"
        {
            // Reconstruct schema URN (everything except the last part which is the attribute name)
            let schema_urn = parts[..parts.len() - 1].join(":");

            // Add to schemas array if not already present
            if let Value::Object(user_obj) = user_json {
                let schemas = user_obj
                    .entry("schemas".to_string())
                    .or_insert(Value::Array(vec![]));
                if let Value::Array(schemas_array) = schemas {
                    let schema_value = Value::String(schema_urn);
                    if !schemas_array.contains(&schema_value) {
                        schemas_array.push(schema_value);
                    }
                }
            }
        }

        Ok(())
    }
}

/// Check if an attribute is a multi-valued attribute that supports primary
fn is_multi_valued_attribute(attr_name: &str) -> bool {
    matches!(
        attr_name,
        "emails"
            | "phoneNumbers"
            | "addresses"
            | "photos"
            | "ims"
            | "entitlements"
            | "roles"
            | "x509Certificates"
    )
}

impl ScimFilter {
    pub fn new(filter_op: FilterOperator) -> Self {
        Self { filter_op }
    }

    /// Get the condition components (attribute, operator, value) from any filter type
    pub fn get_condition(&self) -> (&str, &str, &str) {
        self.extract_first_condition(&self.filter_op)
    }

    #[allow(clippy::only_used_in_recursion)]
    fn extract_first_condition<'a>(
        &self,
        filter_op: &'a FilterOperator,
    ) -> (&'a str, &'a str, &'a str) {
        match filter_op {
            FilterOperator::Equal(attr, val) => (attr, "eq", val.as_str().unwrap_or("")),
            FilterOperator::NotEqual(attr, val) => (attr, "ne", val.as_str().unwrap_or("")),
            FilterOperator::Contains(attr, val) => (attr, "co", val.as_str().unwrap_or("")),
            FilterOperator::StartsWith(attr, val) => (attr, "sw", val.as_str().unwrap_or("")),
            FilterOperator::EndsWith(attr, val) => (attr, "ew", val.as_str().unwrap_or("")),
            FilterOperator::GreaterThan(attr, val) => (attr, "gt", val.as_str().unwrap_or("")),
            FilterOperator::GreaterThanOrEqual(attr, val) => {
                (attr, "ge", val.as_str().unwrap_or(""))
            }
            FilterOperator::LessThan(attr, val) => (attr, "lt", val.as_str().unwrap_or("")),
            FilterOperator::LessThanOrEqual(attr, val) => (attr, "le", val.as_str().unwrap_or("")),
            FilterOperator::Present(attr) => (attr, "pr", ""),
            FilterOperator::And(left, _) | FilterOperator::Or(left, _) => {
                self.extract_first_condition(left)
            }
            FilterOperator::Not(inner) => self.extract_first_condition(inner),
            FilterOperator::Complex(_, inner) => self.extract_first_condition(inner),
        }
    }

    /// Check if a JSON object matches this filter
    pub fn matches(&self, item_obj: &serde_json::Map<String, Value>) -> bool {
        self.evaluate_filter(item_obj, &self.filter_op)
    }

    fn evaluate_filter(
        &self,
        item_obj: &serde_json::Map<String, Value>,
        filter_op: &FilterOperator,
    ) -> bool {
        match filter_op {
            FilterOperator::Equal(attr, val) => self.simple_match(item_obj, attr, "eq", val),
            FilterOperator::NotEqual(attr, val) => self.simple_match(item_obj, attr, "ne", val),
            FilterOperator::Contains(attr, val) => self.simple_match(item_obj, attr, "co", val),
            FilterOperator::StartsWith(attr, val) => self.simple_match(item_obj, attr, "sw", val),
            FilterOperator::EndsWith(attr, val) => self.simple_match(item_obj, attr, "ew", val),
            FilterOperator::GreaterThan(attr, val) => self.simple_match(item_obj, attr, "gt", val),
            FilterOperator::GreaterThanOrEqual(attr, val) => {
                self.simple_match(item_obj, attr, "ge", val)
            }
            FilterOperator::LessThan(attr, val) => self.simple_match(item_obj, attr, "lt", val),
            FilterOperator::LessThanOrEqual(attr, val) => {
                self.simple_match(item_obj, attr, "le", val)
            }
            FilterOperator::Present(attr) => item_obj.contains_key(attr),
            FilterOperator::And(left, right) => {
                self.evaluate_filter(item_obj, left) && self.evaluate_filter(item_obj, right)
            }
            FilterOperator::Or(left, right) => {
                self.evaluate_filter(item_obj, left) || self.evaluate_filter(item_obj, right)
            }
            FilterOperator::Not(inner) => !self.evaluate_filter(item_obj, inner),
            FilterOperator::Complex(_, inner) => self.evaluate_filter(item_obj, inner),
        }
    }

    fn simple_match(
        &self,
        item_obj: &serde_json::Map<String, Value>,
        attribute: &str,
        operator: &str,
        expected_value: &Value,
    ) -> bool {
        // Get the actual value from the object
        let actual_value = match item_obj.get(attribute) {
            Some(val) => val,
            None => return false, // Missing attribute doesn't match
        };

        // Compare values based on operator
        match operator {
            "eq" => actual_value == expected_value,
            "ne" => actual_value != expected_value,
            "co" => {
                if let (Value::String(actual), Value::String(expected)) =
                    (actual_value, expected_value)
                {
                    actual.contains(expected)
                } else {
                    false
                }
            }
            "sw" => {
                if let (Value::String(actual), Value::String(expected)) =
                    (actual_value, expected_value)
                {
                    actual.starts_with(expected)
                } else {
                    false
                }
            }
            "ew" => {
                if let (Value::String(actual), Value::String(expected)) =
                    (actual_value, expected_value)
                {
                    actual.ends_with(expected)
                } else {
                    false
                }
            }
            "gt" => {
                self.compare_values(actual_value, expected_value) == std::cmp::Ordering::Greater
            }
            "ge" => matches!(
                self.compare_values(actual_value, expected_value),
                std::cmp::Ordering::Greater | std::cmp::Ordering::Equal
            ),
            "lt" => self.compare_values(actual_value, expected_value) == std::cmp::Ordering::Less,
            "le" => matches!(
                self.compare_values(actual_value, expected_value),
                std::cmp::Ordering::Less | std::cmp::Ordering::Equal
            ),
            _ => false,
        }
    }

    fn compare_values(&self, actual: &Value, expected: &Value) -> std::cmp::Ordering {
        use std::cmp::Ordering;

        match (actual, expected) {
            (Value::String(a), Value::String(e)) => a.cmp(e),
            (Value::Number(a), Value::Number(e)) => {
                if let (Some(a_f), Some(e_f)) = (a.as_f64(), e.as_f64()) {
                    a_f.partial_cmp(&e_f).unwrap_or(Ordering::Equal)
                } else {
                    Ordering::Equal
                }
            }
            (Value::Bool(a), Value::Bool(e)) => a.cmp(e),
            _ => Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_attr_path() {
        let path = ScimPath::parse("name.givenName").unwrap();
        match path {
            ScimPath::AttrPath(parts) => {
                assert_eq!(parts, vec!["name", "givenName"]);
            }
            _ => panic!("Expected AttrPath"),
        }
    }

    #[test]
    fn test_parse_value_path_with_filter() {
        let path = ScimPath::parse("addresses[type eq \"work\"]").unwrap();
        match path {
            ScimPath::ValuePath {
                attr_path,
                filter,
                sub_attr,
            } => {
                assert_eq!(attr_path, vec!["addresses"]);
                let (attr, op, val) = filter.get_condition();
                assert_eq!(attr, "type");
                assert_eq!(op, "eq");
                assert_eq!(val, "work");
                assert_eq!(sub_attr, None);
            }
            _ => panic!("Expected ValuePath"),
        }
    }

    #[test]
    fn test_parse_value_path_with_sub_attr() {
        let path = ScimPath::parse("addresses[type eq \"work\"].street").unwrap();
        match path {
            ScimPath::ValuePath {
                attr_path,
                filter,
                sub_attr,
            } => {
                assert_eq!(attr_path, vec!["addresses"]);
                let (attr, _, val) = filter.get_condition();
                assert_eq!(attr, "type");
                assert_eq!(val, "work");
                assert_eq!(sub_attr, Some("street".to_string()));
            }
            _ => panic!("Expected ValuePath"),
        }
    }
}
