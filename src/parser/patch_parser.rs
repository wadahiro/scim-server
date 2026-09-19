use crate::config::CompatibilityConfig;
use crate::error::{AppError, AppResult};
use crate::parser::filter_operator::FilterOperator;
use crate::parser::filter_parser::parse_filter;
use crate::parser::ResourceType;
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
    /// Parse a SCIM path according to RFC 7644 PATH ABNF, resolving
    /// attribute names against `resource_type`'s schema (see
    /// `resolve_case_and_validate`).
    pub fn parse(path: &str, resource_type: ResourceType) -> AppResult<Self> {
        let parsed = if path.contains('[') {
            // This is a valuePath with filter
            Self::parse_value_path(path)?
        } else {
            // This is a simple attrPath
            Self::parse_attr_path(path)?
        };
        parsed.resolve_case_and_validate(resource_type)
    }

    /// Resolve every attribute-name segment of this path to the schema's
    /// own casing, and reject a path that names no attribute this server
    /// can actually persist.
    ///
    /// RFC 7644 §3.5.2 incorporates the attribute-notation rules directly:
    /// "The attribute notation rules described in Section 3.10 apply for
    /// describing attribute paths." §3.10 in turn states "All operations
    /// share a common scheme for referencing simple and complex attributes"
    /// and "All facets (URN, attribute, and sub-attribute name) of the fully
    /// encoded attribute name are case insensitive." So resolving `path`
    /// segments case-insensitively is required, not an interpretation.
    ///
    /// Separately, RFC 7644 §3.12 defines `invalidPath` for "The 'path'
    /// attribute was invalid or malformed". This server's `User` model has
    /// an open `additional_fields` map (see `models::User`) that lets a
    /// PATCH create genuinely new, arbitrary top-level attributes -- a
    /// deliberate custom-attribute feature -- so an unrecognized *top-level*
    /// attribute name on a bare (non-schema-qualified) User path is left
    /// alone. Everywhere else -- a sub-attribute of a known complex
    /// attribute, any path on Group (whose model has no such catch-all), or
    /// an attribute inside a registered schema-extension container (e.g.
    /// the enterprise-user extension, whose Rust type likewise has no
    /// catch-all) -- an unresolved path has nowhere to land: it is silently
    /// dropped when the patched JSON round-trips through the typed model,
    /// which would report success (200) for an operation that had no
    /// effect. Those are rejected here instead.
    fn resolve_case_and_validate(self, resource_type: ResourceType) -> AppResult<Self> {
        match self {
            ScimPath::AttrPath(parts) => {
                let resolved = Self::resolve_attr_path(&parts, resource_type)?;
                Ok(ScimPath::AttrPath(resolved))
            }
            ScimPath::ValuePath {
                attr_path,
                filter,
                sub_attr,
            } => {
                let (attr_path, sub_attr) =
                    Self::resolve_value_path(&attr_path, sub_attr.as_deref(), resource_type);
                Ok(ScimPath::ValuePath {
                    attr_path,
                    filter,
                    sub_attr,
                })
            }
        }
    }

    /// Resolve (and validate) the segments of an `AttrPath`. See
    /// `resolve_case_and_validate` for the rules applied.
    fn resolve_attr_path(parts: &[String], resource_type: ResourceType) -> AppResult<Vec<String>> {
        if parts.is_empty() {
            return Ok(Vec::new());
        }

        let first = &parts[0];
        if first.starts_with("urn:ietf:params:scim:schemas:") {
            // The whole path is a bare extension schema URN (RFC 7644
            // §3.5.2, example 3) -- nothing further to resolve or validate.
            if parts.len() == 1 {
                return Ok(parts.to_vec());
            }

            // A schema-URN-qualified attribute. Only a *registered*
            // extension schema (currently just the enterprise-user
            // extension for User) has a known attribute list to resolve
            // and validate against; an unregistered/unknown schema URN is
            // stored as an opaque nested value with no per-attribute
            // validation, so it is left untouched.
            if let Some(schema) = crate::schema::SCHEMA_REGISTRY.get(first.as_str()) {
                let rest = parts[1..].join(".");
                let resolved_rest = crate::schema::resolve_attribute_path_case(schema, &rest);
                if crate::schema::find_attribute(schema, &resolved_rest).is_none() {
                    return Err(AppError::InvalidPath(format!(
                        "No such attribute '{}' in schema '{}'",
                        rest, first
                    )));
                }
                let mut resolved = vec![first.clone()];
                resolved.extend(resolved_rest.split('.').map(|s| s.to_string()));
                return Ok(resolved);
            }

            return Ok(parts.to_vec());
        }

        // A plain path against the resource's own core schema.
        let schema = match resource_type {
            ResourceType::User => &*crate::schema::USER_SCHEMA,
            ResourceType::Group => &*crate::schema::GROUP_SCHEMA,
        };
        let joined = parts.join(".");
        let resolved = crate::schema::resolve_attribute_path_case(schema, &joined);

        if crate::schema::find_attribute(schema, &resolved).is_none() {
            let is_supported_custom_top_level =
                parts.len() == 1 && matches!(resource_type, ResourceType::User);
            if !is_supported_custom_top_level {
                return Err(AppError::InvalidPath(format!(
                    "No such attribute '{}'",
                    joined
                )));
            }
            // Unknown top-level custom attribute on User: keep the
            // client's own casing -- it becomes the literal stored key.
            return Ok(parts.to_vec());
        }

        Ok(resolved.split('.').map(|s| s.to_string()).collect())
    }

    /// Resolve the segments of a `ValuePath`'s base attribute and optional
    /// trailing sub-attribute to the schema's own casing.
    ///
    /// An unresolved base attribute is *not* rejected here: unlike
    /// `AttrPath`, `apply_value_path_operation_with_compatibility` already
    /// requires the target key to be present in the resource and returns
    /// `noTarget`/`invalidValue` otherwise (RFC 7644 §3.5.2.3), so there is
    /// no silent-success case to guard against for the base attribute; an
    /// unresolved sub-attribute is likewise left as given, matching that
    /// same downstream behavior.
    fn resolve_value_path(
        attr_path: &[String],
        sub_attr: Option<&str>,
        resource_type: ResourceType,
    ) -> (Vec<String>, Option<String>) {
        if attr_path.is_empty() {
            return (attr_path.to_vec(), sub_attr.map(|s| s.to_string()));
        }

        let schema = match resource_type {
            ResourceType::User => &*crate::schema::USER_SCHEMA,
            ResourceType::Group => &*crate::schema::GROUP_SCHEMA,
        };

        let joined = attr_path.join(".");
        let resolved_attr = crate::schema::resolve_attribute_path_case(schema, &joined);
        let attr_def = crate::schema::find_attribute(schema, &resolved_attr);

        let resolved_attr_path: Vec<String> =
            resolved_attr.split('.').map(|s| s.to_string()).collect();

        let resolved_sub_attr = sub_attr.map(|s| {
            attr_def
                .and_then(|attr_def| {
                    attr_def
                        .sub_attributes
                        .iter()
                        .find(|a| a.name.eq_ignore_ascii_case(s))
                        .map(|a| a.name.to_string())
                })
                .unwrap_or_else(|| s.to_string())
        });

        (resolved_attr_path, resolved_sub_attr)
    }

    fn parse_attr_path(path: &str) -> AppResult<Self> {
        // Handle schema-qualified attributes like "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department"
        // or "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value",
        // as well as a bare extension schema URN used as the whole `path`
        // (RFC 7644 §3.5.2, example 3), e.g.
        // "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User".
        if path.starts_with("urn:ietf:params:scim:schemas:") {
            // Match against known schema URNs as a whole namespace first.
            // Splitting at the last colon (the previous approach) mis-parses
            // a bare extension URN -- which itself ends in ":User" -- into a
            // fake schema "...:2.0" plus attribute "User".
            for schema_urn in crate::schema::SCHEMA_REGISTRY.keys() {
                if path == *schema_urn {
                    // The whole extension object, e.g. used as
                    // `"path": "urn:...:enterprise:2.0:User"` with an object
                    // value that should be merged into that extension.
                    return Ok(ScimPath::AttrPath(vec![(*schema_urn).to_string()]));
                }

                if let Some(attr_path) = path
                    .strip_prefix(*schema_urn)
                    .and_then(|rest| rest.strip_prefix(':'))
                {
                    if attr_path.is_empty() {
                        continue;
                    }

                    // RFC 7643 §3 places core-schema attributes at the top
                    // level of the resource -- unlike extension attributes,
                    // they are never namespaced under a container keyed by
                    // the schema URN. So a core-schema-qualified path (e.g.
                    // "urn:ietf:params:scim:schemas:core:2.0:User:userName")
                    // must resolve to the plain attribute path ("userName"),
                    // not to a container entry that would create a bogus
                    // top-level "urn:...:core:2.0:User" key.
                    let mut parts = if is_core_schema_urn(schema_urn) {
                        Vec::new()
                    } else {
                        vec![(*schema_urn).to_string()]
                    };
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

            // Fall back to the previous heuristic for schema-like paths that
            // don't match a registered schema (e.g. an unknown extension).
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
    ///
    /// Every in-tree caller now goes through
    /// [`apply_operation_with_compatibility`](Self::apply_operation_with_compatibility)
    /// so tenant compatibility settings are honored consistently (the User
    /// and Group PATCH handlers both do). This compatibility-agnostic
    /// wrapper is kept as public API and is exercised directly by tests.
    #[allow(dead_code)]
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

        // When the path is schema-qualified (an extension attribute, or a
        // bare extension URN), `path[0]` is the schema URN (see
        // `parse_attr_path`) -- not necessarily the last segment, which is
        // the attribute name for a per-attribute path like
        // "urn:...:enterprise:2.0:User:department".
        let schema_urn = path[0]
            .starts_with("urn:ietf:params:scim:schemas:")
            .then(|| path[0].clone());

        self.navigate_and_apply_with_compatibility(user_json, path, op, value, compatibility)?;

        // RFC 7643 §3.1 / RFC 7644 §3.5.2: introducing extension data must be
        // reflected in the resource's `schemas` list.
        if let Some(schema_urn) = schema_urn {
            if op != "remove" {
                self.update_schemas_attribute(user_json, &schema_urn)?;
            }
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
                                // RFC 7643 §2.4 / RFC 7644 §3.5.2: this
                                // operation's own value must not itself
                                // contradict "at most one primary" -- that
                                // case is unspecified by either RFC, and
                                // rejecting it is a deliberate choice (see
                                // `reject_conflicting_primaries_in_operation_value`).
                                crate::schema::reject_conflicting_primaries_in_operation_value(
                                    final_key,
                                    &new_elements,
                                )?;

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
                                crate::schema::reject_conflicting_primaries_in_operation_value(
                                    final_key, arr,
                                )?;
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
                                crate::schema::reject_conflicting_primaries_in_operation_value(
                                    final_key, arr_mut,
                                )?;
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
                        // RFC 7644 §3.5.2.3: "replace" has nothing to
                        // replace when the target attribute itself is
                        // absent, which is a "noTarget" condition.
                        if op == "replace" {
                            AppError::NoTarget(format!("Attribute '{}' not found", segment))
                        } else {
                            AppError::BadRequest(format!("Attribute '{}' not found", segment))
                        }
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

        // RFC 7643 §2.4 / RFC 7644 §3.5.2: a single "replace" operation
        // whose value-path filter matches more than one element, and which
        // sets `primary: true` on every match, is the value-path spelling
        // of the same "operation's own value contradicts itself" case as
        // an attrPath operation whose `value` array holds two elements
        // with `primary: true`. Reject it for the same reason (see
        // `reject_conflicting_primaries_in_operation_value`): RFC 7644
        // §3.5.2 only says a later "primary: true" clears earlier ones, it
        // never says a *single* operation may set more than one, and RFC
        // 7643 §2.4 forbids more than one `primary: true` outright.
        if op == "replace" && matching_indices.len() > 1 {
            let attr_name = attr_path.last().map(String::as_str).unwrap_or_default();
            if crate::schema::attribute_has_primary_subattribute(attr_name) {
                let sets_primary_true = match sub_attr {
                    Some("primary") => matches!(value, Value::Bool(true)),
                    None => {
                        matches!(value, Value::Object(obj) if obj.get("primary") == Some(&Value::Bool(true)))
                    }
                    _ => false,
                };
                if sets_primary_true {
                    return Err(AppError::BadRequest(format!(
                        "PATCH operation's value for '{}' would set primary=true on {} elements; \
                         a single operation may set at most one (RFC 7643 §2.4)",
                        attr_name,
                        matching_indices.len()
                    )));
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
                    // RFC 7644 §3.5.2.3: a "replace" whose value-path filter
                    // matches no element is a "noTarget" condition, not an
                    // "invalidValue" one.
                    let (attr, _, val) = filter.get_condition();
                    return Err(AppError::NoTarget(format!(
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

    fn update_schemas_attribute(&self, user_json: &mut Value, schema_urn: &str) -> AppResult<()> {
        // Add the schema URN to the resource's `schemas` list if not already
        // present (RFC 7643 §3.1: a resource's `schemas` attribute must list
        // every schema, including extensions, that describes its content).
        if let Value::Object(user_obj) = user_json {
            let schemas = user_obj
                .entry("schemas".to_string())
                .or_insert(Value::Array(vec![]));
            if let Value::Array(schemas_array) = schemas {
                let schema_value = Value::String(schema_urn.to_string());
                if !schemas_array.contains(&schema_value) {
                    schemas_array.push(schema_value);
                }
            }
        }

        Ok(())
    }
}

/// Check whether a schema URN identifies a core resource schema (RFC 7643
/// §3), whose attributes live at the top level of the resource, as opposed
/// to an extension schema, whose attributes are namespaced under a
/// container keyed by the schema URN.
fn is_core_schema_urn(schema_urn: &str) -> bool {
    schema_urn == crate::schema::SCIM_SCHEMA_CORE_USER
        || schema_urn == crate::schema::SCIM_SCHEMA_CORE_GROUP
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
        let path = ScimPath::parse("name.givenName", ResourceType::User).unwrap();
        match path {
            ScimPath::AttrPath(parts) => {
                assert_eq!(parts, vec!["name", "givenName"]);
            }
            _ => panic!("Expected AttrPath"),
        }
    }

    #[test]
    fn test_parse_value_path_with_filter() {
        let path = ScimPath::parse("addresses[type eq \"work\"]", ResourceType::User).unwrap();
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
        let path =
            ScimPath::parse("addresses[type eq \"work\"].street", ResourceType::User).unwrap();
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
