use crate::error::AppResult;
use crate::parser::filter_operator::FilterOperator;
use crate::parser::ResourceType;
use async_trait::async_trait;

/// Trait for converting SCIM filters to database-specific queries
///
/// This abstraction allows different database backends to implement
/// their own filter conversion logic while maintaining a common interface.
#[async_trait]
pub trait FilterConverter: Send + Sync {
    /// Convert a SCIM filter to a database-specific WHERE clause
    ///
    /// Returns a tuple of (where_clause, parameters) where:
    /// - where_clause: The SQL WHERE condition with parameter placeholders
    /// - parameters: The values to bind to the placeholders
    fn to_where_clause(
        &self,
        filter: &FilterOperator,
        resource_type: ResourceType,
    ) -> AppResult<(String, Vec<String>)>;

    /// Get the parameter placeholder for the given index
    ///
    /// For example:
    /// - PostgreSQL: $1, $2, $3...
    /// - SQLite: ?1, ?2, ?3... or just ?
    #[allow(dead_code)]
    fn get_param_placeholder(&self, index: usize) -> String;

    /// Check if a given attribute requires case-insensitive comparison
    #[allow(dead_code)]
    fn is_case_insensitive_attribute(&self, attr: &str, resource_type: ResourceType) -> bool;

    /// Get the JSON path expression for an attribute
    ///
    /// This handles differences in JSON syntax between databases
    #[allow(dead_code)]
    fn get_json_path(&self, attr: &str, resource_type: ResourceType) -> String;

    /// Get the LOWER function syntax for case-insensitive comparisons
    ///
    /// Most databases use LOWER(), but this allows for customization
    #[allow(dead_code)]
    fn get_lower_function(&self, expression: &str) -> String {
        format!("LOWER({})", expression)
    }
}
