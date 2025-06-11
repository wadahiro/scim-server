use serde_json::Value;

/// Common filter operator definitions used by both filter and patch parsers
#[derive(Debug, Clone, PartialEq)]
pub enum FilterOperator {
    // Comparison operators
    Equal(String, Value),
    NotEqual(String, Value),
    Contains(String, Value),
    StartsWith(String, Value),
    EndsWith(String, Value),
    GreaterThan(String, Value),
    GreaterThanOrEqual(String, Value),
    LessThan(String, Value),
    LessThanOrEqual(String, Value),
    Present(String),

    // Logical operators
    And(Box<FilterOperator>, Box<FilterOperator>),
    Or(Box<FilterOperator>, Box<FilterOperator>),
    Not(Box<FilterOperator>),

    // Complex filter (for attribute[filter] syntax)
    Complex(String, Box<FilterOperator>),
}
