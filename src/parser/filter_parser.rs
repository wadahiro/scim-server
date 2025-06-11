use serde_json::Value;

use crate::error::{AppError, AppResult};
pub use crate::parser::filter_operator::FilterOperator;

/// Custom SCIM filter parser that handles quoted strings and complex expressions
pub fn parse_filter(filter_str: &str) -> AppResult<FilterOperator> {
    let trimmed = filter_str.trim();
    // eprintln!("DEBUG parser: input filter_str='{}'", filter_str);
    
    // Handle parentheses first - only remove if they are truly outer parentheses
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        // Check if the opening and closing parentheses actually match
        // by ensuring the opening parenthesis at position 0 matches the closing at the end
        let mut depth = 0;
        let mut in_quotes = false;
        let mut escape_next = false;
        let chars: Vec<char> = trimmed.chars().collect();
        
        let mut first_paren_closes_at_end = true;
        
        for (i, ch) in chars.iter().enumerate() {
            if escape_next {
                escape_next = false;
                continue;
            }
            
            if *ch == '\\' {
                escape_next = true;
                continue;
            }
            
            if *ch == '"' && !escape_next {
                in_quotes = !in_quotes;
                continue;
            }
            
            if !in_quotes {
                if *ch == '(' {
                    depth += 1;
                } else if *ch == ')' {
                    depth -= 1;
                    // If we reach depth 0 before the end, the outer parentheses don't match
                    if depth == 0 && i < chars.len() - 1 {
                        first_paren_closes_at_end = false;
                        break;
                    }
                }
            }
        }
        
        // Only remove outer parentheses if the first '(' matches the last ')'
        // (i.e., we never hit depth 0 until the very end)
        if depth == 0 && first_paren_closes_at_end {
            let inner = &trimmed[1..trimmed.len()-1];
            // eprintln!("DEBUG: Removing outer parentheses, inner='{}'", inner);
            return parse_filter(inner);
        }
    }
    
    // Check for NOT operator first (highest precedence for unary operators)
    if trimmed.to_lowercase().starts_with("not ") {
        let inner_expr = &trimmed[4..].trim(); // Skip "not " and trim
        let inner_filter = parse_filter(inner_expr)?;
        return Ok(FilterOperator::Not(Box::new(inner_filter)));
    }
    
    // Then check for logical operators (AND/OR) at the top level
    if let Some(logical_op) = find_logical_operator(trimmed)? {
        return Ok(logical_op);
    }
    
    // Handle complex filter expressions like emails[value eq "alice@example.com"]
    if let Some(bracket_pos) = trimmed.find('[') {
        if let Some(bracket_end) = trimmed.rfind(']') {
            let attr = &trimmed[..bracket_pos];
            let filter_expr = &trimmed[bracket_pos + 1..bracket_end];
            eprintln!("DEBUG parser: complex filter - attr='{}', filter_expr='{}'", attr, filter_expr);
            
            // Parse the inner filter expression
            let inner_filter = parse_simple_filter(filter_expr)?;
            
            // Return as Complex variant to match kanidm structure
            return Ok(FilterOperator::Complex(attr.to_string(), Box::new(inner_filter)));
        }
    }
    
    // Handle simple filter expressions
    parse_simple_filter(trimmed)
}

/// Parse simple SCIM filter expressions (attr op value)
fn parse_simple_filter(filter_str: &str) -> AppResult<FilterOperator> {
    let trimmed = filter_str.trim();
    
    // Handle "pr" (present) operator
    if trimmed.ends_with(" pr") {
        let attr = trimmed[..trimmed.len() - 3].trim();
        return Ok(FilterOperator::Present(attr.to_string()));
    }
    
    // Split by operators, checking longer operators first
    let operators = [
        (">=", "GreaterThanOrEqual"),
        ("<=", "LessThanOrEqual"),
        ("!=", "NotEqual"),
        ("eq", "Equal"),
        ("ne", "NotEqual"),
        ("co", "Contains"),
        ("sw", "StartsWith"),
        ("ew", "EndsWith"),
        ("gt", "GreaterThan"),
        ("ge", "GreaterThanOrEqual"),
        ("lt", "LessThan"),
        ("le", "LessThanOrEqual"),
        ("=", "Equal"),
        (">", "GreaterThan"),
        ("<", "LessThan"),
    ];
    
    for (op_str, op_type) in &operators {
        if let Some(op_pos) = find_operator_position(trimmed, op_str) {
            let attr = trimmed[..op_pos].trim();
            let value_str = trimmed[op_pos + op_str.len()..].trim();
            
            if attr.is_empty() || value_str.is_empty() {
                continue;
            }
            
            let value = parse_filter_value(value_str)?;
            
            return match *op_type {
                "Equal" => Ok(FilterOperator::Equal(attr.to_string(), value)),
                "NotEqual" => Ok(FilterOperator::NotEqual(attr.to_string(), value)),
                "Contains" => Ok(FilterOperator::Contains(attr.to_string(), value)),
                "StartsWith" => Ok(FilterOperator::StartsWith(attr.to_string(), value)),
                "EndsWith" => Ok(FilterOperator::EndsWith(attr.to_string(), value)),
                "GreaterThan" => Ok(FilterOperator::GreaterThan(attr.to_string(), value)),
                "GreaterThanOrEqual" => Ok(FilterOperator::GreaterThanOrEqual(attr.to_string(), value)),
                "LessThan" => Ok(FilterOperator::LessThan(attr.to_string(), value)),
                "LessThanOrEqual" => Ok(FilterOperator::LessThanOrEqual(attr.to_string(), value)),
                _ => Err(AppError::FilterParse(format!("Unknown operator: {}", op_type))),
            };
        }
    }
    
    Err(AppError::FilterParse(format!("Could not parse filter: {}", filter_str)))
}

/// Find the position of an operator, making sure it's not inside quotes
fn find_operator_position(text: &str, operator: &str) -> Option<usize> {
    let mut in_quotes = false;
    let mut escape_next = false;
    let text_bytes = text.as_bytes();
    let op_bytes = operator.as_bytes();
    
    for i in 0..text.len() {
        if escape_next {
            escape_next = false;
            continue;
        }
        
        match text_bytes[i] {
            b'\\' => escape_next = true,
            b'"' => in_quotes = !in_quotes,
            _ => {
                if !in_quotes && i + operator.len() <= text.len() {
                    // Check if we have the operator at this position
                    if &text_bytes[i..i + operator.len()] == op_bytes {
                        // For word operators like "eq", "co", make sure they're word-bounded
                        if operator.chars().all(|c| c.is_alphabetic()) {
                            let before_ok = i == 0 || !text_bytes[i - 1].is_ascii_alphabetic();
                            let after_ok = i + operator.len() >= text.len() || !text_bytes[i + operator.len()].is_ascii_alphabetic();
                            if before_ok && after_ok {
                                return Some(i);
                            }
                        } else {
                            return Some(i);
                        }
                    }
                }
            }
        }
    }
    
    None
}

/// Parse a filter value, handling quoted strings, numbers, and booleans
fn parse_filter_value(value_str: &str) -> AppResult<Value> {
    let trimmed = value_str.trim();
    
    // Handle quoted strings
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        let unquoted = &trimmed[1..trimmed.len() - 1];
        // Unescape any escaped quotes
        let unescaped = unquoted.replace("\\\"", "\"");
        return Ok(Value::String(unescaped));
    }
    
    // Handle boolean values
    if trimmed == "true" {
        return Ok(Value::Bool(true));
    }
    if trimmed == "false" {
        return Ok(Value::Bool(false));
    }
    
    // Handle null
    if trimmed == "null" {
        return Ok(Value::Null);
    }
    
    // Try to parse as number
    if let Ok(num) = trimmed.parse::<i64>() {
        return Ok(Value::Number(serde_json::Number::from(num)));
    }
    
    if let Ok(num) = trimmed.parse::<f64>() {
        if let Some(json_num) = serde_json::Number::from_f64(num) {
            return Ok(Value::Number(json_num));
        }
    }
    
    // If it's not quoted and not a special value, treat it as a string anyway
    // This helps with compatibility for simple filters without quotes
    Ok(Value::String(trimmed.to_string()))
}

/// Find and parse logical operators (AND/OR) at the top level of the expression
/// Returns None if no logical operators are found at the top level
fn find_logical_operator(filter_str: &str) -> AppResult<Option<FilterOperator>> {
    // Look for " and " and " or " operators, but not inside quotes or parentheses
    let mut depth = 0;
    let mut in_quotes = false;
    let mut escape_next = false;
    let chars: Vec<char> = filter_str.chars().collect();
    
    // First pass: find OR operators (lower precedence)
    for i in 0..chars.len() {
        let ch = chars[i];
        
        if escape_next {
            escape_next = false;
            continue;
        }
        
        if ch == '\\' {
            escape_next = true;
            continue;
        }
        
        if ch == '"' && !escape_next {
            in_quotes = !in_quotes;
            continue;
        }
        
        if !in_quotes {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
            }
            
            // Only look for operators at the top level (depth 0)
            if depth == 0 && i + 4 < chars.len() {
                // Check for " or " (with spaces)
                if chars[i] == ' ' && chars[i+1] == 'o' && chars[i+2] == 'r' && chars[i+3] == ' ' {
                    let left_expr = filter_str[..i].trim();
                    let right_expr = filter_str[i+4..].trim();
                    
                    let left = parse_filter(left_expr)?;
                    let right = parse_filter(right_expr)?;
                    
                    return Ok(Some(FilterOperator::Or(Box::new(left), Box::new(right))));
                }
            }
        }
    }
    
    // Second pass: find AND operators (higher precedence)
    depth = 0;
    in_quotes = false;
    escape_next = false;
    
    for i in 0..chars.len() {
        let ch = chars[i];
        
        if escape_next {
            escape_next = false;
            continue;
        }
        
        if ch == '\\' {
            escape_next = true;
            continue;
        }
        
        if ch == '"' && !escape_next {
            in_quotes = !in_quotes;
            continue;
        }
        
        if !in_quotes {
            if ch == '(' {
                depth += 1;
            } else if ch == ')' {
                depth -= 1;
            }
            
            // Only look for operators at the top level (depth 0)
            if depth == 0 && i + 5 < chars.len() {
                // Check for " and " (with spaces)
                if chars[i] == ' ' && chars[i+1] == 'a' && chars[i+2] == 'n' && chars[i+3] == 'd' && chars[i+4] == ' ' {
                    let left_expr = filter_str[..i].trim();
                    let right_expr = filter_str[i+5..].trim();
                    
                    let left = parse_filter(left_expr)?;
                    let right = parse_filter(right_expr)?;
                    
                    return Ok(Some(FilterOperator::And(Box::new(left), Box::new(right))));
                }
            }
        }
    }
    
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_simple_equal_filter() {
        let result = parse_filter("userName eq \"john.doe\"").unwrap();
        assert_eq!(result, FilterOperator::Equal("userName".to_string(), json!("john.doe")));
    }

    #[test]
    fn test_equal_with_spaces() {
        let result = parse_filter("title eq \"Product Manager\"").unwrap();
        assert_eq!(result, FilterOperator::Equal("title".to_string(), json!("Product Manager")));
    }

    #[test]
    fn test_complex_filter_with_brackets() {
        let result = parse_filter("emails[value eq \"alice@example.com\"]").unwrap();
        assert_eq!(result, FilterOperator::Complex("emails".to_string(), Box::new(FilterOperator::Equal("value".to_string(), json!("alice@example.com")))));
    }

    #[test]
    fn test_present_operator() {
        let result = parse_filter("emails pr").unwrap();
        assert_eq!(result, FilterOperator::Present("emails".to_string()));
    }

    #[test]
    fn test_contains_operator() {
        let result = parse_filter("displayName co \"John\"").unwrap();
        assert_eq!(result, FilterOperator::Contains("displayName".to_string(), json!("John")));
    }

    #[test]
    fn test_numeric_filter() {
        let result = parse_filter("age gt 30").unwrap();
        assert_eq!(result, FilterOperator::GreaterThan("age".to_string(), json!(30)));
    }

    #[test]
    fn test_dot_notation() {
        let result = parse_filter("name.givenName eq \"John\"").unwrap();
        assert_eq!(result, FilterOperator::Equal("name.givenName".to_string(), json!("John")));
    }

    #[test]
    fn test_and_operator() {
        let result = parse_filter("userName eq \"john\" and active eq true").unwrap();
        match result {
            FilterOperator::And(left, right) => {
                assert_eq!(*left, FilterOperator::Equal("userName".to_string(), json!("john")));
                assert_eq!(*right, FilterOperator::Equal("active".to_string(), json!(true)));
            }
            _ => panic!("Expected And operator"),
        }
    }

    #[test]
    fn test_or_operator() {
        let result = parse_filter("userName eq \"john\" or userName eq \"jane\"").unwrap();
        match result {
            FilterOperator::Or(left, right) => {
                assert_eq!(*left, FilterOperator::Equal("userName".to_string(), json!("john")));
                assert_eq!(*right, FilterOperator::Equal("userName".to_string(), json!("jane")));
            }
            _ => panic!("Expected Or operator"),
        }
    }

    #[test]
    fn test_operator_precedence() {
        // AND has higher precedence than OR
        let result = parse_filter("a eq \"1\" or b eq \"2\" and c eq \"3\"").unwrap();
        match result {
            FilterOperator::Or(left, right) => {
                assert_eq!(*left, FilterOperator::Equal("a".to_string(), json!("1")));
                match *right {
                    FilterOperator::And(and_left, and_right) => {
                        assert_eq!(*and_left, FilterOperator::Equal("b".to_string(), json!("2")));
                        assert_eq!(*and_right, FilterOperator::Equal("c".to_string(), json!("3")));
                    }
                    _ => panic!("Expected And operator on right side"),
                }
            }
            _ => panic!("Expected Or operator at top level"),
        }
    }

    #[test]
    fn test_simple_parentheses() {
        let result = parse_filter("(userName eq \"john\")").unwrap();
        assert_eq!(result, FilterOperator::Equal("userName".to_string(), json!("john")));
    }

    #[test]
    fn test_parentheses_with_logical_operators() {
        // Test: (userName eq "john" and active eq true)
        let result = parse_filter("(userName eq \"john\" and active eq true)").unwrap();
        match result {
            FilterOperator::And(left, right) => {
                assert_eq!(*left, FilterOperator::Equal("userName".to_string(), json!("john")));
                assert_eq!(*right, FilterOperator::Equal("active".to_string(), json!(true)));
            }
            _ => panic!("Expected And operator"),
        }
    }

    #[test]
    fn test_complex_parentheses_precedence() {
        // Test: (userName eq "admin" or userName eq "manager") and active eq true
        let result = parse_filter("(userName eq \"admin\" or userName eq \"manager\") and active eq true").unwrap();
        match result {
            FilterOperator::And(left, right) => {
                match *left {
                    FilterOperator::Or(or_left, or_right) => {
                        assert_eq!(*or_left, FilterOperator::Equal("userName".to_string(), json!("admin")));
                        assert_eq!(*or_right, FilterOperator::Equal("userName".to_string(), json!("manager")));
                    }
                    _ => panic!("Expected Or operator on left side"),
                }
                assert_eq!(*right, FilterOperator::Equal("active".to_string(), json!(true)));
            }
            _ => panic!("Expected And operator at top level"),
        }
    }

    #[test]
    fn test_nested_parentheses() {
        // Test: ((userName eq "admin" or userName eq "manager") and (role eq "admin")) or active eq false
        let result = parse_filter("((userName eq \"admin\" or userName eq \"manager\") and (role eq \"admin\")) or active eq false").unwrap();
        match result {
            FilterOperator::Or(left, right) => {
                // Left side should be: (userName eq "admin" or userName eq "manager") and (role eq "admin")
                match *left {
                    FilterOperator::And(and_left, and_right) => {
                        // and_left should be: userName eq "admin" or userName eq "manager"
                        match *and_left {
                            FilterOperator::Or(or_left, or_right) => {
                                assert_eq!(*or_left, FilterOperator::Equal("userName".to_string(), json!("admin")));
                                assert_eq!(*or_right, FilterOperator::Equal("userName".to_string(), json!("manager")));
                            }
                            _ => panic!("Expected Or operator in and_left"),
                        }
                        // and_right should be: role eq "admin"
                        assert_eq!(*and_right, FilterOperator::Equal("role".to_string(), json!("admin")));
                    }
                    _ => panic!("Expected And operator on left side"),
                }
                // Right side should be: active eq false
                assert_eq!(*right, FilterOperator::Equal("active".to_string(), json!(false)));
            }
            _ => panic!("Expected Or operator at top level"),
        }
    }

    #[test]
    fn test_complex_filter_with_type() {
        let result = parse_filter("emails[type eq \"work\"]").unwrap();
        assert_eq!(result, FilterOperator::Complex("emails".to_string(), Box::new(FilterOperator::Equal("type".to_string(), json!("work")))));
    }

    #[test]
    fn test_complex_filter_with_contains() {
        let result = parse_filter("phoneNumbers[value co \"555\"]").unwrap();
        assert_eq!(result, FilterOperator::Complex("phoneNumbers".to_string(), Box::new(FilterOperator::Contains("value".to_string(), json!("555")))));
    }

    #[test]
    fn test_complex_filter_with_present() {
        let result = parse_filter("addresses[type pr]").unwrap();
        assert_eq!(result, FilterOperator::Complex("addresses".to_string(), Box::new(FilterOperator::Present("type".to_string()))));
    }

    #[test]
    fn test_not_operator_simple() {
        let result = parse_filter("not active eq true").unwrap();
        assert_eq!(result, FilterOperator::Not(Box::new(FilterOperator::Equal("active".to_string(), json!(true)))));
    }

    #[test]
    fn test_not_operator_with_parentheses() {
        let result = parse_filter("not (userName eq \"john\" and active eq true)").unwrap();
        match result {
            FilterOperator::Not(inner) => {
                match *inner {
                    FilterOperator::And(left, right) => {
                        assert_eq!(*left, FilterOperator::Equal("userName".to_string(), json!("john")));
                        assert_eq!(*right, FilterOperator::Equal("active".to_string(), json!(true)));
                    }
                    _ => panic!("Expected And operator inside Not"),
                }
            }
            _ => panic!("Expected Not operator"),
        }
    }

    #[test]
    fn test_not_operator_case_insensitive() {
        let result = parse_filter("NOT active eq false").unwrap();
        assert_eq!(result, FilterOperator::Not(Box::new(FilterOperator::Equal("active".to_string(), json!(false)))));
    }

    #[test]
    fn test_not_with_complex_filter() {
        let result = parse_filter("not emails[type eq \"work\"]").unwrap();
        assert_eq!(result, FilterOperator::Not(Box::new(FilterOperator::Complex("emails".to_string(), Box::new(FilterOperator::Equal("type".to_string(), json!("work")))))));
    }
}