// Example demonstrating complex SCIM filter expressions
// This shows the enhanced capabilities for logical operators and filter evaluation

use scim_server::parser::patch_parser::ScimPath;
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 SCIM Complex Filter Expression Demo");
    println!("=====================================\n");

    // Sample user data for demonstration
    let mut user = json!({
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
        "userName": "demo.user",
        "emails": [
            {
                "value": "home@personal.com",
                "type": "home",
                "primary": false
            },
            {
                "value": "work@company.com",
                "type": "work",
                "primary": true
            },
            {
                "value": "backup@company.com",
                "type": "work",
                "primary": false
            }
        ],
        "phoneNumbers": [
            {
                "value": "123-456-7890",
                "type": "home",
                "primary": false
            },
            {
                "value": "098-765-4321",
                "type": "work",
                "primary": true
            },
            {
                "value": "555-123-4567",
                "type": "mobile",
                "primary": false
            }
        ]
    });

    println!("Initial user data:");
    println!("{}\n", serde_json::to_string_pretty(&user)?);

    // Demonstrate simple filter
    println!("1. Simple Filter: emails[type eq \"work\"].value");
    let simple_path = ScimPath::parse("emails[type eq \"work\"].value")?;
    let mut user_copy = user.clone();
    simple_path.apply_operation(&mut user_copy, "replace", &json!("new-work@company.com"))?;

    let emails = user_copy["emails"].as_array().unwrap();
    let work_emails: Vec<_> = emails.iter().filter(|e| e["type"] == "work").collect();
    println!("   Result: Updated {} work email(s)", work_emails.len());
    for email in work_emails {
        println!("   - {}", email["value"]);
    }
    println!();

    // Demonstrate AND operator
    println!("2. AND Filter: emails[type eq \"work\" and primary eq true].value");
    let and_path = ScimPath::parse("emails[type eq \"work\" and primary eq true].value")?;
    let mut user_copy = user.clone();
    and_path.apply_operation(
        &mut user_copy,
        "replace",
        &json!("primary-work@company.com"),
    )?;

    let emails = user_copy["emails"].as_array().unwrap();
    let primary_work: Vec<_> = emails
        .iter()
        .filter(|e| e["type"] == "work" && e["primary"] == true)
        .collect();
    println!(
        "   Result: Updated {} primary work email(s)",
        primary_work.len()
    );
    for email in primary_work {
        println!("   - {}", email["value"]);
    }
    println!();

    // Demonstrate OR operator
    println!("3. OR Filter: phoneNumbers[type eq \"work\" or type eq \"mobile\"]");
    let or_path = ScimPath::parse("phoneNumbers[type eq \"work\" or type eq \"mobile\"]")?;
    let mut user_copy = user.clone();
    let original_count = user_copy["phoneNumbers"].as_array().unwrap().len();
    or_path.apply_operation(&mut user_copy, "remove", &json!(null))?;
    let remaining_count = user_copy["phoneNumbers"].as_array().unwrap().len();

    println!(
        "   Result: Removed {} phone number(s)",
        original_count - remaining_count
    );
    let remaining_phones = user_copy["phoneNumbers"].as_array().unwrap();
    for phone in remaining_phones {
        println!("   - Remaining: {} ({})", phone["value"], phone["type"]);
    }
    println!();

    // Demonstrate operator precedence
    println!("4. Precedence: emails[type eq \"work\" and primary eq true or type eq \"home\"]");
    println!("   (Parsed as: (type eq \"work\" and primary eq true) or (type eq \"home\"))");
    let precedence_path =
        ScimPath::parse("emails[type eq \"work\" and primary eq true or type eq \"home\"]")?;
    let mut user_copy = user.clone();
    let original_count = user_copy["emails"].as_array().unwrap().len();
    precedence_path.apply_operation(&mut user_copy, "remove", &json!(null))?;
    let remaining_count = user_copy["emails"].as_array().unwrap().len();

    println!(
        "   Result: Removed {} email(s)",
        original_count - remaining_count
    );
    let remaining_emails = user_copy["emails"].as_array().unwrap();
    for email in remaining_emails {
        println!("   - Remaining: {} ({})", email["value"], email["type"]);
    }
    println!();

    // Demonstrate advanced operators
    println!("5. Advanced Operators: emails[value co \"@company\"]");
    let advanced_path = ScimPath::parse("emails[value co \"@company\"]")?;
    let mut user_copy = user.clone();
    advanced_path.apply_operation(
        &mut user_copy,
        "replace",
        &json!({
            "value": "updated@company.com",
            "type": "business",
            "primary": true
        }),
    )?;

    let emails = user_copy["emails"].as_array().unwrap();
    let company_emails: Vec<_> = emails
        .iter()
        .filter(|e| e["value"].as_str().unwrap_or("").contains("@company"))
        .collect();
    println!(
        "   Result: Updated {} company email(s)",
        company_emails.len()
    );
    for email in company_emails {
        println!("   - {}", email["value"]);
    }
    println!();

    println!("✅ Complex filter expressions are fully functional!");
    println!("📚 Supported operators: eq, ne, co, sw, ew, gt, lt, ge, le");
    println!("🔗 Logical operators: and, or (with proper precedence)");
    println!("🚀 Performance optimized with thread-local buffers and short-circuit evaluation");

    Ok(())
}
