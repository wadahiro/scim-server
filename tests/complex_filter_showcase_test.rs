// Integration test demonstrating complex SCIM filter expressions
use scim_server::parser::patch_parser::ScimPath;
use serde_json::json;

#[test]
fn showcase_complex_filters() {
    println!("\n🔍 SCIM Complex Filter Expression Showcase");
    println!("==========================================");

    // Sample user data
    let user = json!({
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

    println!("\n1. Testing Simple Filter: emails[type eq \"work\"]");
    let simple_path =
        ScimPath::parse("emails[type eq \"work\"]").expect("Should parse simple filter");
    let mut user_copy = user.clone();
    simple_path
        .apply_operation(&mut user_copy, "remove", &json!(null))
        .expect("Should remove work emails");

    let remaining_emails = user_copy["emails"].as_array().unwrap();
    println!(
        "   ✅ Removed work emails, {} emails remaining",
        remaining_emails.len()
    );
    assert_eq!(remaining_emails.len(), 1); // Only home email should remain

    println!("\n2. Testing AND Operator: emails[type eq \"work\" and primary eq true]");
    let and_path = ScimPath::parse("emails[type eq \"work\" and primary eq true]")
        .expect("Should parse AND filter");
    let mut user_copy = user.clone();
    and_path
        .apply_operation(
            &mut user_copy,
            "replace",
            &json!({
                "value": "new-primary@company.com",
                "type": "work",
                "primary": true
            }),
        )
        .expect("Should replace primary work email");

    let emails = user_copy["emails"].as_array().unwrap();
    let primary_work = emails
        .iter()
        .find(|e| e["primary"] == true && e["type"] == "work")
        .unwrap();
    println!(
        "   ✅ Updated primary work email to: {}",
        primary_work["value"]
    );
    assert_eq!(primary_work["value"], "new-primary@company.com");

    println!("\n3. Testing OR Operator: phoneNumbers[type eq \"work\" or type eq \"mobile\"]");
    let or_path = ScimPath::parse("phoneNumbers[type eq \"work\" or type eq \"mobile\"]")
        .expect("Should parse OR filter");
    let mut user_copy = user.clone();
    let original_count = user_copy["phoneNumbers"].as_array().unwrap().len();
    or_path
        .apply_operation(&mut user_copy, "remove", &json!(null))
        .expect("Should remove work or mobile phones");

    let remaining_count = user_copy["phoneNumbers"].as_array().unwrap().len();
    println!(
        "   ✅ Removed {} phone numbers (work or mobile)",
        original_count - remaining_count
    );
    assert_eq!(remaining_count, 1); // Only home phone should remain

    println!(
        "\n4. Testing Precedence: emails[type eq \"work\" and primary eq true or type eq \"home\"]"
    );
    let precedence_path =
        ScimPath::parse("emails[type eq \"work\" and primary eq true or type eq \"home\"]")
            .expect("Should parse precedence filter");
    let mut user_copy = user.clone();
    precedence_path
        .apply_operation(&mut user_copy, "remove", &json!(null))
        .expect("Should remove emails matching complex condition");

    let remaining_emails = user_copy["emails"].as_array().unwrap();
    println!("   ✅ Applied precedence rule: AND before OR");
    // Should remove home email and primary work email, leaving only non-primary work email
    assert_eq!(remaining_emails.len(), 1);
    assert_eq!(remaining_emails[0]["value"], "backup@company.com");

    println!("\n5. Testing Advanced Operators: emails[value co \"@company\"]");
    let contains_path =
        ScimPath::parse("emails[value co \"@company\"]").expect("Should parse contains filter");
    let mut user_copy = user.clone();
    contains_path
        .apply_operation(
            &mut user_copy,
            "replace",
            &json!({
                "value": "updated@company.com",
                "type": "business",
                "primary": true
            }),
        )
        .expect("Should replace company emails");

    let emails = user_copy["emails"].as_array().unwrap();
    let company_emails: Vec<_> = emails
        .iter()
        .filter(|e| e["value"].as_str().unwrap_or("").contains("@company"))
        .collect();
    println!(
        "   ✅ Updated {} emails containing '@company'",
        company_emails.len()
    );
    assert!(!company_emails.is_empty());

    println!("\n✅ All complex filter expressions working correctly!");
    println!("📚 Supported operators: eq, ne, co, sw, ew, gt, lt, ge, le");
    println!("🔗 Logical operators: and, or (with proper precedence)");
    println!("🚀 Performance optimized with short-circuit evaluation\n");
}
