use scim_server::parser::patch_parser::ScimPath;
use scim_server::parser::ResourceType;

fn main() {
    println!("Testing complex filter...");

    let path = ScimPath::parse(
        "emails[type eq \"work\" and primary eq true]",
        ResourceType::User,
    );
    match path {
        Ok(_) => println!("✅ Complex filter parsing works!"),
        Err(e) => println!("❌ Error: {}", e),
    }
}
