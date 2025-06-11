//! SCIM 2.0 Schema Knowledge
//!
//! This module centralizes all SCIM 2.0 schema knowledge in one place.
//! Any schema customization should be done here.

use crate::parser::ResourceType;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// SCIM 2.0 Core Schema identifiers
pub const SCIM_SCHEMA_CORE_USER: &str = "urn:ietf:params:scim:schemas:core:2.0:User";
pub const SCIM_SCHEMA_CORE_GROUP: &str = "urn:ietf:params:scim:schemas:core:2.0:Group";
pub const SCIM_SCHEMA_ENTERPRISE_USER: &str =
    "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";

/// SCIM 2.0 API Schema identifiers
pub const SCIM_API_MESSAGES_LIST_RESPONSE: &str =
    "urn:ietf:params:scim:api:messages:2.0:ListResponse";

/// Attribute type in SCIM
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AttributeType {
    String,
    Boolean,
    Integer,
    Decimal,
    DateTime,
    Reference,
    Complex,
}

/// Mutability of attributes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mutability {
    ReadOnly,
    ReadWrite,
    Immutable,
    WriteOnly,
}

/// When an attribute is returned
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Returned {
    Always,
    Never,
    Default,
    Request,
}

/// Uniqueness constraint
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Uniqueness {
    None,
    Server,
    Global,
}

/// Complete attribute definition
#[derive(Debug, Clone)]
pub struct AttributeDefinition {
    pub name: &'static str,
    pub attr_type: AttributeType,
    pub multi_valued: bool,
    pub description: &'static str,
    pub required: bool,
    pub case_exact: bool,
    pub mutability: Mutability,
    pub returned: Returned,
    pub uniqueness: Uniqueness,
    pub sub_attributes: Vec<AttributeDefinition>,
}

/// Schema definition
#[derive(Debug, Clone)]
pub struct SchemaDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub attributes: Vec<AttributeDefinition>,
}

lazy_static! {
    /// User schema definition
    pub static ref USER_SCHEMA: SchemaDefinition = SchemaDefinition {
        id: SCIM_SCHEMA_CORE_USER,
        name: "User",
        description: "User Account",
        attributes: vec![
            AttributeDefinition {
                name: "id",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Unique identifier for the User",
                required: true,
                case_exact: true,
                mutability: Mutability::ReadOnly,
                returned: Returned::Always,
                uniqueness: Uniqueness::Server,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "externalId",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "External unique identifier for the User",
                required: false,
                case_exact: true,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "userName",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Unique identifier for the User, typically used by the user to directly authenticate to the service provider",
                required: true,
                case_exact: false,  // Case-insensitive per SCIM 2.0 spec
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::Server,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "name",
                attr_type: AttributeType::Complex,
                multi_valued: false,
                description: "The components of the user's real name",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "formatted",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The full name, including all middle names, titles, and suffixes as appropriate",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "familyName",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The family name of the User",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "givenName",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The given name of the User",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "middleName",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The middle name(s) of the User",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "honorificPrefix",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The honorific prefix(es) of the User",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "honorificSuffix",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The honorific suffix(es) of the User",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "displayName",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "The name of the User, suitable for display to end-users",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "nickName",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "The casual way to address the user in real life",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "profileUrl",
                attr_type: AttributeType::Reference,
                multi_valued: false,
                description: "A fully qualified URL pointing to the User's public profile",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "title",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "The User's title",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "userType",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Used to identify the relationship between the organization and the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "preferredLanguage",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Indicates the User's preferred written or spoken language",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "locale",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Used to indicate the User's default location",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "timezone",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "The User's time zone in IANA Time Zone database format",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "emails",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "Email addresses for the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Email addresses for the user",
                        required: false,
                        case_exact: false,  // Email addresses are case-insensitive
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A label indicating the attribute's function",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "A Boolean value indicating the 'primary' or preferred attribute value",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "phoneNumbers",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "Phone numbers for the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Phone number",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Type of phone number",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "Primary phone indicator",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "ims",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "Instant messaging addresses for the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Instant messaging address",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Type of instant messaging service",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "photos",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "URLs of photos of the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::Reference,
                        multi_valued: false,
                        description: "URL of a photo of the user",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Type of photo",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "addresses",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "Physical mailing addresses for the user",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "formatted",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Full mailing address",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "streetAddress",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Full street address component",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "locality",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "City or locality component",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "region",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "State or region component",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "postalCode",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Zip or postal code component",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "country",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Country name component",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Type of address",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "Primary address indicator",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "active",
                attr_type: AttributeType::Boolean,
                multi_valued: false,
                description: "A Boolean value indicating the User's administrative status",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "password",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "The User's cleartext password",
                required: false,
                case_exact: true,
                mutability: Mutability::WriteOnly,
                returned: Returned::Never,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "entitlements",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "A list of entitlements for the User",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The value of an entitlement",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "display",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A human-readable name for the entitlement",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A label indicating the attribute's function",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "A Boolean value indicating the 'primary' or preferred attribute value",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "roles",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "A list of roles for the User",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The value of a role",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "display",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A human-readable name for the role",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A label indicating the attribute's function",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "A Boolean value indicating the 'primary' or preferred attribute value",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "x509Certificates",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "A list of certificates issued to the User",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The value of an X.509 certificate",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "display",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A human-readable name for the X.509 certificate",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A label indicating the attribute's function",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "primary",
                        attr_type: AttributeType::Boolean,
                        multi_valued: false,
                        description: "A Boolean value indicating the 'primary' or preferred attribute value",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "groups",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "A list of groups to which the user belongs",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadOnly,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The identifier of the User's group",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "$ref",
                        attr_type: AttributeType::Reference,
                        multi_valued: false,
                        description: "The URI of the corresponding 'Group' resource",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "display",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A human-readable name for the Group",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "meta",
                attr_type: AttributeType::Complex,
                multi_valued: false,
                description: "Resource metadata",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadOnly,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "resourceType",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The name of the resource type of the resource",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "created",
                        attr_type: AttributeType::DateTime,
                        multi_valued: false,
                        description: "The 'DateTime' that the resource was added to the service provider",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "lastModified",
                        attr_type: AttributeType::DateTime,
                        multi_valued: false,
                        description: "The most recent DateTime that the details of this resource were updated",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "location",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The URI of the resource being returned",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
        ],
    };

    /// Group schema definition
    pub static ref GROUP_SCHEMA: SchemaDefinition = SchemaDefinition {
        id: SCIM_SCHEMA_CORE_GROUP,
        name: "Group",
        description: "Group",
        attributes: vec![
            AttributeDefinition {
                name: "id",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Unique identifier for the Group",
                required: true,
                case_exact: true,
                mutability: Mutability::ReadOnly,
                returned: Returned::Always,
                uniqueness: Uniqueness::Server,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "externalId",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "External unique identifier for the Group",
                required: false,
                case_exact: true,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "displayName",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "A human-readable name for the Group",
                required: true,
                case_exact: false,  // Case-insensitive per SCIM 2.0 spec
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::Server,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "members",
                attr_type: AttributeType::Complex,
                multi_valued: true,
                description: "A list of members of the Group",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "Identifier of the member",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::Immutable,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "$ref",
                        attr_type: AttributeType::Reference,
                        multi_valued: false,
                        description: "The URI corresponding to the member resource",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::Immutable,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "type",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A label indicating the type of resource",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::Immutable,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "display",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "A human-readable name for the Group member",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
            AttributeDefinition {
                name: "meta",
                attr_type: AttributeType::Complex,
                multi_valued: false,
                description: "Resource metadata",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadOnly,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "resourceType",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The name of the resource type of the resource",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "created",
                        attr_type: AttributeType::DateTime,
                        multi_valued: false,
                        description: "The 'DateTime' that the resource was added to the service provider",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "lastModified",
                        attr_type: AttributeType::DateTime,
                        multi_valued: false,
                        description: "The most recent DateTime that the details of this resource were updated",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "location",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The URI of the resource being returned",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
        ],
    };

    /// Enterprise User Extension schema definition
    pub static ref ENTERPRISE_USER_SCHEMA: SchemaDefinition = SchemaDefinition {
        id: SCIM_SCHEMA_ENTERPRISE_USER,
        name: "EnterpriseUser",
        description: "Enterprise User Extension",
        attributes: vec![
            AttributeDefinition {
                name: "employeeNumber",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Numeric or alphanumeric identifier assigned to a person",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "costCenter",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Identifies the name of a cost center",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "organization",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Identifies the name of an organization",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "division",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Identifies the name of a division",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "department",
                attr_type: AttributeType::String,
                multi_valued: false,
                description: "Identifies the name of a department",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![],
            },
            AttributeDefinition {
                name: "manager",
                attr_type: AttributeType::Complex,
                multi_valued: false,
                description: "The User's manager",
                required: false,
                case_exact: false,
                mutability: Mutability::ReadWrite,
                returned: Returned::Default,
                uniqueness: Uniqueness::None,
                sub_attributes: vec![
                    AttributeDefinition {
                        name: "value",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The id of the SCIM resource representing the User's manager",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadWrite,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "$ref",
                        attr_type: AttributeType::Reference,
                        multi_valued: false,
                        description: "The URI of the SCIM resource representing the User's manager",
                        required: false,
                        case_exact: true,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                    AttributeDefinition {
                        name: "displayName",
                        attr_type: AttributeType::String,
                        multi_valued: false,
                        description: "The displayName of the User's manager",
                        required: false,
                        case_exact: false,
                        mutability: Mutability::ReadOnly,
                        returned: Returned::Default,
                        uniqueness: Uniqueness::None,
                        sub_attributes: vec![],
                    },
                ],
            },
        ],
    };

    /// Schema registry
    pub static ref SCHEMA_REGISTRY: HashMap<&'static str, &'static SchemaDefinition> = {
        let mut registry = HashMap::new();
        registry.insert(SCIM_SCHEMA_CORE_USER, &*USER_SCHEMA);
        registry.insert(SCIM_SCHEMA_CORE_GROUP, &*GROUP_SCHEMA);
        registry.insert(SCIM_SCHEMA_ENTERPRISE_USER, &*ENTERPRISE_USER_SCHEMA);
        registry
    };

}

/// Get all registered schemas
pub fn get_all_schemas() -> Vec<&'static SchemaDefinition> {
    SCHEMA_REGISTRY.values().copied().collect()
}

/// Find attribute definition in schema
pub fn find_attribute<'a>(
    schema: &'a SchemaDefinition,
    attr_path: &str,
) -> Option<&'a AttributeDefinition> {
    let parts: Vec<&str> = attr_path.split('.').collect();

    let mut current_attrs = &schema.attributes;
    let mut result = None;

    for (i, part) in parts.iter().enumerate() {
        if let Some(attr) = current_attrs
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(part))
        {
            result = Some(attr);
            if i < parts.len() - 1 && !attr.sub_attributes.is_empty() {
                current_attrs = &attr.sub_attributes;
            }
        } else {
            return None;
        }
    }

    result
}

/// Determine if an attribute should be compared case-insensitively based on SCIM 2.0 specification
pub fn is_case_insensitive_attribute(attr: &str, resource_type: ResourceType) -> bool {
    let schema = match resource_type {
        ResourceType::User => &*USER_SCHEMA,
        ResourceType::Group => &*GROUP_SCHEMA,
    };

    find_attribute(schema, attr)
        .map(|attr_def| !attr_def.case_exact)
        .unwrap_or(false)
}

/// Check if attribute is multi-valued
pub fn is_multi_valued_attribute(attr: &str, resource_type: ResourceType) -> bool {
    let schema = match resource_type {
        ResourceType::User => &*USER_SCHEMA,
        ResourceType::Group => &*GROUP_SCHEMA,
    };

    find_attribute(schema, attr)
        .map(|attr_def| attr_def.multi_valued)
        .unwrap_or(false)
}

/// Check if attribute is case-exact using schema definitions for specific resource type
pub fn is_case_exact_field_for_resource(attr_name: &str, resource_type: ResourceType) -> bool {
    let schema = match resource_type {
        ResourceType::User => &*USER_SCHEMA,
        ResourceType::Group => &*GROUP_SCHEMA,
    };

    if let Some(attr_def) = find_attribute(schema, attr_name) {
        attr_def.case_exact
    } else {
        // Default for custom attributes is NOT case-exact (case-insensitive)
        // They are stored in normalized form in data_norm column
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_case_insensitive_attributes() {
        // User attributes
        assert!(is_case_insensitive_attribute(
            "userName",
            ResourceType::User
        ));
        assert!(is_case_insensitive_attribute(
            "emails.value",
            ResourceType::User
        ));
        assert!(!is_case_insensitive_attribute("id", ResourceType::User));
        assert!(!is_case_insensitive_attribute(
            "externalId",
            ResourceType::User
        ));

        // Group attributes
        assert!(is_case_insensitive_attribute(
            "displayName",
            ResourceType::Group
        ));
        assert!(!is_case_insensitive_attribute("id", ResourceType::Group));
    }

    #[test]
    fn test_multi_valued_attributes() {
        assert!(is_multi_valued_attribute("emails", ResourceType::User));
        assert!(is_multi_valued_attribute("groups", ResourceType::User));
        assert!(!is_multi_valued_attribute("userName", ResourceType::User));

        assert!(is_multi_valued_attribute("members", ResourceType::Group));
        assert!(!is_multi_valued_attribute(
            "displayName",
            ResourceType::Group
        ));
    }

    #[test]
    fn test_find_attribute() {
        let schema = &*USER_SCHEMA;

        // Top-level attribute
        let attr = find_attribute(schema, "userName").unwrap();
        assert_eq!(attr.name, "userName");

        // Nested attribute
        let attr = find_attribute(schema, "name.givenName").unwrap();
        assert_eq!(attr.name, "givenName");

        // Multi-level nested
        let attr = find_attribute(schema, "emails.value").unwrap();
        assert_eq!(attr.name, "value");

        // Non-existent
        assert!(find_attribute(schema, "nonExistent").is_none());
    }

    #[test]
    fn test_case_exact_compatibility() {
        // Test resource-specific case exact functions
        assert!(is_case_exact_field_for_resource("id", ResourceType::User));
        assert!(is_case_exact_field_for_resource(
            "externalId",
            ResourceType::User
        ));
        assert!(!is_case_exact_field_for_resource(
            "userName",
            ResourceType::User
        ));
        assert!(!is_case_exact_field_for_resource(
            "displayName",
            ResourceType::User
        ));

        assert!(is_multi_valued_attribute("emails", ResourceType::User));
        assert!(is_multi_valued_attribute(
            "phoneNumbers",
            ResourceType::User
        ));
        assert!(!is_multi_valued_attribute("userName", ResourceType::User));
    }
}
