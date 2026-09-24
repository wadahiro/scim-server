//! Flattens a provider's `GET /Schemas` response into one [`AttrDecl`] per
//! attribute and sub-attribute. Ported 1:1 from the Python prototype's
//! `schema_walk.py`.

use serde::Serialize;
use serde_json::Value;

/// The three resources this crate walks. `ServiceProviderConfig` is
/// intentionally excluded (see [`decls_from_schemas`]): it has no write
/// endpoint, so none of the enforcement checks below apply to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Resource {
    User,
    Group,
    EnterpriseUser,
}

impl Resource {
    pub fn endpoint(&self) -> &'static str {
        match self {
            Resource::User | Resource::EnterpriseUser => "/Users",
            Resource::Group => "/Groups",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "User" => Some(Resource::User),
            "Group" => Some(Resource::Group),
            "EnterpriseUser" => Some(Resource::EnterpriseUser),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
    String,
    Boolean,
    Decimal,
    Integer,
    DateTime,
    Reference,
    Complex,
    Binary,
}

impl AttrType {
    fn from_str(s: &str) -> Self {
        match s {
            "boolean" => AttrType::Boolean,
            "decimal" => AttrType::Decimal,
            "integer" => AttrType::Integer,
            "dateTime" => AttrType::DateTime,
            "reference" => AttrType::Reference,
            "complex" => AttrType::Complex,
            "binary" => AttrType::Binary,
            _ => AttrType::String,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutability {
    ReadWrite,
    ReadOnly,
    Immutable,
    WriteOnly,
}

impl Mutability {
    fn from_str(s: &str) -> Self {
        match s {
            "readOnly" => Mutability::ReadOnly,
            "immutable" => Mutability::Immutable,
            "writeOnly" => Mutability::WriteOnly,
            _ => Mutability::ReadWrite,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Returned {
    Always,
    Never,
    Default,
    Request,
}

impl Returned {
    fn from_str(s: &str) -> Self {
        match s {
            "always" => Returned::Always,
            "never" => Returned::Never,
            "request" => Returned::Request,
            _ => Returned::Default,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Uniqueness {
    None,
    Server,
    Global,
}

impl Uniqueness {
    fn from_str(s: &str) -> Self {
        match s {
            "server" => Uniqueness::Server,
            "global" => Uniqueness::Global,
            _ => Uniqueness::None,
        }
    }
}

/// One attribute or sub-attribute, as declared by the server's own
/// `/Schemas` response. Sub-attributes are flattened: `name.givenName`,
/// `members.value`, `urn:...:EnterpriseUser:manager.value` never appear as
/// nested structures here, only as dotted `path` strings with `parent` set.
#[derive(Debug, Clone, PartialEq)]
pub struct AttrDecl {
    pub schema: String,
    pub resource: Resource,
    /// Dotted path, e.g. `"name"`, `"name.givenName"`, `"members.value"`.
    /// Never includes the schema URN prefix (see `dotted_path` in
    /// `matrix::exec` for the enterprise-qualified PATCH form).
    pub path: String,
    /// `Some("name")` for `"name.givenName"`; `None` for top-level attributes.
    pub parent: Option<String>,
    pub r#type: AttrType,
    pub mutability: Mutability,
    pub returned: Returned,
    pub uniqueness: Uniqueness,
    pub case_exact: bool,
    pub required: bool,
    /// This attribute's own `multiValued` flag.
    pub multi_valued: bool,
    /// The `multiValued`-ness of `path`'s first segment — this is what
    /// decides whether `set_attr` wraps the value in `[{ .. }]` or `{ .. }`.
    pub top_multi_valued: bool,
    pub canonical_values: Option<Vec<String>>,
    /// Whether this attribute itself declares `subAttributes` (used to
    /// decide whether a readOnly complex container decomposes into
    /// per-subattribute checks instead of being probed directly).
    pub has_sub_attributes: bool,
}

impl AttrDecl {
    pub fn top(&self) -> &str {
        self.path.split('.').next().unwrap_or(&self.path)
    }

    pub fn last(&self) -> &str {
        self.path.rsplit('.').next().unwrap_or(&self.path)
    }

    pub fn depth(&self) -> usize {
        self.path.matches('.').count() + 1
    }
}

fn walk(
    attrs: &[Value],
    path: &mut Vec<String>,
    top_mv: bool,
    resource: Resource,
    schema: &str,
    out: &mut Vec<AttrDecl>,
) {
    for a in attrs {
        let Some(name) = a.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        path.push(name.to_string());

        let own_multi_valued = a
            .get("multiValued")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let this_top_mv = if path.len() == 1 {
            own_multi_valued
        } else {
            top_mv
        };
        let parent = if path.len() > 1 {
            Some(path[..path.len() - 1].join("."))
        } else {
            None
        };
        let sub_attributes = a.get("subAttributes").and_then(|v| v.as_array());

        out.push(AttrDecl {
            schema: schema.to_string(),
            resource,
            path: path.join("."),
            parent,
            r#type: AttrType::from_str(a.get("type").and_then(|v| v.as_str()).unwrap_or("string")),
            mutability: Mutability::from_str(
                a.get("mutability").and_then(|v| v.as_str()).unwrap_or(""),
            ),
            returned: Returned::from_str(a.get("returned").and_then(|v| v.as_str()).unwrap_or("")),
            uniqueness: Uniqueness::from_str(
                a.get("uniqueness").and_then(|v| v.as_str()).unwrap_or(""),
            ),
            case_exact: a
                .get("caseExact")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            required: a.get("required").and_then(|v| v.as_bool()).unwrap_or(false),
            multi_valued: own_multi_valued,
            top_multi_valued: this_top_mv,
            canonical_values: a
                .get("canonicalValues")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                }),
            has_sub_attributes: sub_attributes.is_some_and(|s| !s.is_empty()),
        });

        if let Some(subs) = sub_attributes {
            if !subs.is_empty() {
                walk(subs, path, this_top_mv, resource, schema, out);
            }
        }
        path.pop();
    }
}

/// Flattens every attribute/sub-attribute of every resource in a `/Schemas`
/// ListResponse, except `ServiceProviderConfig` (it has no write endpoint,
/// so none of the generated checks apply to it — RFC 7643 §5 vs. §7
/// distinction).
pub fn decls_from_schemas(schemas: &Value) -> Vec<AttrDecl> {
    let mut out = Vec::new();
    let Some(resources) = schemas.get("Resources").and_then(|v| v.as_array()) else {
        return out;
    };
    for r in resources {
        let name = r.get("name").and_then(|v| v.as_str()).unwrap_or("");
        if name == "ServiceProviderConfig" {
            continue;
        }
        let Some(resource) = Resource::from_name(name) else {
            continue;
        };
        let schema_urn = r
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut path = Vec::new();
        if let Some(attrs) = r.get("attributes").and_then(|v| v.as_array()) {
            walk(attrs, &mut path, false, resource, &schema_urn, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Value {
        json!({
            "Resources": [
                {
                    "id": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
                    "name": "ServiceProviderConfig",
                    "attributes": [
                        { "name": "patch", "type": "complex", "mutability": "readOnly", "multiValued": false,
                          "subAttributes": [{ "name": "supported", "type": "boolean", "mutability": "readOnly" }] }
                    ]
                },
                {
                    "id": "urn:ietf:params:scim:schemas:core:2.0:User",
                    "name": "User",
                    "attributes": [
                        { "name": "userName", "type": "string", "mutability": "readWrite", "required": true, "caseExact": false },
                        { "name": "name", "type": "complex", "mutability": "readWrite", "multiValued": false,
                          "subAttributes": [
                              { "name": "givenName", "type": "string", "mutability": "readWrite" },
                              { "name": "familyName", "type": "string", "mutability": "readWrite" }
                          ] },
                        { "name": "emails", "type": "complex", "mutability": "readWrite", "multiValued": true,
                          "subAttributes": [
                              { "name": "value", "type": "string", "mutability": "readWrite" },
                              { "name": "type", "type": "string", "mutability": "readWrite", "canonicalValues": ["work", "home"] }
                          ] }
                    ]
                }
            ]
        })
    }

    #[test]
    fn service_provider_config_is_excluded() {
        let decls = decls_from_schemas(&fixture());
        assert!(decls
            .iter()
            .all(|d| !d.schema.contains("ServiceProviderConfig")));
    }

    #[test]
    fn flattens_sub_attributes_with_dotted_paths_and_parent() {
        let decls = decls_from_schemas(&fixture());
        let given_name = decls
            .iter()
            .find(|d| d.path == "name.givenName")
            .expect("name.givenName must be flattened");
        assert_eq!(given_name.parent.as_deref(), Some("name"));
        assert_eq!(given_name.resource, Resource::User);
        assert!(!given_name.top_multi_valued, "name is not multiValued");

        let email_type = decls
            .iter()
            .find(|d| d.path == "emails.type")
            .expect("emails.type must be flattened");
        assert_eq!(email_type.parent.as_deref(), Some("emails"));
        assert!(email_type.top_multi_valued, "emails is multiValued");
        assert_eq!(
            email_type.canonical_values.as_deref(),
            Some(&["work".to_string(), "home".to_string()][..])
        );
    }

    #[test]
    fn top_level_attribute_has_no_parent() {
        let decls = decls_from_schemas(&fixture());
        let username = decls.iter().find(|d| d.path == "userName").unwrap();
        assert_eq!(username.parent, None);
        assert!(username.required);
        assert_eq!(username.depth(), 1);
    }

    #[test]
    fn has_sub_attributes_flags_complex_containers_only() {
        let decls = decls_from_schemas(&fixture());
        let name = decls.iter().find(|d| d.path == "name").unwrap();
        assert!(name.has_sub_attributes);
        let username = decls.iter().find(|d| d.path == "userName").unwrap();
        assert!(!username.has_sub_attributes);
    }

    #[test]
    fn decls_from_schemas_is_deterministic() {
        let f = fixture();
        assert_eq!(decls_from_schemas(&f), decls_from_schemas(&f));
    }
}
