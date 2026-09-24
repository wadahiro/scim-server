//! Tests for `AppConfig::validate()` (and its use inside
//! `AppConfig::load_from_file`), which turns a set of config mistakes that
//! previously surfaced late -- after the database file and tenant tables
//! were already created, or an axum panic at startup, or (worst of all)
//! silently at request time -- into load-time errors that name every
//! problem in one pass.
//!
//! These tests go through `AppConfig::load_from_file` (not
//! `serde_yaml::from_str` + `validate()` directly) so they exercise exactly
//! what a real `-c config.yaml` run would see, matching the style already
//! used by `tests/meta_datetime_format_validation_test.rs`.

use scim_server::config::AppConfig;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A small RAII guard around a config file written to the OS temp dir,
/// deleted when the test drops it.
struct TempConfigFile(PathBuf);

impl TempConfigFile {
    fn write(yaml: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "scim_server_config_validation_test_{}_{}.yaml",
            std::process::id(),
            n
        ));
        std::fs::write(&path, yaml).expect("write temp config file");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const HEADER: &str = r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
"#;

fn load(yaml: &str) -> Result<AppConfig, String> {
    let file = TempConfigFile::write(yaml);
    AppConfig::load_from_file(file.path())
}

// ---------------------------------------------------------------------
// Rule 1 + 2: auth.type must be a recognized value, and bearer/token/basic
// need their required fields.
// ---------------------------------------------------------------------

#[test]
fn unknown_auth_type_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"bear\"\n"
    );
    let err = load(&yaml).expect_err("typo'd auth.type must be rejected");
    assert!(err.contains("bear"), "got: {err}");
    assert!(err.contains("auth.type"), "got: {err}");
}

#[test]
fn known_auth_types_are_accepted() {
    for auth_yaml in [
        "type: \"unauthenticated\"",
        "type: \"bearer\"\n      token: \"secret\"",
        "type: \"token\"\n      token: \"secret\"",
        "type: \"basic\"\n      basic:\n        username: \"u\"\n        password: \"p\"",
    ] {
        let yaml = format!(
            "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      {auth_yaml}\n"
        );
        load(&yaml).unwrap_or_else(|e| panic!("auth {auth_yaml:?} should be valid: {e}"));
    }
}

#[test]
fn bearer_without_token_is_rejected() {
    let yaml =
        format!("{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"bearer\"\n");
    let err = load(&yaml).expect_err("bearer without a token must be rejected");
    assert!(err.contains("token"), "got: {err}");
}

#[test]
fn bearer_with_empty_token_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"bearer\"\n      token: \"\"\n"
    );
    let err = load(&yaml).expect_err("bearer with an empty token must be rejected");
    assert!(err.contains("empty token"), "got: {err}");
}

#[test]
fn basic_without_basic_block_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"basic\"\n"
    );
    let err = load(&yaml).expect_err("basic without a basic: block must be rejected");
    assert!(err.contains("requires a basic: block"), "got: {err}");
}

// ---------------------------------------------------------------------
// Rule 3: trusted_proxies entries must parse as an IP or CIDR.
// ---------------------------------------------------------------------

#[test]
fn invalid_trusted_proxies_entry_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    host: \"example.com\"\n    host_resolution:\n      type: \"forwarded\"\n      trusted_proxies: [\"172.16.0.0/122\"]\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("an invalid CIDR must be rejected");
    assert!(err.contains("172.16.0.0/122"), "got: {err}");
    assert!(err.contains("trusted_proxies"), "got: {err}");
}

#[test]
fn valid_trusted_proxies_entries_are_accepted() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    host: \"example.com\"\n    host_resolution:\n      type: \"forwarded\"\n      trusted_proxies: [\"192.168.1.100\", \"10.0.0.0/8\"]\n    auth:\n      type: \"unauthenticated\"\n"
    );
    load(&yaml).unwrap_or_else(|e| panic!("valid trusted_proxies should load: {e}"));
}

// ---------------------------------------------------------------------
// Rule 4: tenant `path` uniqueness (the one that panics after creating
// tables).
// ---------------------------------------------------------------------

#[test]
fn duplicate_tenant_paths_are_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n  - id: 2\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("duplicate tenant paths must be rejected");
    assert!(err.contains("/scim/v2"), "got: {err}");
    assert!(err.contains("Overlapping method route"), "got: {err}");
}

#[test]
fn duplicate_tenant_paths_after_normalization_are_rejected() {
    // A trailing slash doesn't change the route path build_scim_router
    // registers, so this must be caught too.
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n  - id: 2\n    path: \"/scim/v2/\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("paths equal after trailing-slash normalization must collide");
    assert!(err.contains("tenant id 1"), "got: {err}");
    assert!(err.contains("tenant id 2"), "got: {err}");
    assert!(err.contains("/scim/v2"), "got: {err}");
}

#[test]
fn distinct_tenant_paths_are_accepted() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n  - id: 2\n    path: \"/scim/v3\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    load(&yaml).unwrap_or_else(|e| panic!("distinct tenant paths should load: {e}"));
}

// ---------------------------------------------------------------------
// Rule 5: tenant `id` uniqueness.
// ---------------------------------------------------------------------

#[test]
fn duplicate_tenant_ids_are_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n  - id: 1\n    path: \"/scim/v3\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("duplicate tenant ids must be rejected");
    assert!(err.contains("duplicate tenant id 1"), "got: {err}");
}

#[test]
fn distinct_tenant_ids_are_accepted() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n  - id: 2\n    path: \"/scim/v3\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    load(&yaml).unwrap_or_else(|e| panic!("distinct tenant ids should load: {e}"));
}

// ---------------------------------------------------------------------
// Rule 6: backend.type / backend.database / database.type.
// ---------------------------------------------------------------------

#[test]
fn unsupported_backend_type_is_rejected() {
    let yaml = r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "ldap"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
"#;
    let err = load(yaml).expect_err("unsupported backend.type must be rejected");
    assert!(err.contains("ldap"), "got: {err}");
}

#[test]
fn unsupported_database_type_is_rejected() {
    let yaml = r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "mysql"
    url: "mysql://localhost/scim"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
"#;
    let err = load(yaml).expect_err("unsupported database.type must be rejected");
    assert!(err.contains("mysql"), "got: {err}");
}

#[test]
fn database_backend_requires_database_block() {
    // Constructing this case through YAML is awkward since `database` is
    // the only way to populate `DatabaseConfig`, so build the struct
    // in-memory and call `validate()` directly for this one case.
    use scim_server::config::{AppConfig, AuthConfig, BackendConfig, ServerConfig, TenantConfig};

    let config = AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
        },
        backend: BackendConfig {
            backend_type: "database".to_string(),
            database: None,
        },
        compatibility: Default::default(),
        tenants: vec![TenantConfig {
            id: 1,
            path: "/scim/v2".to_string(),
            host: None,
            host_resolution: None,
            auth: AuthConfig {
                auth_type: "unauthenticated".to_string(),
                token: None,
                basic: None,
            },
            override_base_url: None,
            custom_endpoints: vec![],
            compatibility: None,
        }],
    };

    let err = config
        .validate()
        .expect_err("missing database block must be rejected");
    assert!(err.to_string().contains("backend.database"));
}

#[test]
fn supported_backend_and_database_types_are_accepted() {
    for db_type in ["postgresql", "sqlite"] {
        let yaml = format!(
            "server:\n  host: \"127.0.0.1\"\n  port: 3000\nbackend:\n  type: \"database\"\n  database:\n    type: \"{db_type}\"\n    url: \"whatever\"\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n"
        );
        load(&yaml).unwrap_or_else(|e| panic!("database.type {db_type:?} should be valid: {e}"));
    }
}

// ---------------------------------------------------------------------
// Rule 7: override_base_url must be an absolute http/https URL.
// ---------------------------------------------------------------------

#[test]
fn invalid_override_base_url_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    override_base_url: \"not a url\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("a non-URL override_base_url must be rejected");
    assert!(err.contains("override_base_url"), "got: {err}");
}

#[test]
fn non_http_override_base_url_scheme_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    override_base_url: \"ftp://example.com\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("a non-http(s) scheme must be rejected");
    assert!(err.contains("ftp"), "got: {err}");
}

#[test]
fn valid_override_base_url_is_accepted() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    override_base_url: \"https://public.example.com\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    load(&yaml).unwrap_or_else(|e| panic!("a valid override_base_url should load: {e}"));
}

// ---------------------------------------------------------------------
// Rule 8: custom_endpoints path collisions.
// ---------------------------------------------------------------------

#[test]
fn duplicate_custom_endpoint_path_within_a_tenant_is_rejected() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/health\"\n        response: \"a\"\n      - path: \"/health\"\n        response: \"b\"\n"
    );
    let err = load(&yaml).expect_err("duplicate custom_endpoints path must be rejected");
    assert!(err.contains("/health"), "got: {err}");
}

#[test]
fn custom_endpoint_path_colliding_with_another_tenants_custom_endpoint_is_rejected() {
    // Verified empirically: app::build_custom_router registers every
    // tenant's custom endpoints into one shared router, so this panics at
    // startup exactly like a duplicate tenant path does.
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/health\"\n        response: \"a\"\n  - id: 2\n    path: \"/scim/v3\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/health\"\n        response: \"b\"\n"
    );
    let err =
        load(&yaml).expect_err("cross-tenant custom_endpoints path collision must be rejected");
    assert!(err.contains("/health"), "got: {err}");
    assert!(err.contains("not scoped per tenant"), "got: {err}");
}

#[test]
fn custom_endpoint_path_colliding_with_scim_route_is_rejected() {
    // Verified empirically: a custom endpoint at the same path as a
    // built-in SCIM GET route panics build_router the same way.
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/scim/v2/Users\"\n        response: \"a\"\n"
    );
    let err =
        load(&yaml).expect_err("a custom endpoint colliding with a SCIM route must be rejected");
    assert!(err.contains("/scim/v2/Users"), "got: {err}");
    assert!(err.contains("built-in SCIM GET route"), "got: {err}");
}

#[test]
fn distinct_custom_endpoint_paths_are_accepted() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/health\"\n        response: \"a\"\n      - path: \"/version\"\n        response: \"b\"\n"
    );
    load(&yaml).unwrap_or_else(|e| panic!("distinct custom endpoint paths should load: {e}"));
}

#[test]
fn custom_endpoint_auth_override_is_validated_like_tenant_auth() {
    // CustomEndpoint::effective_auth_config lets a custom endpoint override
    // the tenant's auth config; that override is real auth.rs behavior, so
    // it must be validated the same way tenant-level auth is.
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n    custom_endpoints:\n      - path: \"/health\"\n        response: \"a\"\n        auth:\n          type: \"bear\"\n"
    );
    let err = load(&yaml)
        .expect_err("an invalid auth.type on a custom endpoint override must be rejected");
    assert!(err.contains("/health"), "got: {err}");
    assert!(err.contains("bear"), "got: {err}");
}

// ---------------------------------------------------------------------
// Rule 9: meta_datetime_format (folded in from the pre-existing check;
// tests/meta_datetime_format_validation_test.rs covers this in more
// detail, this is just a presence check within the combined validator).
// ---------------------------------------------------------------------

#[test]
fn invalid_meta_datetime_format_is_still_rejected() {
    let yaml = format!(
        "{HEADER}\ncompatibility:\n  meta_datetime_format: \"ISO8601\"\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("invalid meta_datetime_format must be rejected");
    assert!(err.contains("ISO8601"), "got: {err}");
}

// ---------------------------------------------------------------------
// Collect-all-errors contract, zero-config mode, and the shipped
// config.yaml regression guard.
// ---------------------------------------------------------------------

#[test]
fn three_distinct_problems_are_all_reported_at_once() {
    let yaml = format!(
        "{HEADER}\ntenants:\n  - id: 1\n    path: \"/scim/v2\"\n    auth:\n      type: \"bear\"\n  - id: 1\n    path: \"/scim/v3\"\n    host: \"example.com\"\n    host_resolution:\n      type: \"forwarded\"\n      trusted_proxies: [\"not-an-ip\"]\n    auth:\n      type: \"unauthenticated\"\n"
    );
    let err = load(&yaml).expect_err("a config with three problems must be rejected");

    // 1. unknown auth.type on tenant 1
    assert!(
        err.contains("bear"),
        "missing auth.type problem, got: {err}"
    );
    // 2. duplicate tenant id 1
    assert!(
        err.contains("duplicate tenant id 1"),
        "missing duplicate tenant id problem, got: {err}"
    );
    // 3. invalid trusted_proxies entry
    assert!(
        err.contains("not-an-ip"),
        "missing trusted_proxies problem, got: {err}"
    );

    // And it must be exactly three lines -- one per problem, not
    // short-circuited after the first.
    let line_count = err.lines().count();
    assert_eq!(
        line_count, 3,
        "expected exactly 3 reported problems, got {line_count}:\n{err}"
    );
}

#[test]
fn default_config_validates() {
    AppConfig::default_config()
        .validate()
        .expect("the zero-config default must pass validation");
}

#[test]
fn shipped_config_yaml_validates() {
    // Regression guard: the sample config the README and CLAUDE.md point
    // readers at must keep passing validation. Run from the crate root
    // (cargo sets this for integration tests), so `config.yaml` here is
    // the one at the repository root.
    let result = AppConfig::load_from_file("config.yaml");
    assert!(
        result.is_ok(),
        "the repo's own config.yaml must pass validation, got: {:?}",
        result.err()
    );
}
