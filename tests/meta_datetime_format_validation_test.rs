//! `meta_datetime_format` was previously an unvalidated `String`: the only
//! consumer (`utils.rs`) checked `format_type == "epoch"` and silently
//! fell through to rfc3339 for anything else, so a config with e.g.
//! `meta_datetime_format: "ISO8601"` loaded successfully with no warning
//! and quietly behaved as rfc3339.
//!
//! `AppConfig::load_from_file` now rejects any value other than the exact
//! strings "rfc3339" or "epoch", for both the global `compatibility:`
//! block and any tenant `compatibility:` override. These tests write a
//! temporary config file and load it through `AppConfig::load_from_file`
//! (not `serde_yaml::from_str` directly) since that's where the
//! validation actually runs.

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
            "scim_server_meta_datetime_format_test_{}_{}.yaml",
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

#[test]
fn global_unknown_meta_datetime_format_is_rejected() {
    let yaml = r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
compatibility:
  meta_datetime_format: "ISO8601"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
"#;
    let file = TempConfigFile::write(yaml);
    let result = AppConfig::load_from_file(file.path());
    let err = result.expect_err("ISO8601 is not a valid meta_datetime_format");
    assert!(
        err.contains("ISO8601"),
        "error should name the offending value, got: {err}"
    );
}

#[test]
fn tenant_unknown_meta_datetime_format_is_rejected_and_names_the_tenant() {
    let yaml = r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
tenants:
  - id: 42
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      meta_datetime_format: "Epoch"
"#;
    let file = TempConfigFile::write(yaml);
    let result = AppConfig::load_from_file(file.path());
    let err = result.expect_err("\"Epoch\" (wrong case) is not a valid meta_datetime_format");
    assert!(
        err.contains("Epoch"),
        "error should name the offending value, got: {err}"
    );
    assert!(
        err.contains("42"),
        "error should name the offending tenant id, got: {err}"
    );
}

#[test]
fn rfc3339_and_epoch_both_load_successfully() {
    for value in ["rfc3339", "epoch"] {
        let yaml = format!(
            r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
compatibility:
  meta_datetime_format: "{value}"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      meta_datetime_format: "{value}"
"#
        );
        let file = TempConfigFile::write(&yaml);
        AppConfig::load_from_file(file.path())
            .unwrap_or_else(|e| panic!("{value:?} should be a valid meta_datetime_format: {e}"));
    }
}
