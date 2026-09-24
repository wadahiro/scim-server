//! Tests for the `--validate` CLI flag.
//!
//! `Args` (the clap struct) is private to `src/main.rs` and not part of the
//! library crate, so it can't be constructed and parsed in-process from an
//! integration test. These tests instead drive the actual built binary via
//! `std::process::Command`, using `env!("CARGO_BIN_EXE_scim-server")` --
//! which also lets the "no database file is created" test prove something
//! an in-process clap-only test couldn't: that `--validate` really does
//! exit before `setup_backend` runs.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_path(suffix: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "scim_server_cli_validate_test_{}_{}{}",
        std::process::id(),
        n,
        suffix
    ))
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_scim-server")
}

#[test]
fn validate_flag_is_documented_in_help() {
    let output = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run scim-server --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--validate"),
        "--help output should document --validate, got:\n{stdout}"
    );
}

#[test]
fn validate_with_no_config_uses_defaults_and_exits_zero() {
    let output = Command::new(bin())
        .arg("--validate")
        .output()
        .expect("run scim-server --validate");
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("valid"), "got: {stdout}");
}

#[test]
fn validate_with_valid_config_exits_zero_and_creates_no_database_file() {
    let db_path = temp_path(".sqlite");
    let config_path = temp_path(".yaml");
    std::fs::write(
        &config_path,
        format!(
            r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: "{}"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
"#,
            db_path.display()
        ),
    )
    .expect("write temp config");

    let output = Command::new(bin())
        .arg("-c")
        .arg(&config_path)
        .arg("--validate")
        .output()
        .expect("run scim-server -c ... --validate");

    let _ = std::fs::remove_file(&config_path);

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !db_path.exists(),
        "--validate must not create the database file, but {} exists",
        db_path.display()
    );

    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn validate_with_three_problems_exits_nonzero_and_lists_all_of_them() {
    let config_path = temp_path(".yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  host: "127.0.0.1"
  port: 3000
backend:
  type: "database"
  database:
    type: "sqlite"
    url: ":memory:"
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "bear"
  - id: 1
    path: "/scim/v3"
    host: "example.com"
    host_resolution:
      type: "forwarded"
      trusted_proxies: ["not-an-ip"]
    auth:
      type: "unauthenticated"
"#,
    )
    .expect("write temp config");

    let output = Command::new(bin())
        .arg("-c")
        .arg(&config_path)
        .arg("--validate")
        .output()
        .expect("run scim-server -c ... --validate");

    let _ = std::fs::remove_file(&config_path);

    assert!(
        !output.status.success(),
        "an invalid config must exit non-zero"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bear"),
        "missing auth.type problem, got: {stderr}"
    );
    assert!(
        stderr.contains("duplicate tenant id 1"),
        "missing duplicate tenant id problem, got: {stderr}"
    );
    assert!(
        stderr.contains("not-an-ip"),
        "missing trusted_proxies problem, got: {stderr}"
    );
}
