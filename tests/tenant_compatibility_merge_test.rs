//! Regression tests for `AppConfig::get_effective_compatibility`.
//!
//! A tenant's `compatibility:` block is documented (see CLAUDE.md) as
//! overriding the global `compatibility:` block on a *field-by-field*
//! basis. The original implementation instead replaced the whole global
//! `CompatibilityConfig` with the tenant's struct: because every field of
//! `CompatibilityConfig` carries a serde default, a tenant block naming
//! just one knob silently reverted every other knob to its serde default,
//! discarding any non-default global settings.
//!
//! These tests build configs by parsing YAML through
//! `serde_yaml::from_str::<AppConfig>`, since that is where the bug lives
//! (a hand-built struct literal would not exercise deserialization at
//! all).

use scim_server::config::AppConfig;

/// Global config with four knobs moved off their defaults; tenant 1
/// overrides only `meta_datetime_format`. All four deliberate global
/// settings must survive, and the tenant's one override must apply.
#[test]
fn tenant_override_of_one_field_preserves_other_global_settings() {
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
  include_user_groups: false
  support_group_members_filter: false
  support_group_displayname_filter: false
  support_patch_replace_empty_value: true
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      meta_datetime_format: "epoch"
"#;

    let config: AppConfig = serde_yaml::from_str(yaml).expect("config should parse");
    let effective = config.get_effective_compatibility(1);

    // Tenant's explicit override applies.
    assert_eq!(effective.meta_datetime_format, "epoch");

    // Global settings that the tenant did not mention must survive,
    // not silently revert to CompatibilityConfig's serde defaults.
    assert!(
        !effective.include_user_groups,
        "global include_user_groups=false must survive a tenant override of an unrelated field"
    );
    assert!(
        !effective.support_group_members_filter,
        "global support_group_members_filter=false must survive"
    );
    assert!(
        !effective.support_group_displayname_filter,
        "global support_group_displayname_filter=false must survive"
    );
    assert!(
        effective.support_patch_replace_empty_value,
        "global support_patch_replace_empty_value=true must survive"
    );

    // Untouched knobs (global and default agree) stay at the default.
    assert!(effective.show_empty_groups_members);
    assert!(effective.support_patch_replace_empty_array);
}

/// A tenant with no `compatibility:` block at all should apply the
/// global config unchanged (regression guard).
#[test]
fn tenant_without_compatibility_block_inherits_global_config() {
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
  meta_datetime_format: "epoch"
  include_user_groups: false
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
"#;

    let config: AppConfig = serde_yaml::from_str(yaml).expect("config should parse");
    let effective = config.get_effective_compatibility(1);

    assert_eq!(effective.meta_datetime_format, "epoch");
    assert!(!effective.include_user_groups);
    // Defaults for everything else.
    assert!(effective.show_empty_groups_members);
    assert!(effective.support_group_members_filter);
    assert!(effective.support_group_displayname_filter);
    assert!(effective.support_patch_replace_empty_array);
    assert!(!effective.support_patch_replace_empty_value);
}

/// A tenant explicitly setting a knob to the *same value as the serde
/// default*, while the global config has that knob off-default, must
/// still have its explicit value win. This is exactly the case that
/// requires `Option` fields to distinguish "unspecified" from
/// "explicitly set to the default".
#[test]
fn tenant_explicit_default_value_wins_over_nondefault_global() {
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
  include_user_groups: false
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      include_user_groups: true
"#;

    let config: AppConfig = serde_yaml::from_str(yaml).expect("config should parse");
    let effective = config.get_effective_compatibility(1);

    assert!(
        effective.include_user_groups,
        "tenant's explicit include_user_groups=true must win over global's false, \
         even though true is also CompatibilityConfig's serde default"
    );
}

/// A tenant overriding every field: all tenant values apply.
#[test]
fn tenant_overriding_every_field_applies_all_overrides() {
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
  meta_datetime_format: "rfc3339"
  show_empty_groups_members: true
  include_user_groups: true
  support_group_members_filter: true
  support_group_displayname_filter: true
  support_patch_replace_empty_array: true
  support_patch_replace_empty_value: false
tenants:
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      meta_datetime_format: "epoch"
      show_empty_groups_members: false
      include_user_groups: false
      support_group_members_filter: false
      support_group_displayname_filter: false
      support_patch_replace_empty_array: false
      support_patch_replace_empty_value: true
"#;

    let config: AppConfig = serde_yaml::from_str(yaml).expect("config should parse");
    let effective = config.get_effective_compatibility(1);

    assert_eq!(effective.meta_datetime_format, "epoch");
    assert!(!effective.show_empty_groups_members);
    assert!(!effective.include_user_groups);
    assert!(!effective.support_group_members_filter);
    assert!(!effective.support_group_displayname_filter);
    assert!(!effective.support_patch_replace_empty_array);
    assert!(effective.support_patch_replace_empty_value);
}

/// An unknown key inside a tenant's `compatibility:` block must be a load
/// error (deny_unknown_fields), not a silent no-op.
#[test]
fn unknown_key_in_tenant_compatibility_override_is_rejected() {
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
  - id: 1
    path: "/scim/v2"
    auth:
      type: "unauthenticated"
    compatibility:
      meta_datetim_format: "epoch"
"#;

    let result: Result<AppConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        result.is_err(),
        "a typo'd compatibility knob name should fail to parse, not be silently ignored"
    );
}
