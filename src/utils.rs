//! Utility functions for SCIM server

use chrono::{DateTime, Utc};

/// Formats a DateTime to SCIM 2.0 compliant XSD dateTime format
///
/// SCIM 2.0 (RFC 7644) requires XSD dateTime format as specified in Section 3.3.7
/// of XML Schema. This function formats timestamps to a standard format with
/// millisecond precision, which is commonly used in SCIM implementations.
///
/// Example output: "2025-06-14T10:03:54.374Z"
pub fn format_scim_datetime(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Formats a DateTime to epoch timestamp (milliseconds since Unix epoch)
///
/// Some legacy SCIM servers return DateTime fields as long integers representing
/// milliseconds since the Unix epoch (January 1, 1970 00:00:00 UTC).
///
/// Example output: 1749891834374
pub fn format_epoch_datetime(dt: DateTime<Utc>) -> i64 {
    dt.timestamp_millis()
}

/// Formats a DateTime according to the specified format type
///
/// Supports both standard SCIM 2.0 format and legacy epoch format.
///
/// # Arguments
/// * `dt` - The DateTime to format
/// * `format_type` - Either "rfc3339" for standard format or "epoch" for timestamp
///
/// # Examples
/// ```
/// use chrono::Utc;
/// use scim_server::utils::format_datetime_with_type;
///
/// let now = Utc::now();
/// let rfc3339 = format_datetime_with_type(now, "rfc3339");
/// let epoch = format_datetime_with_type(now, "epoch");
/// ```
pub fn format_datetime_with_type(dt: DateTime<Utc>, format_type: &str) -> String {
    match format_type {
        "epoch" => format_epoch_datetime(dt).to_string(),
        _ => format_scim_datetime(dt), // Default to rfc3339 for any other value
    }
}

/// Gets the current time formatted for SCIM 2.0
pub fn current_scim_datetime() -> String {
    format_scim_datetime(Utc::now())
}

/// Convert datetime strings in User metadata to epoch format if needed
///
/// This function modifies the User's meta.created and meta.lastModified fields
/// to use epoch timestamps when the datetime format is set to "epoch".
pub fn convert_user_datetime_for_response(
    mut user: crate::models::User,
    format_type: &str,
) -> crate::models::User {
    if format_type == "epoch" {
        if let Some(meta) = user.meta_mut() {
            if let Some(ref created) = meta.created {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created) {
                    meta.created = Some(format_epoch_datetime(dt.with_timezone(&Utc)).to_string());
                }
            }
            if let Some(ref last_modified) = meta.last_modified {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last_modified) {
                    meta.last_modified =
                        Some(format_epoch_datetime(dt.with_timezone(&Utc)).to_string());
                }
            }
        }
    }
    user
}

/// Convert datetime strings in Group metadata to epoch format if needed
///
/// This function modifies the Group's meta.created and meta.lastModified fields
/// to use epoch timestamps when the datetime format is set to "epoch".
pub fn convert_group_datetime_for_response(
    mut group: crate::models::Group,
    format_type: &str,
) -> crate::models::Group {
    if format_type == "epoch" {
        if let Some(meta) = group.meta_mut() {
            if let Some(ref created) = meta.created {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(created) {
                    meta.created = Some(format_epoch_datetime(dt.with_timezone(&Utc)).to_string());
                }
            }
            if let Some(ref last_modified) = meta.last_modified {
                if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(last_modified) {
                    meta.last_modified =
                        Some(format_epoch_datetime(dt.with_timezone(&Utc)).to_string());
                }
            }
        }
    }
    group
}

/// Handle User groups field inclusion based on compatibility settings
///
/// This function controls whether to include the groups field at all in User responses.
/// - true: Include groups field (may be empty array or populated)
/// - false: Remove groups field entirely from the response
pub fn handle_user_groups_inclusion_for_response(
    mut user: crate::models::User,
    include_user_groups: bool,
) -> crate::models::User {
    if !include_user_groups {
        // Remove groups field entirely
        user.base.groups = None;
    }
    user
}

/// Handle empty groups arrays based on compatibility settings for User responses
///
/// This function modifies User's groups array based on the show_empty_groups_members setting.
/// - true: Keep empty arrays as []
/// - false: Remove empty arrays from the response
/// Note: This only applies if groups field is included (see handle_user_groups_inclusion_for_response)
/// IMPORTANT: Only operates on existing groups, respects include_user_groups setting
pub fn handle_user_empty_groups_for_response(
    mut user: crate::models::User,
    show_empty_groups_members: bool,
) -> crate::models::User {
    // Only modify behavior if groups field is present
    if let Some(ref groups) = user.base.groups {
        if show_empty_groups_members {
            // Keep empty groups array as is (already Some([]))
        } else {
            // Remove empty groups array
            if groups.is_empty() {
                user.base.groups = None;
            }
        }
    } else {
        // If groups is None, it means include_user_groups: false
        // Don't add it back regardless of show_empty_groups_members setting
    }
    user
}

/// Handle empty members arrays based on compatibility settings for Group responses
///
/// This function modifies Group's members array based on the show_empty_groups_members setting.
/// - true: Keep empty arrays as []
/// - false: Remove empty arrays from the response
pub fn handle_group_empty_members_for_response(
    mut group: crate::models::Group,
    show_empty_groups_members: bool,
) -> crate::models::Group {
    if show_empty_groups_members {
        // Ensure empty members array is shown as []
        if group.base.members.is_none() {
            group.base.members = Some(Vec::new());
        }
    } else {
        // Remove empty members array
        if let Some(ref members) = group.base.members {
            if members.is_empty() {
                group.base.members = None;
            }
        }
    }
    group
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Timelike};

    #[test]
    fn test_scim_datetime_format() {
        // Test with a known timestamp
        let dt = Utc
            .with_ymd_and_hms(2025, 6, 14, 10, 3, 54)
            .unwrap()
            .with_nanosecond(374_572_153)
            .unwrap();

        let formatted = format_scim_datetime(dt);
        assert_eq!(formatted, "2025-06-14T10:03:54.374Z");
    }

    #[test]
    fn test_current_scim_datetime_format() {
        let formatted = current_scim_datetime();

        // Check format by verifying it's a valid timestamp and has expected length
        assert_eq!(formatted.len(), 24); // YYYY-MM-DDTHH:MM:SS.sssZ format
        assert!(formatted.ends_with('Z'), "Should end with Z");
        assert!(formatted.contains('T'), "Should contain T separator");
        assert!(
            formatted.chars().nth(19) == Some('.'),
            "Should have . before milliseconds"
        );

        // Verify it can be parsed back to a valid DateTime
        use chrono::DateTime;
        assert!(
            DateTime::parse_from_rfc3339(&formatted).is_ok(),
            "Should be valid RFC3339"
        );
    }

    #[test]
    fn test_epoch_datetime_format() {
        // Test with a known timestamp
        let dt = Utc
            .with_ymd_and_hms(2025, 6, 14, 10, 3, 54)
            .unwrap()
            .with_nanosecond(374_572_153)
            .unwrap();

        let epoch = format_epoch_datetime(dt);
        assert_eq!(epoch, 1749895434374); // Expected epoch milliseconds
    }

    #[test]
    fn test_format_datetime_with_type() {
        let dt = Utc
            .with_ymd_and_hms(2025, 6, 14, 10, 3, 54)
            .unwrap()
            .with_nanosecond(374_572_153)
            .unwrap();

        // Test RFC3339 format
        let rfc3339 = format_datetime_with_type(dt, "rfc3339");
        assert_eq!(rfc3339, "2025-06-14T10:03:54.374Z");

        // Test epoch format
        let epoch = format_datetime_with_type(dt, "epoch");
        assert_eq!(epoch, "1749895434374");

        // Test default fallback
        let default = format_datetime_with_type(dt, "unknown");
        assert_eq!(default, "2025-06-14T10:03:54.374Z");
    }

    #[test]
    fn test_handle_user_groups_inclusion_for_response() {
        use crate::models::User;
        use scim_v2::models::user::Group as UserGroup;

        // Create a test user with groups
        let mut user = User::default();
        user.base.groups = Some(vec![UserGroup {
            value: Some("group1".to_string()),
            ref_: Some("/Groups/group1".to_string()),
            display: Some("Group 1".to_string()),
            type_: Some("direct".to_string()),
        }]);

        // Test include_user_groups = true (should preserve groups)
        let result = handle_user_groups_inclusion_for_response(user.clone(), true);
        assert!(result.base.groups.is_some());
        assert_eq!(result.base.groups.as_ref().unwrap().len(), 1);

        // Test include_user_groups = false (should remove groups)
        let result = handle_user_groups_inclusion_for_response(user, false);
        assert!(result.base.groups.is_none());
    }

    #[test]
    fn test_handle_user_empty_groups_for_response() {
        use crate::models::User;

        // Test with None groups (include_user_groups: false) and show_empty_groups_members = true
        // Should remain None (respects include_user_groups setting)
        let mut user = User::default();
        user.base.groups = None;

        let result = handle_user_empty_groups_for_response(user, true);
        assert!(
            result.base.groups.is_none(),
            "None groups should remain None regardless of show_empty_groups_members"
        );

        // Test with None groups and show_empty_groups_members = false
        let mut user = User::default();
        user.base.groups = None;

        let result = handle_user_empty_groups_for_response(user, false);
        assert!(result.base.groups.is_none());

        // Test with empty groups and show_empty_groups_members = true
        let mut user = User::default();
        user.base.groups = Some(Vec::new());

        let result = handle_user_empty_groups_for_response(user, true);
        assert!(result.base.groups.is_some());
        assert!(result.base.groups.as_ref().unwrap().is_empty());

        // Test with empty groups and show_empty_groups_members = false
        let mut user = User::default();
        user.base.groups = Some(Vec::new());

        let result = handle_user_empty_groups_for_response(user, false);
        assert!(result.base.groups.is_none());
    }

    #[test]
    fn test_handle_group_empty_members_for_response() {
        use crate::models::Group;

        // Test with None members and show_empty_groups_members = true
        let mut group = Group::default();
        group.base.members = None;

        let result = handle_group_empty_members_for_response(group, true);
        assert!(result.base.members.is_some());
        assert!(result.base.members.as_ref().unwrap().is_empty());

        // Test with None members and show_empty_groups_members = false
        let mut group = Group::default();
        group.base.members = None;

        let result = handle_group_empty_members_for_response(group, false);
        assert!(result.base.members.is_none());

        // Test with empty members and show_empty_groups_members = true
        let mut group = Group::default();
        group.base.members = Some(Vec::new());

        let result = handle_group_empty_members_for_response(group, true);
        assert!(result.base.members.is_some());
        assert!(result.base.members.as_ref().unwrap().is_empty());

        // Test with empty members and show_empty_groups_members = false
        let mut group = Group::default();
        group.base.members = Some(Vec::new());

        let result = handle_group_empty_members_for_response(group, false);
        assert!(result.base.members.is_none());
    }
}
