pub mod definitions;
pub mod normalization;
pub mod validation;

// Re-export commonly used items from definitions
pub use definitions::*;
// Re-export validation functions that are actually used
pub use validation::{
    attribute_has_primary_subattribute, dedupe_multivalued_attributes, enforce_single_primary,
    reject_conflicting_primaries_in_operation_value, validate_addresses_primary_constraint,
    validate_required_attributes_present, validate_user,
};
