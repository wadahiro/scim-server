pub mod definitions;
pub mod normalization;
pub mod validation;

// Re-export commonly used items from definitions
pub use definitions::*;
// Re-export validation functions that are actually used
pub use validation::{
    dedupe_multivalued_attributes, enforce_single_primary, validate_addresses_primary_constraint,
    validate_required_attributes_present, validate_user,
};
