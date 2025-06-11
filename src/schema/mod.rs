pub mod definitions;
pub mod normalization;
pub mod validation;

// Re-export commonly used items from definitions
pub use definitions::*;
// Re-export validation functions that are actually used
pub use validation::{enforce_single_primary, validate_user};
