//! Protectinator Core
//!
//! Core types, traits, and error handling for the Protectinator security monitoring tool.

pub mod config;
pub mod error;
pub mod report;
pub mod traits;

pub use config::*;
pub use error::{ProtectinatorError, Result};
pub use report::*;
pub use traits::*;
