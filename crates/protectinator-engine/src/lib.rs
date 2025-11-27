//! Orchestration engine for Protectinator security checks
//!
//! Coordinates running multiple check providers and aggregating results.

mod runner;
mod output;

pub use runner::*;
pub use output::*;
