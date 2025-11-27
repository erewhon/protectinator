//! System Hardening Checks for Protectinator
//!
//! Provides security configuration checks for Linux and macOS.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

pub mod checks;

/// System hardening check provider
pub struct HardeningProvider {
    categories: Vec<String>,
    skip_checks: Vec<String>,
}

impl HardeningProvider {
    /// Create a new hardening provider
    pub fn new() -> Self {
        Self {
            categories: Vec::new(),
            skip_checks: Vec::new(),
        }
    }

    /// Filter by categories
    pub fn with_categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }

    /// Skip specific checks
    pub fn skip(mut self, checks: Vec<String>) -> Self {
        self.skip_checks = checks;
        self
    }
}

impl Default for HardeningProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for HardeningProvider {
    fn name(&self) -> &str {
        "hardening"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // Hardening checks will be added in Phase 3
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
