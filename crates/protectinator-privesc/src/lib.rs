//! Privilege Escalation Path Finder for Protectinator
//!
//! Finds potential privilege escalation vectors on Linux and macOS.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Privilege escalation check provider
pub struct PrivescProvider;

impl PrivescProvider {
    /// Create a new privilege escalation provider
    pub fn new() -> Self {
        Self
    }
}

impl Default for PrivescProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for PrivescProvider {
    fn name(&self) -> &str {
        "privesc"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // Privilege escalation checks will be added in Phase 6d
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
