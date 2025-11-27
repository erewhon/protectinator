//! Persistence Mechanism Scanner for Protectinator
//!
//! Scans for malware persistence mechanisms on Linux and macOS.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

/// Persistence mechanism check provider
pub struct PersistenceProvider;

impl PersistenceProvider {
    /// Create a new persistence provider
    pub fn new() -> Self {
        Self
    }
}

impl Default for PersistenceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for PersistenceProvider {
    fn name(&self) -> &str {
        "persistence"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // Persistence checks will be added in Phase 6a
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
