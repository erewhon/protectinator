//! OS File Verification for Protectinator
//!
//! Verifies OS files against known-good hash manifests.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

/// OS verification check provider
pub struct OsVerifyProvider {
    manifest_sources: Vec<String>,
    use_package_manager: bool,
}

impl OsVerifyProvider {
    /// Create a new OS verification provider
    pub fn new() -> Self {
        Self {
            manifest_sources: Vec::new(),
            use_package_manager: true,
        }
    }

    /// Add manifest sources
    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.manifest_sources = sources;
        self
    }

    /// Set whether to use package manager verification
    pub fn use_package_manager(mut self, use_pm: bool) -> Self {
        self.use_package_manager = use_pm;
        self
    }
}

impl Default for OsVerifyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for OsVerifyProvider {
    fn name(&self) -> &str {
        "osverify"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // OS verification checks will be added in Phase 5
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
