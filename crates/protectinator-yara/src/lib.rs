//! YARA Scanning for Protectinator
//!
//! Scans files for malware signatures using YARA rules.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

/// YARA scanning check provider
pub struct YaraProvider {
    rule_paths: Vec<std::path::PathBuf>,
    scan_paths: Vec<std::path::PathBuf>,
}

impl YaraProvider {
    /// Create a new YARA provider
    pub fn new() -> Self {
        Self {
            rule_paths: Vec::new(),
            scan_paths: Vec::new(),
        }
    }

    /// Add rule paths
    pub fn with_rules(mut self, paths: Vec<std::path::PathBuf>) -> Self {
        self.rule_paths = paths;
        self
    }

    /// Add scan paths
    pub fn with_scan_paths(mut self, paths: Vec<std::path::PathBuf>) -> Self {
        self.scan_paths = paths;
        self
    }
}

impl Default for YaraProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for YaraProvider {
    fn name(&self) -> &str {
        "yara"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // YARA checks will be added in Phase 6c
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
