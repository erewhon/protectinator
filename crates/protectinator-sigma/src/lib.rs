//! Sigma Rules Engine for Protectinator
//!
//! Provides Sigma rule parsing, log source adapters, and rule evaluation.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

/// Sigma rules check provider
pub struct SigmaProvider {
    rule_paths: Vec<std::path::PathBuf>,
    use_embedded: bool,
}

impl SigmaProvider {
    /// Create a new Sigma provider
    pub fn new() -> Self {
        Self {
            rule_paths: Vec::new(),
            use_embedded: true,
        }
    }

    /// Add a rule path
    pub fn with_rule_path(mut self, path: std::path::PathBuf) -> Self {
        self.rule_paths.push(path);
        self
    }

    /// Set whether to use embedded rules
    pub fn use_embedded(mut self, use_embedded: bool) -> Self {
        self.use_embedded = use_embedded;
        self
    }
}

impl Default for SigmaProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for SigmaProvider {
    fn name(&self) -> &str {
        "sigma"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // Sigma checks will be added in Phase 4
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
