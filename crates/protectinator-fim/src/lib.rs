//! File Integrity Monitoring for Protectinator
//!
//! Provides file hashing, baseline creation, and verification capabilities.

pub mod hasher;
pub mod scanner;
pub mod database;
pub mod verifier;

pub use hasher::{HashAlgorithm, Hasher};
pub use scanner::FileScanner;
pub use database::BaselineDatabase;
pub use verifier::BaselineVerifier;

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

/// File integrity monitoring check provider
pub struct FimProvider {
    baseline_path: Option<std::path::PathBuf>,
}

impl FimProvider {
    /// Create a new FIM provider
    pub fn new() -> Self {
        Self { baseline_path: None }
    }

    /// Set the baseline database path
    pub fn with_baseline(mut self, path: std::path::PathBuf) -> Self {
        self.baseline_path = Some(path);
        self
    }
}

impl Default for FimProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for FimProvider {
    fn name(&self) -> &str {
        "fim"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // FIM checks will be added in Phase 2
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
