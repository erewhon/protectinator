//! OS File Verification for Protectinator
//!
//! Verifies OS files against known-good hash manifests and uses package manager
//! built-in verification to detect tampering.
//!
//! # Features
//!
//! - Package manager integration (dpkg, rpm, pacman, pkgutil)
//! - Hash-based verification using SHA-256 or BLAKE3
//! - Manifest support for custom verification
//! - Parallel file verification
//!
//! # Example
//!
//! ```no_run
//! use protectinator_osverify::{VerificationEngine, VerifyConfig, VerificationMode};
//!
//! let config = VerifyConfig {
//!     mode: VerificationMode::PackageManager,
//!     ..Default::default()
//! };
//!
//! let engine = VerificationEngine::new(config);
//! let summary = engine.verify().expect("verification failed");
//!
//! println!("Verified {} files", summary.total_files);
//! if summary.passed() {
//!     println!("All files OK!");
//! } else {
//!     println!("Found {} modified files", summary.files_modified);
//! }
//! ```

pub mod engine;
pub mod error;
pub mod manifest;
pub mod pkgmgr;

pub use engine::{VerificationEngine, VerificationMode, VerifyConfig, VerifyIssue, VerifySummary};
pub use error::{OsVerifyError, Result};
pub use manifest::{FileEntry, HashAlgorithm, Manifest};
pub use pkgmgr::{
    detect_package_manager, get_package_manager, FileStatus, PackageManager, PackageManagerType,
    VerificationResult,
};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource,
    ProtectinatorError, Result as CoreResult, SecurityCheck, Severity,
};
use std::sync::Arc;

/// OS verification check provider
pub struct OsVerifyProvider {
    config: VerifyConfig,
    manifest: Option<Manifest>,
}

impl OsVerifyProvider {
    /// Create a new OS verification provider
    pub fn new() -> Self {
        Self {
            config: VerifyConfig::default(),
            manifest: None,
        }
    }

    /// Add manifest sources
    pub fn with_manifest(mut self, manifest: Manifest) -> Self {
        self.manifest = Some(manifest);
        self
    }

    /// Configure verification mode
    pub fn with_mode(mut self, mode: VerificationMode) -> Self {
        self.config.mode = mode;
        self
    }

    /// Set whether to skip config files
    pub fn skip_config(mut self, skip: bool) -> Self {
        self.config.skip_config = skip;
        self
    }

    /// Set packages to verify (empty = all)
    pub fn with_packages(mut self, packages: Vec<String>) -> Self {
        self.config.packages = packages;
        self
    }

    /// Run verification and return summary
    pub fn verify(&self) -> Result<VerifySummary> {
        let mut engine = VerificationEngine::new(self.config.clone());
        if let Some(ref manifest) = self.manifest {
            engine = engine.with_manifest(manifest.clone());
        }
        engine.verify()
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
        vec![Arc::new(OsVerifySecurityCheck {
            config: self.config.clone(),
        })]
    }

    fn refresh(&mut self) -> CoreResult<()> {
        Ok(())
    }
}

/// Security check that runs OS file verification
struct OsVerifySecurityCheck {
    config: VerifyConfig,
}

impl SecurityCheck for OsVerifySecurityCheck {
    fn id(&self) -> &str {
        "os-file-verification"
    }

    fn name(&self) -> &str {
        "OS File Verification"
    }

    fn description(&self) -> &str {
        "Verifies OS files against known-good hashes to detect tampering"
    }

    fn category(&self) -> &str {
        "integrity"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        // Check if package manager is available
        match detect_package_manager() {
            PackageManagerType::Unknown => Applicability::NotApplicable(
                "No supported package manager found".to_string(),
            ),
            _ => Applicability::Applicable,
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> CoreResult<Vec<Finding>> {
        let engine = VerificationEngine::new(self.config.clone());
        let summary = engine.verify().map_err(|e| {
            ProtectinatorError::Other(format!("Verification failed: {}", e))
        })?;

        let mut findings = Vec::new();

        for issue in &summary.issues {
            let severity = match issue.status {
                FileStatus::Modified | FileStatus::Missing => Severity::High,
                FileStatus::Replaced => Severity::Critical,
                FileStatus::PermissionsChanged => Severity::Medium,
                _ => Severity::Low,
            };

            let title = match issue.status {
                FileStatus::Modified => "OS file modified",
                FileStatus::Missing => "OS file missing",
                FileStatus::Replaced => "OS file replaced",
                FileStatus::PermissionsChanged => "OS file permissions changed",
                _ => "OS file integrity issue",
            };

            let description = match issue.status {
                FileStatus::Modified => format!("File has been modified: {}", issue.path),
                FileStatus::Missing => format!("File is missing: {}", issue.path),
                FileStatus::Replaced => format!("File was replaced: {}", issue.path),
                FileStatus::PermissionsChanged => {
                    format!("File permissions changed: {}", issue.path)
                }
                _ => format!("File issue: {}", issue.path),
            };

            let source = FindingSource::OsVerification {
                manifest_source: issue
                    .package
                    .clone()
                    .unwrap_or_else(|| "package-manager".to_string()),
            };

            findings.push(Finding::new(
                "os-file-modified",
                title,
                description,
                severity,
                source,
            ));
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}
