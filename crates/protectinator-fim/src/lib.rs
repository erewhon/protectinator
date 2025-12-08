//! File Integrity Monitoring for Protectinator
//!
//! Provides file hashing, baseline creation, and verification capabilities.
//!
//! # Features
//!
//! - Multiple hash algorithms (SHA-256, SHA-512, BLAKE3)
//! - Parallel file hashing with rayon
//! - SQLite-based baseline storage
//! - Verification with detailed change detection
//! - Baseline diff comparison
//!
//! # Example
//!
//! ```no_run
//! use protectinator_fim::{FileScanner, BaselineDatabase, BaselineVerifier, HashAlgorithm};
//! use std::path::Path;
//!
//! // Create a baseline
//! let scanner = FileScanner::new(HashAlgorithm::Sha256);
//! let entries = scanner.scan_parallel(Path::new("/path/to/scan")).unwrap();
//!
//! let mut db = BaselineDatabase::create(Path::new("baseline.db")).unwrap();
//! db.add_files(&entries).unwrap();
//!
//! // Later, verify against baseline
//! let db = BaselineDatabase::open(Path::new("baseline.db")).unwrap();
//! let verifier = BaselineVerifier::new(HashAlgorithm::Sha256);
//! let results = verifier.verify(&db).unwrap();
//! ```

pub mod database;
pub mod hasher;
pub mod scanner;
pub mod verifier;

pub use database::{BaselineDatabase, StoredFileEntry};
pub use hasher::{HashAlgorithm, Hasher};
pub use scanner::{FileEntry, FileScanner, FileType, ScanStats};
pub use verifier::{
    diff_baselines, BaselineDiff, BaselineVerifier, DiffType, FileVerification,
    FimProgressCallback, FimProgressInfo, VerificationResult, VerificationSummary, VerifierConfig,
};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource, Result, SecurityCheck,
    Severity,
};
use std::path::PathBuf;
use std::sync::Arc;

/// File integrity monitoring check provider
pub struct FimProvider {
    baseline_path: Option<PathBuf>,
    scan_paths: Vec<PathBuf>,
    algorithm: HashAlgorithm,
}

impl FimProvider {
    /// Create a new FIM provider
    pub fn new() -> Self {
        Self {
            baseline_path: None,
            scan_paths: Vec::new(),
            algorithm: HashAlgorithm::Sha256,
        }
    }

    /// Set the baseline database path
    pub fn with_baseline(mut self, path: PathBuf) -> Self {
        self.baseline_path = Some(path);
        self
    }

    /// Add paths to scan
    pub fn with_scan_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.scan_paths = paths;
        self
    }

    /// Set hash algorithm
    pub fn with_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = algorithm;
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
        let mut checks: Vec<Arc<dyn SecurityCheck>> = Vec::new();

        // Only add verification check if we have a baseline
        if let Some(baseline_path) = &self.baseline_path {
            checks.push(Arc::new(FimVerificationCheck {
                baseline_path: baseline_path.clone(),
                algorithm: self.algorithm,
            }));
        }

        checks
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check that verifies files against a baseline
struct FimVerificationCheck {
    baseline_path: PathBuf,
    algorithm: HashAlgorithm,
}

impl SecurityCheck for FimVerificationCheck {
    fn id(&self) -> &str {
        "fim-verification"
    }

    fn name(&self) -> &str {
        "File Integrity Verification"
    }

    fn description(&self) -> &str {
        "Verifies files against a stored baseline to detect unauthorized modifications"
    }

    fn category(&self) -> &str {
        "integrity"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        if self.baseline_path.exists() {
            Applicability::Applicable
        } else {
            Applicability::NotApplicable(format!(
                "Baseline not found: {}",
                self.baseline_path.display()
            ))
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let db = BaselineDatabase::open(&self.baseline_path)?;
        let verifier = BaselineVerifier::new(self.algorithm);
        let results = verifier.verify(&db)?;

        let mut findings = Vec::new();

        for result in results {
            if let Some(finding) = verification_to_finding(&result) {
                findings.push(finding);
            }
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(60)
    }
}

/// Convert a verification result to a security finding
fn verification_to_finding(result: &FileVerification) -> Option<Finding> {
    match &result.result {
        VerificationResult::Match => None,
        VerificationResult::Modified { expected, actual } => Some(
            Finding::new(
                "fim-modified",
                "File Modified",
                format!(
                    "File has been modified. Expected hash: {}, Actual: {}",
                    &expected[..16],
                    &actual[..16]
                ),
                Severity::High,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Modified,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::Deleted => Some(
            Finding::new(
                "fim-deleted",
                "File Deleted",
                "File has been deleted from the system",
                Severity::High,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Deleted,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::PermissionsChanged { expected, actual } => Some(
            Finding::new(
                "fim-permissions",
                "Permissions Changed",
                format!(
                    "File permissions changed from {:o} to {:o}",
                    expected, actual
                ),
                Severity::Medium,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::PermissionsChanged,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::OwnerChanged {
            expected_uid,
            expected_gid,
            actual_uid,
            actual_gid,
        } => Some(
            Finding::new(
                "fim-owner",
                "Ownership Changed",
                format!(
                    "File ownership changed from {:?}:{:?} to {}:{}",
                    expected_uid, expected_gid, actual_uid, actual_gid
                ),
                Severity::Medium,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::OwnershipChanged,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::SizeChanged { expected, actual } => Some(
            Finding::new(
                "fim-size",
                "File Size Changed",
                format!("File size changed from {} to {} bytes", expected, actual),
                Severity::High,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Modified,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::TypeChanged { expected, actual } => Some(
            Finding::new(
                "fim-type",
                "File Type Changed",
                format!("File type changed from {:?} to {:?}", expected, actual),
                Severity::Critical,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Modified,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::Added => Some(
            Finding::new(
                "fim-added",
                "New File Detected",
                "New file detected that was not in baseline",
                Severity::Medium,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Added,
                },
            )
            .with_resource(&result.path),
        ),
        VerificationResult::Error(e) => Some(
            Finding::new(
                "fim-error",
                "Verification Error",
                format!("Error verifying file: {}", e),
                Severity::Low,
                FindingSource::FileIntegrity {
                    baseline_path: String::new(),
                    change_type: protectinator_core::FileChangeType::Modified,
                },
            )
            .with_resource(&result.path),
        ),
    }
}

/// Format file size in human-readable form
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
