//! Baseline verification

use crate::database::{BaselineDatabase, StoredFileEntry};
use crate::hasher::{HashAlgorithm, Hasher};
use crate::scanner::FileType;
use protectinator_core::{ProgressReporter, Result};
use rayon::prelude::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Progress information passed to the progress callback
#[derive(Debug, Clone)]
pub struct FimProgressInfo {
    /// Number of files checked so far
    pub files_checked: usize,
    /// Total number of files to check
    pub total_files: usize,
    /// Total bytes checked so far
    pub bytes_checked: u64,
    /// Elapsed time since verification started
    pub elapsed: Duration,
}

/// Callback type for FIM progress reporting
pub type FimProgressCallback = Arc<dyn Fn(FimProgressInfo) + Send + Sync>;

/// Result of verifying a file against baseline
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// File matches baseline
    Match,
    /// File was modified (hash changed)
    Modified { expected: String, actual: String },
    /// File was added (not in baseline)
    Added,
    /// File was deleted (in baseline but not on disk)
    Deleted,
    /// Permissions changed
    PermissionsChanged { expected: u32, actual: u32 },
    /// Owner changed (Unix only)
    OwnerChanged {
        expected_uid: Option<u32>,
        expected_gid: Option<u32>,
        actual_uid: u32,
        actual_gid: u32,
    },
    /// Size changed (quick check before full hash)
    SizeChanged { expected: u64, actual: u64 },
    /// File type changed
    TypeChanged {
        expected: FileType,
        actual: FileType,
    },
    /// Error reading file
    Error(String),
}

impl VerificationResult {
    /// Check if this result indicates a change
    pub fn is_change(&self) -> bool {
        !matches!(self, VerificationResult::Match)
    }

    /// Get severity of the change (for sorting)
    pub fn severity(&self) -> u8 {
        match self {
            VerificationResult::Match => 0,
            VerificationResult::PermissionsChanged { .. } => 1,
            VerificationResult::OwnerChanged { .. } => 2,
            VerificationResult::SizeChanged { .. } => 3,
            VerificationResult::TypeChanged { .. } => 4,
            VerificationResult::Modified { .. } => 5,
            VerificationResult::Added => 6,
            VerificationResult::Deleted => 7,
            VerificationResult::Error(_) => 8,
        }
    }
}

/// File verification result with path
#[derive(Debug, Clone)]
pub struct FileVerification {
    pub path: String,
    pub result: VerificationResult,
}

/// Baseline verifier configuration
#[derive(Clone)]
pub struct VerifierConfig {
    /// Check file permissions
    pub check_permissions: bool,
    /// Check file ownership (Unix)
    pub check_ownership: bool,
    /// Use quick size check before hashing
    pub quick_check: bool,
    /// Use parallel verification
    pub parallel: bool,
    /// Progress callback for cumulative progress reporting
    pub progress_callback: Option<FimProgressCallback>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            check_permissions: true,
            check_ownership: true,
            quick_check: true,
            parallel: true,
            progress_callback: None,
        }
    }
}

impl std::fmt::Debug for VerifierConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierConfig")
            .field("check_permissions", &self.check_permissions)
            .field("check_ownership", &self.check_ownership)
            .field("quick_check", &self.quick_check)
            .field("parallel", &self.parallel)
            .field("progress_callback", &self.progress_callback.is_some())
            .finish()
    }
}

/// Baseline verifier
pub struct BaselineVerifier {
    hasher: Hasher,
    config: VerifierConfig,
}

impl BaselineVerifier {
    /// Create a new verifier
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            hasher: Hasher::new(algorithm),
            config: VerifierConfig::default(),
        }
    }

    /// Create a new verifier with custom configuration
    pub fn with_config(algorithm: HashAlgorithm, config: VerifierConfig) -> Self {
        Self {
            hasher: Hasher::new(algorithm),
            config,
        }
    }

    /// Verify files against a baseline database
    pub fn verify(&self, db: &BaselineDatabase) -> Result<Vec<FileVerification>> {
        self.verify_with_progress(db, None)
    }

    /// Verify files with progress reporting
    pub fn verify_with_progress(
        &self,
        db: &BaselineDatabase,
        progress: Option<&dyn ProgressReporter>,
    ) -> Result<Vec<FileVerification>> {
        let baseline_files = db.get_all_files()?;
        let total_files = baseline_files.len();

        if let Some(p) = progress {
            p.phase_started("Verifying files", total_files);
        }

        let results = if self.config.parallel {
            self.verify_parallel(&baseline_files, total_files, progress)
        } else {
            self.verify_sequential(&baseline_files, total_files, progress)
        };

        if let Some(p) = progress {
            p.phase_completed("Verifying files");
        }

        Ok(results)
    }

    /// Verify files sequentially
    fn verify_sequential(
        &self,
        baseline_files: &[StoredFileEntry],
        total_files: usize,
        progress: Option<&dyn ProgressReporter>,
    ) -> Vec<FileVerification> {
        let mut results = Vec::new();
        let start = Instant::now();
        let mut bytes_checked: u64 = 0;

        for (i, entry) in baseline_files.iter().enumerate() {
            if let Some(p) = progress {
                p.progress(i + 1, &entry.path);
            }

            // Call progress callback if set
            if let Some(ref callback) = self.config.progress_callback {
                bytes_checked += entry.size;
                callback(FimProgressInfo {
                    files_checked: i + 1,
                    total_files,
                    bytes_checked,
                    elapsed: start.elapsed(),
                });
            }

            let result = self.verify_file(entry);
            results.push(result);
        }

        results
    }

    /// Verify files in parallel
    fn verify_parallel(
        &self,
        baseline_files: &[StoredFileEntry],
        total_files: usize,
        progress: Option<&dyn ProgressReporter>,
    ) -> Vec<FileVerification> {
        let counter = AtomicUsize::new(0);
        let bytes_counter = AtomicU64::new(0);
        let algorithm = self.hasher.algorithm();
        let progress_callback = self.config.progress_callback.clone();
        let start = Instant::now();

        baseline_files
            .par_iter()
            .map(|entry| {
                let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
                let current_bytes = bytes_counter.fetch_add(entry.size, Ordering::SeqCst) + entry.size;

                if let Some(p) = progress {
                    if current % 100 == 0 {
                        p.progress(current, &entry.path);
                    }
                }

                // Call progress callback if set
                if let Some(ref callback) = progress_callback {
                    callback(FimProgressInfo {
                        files_checked: current,
                        total_files,
                        bytes_checked: current_bytes,
                        elapsed: start.elapsed(),
                    });
                }

                // Create a new hasher for this thread
                let verifier = BaselineVerifier {
                    hasher: Hasher::new(algorithm),
                    config: self.config.clone(),
                };
                verifier.verify_file(entry)
            })
            .collect()
    }

    /// Verify a single file against its baseline entry
    fn verify_file(&self, entry: &StoredFileEntry) -> FileVerification {
        let path = Path::new(&entry.path);

        // Check if file exists
        if !path.exists() {
            return FileVerification {
                path: entry.path.clone(),
                result: VerificationResult::Deleted,
            };
        }

        // Get current metadata
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return FileVerification {
                    path: entry.path.clone(),
                    result: VerificationResult::Error(e.to_string()),
                };
            }
        };

        // Quick size check
        if self.config.quick_check && metadata.len() != entry.size {
            return FileVerification {
                path: entry.path.clone(),
                result: VerificationResult::SizeChanged {
                    expected: entry.size,
                    actual: metadata.len(),
                },
            };
        }

        // Check permissions (Unix)
        #[cfg(unix)]
        if self.config.check_permissions {
            use std::os::unix::fs::PermissionsExt;
            let current_perms = metadata.permissions().mode();
            if current_perms != entry.permissions {
                return FileVerification {
                    path: entry.path.clone(),
                    result: VerificationResult::PermissionsChanged {
                        expected: entry.permissions,
                        actual: current_perms,
                    },
                };
            }
        }

        // Check ownership (Unix)
        #[cfg(unix)]
        if self.config.check_ownership {
            use std::os::unix::fs::MetadataExt;
            let current_uid = metadata.uid();
            let current_gid = metadata.gid();

            let owner_changed = entry.uid.map(|u| u != current_uid).unwrap_or(false)
                || entry.gid.map(|g| g != current_gid).unwrap_or(false);

            if owner_changed {
                return FileVerification {
                    path: entry.path.clone(),
                    result: VerificationResult::OwnerChanged {
                        expected_uid: entry.uid,
                        expected_gid: entry.gid,
                        actual_uid: current_uid,
                        actual_gid: current_gid,
                    },
                };
            }
        }

        // Hash the file
        match self.hasher.hash_file(path) {
            Ok(current_hash) => {
                if current_hash != entry.hash {
                    FileVerification {
                        path: entry.path.clone(),
                        result: VerificationResult::Modified {
                            expected: entry.hash.clone(),
                            actual: current_hash,
                        },
                    }
                } else {
                    FileVerification {
                        path: entry.path.clone(),
                        result: VerificationResult::Match,
                    }
                }
            }
            Err(e) => FileVerification {
                path: entry.path.clone(),
                result: VerificationResult::Error(e.to_string()),
            },
        }
    }

    /// Get summary of verification results
    pub fn summarize(results: &[FileVerification]) -> VerificationSummary {
        let mut summary = VerificationSummary::default();

        for result in results {
            match &result.result {
                VerificationResult::Match => summary.matched += 1,
                VerificationResult::Modified { .. } => summary.modified += 1,
                VerificationResult::Added => summary.added += 1,
                VerificationResult::Deleted => summary.deleted += 1,
                VerificationResult::PermissionsChanged { .. } => summary.permissions_changed += 1,
                VerificationResult::OwnerChanged { .. } => summary.ownership_changed += 1,
                VerificationResult::SizeChanged { .. } => summary.size_changed += 1,
                VerificationResult::TypeChanged { .. } => summary.type_changed += 1,
                VerificationResult::Error(_) => summary.errors += 1,
            }
        }

        summary
    }

    /// Filter results to only show changes
    pub fn changes_only(results: Vec<FileVerification>) -> Vec<FileVerification> {
        results
            .into_iter()
            .filter(|r| r.result.is_change())
            .collect()
    }

    /// Sort results by severity (most severe first)
    pub fn sort_by_severity(results: &mut [FileVerification]) {
        results.sort_by(|a, b| b.result.severity().cmp(&a.result.severity()));
    }
}

impl Default for BaselineVerifier {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

/// Summary of verification results
#[derive(Debug, Clone, Default)]
pub struct VerificationSummary {
    pub matched: usize,
    pub modified: usize,
    pub added: usize,
    pub deleted: usize,
    pub permissions_changed: usize,
    pub ownership_changed: usize,
    pub size_changed: usize,
    pub type_changed: usize,
    pub errors: usize,
}

impl VerificationSummary {
    /// Check if all files match
    pub fn all_match(&self) -> bool {
        self.modified == 0
            && self.added == 0
            && self.deleted == 0
            && self.permissions_changed == 0
            && self.ownership_changed == 0
            && self.size_changed == 0
            && self.type_changed == 0
            && self.errors == 0
    }

    /// Total number of changes detected
    pub fn total_changes(&self) -> usize {
        self.modified
            + self.added
            + self.deleted
            + self.permissions_changed
            + self.ownership_changed
            + self.size_changed
            + self.type_changed
    }

    /// Total files checked
    pub fn total_files(&self) -> usize {
        self.matched + self.total_changes() + self.errors
    }
}

/// Compare two baselines and find differences
pub fn diff_baselines(
    db1: &BaselineDatabase,
    db2: &BaselineDatabase,
) -> Result<Vec<BaselineDiff>> {
    let files1 = db1.get_all_files()?;
    let files2 = db2.get_all_files()?;

    let map1: HashMap<&str, &StoredFileEntry> = files1.iter().map(|e| (e.path.as_str(), e)).collect();
    let map2: HashMap<&str, &StoredFileEntry> = files2.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut diffs = Vec::new();

    // Find files in db1 but not in db2, or modified
    for (path, entry1) in &map1 {
        if let Some(entry2) = map2.get(path) {
            if entry1.hash != entry2.hash {
                diffs.push(BaselineDiff {
                    path: path.to_string(),
                    diff_type: DiffType::Modified {
                        old_hash: entry1.hash.clone(),
                        new_hash: entry2.hash.clone(),
                        old_size: entry1.size,
                        new_size: entry2.size,
                    },
                });
            }
        } else {
            diffs.push(BaselineDiff {
                path: path.to_string(),
                diff_type: DiffType::Removed,
            });
        }
    }

    // Find files in db2 but not in db1 (added)
    for (path, _entry2) in &map2 {
        if !map1.contains_key(path) {
            diffs.push(BaselineDiff {
                path: path.to_string(),
                diff_type: DiffType::Added,
            });
        }
    }

    // Sort by path for consistent output
    diffs.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(diffs)
}

/// Difference between two baselines
#[derive(Debug, Clone)]
pub struct BaselineDiff {
    pub path: String,
    pub diff_type: DiffType,
}

/// Type of difference
#[derive(Debug, Clone)]
pub enum DiffType {
    Added,
    Removed,
    Modified {
        old_hash: String,
        new_hash: String,
        old_size: u64,
        new_size: u64,
    },
}
