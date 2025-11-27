//! Baseline verification

use crate::database::{BaselineDatabase, StoredFileEntry};
use crate::hasher::{HashAlgorithm, Hasher};
use protectinator_core::Result;
use std::collections::HashMap;
use std::path::Path;

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
    /// Error reading file
    Error(String),
}

/// File verification result with path
#[derive(Debug, Clone)]
pub struct FileVerification {
    pub path: String,
    pub result: VerificationResult,
}

/// Baseline verifier
pub struct BaselineVerifier {
    hasher: Hasher,
}

impl BaselineVerifier {
    /// Create a new verifier
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            hasher: Hasher::new(algorithm),
        }
    }

    /// Verify files against a baseline database
    pub fn verify(&self, db: &BaselineDatabase) -> Result<Vec<FileVerification>> {
        let baseline_files = db.get_all_files()?;
        let mut results = Vec::new();

        // Create a map for quick lookup
        let baseline_map: HashMap<&str, &StoredFileEntry> = baseline_files
            .iter()
            .map(|e| (e.path.as_str(), e))
            .collect();

        // Check each file in baseline
        for entry in &baseline_files {
            let path = Path::new(&entry.path);

            if !path.exists() {
                results.push(FileVerification {
                    path: entry.path.clone(),
                    result: VerificationResult::Deleted,
                });
                continue;
            }

            // Hash current file
            match self.hasher.hash_file(path) {
                Ok(current_hash) => {
                    if current_hash != entry.hash {
                        results.push(FileVerification {
                            path: entry.path.clone(),
                            result: VerificationResult::Modified {
                                expected: entry.hash.clone(),
                                actual: current_hash,
                            },
                        });
                    } else {
                        // Check permissions on Unix
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(metadata) = path.metadata() {
                                let current_perms = metadata.permissions().mode();
                                if current_perms != entry.permissions {
                                    results.push(FileVerification {
                                        path: entry.path.clone(),
                                        result: VerificationResult::PermissionsChanged {
                                            expected: entry.permissions,
                                            actual: current_perms,
                                        },
                                    });
                                    continue;
                                }
                            }
                        }

                        results.push(FileVerification {
                            path: entry.path.clone(),
                            result: VerificationResult::Match,
                        });
                    }
                }
                Err(e) => {
                    results.push(FileVerification {
                        path: entry.path.clone(),
                        result: VerificationResult::Error(e.to_string()),
                    });
                }
            }
        }

        Ok(results)
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
                VerificationResult::Error(_) => summary.errors += 1,
            }
        }

        summary
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
    pub errors: usize,
}

impl VerificationSummary {
    /// Check if all files match
    pub fn all_match(&self) -> bool {
        self.modified == 0
            && self.added == 0
            && self.deleted == 0
            && self.permissions_changed == 0
            && self.errors == 0
    }

    /// Total number of changes detected
    pub fn total_changes(&self) -> usize {
        self.modified + self.added + self.deleted + self.permissions_changed
    }
}
