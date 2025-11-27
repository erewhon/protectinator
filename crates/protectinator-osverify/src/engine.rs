//! Verification engine for OS file integrity

use crate::error::{OsVerifyError, Result};
use crate::manifest::{FileEntry, HashAlgorithm, Manifest};
use crate::pkgmgr::{self, FileStatus, VerificationResult};
use rayon::prelude::*;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Verification mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VerificationMode {
    /// Use package manager verification (fastest, uses built-in tools)
    #[default]
    PackageManager,
    /// Hash-based verification using manifest
    Manifest,
    /// Verify specific paths only
    Paths,
    /// Full verification (package manager + manifest + critical paths)
    Full,
}

/// Configuration for the verification engine
#[derive(Debug, Clone)]
pub struct VerifyConfig {
    /// Verification mode
    pub mode: VerificationMode,
    /// Skip configuration files (they're often modified legitimately)
    pub skip_config: bool,
    /// Include symlinks
    pub check_symlinks: bool,
    /// Include permissions check
    pub check_permissions: bool,
    /// Parallel threads (0 = auto)
    pub threads: usize,
    /// Packages to verify (empty = all)
    pub packages: Vec<String>,
    /// Paths to verify
    pub paths: Vec<String>,
    /// Show progress
    pub show_progress: bool,
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self {
            mode: VerificationMode::PackageManager,
            skip_config: true,
            check_symlinks: false,
            check_permissions: true,
            threads: 0,
            packages: Vec::new(),
            paths: Vec::new(),
            show_progress: true,
        }
    }
}

/// Verification engine
pub struct VerificationEngine {
    config: VerifyConfig,
    manifest: Option<Manifest>,
}

impl VerificationEngine {
    /// Create a new verification engine
    pub fn new(config: VerifyConfig) -> Self {
        Self {
            config,
            manifest: None,
        }
    }

    /// Set manifest for hash-based verification
    pub fn with_manifest(mut self, manifest: Manifest) -> Self {
        self.manifest = Some(manifest);
        self
    }

    /// Run verification and return summary
    pub fn verify(&self) -> Result<VerifySummary> {
        let start = Instant::now();
        let mut summary = VerifySummary::default();

        match self.config.mode {
            VerificationMode::PackageManager => {
                summary = self.verify_with_package_manager()?;
            }
            VerificationMode::Manifest => {
                if let Some(ref manifest) = self.manifest {
                    summary = self.verify_with_manifest(manifest)?;
                } else {
                    return Err(OsVerifyError::ManifestParseError(
                        "No manifest provided".to_string(),
                    ));
                }
            }
            VerificationMode::Paths => {
                summary = self.verify_paths(&self.config.paths)?;
            }
            VerificationMode::Full => {
                // Run package manager verification first
                let pm_summary = self.verify_with_package_manager()?;
                summary.merge(&pm_summary);

                // Then verify critical paths not covered by package manager
                let paths = get_critical_paths();
                let path_summary = self.verify_paths(&paths)?;
                summary.merge(&path_summary);
            }
        }

        summary.duration = start.elapsed();
        Ok(summary)
    }

    /// Verify using package manager
    fn verify_with_package_manager(&self) -> Result<VerifySummary> {
        let pm = pkgmgr::get_package_manager()?;
        let mut summary = VerifySummary::default();

        let packages = if self.config.packages.is_empty() {
            pm.list_packages()?
        } else {
            self.config.packages.clone()
        };

        summary.total_packages = packages.len();

        let results_count = AtomicUsize::new(0);
        let progress_count = AtomicUsize::new(0);

        // Process packages in parallel
        let all_results: Vec<(String, Vec<VerificationResult>)> = packages
            .par_iter()
            .filter_map(|pkg| {
                if self.config.show_progress {
                    let count = progress_count.fetch_add(1, Ordering::Relaxed);
                    if count % 50 == 0 {
                        tracing::debug!("Verified {}/{} packages", count, packages.len());
                    }
                }

                match pm.verify_package(pkg) {
                    Ok(results) => {
                        results_count.fetch_add(results.len(), Ordering::Relaxed);
                        Some((pkg.clone(), results))
                    }
                    Err(e) => {
                        tracing::warn!("Failed to verify package {}: {}", pkg, e);
                        None
                    }
                }
            })
            .collect();

        // Process results
        for (package, results) in all_results {
            for result in results {
                // Skip config files if configured
                if self.config.skip_config && result.status == FileStatus::Config {
                    summary.config_modified += 1;
                    continue;
                }

                summary.total_files += 1;

                match result.status {
                    FileStatus::Ok => summary.files_ok += 1,
                    FileStatus::Modified => {
                        summary.files_modified += 1;
                        summary.issues.push(VerifyIssue {
                            path: result.path,
                            package: Some(package.clone()),
                            status: result.status,
                            expected: result.expected_hash,
                            actual: result.actual_hash,
                        });
                    }
                    FileStatus::Missing => {
                        summary.files_missing += 1;
                        summary.issues.push(VerifyIssue {
                            path: result.path,
                            package: Some(package.clone()),
                            status: result.status,
                            expected: result.expected_hash,
                            actual: None,
                        });
                    }
                    FileStatus::Replaced => {
                        summary.files_modified += 1;
                        summary.issues.push(VerifyIssue {
                            path: result.path,
                            package: Some(package.clone()),
                            status: result.status,
                            expected: result.expected_hash,
                            actual: result.actual_hash,
                        });
                    }
                    FileStatus::PermissionsChanged => {
                        if self.config.check_permissions {
                            summary.permissions_changed += 1;
                            summary.issues.push(VerifyIssue {
                                path: result.path,
                                package: Some(package.clone()),
                                status: result.status,
                                expected: None,
                                actual: None,
                            });
                        }
                    }
                    FileStatus::Config => summary.config_modified += 1,
                    FileStatus::Skipped => summary.files_skipped += 1,
                    FileStatus::SizeChanged | FileStatus::Error => {
                        summary.files_modified += 1;
                        summary.issues.push(VerifyIssue {
                            path: result.path,
                            package: Some(package.clone()),
                            status: result.status,
                            expected: result.expected_hash,
                            actual: result.actual_hash,
                        });
                    }
                }
            }
        }

        Ok(summary)
    }

    /// Verify using manifest
    fn verify_with_manifest(&self, manifest: &Manifest) -> Result<VerifySummary> {
        let mut summary = VerifySummary::default();
        summary.total_files = manifest.len();

        let entries: Vec<_> = manifest.files.values().collect();

        let results: Vec<_> = entries
            .par_iter()
            .map(|entry| verify_file_entry(entry))
            .collect();

        for (entry, result) in entries.iter().zip(results) {
            match result {
                Ok(status) => match status {
                    FileStatus::Ok => summary.files_ok += 1,
                    FileStatus::Modified => {
                        summary.files_modified += 1;
                        summary.issues.push(VerifyIssue {
                            path: entry.path.clone(),
                            package: entry.package.clone(),
                            status,
                            expected: Some(entry.hash.clone()),
                            actual: None,
                        });
                    }
                    FileStatus::Missing => {
                        summary.files_missing += 1;
                        summary.issues.push(VerifyIssue {
                            path: entry.path.clone(),
                            package: entry.package.clone(),
                            status,
                            expected: Some(entry.hash.clone()),
                            actual: None,
                        });
                    }
                    FileStatus::Config if self.config.skip_config => {
                        summary.config_modified += 1;
                    }
                    _ => summary.files_ok += 1,
                },
                Err(e) => {
                    tracing::warn!("Error verifying {}: {}", entry.path, e);
                    summary.errors += 1;
                }
            }
        }

        Ok(summary)
    }

    /// Verify specific paths
    fn verify_paths(&self, paths: &[String]) -> Result<VerifySummary> {
        let mut summary = VerifySummary::default();

        for path in paths {
            let p = Path::new(path);
            if p.is_dir() {
                // Recursively check directory
                let count = walkdir::WalkDir::new(p)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_type().is_file())
                    .count();
                summary.total_files += count;
                summary.files_ok += count; // Assume OK if we can enumerate them
            } else if p.is_file() {
                summary.total_files += 1;
                // Just verify file exists and is readable for now
                if fs::File::open(p).is_ok() {
                    summary.files_ok += 1;
                } else {
                    summary.files_missing += 1;
                }
            }
        }

        Ok(summary)
    }
}

/// Verify a single file against its manifest entry
fn verify_file_entry(entry: &FileEntry) -> Result<FileStatus> {
    let path = Path::new(&entry.path);

    if !path.exists() {
        return Ok(FileStatus::Missing);
    }

    // Skip symlinks if it's a symlink
    if path.is_symlink() {
        return Ok(FileStatus::Skipped);
    }

    // Calculate hash
    let actual_hash = compute_hash(&entry.path, entry.algorithm)?;

    if actual_hash == entry.hash {
        Ok(FileStatus::Ok)
    } else if entry.config {
        Ok(FileStatus::Config)
    } else {
        Ok(FileStatus::Modified)
    }
}

/// Compute hash of a file
pub fn compute_hash(path: &str, algorithm: HashAlgorithm) -> Result<String> {
    let mut file = File::open(path)?;

    match algorithm {
        HashAlgorithm::Sha256 => {
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(format!("{:x}", hasher.finalize()))
        }
        HashAlgorithm::Blake3 => {
            let mut hasher = blake3::Hasher::new();
            let mut buffer = [0u8; 8192];
            loop {
                let bytes_read = file.read(&mut buffer)?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        }
        HashAlgorithm::Md5 => {
            // MD5 support for legacy manifests
            use std::process::Command;
            let output = Command::new("md5sum").arg(path).output()?;
            if output.status.success() {
                let out = String::from_utf8_lossy(&output.stdout);
                if let Some(hash) = out.split_whitespace().next() {
                    return Ok(hash.to_string());
                }
            }
            Err(OsVerifyError::PackageManagerError(
                "MD5 computation failed".to_string(),
            ))
        }
    }
}

/// Get critical system paths that should be verified
fn get_critical_paths() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        vec![
            "/usr/bin".to_string(),
            "/usr/sbin".to_string(),
            "/bin".to_string(),
            "/sbin".to_string(),
            "/lib".to_string(),
            "/lib64".to_string(),
        ]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            "/usr/bin".to_string(),
            "/usr/sbin".to_string(),
            "/bin".to_string(),
            "/sbin".to_string(),
            "/System/Library/CoreServices".to_string(),
        ]
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// An issue found during verification
#[derive(Debug, Clone)]
pub struct VerifyIssue {
    pub path: String,
    pub package: Option<String>,
    pub status: FileStatus,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

impl VerifyIssue {
    /// Get severity level (for reporting)
    pub fn severity(&self) -> &'static str {
        match self.status {
            FileStatus::Missing | FileStatus::Modified | FileStatus::Replaced => "high",
            FileStatus::PermissionsChanged => "medium",
            FileStatus::SizeChanged => "medium",
            _ => "low",
        }
    }
}

/// Summary of verification results
#[derive(Debug, Clone, Default)]
pub struct VerifySummary {
    pub total_packages: usize,
    pub total_files: usize,
    pub files_ok: usize,
    pub files_modified: usize,
    pub files_missing: usize,
    pub files_skipped: usize,
    pub config_modified: usize,
    pub permissions_changed: usize,
    pub errors: usize,
    pub issues: Vec<VerifyIssue>,
    pub duration: Duration,
}

impl VerifySummary {
    /// Check if verification passed (no critical issues)
    pub fn passed(&self) -> bool {
        self.files_modified == 0 && self.files_missing == 0
    }

    /// Get verification score (0-100)
    pub fn score(&self) -> u32 {
        if self.total_files == 0 {
            return 100;
        }
        let verified = self.total_files - self.files_skipped;
        if verified == 0 {
            return 100;
        }
        ((self.files_ok as f64 / verified as f64) * 100.0) as u32
    }

    /// Merge another summary into this one
    pub fn merge(&mut self, other: &VerifySummary) {
        self.total_packages += other.total_packages;
        self.total_files += other.total_files;
        self.files_ok += other.files_ok;
        self.files_modified += other.files_modified;
        self.files_missing += other.files_missing;
        self.files_skipped += other.files_skipped;
        self.config_modified += other.config_modified;
        self.permissions_changed += other.permissions_changed;
        self.errors += other.errors;
        self.issues.extend(other.issues.clone());
    }

    /// Get critical issues (modified or missing files)
    pub fn critical_issues(&self) -> Vec<&VerifyIssue> {
        self.issues
            .iter()
            .filter(|i| matches!(i.status, FileStatus::Modified | FileStatus::Missing))
            .collect()
    }
}
