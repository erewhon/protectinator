//! Linux package manager implementations

use super::{command_exists, run_command, FileStatus, PackageManager, PackageManagerType, VerificationResult};
use crate::error::{OsVerifyError, Result};
use crate::manifest::{HashAlgorithm, PackageFile};
use regex::Regex;
use std::sync::OnceLock;

/// Debian/Ubuntu dpkg package manager
pub struct DpkgManager;

impl DpkgManager {
    pub fn new() -> Self {
        Self
    }

    /// Parse dpkg -V output
    fn parse_verify_output(&self, output: &str, package: &str) -> Vec<VerificationResult> {
        // dpkg -V format: SM5DLUGTP c <path>
        // S = size, M = mode, 5 = md5sum, D = device, L = link, U = user, G = group, T = mtime
        // c = configuration file
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        let pattern = PATTERN.get_or_init(|| {
            Regex::new(r"^([.S][.M][.5][.D][.L][.U][.G][.T][.P])\s+([c\s])\s+(.+)$").unwrap()
        });

        let mut results = Vec::new();

        for line in output.lines() {
            if let Some(caps) = pattern.captures(line.trim()) {
                let flags = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let config = caps.get(2).map(|m| m.as_str().trim()) == Some("c");
                let path = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                // Determine status from flags
                let status = if flags.contains("missing") {
                    FileStatus::Missing
                } else if flags.chars().nth(2) == Some('5') {
                    // MD5 mismatch
                    if config {
                        FileStatus::Config
                    } else {
                        FileStatus::Modified
                    }
                } else if flags.chars().nth(1) == Some('M') {
                    FileStatus::PermissionsChanged
                } else if flags.chars().nth(0) == Some('S') {
                    FileStatus::SizeChanged
                } else {
                    FileStatus::Ok
                };

                results.push(VerificationResult {
                    path: path.to_string(),
                    package: package.to_string(),
                    status,
                    expected_hash: None,
                    actual_hash: None,
                    algorithm: HashAlgorithm::Md5,
                });
            }
        }

        results
    }
}

impl PackageManager for DpkgManager {
    fn manager_type(&self) -> PackageManagerType {
        PackageManagerType::Dpkg
    }

    fn is_available(&self) -> bool {
        command_exists("dpkg")
    }

    fn list_packages(&self) -> Result<Vec<String>> {
        let output = run_command("dpkg-query", &["-W", "-f", "${Package}\\n"])?;
        Ok(output.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }

    fn get_package_files(&self, package: &str) -> Result<Vec<PackageFile>> {
        let output = run_command("dpkg", &["-L", package])?;

        let mut files = Vec::new();
        for line in output.lines() {
            let path = line.trim();
            if path.is_empty() || std::path::Path::new(path).is_dir() {
                continue;
            }
            files.push(PackageFile::new(path, package));
        }

        Ok(files)
    }

    fn verify_package(&self, package: &str) -> Result<Vec<VerificationResult>> {
        // dpkg -V verifies installed files
        let output = match run_command("dpkg", &["-V", package]) {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()), // No issues found
        };

        Ok(self.parse_verify_output(&output, package))
    }
}

/// Red Hat/Fedora RPM package manager
pub struct RpmManager;

impl RpmManager {
    pub fn new() -> Self {
        Self
    }

    /// Parse rpm -V output
    fn parse_verify_output(&self, output: &str, package: &str) -> Vec<VerificationResult> {
        // rpm -V format: SM5DLUGT c <path>
        // S = size, M = mode, 5 = md5/sha256, D = device, L = link, U = user, G = group, T = mtime
        // c = configuration file
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        let pattern = PATTERN.get_or_init(|| {
            Regex::new(r"^([.S][.M][.5][.D][.L][.U][.G][.T])\s+([cdglr\s])\s+(.+)$").unwrap()
        });

        let mut results = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("package") {
                continue;
            }

            if line.contains("missing") {
                // Handle "missing <path>" format
                if let Some(path) = line.strip_prefix("missing").map(|s| s.trim()) {
                    results.push(VerificationResult {
                        path: path.to_string(),
                        package: package.to_string(),
                        status: FileStatus::Missing,
                        expected_hash: None,
                        actual_hash: None,
                        algorithm: HashAlgorithm::Sha256,
                    });
                }
                continue;
            }

            if let Some(caps) = pattern.captures(line) {
                let flags = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let file_type = caps.get(2).map(|m| m.as_str().trim()).unwrap_or("");
                let path = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                let is_config = file_type == "c";

                // Determine status from flags
                let status = if flags.chars().nth(2) == Some('5') {
                    if is_config {
                        FileStatus::Config
                    } else {
                        FileStatus::Modified
                    }
                } else if flags.chars().nth(1) == Some('M') {
                    FileStatus::PermissionsChanged
                } else if flags.chars().nth(0) == Some('S') {
                    FileStatus::SizeChanged
                } else {
                    FileStatus::Ok
                };

                results.push(VerificationResult {
                    path: path.to_string(),
                    package: package.to_string(),
                    status,
                    expected_hash: None,
                    actual_hash: None,
                    algorithm: HashAlgorithm::Sha256,
                });
            }
        }

        results
    }
}

impl PackageManager for RpmManager {
    fn manager_type(&self) -> PackageManagerType {
        PackageManagerType::Rpm
    }

    fn is_available(&self) -> bool {
        command_exists("rpm")
    }

    fn list_packages(&self) -> Result<Vec<String>> {
        let output = run_command("rpm", &["-qa", "--qf", "%{NAME}\\n"])?;
        Ok(output.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }

    fn get_package_files(&self, package: &str) -> Result<Vec<PackageFile>> {
        let output = run_command("rpm", &["-ql", package])?;

        let mut files = Vec::new();
        for line in output.lines() {
            let path = line.trim();
            if path.is_empty() || path.starts_with("(contains") || std::path::Path::new(path).is_dir() {
                continue;
            }
            files.push(PackageFile::new(path, package));
        }

        // Try to get config files
        if let Ok(config_output) = run_command("rpm", &["-qc", package]) {
            for line in config_output.lines() {
                let path = line.trim();
                if !path.is_empty() {
                    // Mark existing files as config
                    for file in &mut files {
                        if file.path == path {
                            file.config = true;
                        }
                    }
                }
            }
        }

        Ok(files)
    }

    fn verify_package(&self, package: &str) -> Result<Vec<VerificationResult>> {
        let output = match run_command("rpm", &["-V", package]) {
            Ok(out) => out,
            Err(_) => return Ok(Vec::new()),
        };

        Ok(self.parse_verify_output(&output, package))
    }
}

/// Arch Linux pacman package manager
pub struct PacmanManager;

impl PacmanManager {
    pub fn new() -> Self {
        Self
    }

    /// Parse pacman -Qkk output
    fn parse_verify_output(&self, output: &str, package: &str) -> Vec<VerificationResult> {
        // pacman -Qkk format varies:
        // "package: /path (Modification time mismatch)"
        // "package: /path (Size mismatch)"
        // "package: /path (MISSING)"
        // "package: /path (Checksum mismatch)"
        static PATTERN: OnceLock<Regex> = OnceLock::new();
        let pattern = PATTERN.get_or_init(|| {
            Regex::new(r"^[^:]+:\s+(/[^\s]+)\s+\(([^)]+)\)").unwrap()
        });

        let mut results = Vec::new();

        for line in output.lines() {
            if let Some(caps) = pattern.captures(line) {
                let path = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                let reason = caps.get(2).map(|m| m.as_str()).unwrap_or("");

                let status = match reason.to_lowercase().as_str() {
                    s if s.contains("missing") => FileStatus::Missing,
                    s if s.contains("checksum") => FileStatus::Modified,
                    s if s.contains("size") => FileStatus::SizeChanged,
                    s if s.contains("permission") || s.contains("mode") => FileStatus::PermissionsChanged,
                    _ => FileStatus::Modified,
                };

                results.push(VerificationResult {
                    path: path.to_string(),
                    package: package.to_string(),
                    status,
                    expected_hash: None,
                    actual_hash: None,
                    algorithm: HashAlgorithm::Sha256,
                });
            }
        }

        results
    }
}

impl PackageManager for PacmanManager {
    fn manager_type(&self) -> PackageManagerType {
        PackageManagerType::Pacman
    }

    fn is_available(&self) -> bool {
        command_exists("pacman")
    }

    fn list_packages(&self) -> Result<Vec<String>> {
        let output = run_command("pacman", &["-Qq"])?;
        Ok(output.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }

    fn get_package_files(&self, package: &str) -> Result<Vec<PackageFile>> {
        let output = run_command("pacman", &["-Ql", package])?;

        let mut files = Vec::new();
        for line in output.lines() {
            // Format: "package /path"
            let parts: Vec<&str> = line.splitn(2, ' ').collect();
            if parts.len() == 2 {
                let path = parts[1].trim();
                if !path.is_empty() && !std::path::Path::new(path).is_dir() {
                    files.push(PackageFile::new(path, package));
                }
            }
        }

        Ok(files)
    }

    fn verify_package(&self, package: &str) -> Result<Vec<VerificationResult>> {
        // pacman -Qkk checks file integrity
        let output = match run_command("pacman", &["-Qkk", package]) {
            Ok(out) => out,
            Err(e) => {
                // pacman returns error when there are issues
                if let OsVerifyError::PackageManagerError(msg) = &e {
                    // Try to parse the error output
                    return Ok(self.parse_verify_output(msg, package));
                }
                return Err(e);
            }
        };

        Ok(self.parse_verify_output(&output, package))
    }
}
