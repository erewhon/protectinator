//! macOS package manager implementations

use super::{command_exists, run_command, FileStatus, PackageManager, PackageManagerType, VerificationResult};
use crate::error::{OsVerifyError, Result};
use crate::manifest::{HashAlgorithm, PackageFile};
use std::collections::HashSet;

/// macOS pkgutil package manager
pub struct PkgutilManager;

impl PkgutilManager {
    pub fn new() -> Self {
        Self
    }

    /// Get the BOM (Bill of Materials) for a package
    fn get_bom_files(&self, package: &str) -> Result<Vec<PackageFile>> {
        // lsbom lists files from the package receipt
        let output = run_command(
            "lsbom",
            &["-pf", &format!("/var/db/receipts/{}.bom", package)],
        )?;

        let mut files = Vec::new();
        for line in output.lines() {
            let path = line.trim();
            if path.is_empty() || path == "." {
                continue;
            }

            // Paths in BOM are relative, prefix with /
            let full_path = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{}", path)
            };

            if !std::path::Path::new(&full_path).is_dir() {
                files.push(PackageFile::new(&full_path, package));
            }
        }

        Ok(files)
    }

    /// Parse pkgutil --verify output
    fn parse_verify_output(&self, output: &str, package: &str) -> Vec<VerificationResult> {
        // pkgutil --verify output:
        // Checking /path... MODIFIED
        // Checking /path... MISSING

        let mut results = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if !line.starts_with("Checking ") {
                continue;
            }

            // Parse "Checking /path... STATUS"
            if let Some(rest) = line.strip_prefix("Checking ") {
                if let Some(idx) = rest.rfind("...") {
                    let path = rest[..idx].trim();
                    let status_str = rest[idx + 3..].trim().to_lowercase();

                    let status = match status_str.as_str() {
                        "" | "ok" => continue, // Skip OK files
                        "modified" => FileStatus::Modified,
                        "missing" => FileStatus::Missing,
                        "permissions" => FileStatus::PermissionsChanged,
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
        }

        results
    }
}

impl PackageManager for PkgutilManager {
    fn manager_type(&self) -> PackageManagerType {
        PackageManagerType::Pkgutil
    }

    fn is_available(&self) -> bool {
        command_exists("pkgutil")
    }

    fn list_packages(&self) -> Result<Vec<String>> {
        let output = run_command("pkgutil", &["--pkgs"])?;
        Ok(output
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    fn get_package_files(&self, package: &str) -> Result<Vec<PackageFile>> {
        // First try pkgutil --files
        let output = run_command("pkgutil", &["--files", package])?;

        let mut files = Vec::new();
        for line in output.lines() {
            let path = line.trim();
            if path.is_empty() {
                continue;
            }

            // Paths from pkgutil are relative, need to determine base
            // Most system packages install to / or /Applications
            let full_path = if path.starts_with('/') {
                path.to_string()
            } else {
                format!("/{}", path)
            };

            if !std::path::Path::new(&full_path).is_dir() {
                files.push(PackageFile::new(&full_path, package));
            }
        }

        // If no files from pkgutil, try BOM
        if files.is_empty() {
            if let Ok(bom_files) = self.get_bom_files(package) {
                files = bom_files;
            }
        }

        Ok(files)
    }

    fn verify_package(&self, package: &str) -> Result<Vec<VerificationResult>> {
        // pkgutil --verify checks package integrity
        let output = match run_command("pkgutil", &["--verify", package]) {
            Ok(out) => out,
            Err(e) => {
                // pkgutil returns error when issues found
                if let OsVerifyError::PackageManagerError(msg) = &e {
                    return Ok(self.parse_verify_output(msg, package));
                }
                return Err(e);
            }
        };

        Ok(self.parse_verify_output(&output, package))
    }
}

/// Verify macOS system files using built-in mechanisms
pub struct MacOsSystemVerifier;

impl MacOsSystemVerifier {
    /// Get list of critical system paths to verify
    pub fn critical_paths() -> Vec<&'static str> {
        vec![
            "/usr/bin",
            "/usr/sbin",
            "/bin",
            "/sbin",
            "/System/Library/CoreServices",
            "/System/Library/Frameworks",
        ]
    }

    /// Check code signature of a binary
    pub fn verify_code_signature(path: &str) -> Result<bool> {
        let output = run_command("codesign", &["-v", "-v", path])?;
        Ok(output.contains("valid on disk"))
    }

    /// Get list of binaries with invalid signatures
    pub fn find_unsigned_binaries(path: &str) -> Result<Vec<String>> {
        // Find all executables and check signatures
        let find_output = run_command("find", &[path, "-type", "f", "-perm", "+111"])?;

        let mut unsigned = Vec::new();
        for file in find_output.lines() {
            let file = file.trim();
            if file.is_empty() {
                continue;
            }

            // Check signature
            match run_command("codesign", &["-v", file]) {
                Ok(_) => {} // Valid signature
                Err(_) => {
                    unsigned.push(file.to_string());
                }
            }
        }

        Ok(unsigned)
    }
}

/// Get Apple-signed packages (system packages)
pub fn get_apple_packages() -> Result<Vec<String>> {
    let output = run_command("pkgutil", &["--pkgs"])?;

    Ok(output
        .lines()
        .filter(|p| p.starts_with("com.apple."))
        .map(|s| s.trim().to_string())
        .collect())
}
