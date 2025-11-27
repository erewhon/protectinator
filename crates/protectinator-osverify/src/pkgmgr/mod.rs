//! Package manager integration for OS verification

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;

use crate::error::{OsVerifyError, Result};
use crate::manifest::{HashAlgorithm, PackageFile};
use std::process::Command;

/// Detected package manager type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManagerType {
    /// Debian/Ubuntu dpkg
    Dpkg,
    /// Red Hat/Fedora RPM
    Rpm,
    /// Arch Linux pacman
    Pacman,
    /// Alpine APK
    Apk,
    /// macOS pkgutil
    Pkgutil,
    /// Unknown/unsupported
    Unknown,
}

impl PackageManagerType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackageManagerType::Dpkg => "dpkg",
            PackageManagerType::Rpm => "rpm",
            PackageManagerType::Pacman => "pacman",
            PackageManagerType::Apk => "apk",
            PackageManagerType::Pkgutil => "pkgutil",
            PackageManagerType::Unknown => "unknown",
        }
    }
}

/// Trait for package manager operations
pub trait PackageManager: Send + Sync {
    /// Get the package manager type
    fn manager_type(&self) -> PackageManagerType;

    /// Check if package manager is available
    fn is_available(&self) -> bool;

    /// List all installed packages
    fn list_packages(&self) -> Result<Vec<String>>;

    /// Get files for a specific package
    fn get_package_files(&self, package: &str) -> Result<Vec<PackageFile>>;

    /// Verify a package's files (if supported by package manager)
    fn verify_package(&self, package: &str) -> Result<Vec<VerificationResult>>;

    /// Get all files from all packages
    fn get_all_files(&self) -> Result<Vec<PackageFile>> {
        let packages = self.list_packages()?;
        let mut all_files = Vec::new();

        for pkg in packages {
            match self.get_package_files(&pkg) {
                Ok(files) => all_files.extend(files),
                Err(e) => {
                    tracing::warn!("Failed to get files for package {}: {}", pkg, e);
                }
            }
        }

        Ok(all_files)
    }
}

/// Result of verifying a single file
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub path: String,
    pub package: String,
    pub status: FileStatus,
    pub expected_hash: Option<String>,
    pub actual_hash: Option<String>,
    pub algorithm: HashAlgorithm,
}

/// Status of a verified file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileStatus {
    /// File matches expected hash
    Ok,
    /// File hash doesn't match
    Modified,
    /// File is missing
    Missing,
    /// File was replaced (different type)
    Replaced,
    /// Permissions changed
    PermissionsChanged,
    /// Size changed
    SizeChanged,
    /// Configuration file (may be modified)
    Config,
    /// Verification skipped (e.g., symlink)
    Skipped,
    /// Error during verification
    Error,
}

impl FileStatus {
    pub fn is_problem(&self) -> bool {
        matches!(
            self,
            FileStatus::Modified | FileStatus::Missing | FileStatus::Replaced
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            FileStatus::Ok => "ok",
            FileStatus::Modified => "modified",
            FileStatus::Missing => "missing",
            FileStatus::Replaced => "replaced",
            FileStatus::PermissionsChanged => "permissions",
            FileStatus::SizeChanged => "size",
            FileStatus::Config => "config",
            FileStatus::Skipped => "skipped",
            FileStatus::Error => "error",
        }
    }
}

/// Detect the primary package manager on the system
pub fn detect_package_manager() -> PackageManagerType {
    #[cfg(target_os = "linux")]
    {
        if command_exists("dpkg") {
            return PackageManagerType::Dpkg;
        }
        if command_exists("rpm") {
            return PackageManagerType::Rpm;
        }
        if command_exists("pacman") {
            return PackageManagerType::Pacman;
        }
        if command_exists("apk") {
            return PackageManagerType::Apk;
        }
    }

    #[cfg(target_os = "macos")]
    {
        if command_exists("pkgutil") {
            return PackageManagerType::Pkgutil;
        }
    }

    PackageManagerType::Unknown
}

/// Get a package manager implementation
pub fn get_package_manager() -> Result<Box<dyn PackageManager>> {
    let pm_type = detect_package_manager();

    match pm_type {
        #[cfg(target_os = "linux")]
        PackageManagerType::Dpkg => Ok(Box::new(linux::DpkgManager::new())),
        #[cfg(target_os = "linux")]
        PackageManagerType::Rpm => Ok(Box::new(linux::RpmManager::new())),
        #[cfg(target_os = "linux")]
        PackageManagerType::Pacman => Ok(Box::new(linux::PacmanManager::new())),
        #[cfg(target_os = "macos")]
        PackageManagerType::Pkgutil => Ok(Box::new(macos::PkgutilManager::new())),
        _ => Err(OsVerifyError::PackageManagerNotFound(
            "No supported package manager found".to_string(),
        )),
    }
}

/// Check if a command exists
pub fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command and get output
pub fn run_command(cmd: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| OsVerifyError::PackageManagerError(format!("Failed to run {}: {}", cmd, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(OsVerifyError::PackageManagerError(format!(
            "{} failed: {}",
            cmd, stderr
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
