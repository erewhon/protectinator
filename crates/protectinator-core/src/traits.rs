//! Core traits that define the security check abstraction layer.
//!
//! All security modules implement these traits for consistent orchestration.

use crate::error::Result;
use crate::report::Finding;
use std::sync::Arc;

/// Represents the applicability of a check to the current system
#[derive(Debug, Clone, PartialEq)]
pub enum Applicability {
    /// Check is applicable and should be run
    Applicable,
    /// Check is not applicable (with reason)
    NotApplicable(String),
    /// Cannot determine applicability
    Unknown,
}

/// Operating system information
#[derive(Debug, Clone)]
pub struct OsInfo {
    /// Operating system type
    pub os_type: OsType,
    /// OS version string
    pub version: String,
    /// Architecture
    pub arch: String,
    /// Distribution (for Linux)
    pub distribution: Option<String>,
}

/// Supported operating system types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsType {
    Linux,
    MacOS,
    Windows,
    Unknown,
}

impl std::fmt::Display for OsType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsType::Linux => write!(f, "Linux"),
            OsType::MacOS => write!(f, "macOS"),
            OsType::Windows => write!(f, "Windows"),
            OsType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// System capabilities that may affect what checks can run
#[derive(Debug, Clone, Default)]
pub struct Capabilities {
    /// Can read system logs
    pub can_read_logs: bool,
    /// Can access network information
    pub can_access_network: bool,
    /// Can read all files (elevated)
    pub can_read_all_files: bool,
    /// Can access process information
    pub can_access_processes: bool,
}

/// Configuration for a check run
#[derive(Debug, Clone, Default)]
pub struct CheckConfig {
    /// Paths to exclude from scanning
    pub exclude_paths: Vec<String>,
    /// Patterns to exclude
    pub exclude_patterns: Vec<String>,
    /// Maximum depth for recursive operations
    pub max_depth: Option<usize>,
    /// Timeout for individual checks
    pub timeout: Option<std::time::Duration>,
    /// Verbose output
    pub verbose: bool,
}

/// Context provided to security checks containing system information
pub trait CheckContext: Send + Sync {
    /// Get the detected operating system info
    fn os(&self) -> &OsInfo;

    /// Get platform-specific capabilities
    fn capabilities(&self) -> &Capabilities;

    /// Check if running with elevated privileges
    fn is_elevated(&self) -> bool;

    /// Get the configuration for this run
    fn config(&self) -> &CheckConfig;
}

/// A security check that can be evaluated against the system
pub trait SecurityCheck: Send + Sync {
    /// Unique identifier for this check
    fn id(&self) -> &str;

    /// Human-readable name
    fn name(&self) -> &str;

    /// Detailed description of what this check verifies
    fn description(&self) -> &str;

    /// Category of the check (e.g., "network", "filesystem", "authentication")
    fn category(&self) -> &str;

    /// Determine if this check applies to the current system
    fn applicability(&self, ctx: &dyn CheckContext) -> Applicability;

    /// Execute the check and return findings
    fn execute(&self, ctx: &dyn CheckContext) -> Result<Vec<Finding>>;

    /// Estimated time to complete (for progress reporting)
    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_millis(100)
    }
}

/// A provider that supplies security checks
pub trait CheckProvider: Send + Sync {
    /// Provider name (e.g., "sigma", "hardening", "fim")
    fn name(&self) -> &str;

    /// Get all checks from this provider
    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>>;

    /// Reload/refresh checks from source
    fn refresh(&mut self) -> Result<()>;
}

/// Progress reporting abstraction for UI/CLI
pub trait ProgressReporter: Send + Sync {
    /// Called when a new phase begins
    fn phase_started(&self, name: &str, total_items: usize);

    /// Called when progress is made within a phase
    fn progress(&self, current: usize, message: &str);

    /// Called when a phase completes
    fn phase_completed(&self, name: &str);

    /// Called when a finding is discovered
    fn finding_discovered(&self, finding: &Finding);

    /// Called on error
    fn error(&self, module: &str, message: &str);
}

/// No-op progress reporter for silent operation
pub struct NullProgressReporter;

impl ProgressReporter for NullProgressReporter {
    fn phase_started(&self, _name: &str, _total_items: usize) {}
    fn progress(&self, _current: usize, _message: &str) {}
    fn phase_completed(&self, _name: &str) {}
    fn finding_discovered(&self, _finding: &Finding) {}
    fn error(&self, _module: &str, _message: &str) {}
}

/// Output format for scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Human-readable text
    Text,
    /// JSON format
    Json,
    /// Pretty-printed JSON
    JsonPretty,
}

/// Output handler for scan results
pub trait OutputHandler: Send + Sync {
    /// Handle the complete scan results
    fn handle(&self, results: &crate::report::ScanResults) -> Result<()>;
}
