//! Configuration structures for Protectinator

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Main configuration for Protectinator
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,

    /// File integrity monitoring settings
    #[serde(default)]
    pub fim: FimConfig,

    /// Sigma rules settings
    #[serde(default)]
    pub sigma: SigmaConfig,

    /// Hardening check settings
    #[serde(default)]
    pub hardening: HardeningConfig,

    /// OS verification settings
    #[serde(default)]
    pub osverify: OsVerifyConfig,
}

/// General configuration settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Paths to exclude from all scans
    #[serde(default)]
    pub exclude_paths: Vec<String>,

    /// Verbose output
    #[serde(default)]
    pub verbose: bool,

    /// Output format (text, json)
    #[serde(default)]
    pub output_format: String,

    /// Maximum parallel operations
    #[serde(default = "default_parallelism")]
    pub parallelism: usize,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            exclude_paths: Vec::new(),
            verbose: false,
            output_format: "text".to_string(),
            parallelism: default_parallelism(),
        }
    }
}

fn default_parallelism() -> usize {
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

/// File integrity monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FimConfig {
    /// Hash algorithm to use
    #[serde(default = "default_hash_algorithm")]
    pub hash_algorithm: String,

    /// Paths to monitor
    #[serde(default)]
    pub paths: Vec<PathBuf>,

    /// Patterns to exclude
    #[serde(default)]
    pub exclude_patterns: Vec<String>,

    /// Database file path
    pub database_path: Option<PathBuf>,

    /// Follow symbolic links
    #[serde(default)]
    pub follow_symlinks: bool,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            hash_algorithm: default_hash_algorithm(),
            paths: Vec::new(),
            exclude_patterns: vec![
                "*.log".to_string(),
                "*.tmp".to_string(),
                "*.cache".to_string(),
            ],
            database_path: None,
            follow_symlinks: false,
        }
    }
}

fn default_hash_algorithm() -> String {
    "sha256".to_string()
}

/// Sigma rules configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SigmaConfig {
    /// Paths to Sigma rule files/directories
    #[serde(default)]
    pub rule_paths: Vec<PathBuf>,

    /// Use embedded rules
    #[serde(default = "default_true")]
    pub use_embedded_rules: bool,

    /// Rule severity threshold (only run rules at or above this level)
    pub min_severity: Option<String>,

    /// Categories to include
    #[serde(default)]
    pub include_categories: Vec<String>,

    /// Categories to exclude
    #[serde(default)]
    pub exclude_categories: Vec<String>,
}

/// Hardening check configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardeningConfig {
    /// Categories of checks to run
    #[serde(default)]
    pub categories: Vec<String>,

    /// Specific checks to skip
    #[serde(default)]
    pub skip_checks: Vec<String>,

    /// Minimum severity to report
    pub min_severity: Option<String>,
}

/// OS verification configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsVerifyConfig {
    /// Manifest sources (URLs or file paths)
    #[serde(default)]
    pub manifest_sources: Vec<String>,

    /// Use package manager verification
    #[serde(default = "default_true")]
    pub use_package_manager: bool,

    /// Paths to verify
    #[serde(default)]
    pub paths: Vec<PathBuf>,
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: &std::path::Path) -> crate::error::Result<Self> {
        let content = std::fs::read_to_string(path)?;

        if path.extension().map(|e| e == "json").unwrap_or(false) {
            serde_json::from_str(&content).map_err(|e| {
                crate::error::ProtectinatorError::Parse {
                    context: path.display().to_string(),
                    message: e.to_string(),
                }
            })
        } else {
            // Assume YAML for other extensions
            serde_yaml::from_str(&content).map_err(|e| {
                crate::error::ProtectinatorError::Parse {
                    context: path.display().to_string(),
                    message: e.to_string(),
                }
            })
        }
    }

    /// Save configuration to a file
    pub fn to_file(&self, path: &std::path::Path) -> crate::error::Result<()> {
        let content = if path.extension().map(|e| e == "json").unwrap_or(false) {
            serde_json::to_string_pretty(self)?
        } else {
            serde_yaml::to_string(self).map_err(|e| {
                crate::error::ProtectinatorError::Serialization(e.to_string())
            })?
        };

        std::fs::write(path, content)?;
        Ok(())
    }
}
