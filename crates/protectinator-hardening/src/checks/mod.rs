//! Hardening check implementations

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub mod common;

use protectinator_core::{Finding, FindingSource, Severity};
use serde::{Deserialize, Serialize};

/// Category of hardening check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    /// Authentication and access control
    Authentication,
    /// Network security
    Network,
    /// Filesystem security
    Filesystem,
    /// Kernel security features
    Kernel,
    /// Service hardening
    Services,
    /// Encryption and data protection
    Encryption,
    /// Audit and logging
    Audit,
    /// Malware protection
    Malware,
    /// System integrity
    Integrity,
}

impl std::fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckCategory::Authentication => write!(f, "authentication"),
            CheckCategory::Network => write!(f, "network"),
            CheckCategory::Filesystem => write!(f, "filesystem"),
            CheckCategory::Kernel => write!(f, "kernel"),
            CheckCategory::Services => write!(f, "services"),
            CheckCategory::Encryption => write!(f, "encryption"),
            CheckCategory::Audit => write!(f, "audit"),
            CheckCategory::Malware => write!(f, "malware"),
            CheckCategory::Integrity => write!(f, "integrity"),
        }
    }
}

impl std::str::FromStr for CheckCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "authentication" | "auth" => Ok(CheckCategory::Authentication),
            "network" | "net" => Ok(CheckCategory::Network),
            "filesystem" | "fs" => Ok(CheckCategory::Filesystem),
            "kernel" => Ok(CheckCategory::Kernel),
            "services" | "svc" => Ok(CheckCategory::Services),
            "encryption" | "crypto" => Ok(CheckCategory::Encryption),
            "audit" | "logging" => Ok(CheckCategory::Audit),
            "malware" => Ok(CheckCategory::Malware),
            "integrity" => Ok(CheckCategory::Integrity),
            _ => Err(format!("Unknown category: {}", s)),
        }
    }
}

/// Result of a hardening check
#[derive(Debug, Clone)]
pub enum CheckResult {
    /// Check passed - system is properly hardened
    Pass {
        message: String,
    },
    /// Check failed - security issue found
    Fail {
        message: String,
        severity: Severity,
        remediation: Option<String>,
    },
    /// Check was skipped
    Skipped {
        reason: String,
    },
    /// Error during check
    Error {
        message: String,
    },
}

impl CheckResult {
    pub fn pass(message: impl Into<String>) -> Self {
        CheckResult::Pass {
            message: message.into(),
        }
    }

    pub fn fail(message: impl Into<String>, severity: Severity) -> Self {
        CheckResult::Fail {
            message: message.into(),
            severity,
            remediation: None,
        }
    }

    pub fn fail_with_remediation(
        message: impl Into<String>,
        severity: Severity,
        remediation: impl Into<String>,
    ) -> Self {
        CheckResult::Fail {
            message: message.into(),
            severity,
            remediation: Some(remediation.into()),
        }
    }

    pub fn skipped(reason: impl Into<String>) -> Self {
        CheckResult::Skipped {
            reason: reason.into(),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        CheckResult::Error {
            message: message.into(),
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, CheckResult::Pass { .. })
    }

    pub fn is_fail(&self) -> bool {
        matches!(self, CheckResult::Fail { .. })
    }
}

/// Definition of a hardening check
#[derive(Debug, Clone)]
pub struct HardeningCheck {
    /// Unique check ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Category
    pub category: CheckCategory,
    /// Default severity if check fails
    pub default_severity: Severity,
    /// Platforms this check applies to
    pub platforms: Vec<&'static str>,
    /// CIS Benchmark reference (if applicable)
    pub cis_reference: Option<String>,
    /// Remediation guidance
    pub remediation: Option<String>,
    /// References/documentation
    pub references: Vec<String>,
}

impl HardeningCheck {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        category: CheckCategory,
        severity: Severity,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            category,
            default_severity: severity,
            platforms: Vec::new(),
            cis_reference: None,
            remediation: None,
            references: Vec::new(),
        }
    }

    pub fn with_platforms(mut self, platforms: Vec<&'static str>) -> Self {
        self.platforms = platforms;
        self
    }

    pub fn with_cis_reference(mut self, reference: impl Into<String>) -> Self {
        self.cis_reference = Some(reference.into());
        self
    }

    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }

    /// Convert check result to a Finding
    pub fn to_finding(&self, result: &CheckResult) -> Option<Finding> {
        match result {
            CheckResult::Fail {
                message,
                severity,
                remediation,
            } => {
                let mut finding = Finding::new(
                    &self.id,
                    &self.name,
                    message,
                    *severity,
                    FindingSource::Hardening {
                        check_id: self.id.clone(),
                        category: self.category.to_string(),
                    },
                );

                if let Some(rem) = remediation.as_ref().or(self.remediation.as_ref()) {
                    finding = finding.with_remediation(rem);
                }

                for reference in &self.references {
                    finding = finding.with_reference(reference);
                }

                Some(finding)
            }
            _ => None,
        }
    }
}

/// Trait for runnable hardening checks
pub trait RunnableCheck: Send + Sync {
    /// Get the check definition
    fn definition(&self) -> &HardeningCheck;

    /// Execute the check
    fn run(&self) -> CheckResult;

    /// Check if this check is applicable on current system
    fn is_applicable(&self) -> bool {
        true
    }
}

/// Collection of hardening checks for a platform
pub struct CheckRegistry {
    checks: Vec<Box<dyn RunnableCheck>>,
}

impl CheckRegistry {
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    pub fn register(&mut self, check: Box<dyn RunnableCheck>) {
        self.checks.push(check);
    }

    pub fn checks(&self) -> &[Box<dyn RunnableCheck>] {
        &self.checks
    }

    pub fn filter_by_category(&self, category: CheckCategory) -> Vec<&dyn RunnableCheck> {
        self.checks
            .iter()
            .filter(|c| c.definition().category == category)
            .map(|c| c.as_ref())
            .collect()
    }

    pub fn filter_by_id(&self, id: &str) -> Option<&dyn RunnableCheck> {
        self.checks
            .iter()
            .find(|c| c.definition().id == id)
            .map(|c| c.as_ref())
    }

    pub fn len(&self) -> usize {
        self.checks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }
}

impl Default for CheckRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Get all available checks for the current platform
pub fn get_platform_checks() -> CheckRegistry {
    let mut registry = CheckRegistry::new();

    #[cfg(target_os = "linux")]
    {
        linux::register_checks(&mut registry);
    }

    #[cfg(target_os = "macos")]
    {
        macos::register_checks(&mut registry);
    }

    registry
}

/// Get all available categories
pub fn get_categories() -> Vec<CheckCategory> {
    vec![
        CheckCategory::Authentication,
        CheckCategory::Network,
        CheckCategory::Filesystem,
        CheckCategory::Kernel,
        CheckCategory::Services,
        CheckCategory::Encryption,
        CheckCategory::Audit,
        CheckCategory::Malware,
        CheckCategory::Integrity,
    ]
}
