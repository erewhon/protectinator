//! Report types for security findings and scan results

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Severity level of a finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational finding, no immediate action required
    Info,
    /// Low severity, should be reviewed
    Low,
    /// Medium severity, should be addressed
    Medium,
    /// High severity, requires prompt attention
    High,
    /// Critical severity, requires immediate action
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

/// Source module that generated the finding
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FindingSource {
    /// Finding from Sigma rule evaluation
    Sigma {
        rule_id: String,
        rule_name: String,
        rule_file: Option<String>,
    },
    /// Finding from file integrity monitoring
    FileIntegrity {
        baseline_path: String,
        change_type: FileChangeType,
    },
    /// Finding from system hardening check
    Hardening {
        check_id: String,
        category: String,
    },
    /// Finding from OS file verification
    OsVerification {
        manifest_source: String,
    },
    /// Finding from persistence mechanism scan
    Persistence {
        persistence_type: String,
        location: String,
    },
    /// Finding from process monitoring
    ProcessMonitor {
        pid: u32,
        process_name: String,
    },
    /// Finding from YARA scan
    Yara {
        rule_name: String,
        rule_file: Option<String>,
    },
    /// Finding from privilege escalation scan
    PrivilegeEscalation {
        vector_type: String,
    },
}

/// Type of file change detected
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileChangeType {
    /// File was added
    Added,
    /// File was modified
    Modified,
    /// File was deleted
    Deleted,
    /// File permissions changed
    PermissionsChanged,
    /// File ownership changed
    OwnershipChanged,
}

/// A security finding from any check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for this finding type
    pub id: String,

    /// Human-readable title
    pub title: String,

    /// Detailed description
    pub description: String,

    /// Severity level
    pub severity: Severity,

    /// Source module and context
    pub source: FindingSource,

    /// When the finding was discovered
    pub timestamp: chrono::DateTime<chrono::Utc>,

    /// Affected resource (file path, registry key, process, etc.)
    pub resource: Option<String>,

    /// Remediation guidance
    pub remediation: Option<String>,

    /// Additional structured data
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// References (CVEs, documentation links, etc.)
    #[serde(default)]
    pub references: Vec<String>,
}

impl Finding {
    /// Create a new finding with required fields
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        source: FindingSource,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            description: description.into(),
            severity,
            source,
            timestamp: chrono::Utc::now(),
            resource: None,
            remediation: None,
            metadata: HashMap::new(),
            references: Vec::new(),
        }
    }

    /// Set the affected resource
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Set remediation guidance
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Add a reference
    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }
}

/// System information collected during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Operating system name
    pub os_name: String,

    /// Operating system version
    pub os_version: String,

    /// Hostname
    pub hostname: String,

    /// Architecture (x86_64, aarch64, etc.)
    pub architecture: String,

    /// Whether running with elevated privileges
    pub is_elevated: bool,

    /// Kernel version (if available)
    pub kernel_version: Option<String>,
}

/// Summary statistics for a scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total number of checks executed
    pub total_checks: usize,

    /// Number of checks that passed
    pub checks_passed: usize,

    /// Number of checks that found issues
    pub checks_failed: usize,

    /// Number of checks skipped (not applicable)
    pub checks_skipped: usize,

    /// Findings grouped by severity
    pub findings_by_severity: HashMap<Severity, usize>,
}

impl ScanSummary {
    /// Update summary with a new finding
    pub fn add_finding(&mut self, severity: Severity) {
        *self.findings_by_severity.entry(severity).or_insert(0) += 1;
    }
}

/// Error that occurred during scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    /// Module where error occurred
    pub module: String,

    /// Error message
    pub message: String,

    /// Whether the error was recoverable
    pub recoverable: bool,

    /// When the error occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// When the scan started
    pub started_at: chrono::DateTime<chrono::Utc>,

    /// When the scan completed
    pub completed_at: chrono::DateTime<chrono::Utc>,

    /// System information
    pub system_info: SystemInfo,

    /// All findings
    pub findings: Vec<Finding>,

    /// Summary statistics
    pub summary: ScanSummary,

    /// Errors encountered during scan
    pub errors: Vec<ScanError>,
}

impl ScanResults {
    /// Create new scan results
    pub fn new(system_info: SystemInfo) -> Self {
        let now = chrono::Utc::now();
        Self {
            started_at: now,
            completed_at: now,
            system_info,
            findings: Vec::new(),
            summary: ScanSummary::default(),
            errors: Vec::new(),
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.summary.add_finding(finding.severity);
        self.findings.push(finding);
    }

    /// Add an error
    pub fn add_error(&mut self, module: impl Into<String>, message: impl Into<String>, recoverable: bool) {
        self.errors.push(ScanError {
            module: module.into(),
            message: message.into(),
            recoverable,
            timestamp: chrono::Utc::now(),
        });
    }

    /// Mark scan as completed
    pub fn complete(&mut self) {
        self.completed_at = chrono::Utc::now();
    }

    /// Get findings filtered by severity
    pub fn findings_by_severity(&self, severity: Severity) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.severity == severity).collect()
    }

    /// Check if scan has critical findings
    pub fn has_critical_findings(&self) -> bool {
        self.findings.iter().any(|f| f.severity == Severity::Critical)
    }
}
