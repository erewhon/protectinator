//! Types for privilege escalation detection

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of privilege escalation vector
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivescType {
    /// SUID binary
    SuidBinary,
    /// SGID binary
    SgidBinary,
    /// File with capabilities
    Capability,
    /// Writable directory in PATH
    WritablePath,
    /// Sudo misconfiguration
    SudoMisconfig,
    /// World-writable sensitive file
    WorldWritable,
    /// Weak file permissions
    WeakPermissions,
    /// Cron job running as root
    CronJob,
    /// Docker socket access
    DockerSocket,
    /// Kernel vulnerability
    KernelVuln,
}

impl PrivescType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PrivescType::SuidBinary => "suid_binary",
            PrivescType::SgidBinary => "sgid_binary",
            PrivescType::Capability => "capability",
            PrivescType::WritablePath => "writable_path",
            PrivescType::SudoMisconfig => "sudo_misconfig",
            PrivescType::WorldWritable => "world_writable",
            PrivescType::WeakPermissions => "weak_permissions",
            PrivescType::CronJob => "cron_job",
            PrivescType::DockerSocket => "docker_socket",
            PrivescType::KernelVuln => "kernel_vuln",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PrivescType::SuidBinary => "SUID binary that can be exploited for privilege escalation",
            PrivescType::SgidBinary => "SGID binary",
            PrivescType::Capability => "File with dangerous Linux capabilities",
            PrivescType::WritablePath => "Writable directory in PATH allows binary hijacking",
            PrivescType::SudoMisconfig => "Sudo configuration that allows privilege escalation",
            PrivescType::WorldWritable => "World-writable file in sensitive location",
            PrivescType::WeakPermissions => "File with weak permissions in sensitive location",
            PrivescType::CronJob => "Cron job that could be exploited",
            PrivescType::DockerSocket => "Docker socket accessible to non-root users",
            PrivescType::KernelVuln => "Potential kernel vulnerability",
        }
    }
}

impl std::fmt::Display for PrivescType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk level for a privesc finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    #[default]
    Low,
    Medium,
    High,
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "low",
            RiskLevel::Medium => "medium",
            RiskLevel::High => "high",
            RiskLevel::Critical => "critical",
        }
    }
}

/// A detected privilege escalation vector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivescEntry {
    /// Type of privesc vector
    pub privesc_type: PrivescType,
    /// Path to the file/resource
    pub path: PathBuf,
    /// Name or identifier
    pub name: String,
    /// Description
    pub description: String,
    /// Owner of the file
    pub owner: Option<String>,
    /// File permissions
    pub permissions: Option<String>,
    /// Risk level
    pub risk: RiskLevel,
    /// Reasons for the risk level
    pub risk_reasons: Vec<String>,
    /// MITRE ATT&CK technique ID
    pub mitre_id: Option<String>,
    /// Remediation guidance
    pub remediation: Option<String>,
}

/// Summary of privesc scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivescSummary {
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub by_type: std::collections::HashMap<PrivescType, usize>,
}

impl PrivescSummary {
    pub fn from_entries(entries: &[PrivescEntry]) -> Self {
        let mut summary = Self::default();
        summary.total_findings = entries.len();

        for entry in entries {
            *summary.by_type.entry(entry.privesc_type).or_insert(0) += 1;

            match entry.risk {
                RiskLevel::Critical => summary.critical_count += 1,
                RiskLevel::High => summary.high_count += 1,
                RiskLevel::Medium => summary.medium_count += 1,
                RiskLevel::Low => summary.low_count += 1,
            }
        }

        summary
    }

    pub fn has_critical(&self) -> bool {
        self.critical_count > 0 || self.high_count > 0
    }
}
