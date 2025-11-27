//! Types for persistence mechanism detection

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Type of persistence mechanism
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceType {
    /// Cron job
    Cron,
    /// Systemd service/timer
    Systemd,
    /// Init script (SysV)
    InitScript,
    /// Shell profile/rc file
    ShellProfile,
    /// LD_PRELOAD hijacking
    LdPreload,
    /// Kernel module
    KernelModule,
    /// SSH authorized keys
    SshAuthorizedKeys,
    /// At job
    AtJob,
    /// XDG autostart
    XdgAutostart,
    /// macOS LaunchAgent
    LaunchAgent,
    /// macOS LaunchDaemon
    LaunchDaemon,
    /// macOS Login Item
    LoginItem,
    /// macOS Startup Item
    StartupItem,
    /// DYLD injection (macOS)
    DyldInjection,
    /// Periodic script (macOS)
    Periodic,
    /// Emond rule (macOS)
    Emond,
}

impl PersistenceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            PersistenceType::Cron => "cron",
            PersistenceType::Systemd => "systemd",
            PersistenceType::InitScript => "init_script",
            PersistenceType::ShellProfile => "shell_profile",
            PersistenceType::LdPreload => "ld_preload",
            PersistenceType::KernelModule => "kernel_module",
            PersistenceType::SshAuthorizedKeys => "ssh_authorized_keys",
            PersistenceType::AtJob => "at_job",
            PersistenceType::XdgAutostart => "xdg_autostart",
            PersistenceType::LaunchAgent => "launch_agent",
            PersistenceType::LaunchDaemon => "launch_daemon",
            PersistenceType::LoginItem => "login_item",
            PersistenceType::StartupItem => "startup_item",
            PersistenceType::DyldInjection => "dyld_injection",
            PersistenceType::Periodic => "periodic",
            PersistenceType::Emond => "emond",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            PersistenceType::Cron => "Scheduled task via cron",
            PersistenceType::Systemd => "Systemd service or timer unit",
            PersistenceType::InitScript => "SysV init script",
            PersistenceType::ShellProfile => "Shell startup script (bashrc, profile, etc.)",
            PersistenceType::LdPreload => "LD_PRELOAD library injection",
            PersistenceType::KernelModule => "Loadable kernel module",
            PersistenceType::SshAuthorizedKeys => "SSH authorized_keys file",
            PersistenceType::AtJob => "One-time scheduled task via at",
            PersistenceType::XdgAutostart => "XDG autostart desktop entry",
            PersistenceType::LaunchAgent => "macOS LaunchAgent (user context)",
            PersistenceType::LaunchDaemon => "macOS LaunchDaemon (root context)",
            PersistenceType::LoginItem => "macOS Login Item",
            PersistenceType::StartupItem => "Legacy macOS Startup Item",
            PersistenceType::DyldInjection => "DYLD library injection",
            PersistenceType::Periodic => "macOS periodic script",
            PersistenceType::Emond => "macOS Event Monitor daemon rule",
        }
    }

    /// Get MITRE ATT&CK technique ID
    pub fn mitre_id(&self) -> &'static str {
        match self {
            PersistenceType::Cron => "T1053.003",
            PersistenceType::Systemd => "T1543.002",
            PersistenceType::InitScript => "T1037.004",
            PersistenceType::ShellProfile => "T1546.004",
            PersistenceType::LdPreload => "T1574.006",
            PersistenceType::KernelModule => "T1547.006",
            PersistenceType::SshAuthorizedKeys => "T1098.004",
            PersistenceType::AtJob => "T1053.002",
            PersistenceType::XdgAutostart => "T1547.013",
            PersistenceType::LaunchAgent => "T1543.001",
            PersistenceType::LaunchDaemon => "T1543.004",
            PersistenceType::LoginItem => "T1547.015",
            PersistenceType::StartupItem => "T1037.005",
            PersistenceType::DyldInjection => "T1574.006",
            PersistenceType::Periodic => "T1053.003",
            PersistenceType::Emond => "T1546.014",
        }
    }
}

impl std::fmt::Display for PersistenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Risk level for a persistence finding
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Low risk - common/expected persistence
    Low,
    /// Medium risk - unusual but may be legitimate
    Medium,
    /// High risk - suspicious persistence mechanism
    High,
    /// Critical - likely malicious
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

/// A detected persistence mechanism
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    /// Type of persistence
    pub persistence_type: PersistenceType,
    /// Path to the persistence configuration/script
    pub path: PathBuf,
    /// Name or identifier
    pub name: String,
    /// Description of what it does
    pub description: Option<String>,
    /// Command or target being executed
    pub command: Option<String>,
    /// User context
    pub user: Option<String>,
    /// Whether it's enabled
    pub enabled: bool,
    /// Risk assessment
    pub risk: RiskLevel,
    /// Reasons for the risk assessment
    pub risk_reasons: Vec<String>,
    /// When the file was modified
    pub modified: Option<chrono::DateTime<chrono::Utc>>,
    /// File hash for the persistence config
    pub hash: Option<String>,
}

impl PersistenceEntry {
    pub fn new(
        persistence_type: PersistenceType,
        path: impl Into<PathBuf>,
        name: impl Into<String>,
    ) -> Self {
        Self {
            persistence_type,
            path: path.into(),
            name: name.into(),
            description: None,
            command: None,
            user: None,
            enabled: true,
            risk: RiskLevel::Low,
            risk_reasons: Vec::new(),
            modified: None,
            hash: None,
        }
    }

    pub fn with_command(mut self, cmd: impl Into<String>) -> Self {
        self.command = Some(cmd.into());
        self
    }

    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }

    pub fn with_risk(mut self, risk: RiskLevel, reasons: Vec<String>) -> Self {
        self.risk = risk;
        self.risk_reasons = reasons;
        self
    }

    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Summary of persistence scan results
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistenceSummary {
    pub total_entries: usize,
    pub by_type: std::collections::HashMap<PersistenceType, usize>,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

impl PersistenceSummary {
    pub fn from_entries(entries: &[PersistenceEntry]) -> Self {
        let mut summary = Self::default();
        summary.total_entries = entries.len();

        for entry in entries {
            *summary.by_type.entry(entry.persistence_type).or_insert(0) += 1;

            match entry.risk {
                RiskLevel::Critical => summary.critical_count += 1,
                RiskLevel::High => summary.high_count += 1,
                RiskLevel::Medium => summary.medium_count += 1,
                RiskLevel::Low => summary.low_count += 1,
            }
        }

        summary
    }

    pub fn has_critical_findings(&self) -> bool {
        self.critical_count > 0 || self.high_count > 0
    }
}
