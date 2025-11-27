//! Persistence Mechanism Scanner for Protectinator
//!
//! Scans for malware persistence mechanisms on Linux and macOS.
//!
//! # Features
//!
//! - Cron jobs, systemd services, init scripts (Linux)
//! - LaunchAgents, LaunchDaemons, Login Items (macOS)
//! - Shell profiles (bashrc, zshrc, etc.)
//! - LD_PRELOAD/DYLD hijacking
//! - SSH authorized keys
//! - Risk assessment with MITRE ATT&CK mapping
//!
//! # Example
//!
//! ```no_run
//! use protectinator_persistence::{scan_persistence, PersistenceSummary};
//!
//! let entries = scan_persistence();
//! let summary = PersistenceSummary::from_entries(&entries);
//!
//! println!("Found {} persistence mechanisms", summary.total_entries);
//! if summary.has_critical_findings() {
//!     println!("Warning: {} high-risk findings", summary.high_count);
//! }
//! ```

pub mod types;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub use types::{PersistenceEntry, PersistenceSummary, PersistenceType, RiskLevel};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource,
    ProtectinatorError, Result, SecurityCheck, Severity,
};
use std::sync::Arc;

/// Scan for persistence mechanisms on the current platform
pub fn scan_persistence() -> Vec<PersistenceEntry> {
    #[cfg(target_os = "linux")]
    {
        linux::scan_all()
    }

    #[cfg(target_os = "macos")]
    {
        macos::scan_all()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Get list of persistence locations for the current platform
pub fn get_persistence_locations() -> Vec<(&'static str, PersistenceType)> {
    #[cfg(target_os = "linux")]
    {
        linux::get_persistence_locations()
    }

    #[cfg(target_os = "macos")]
    {
        macos::get_persistence_locations()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Persistence mechanism check provider
pub struct PersistenceProvider {
    min_risk: RiskLevel,
}

impl PersistenceProvider {
    /// Create a new persistence provider
    pub fn new() -> Self {
        Self {
            min_risk: RiskLevel::Low,
        }
    }

    /// Set minimum risk level to report
    pub fn with_min_risk(mut self, risk: RiskLevel) -> Self {
        self.min_risk = risk;
        self
    }

    /// Scan and return entries
    pub fn scan(&self) -> Vec<PersistenceEntry> {
        let entries = scan_persistence();

        // Filter by risk level
        entries
            .into_iter()
            .filter(|e| e.risk >= self.min_risk)
            .collect()
    }
}

impl Default for PersistenceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for PersistenceProvider {
    fn name(&self) -> &str {
        "persistence"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        vec![Arc::new(PersistenceSecurityCheck {
            min_risk: self.min_risk,
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check that scans for persistence mechanisms
struct PersistenceSecurityCheck {
    min_risk: RiskLevel,
}

impl SecurityCheck for PersistenceSecurityCheck {
    fn id(&self) -> &str {
        "persistence-scan"
    }

    fn name(&self) -> &str {
        "Persistence Mechanism Scanner"
    }

    fn description(&self) -> &str {
        "Scans for malware persistence mechanisms"
    }

    fn category(&self) -> &str {
        "persistence"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            Applicability::Applicable
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Applicability::NotApplicable("Platform not supported".to_string())
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let entries = scan_persistence();
        let mut findings = Vec::new();

        for entry in entries {
            if entry.risk < self.min_risk {
                continue;
            }

            let severity = match entry.risk {
                RiskLevel::Critical => Severity::Critical,
                RiskLevel::High => Severity::High,
                RiskLevel::Medium => Severity::Medium,
                RiskLevel::Low => Severity::Low,
            };

            let title = format!(
                "{} persistence: {}",
                entry.persistence_type.as_str(),
                entry.name
            );

            let description = if entry.risk_reasons.is_empty() {
                entry.persistence_type.description().to_string()
            } else {
                format!(
                    "{}: {}",
                    entry.persistence_type.description(),
                    entry.risk_reasons.join(", ")
                )
            };

            let source = FindingSource::Persistence {
                persistence_type: entry.persistence_type.to_string(),
                location: entry.path.to_string_lossy().to_string(),
            };

            let mut finding = Finding::new(
                format!("persistence-{}", entry.persistence_type.as_str()),
                title,
                description,
                severity,
                source,
            );

            // Add MITRE ATT&CK reference
            finding.references.push(format!(
                "https://attack.mitre.org/techniques/{}/",
                entry.persistence_type.mitre_id()
            ));

            findings.push(finding);
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }
}
