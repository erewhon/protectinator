//! Privilege Escalation Path Finder for Protectinator
//!
//! Finds potential privilege escalation vectors on Linux and macOS.
//!
//! # Features
//!
//! - SUID/SGID binary detection with GTFOBins knowledge
//! - Linux capabilities scanning
//! - Sudo misconfiguration detection
//! - Writable PATH directories
//! - World-writable sensitive files
//! - MITRE ATT&CK mapping
//!
//! # Example
//!
//! ```no_run
//! use protectinator_privesc::{scan_privesc, PrivescSummary};
//!
//! let entries = scan_privesc();
//! let summary = PrivescSummary::from_entries(&entries);
//!
//! println!("Found {} potential privesc vectors", summary.total_findings);
//! if summary.has_critical() {
//!     println!("Warning: {} critical findings", summary.critical_count);
//! }
//! ```

pub mod types;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub use types::{PrivescEntry, PrivescSummary, PrivescType, RiskLevel};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource, Result, SecurityCheck,
    Severity,
};
use std::sync::Arc;

/// Scan for privilege escalation vectors
pub fn scan_privesc() -> Vec<PrivescEntry> {
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

/// Privilege escalation check provider
pub struct PrivescProvider {
    min_risk: RiskLevel,
}

impl PrivescProvider {
    /// Create a new privilege escalation provider
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
    pub fn scan(&self) -> Vec<PrivescEntry> {
        let entries = scan_privesc();
        entries
            .into_iter()
            .filter(|e| e.risk >= self.min_risk)
            .collect()
    }
}

impl Default for PrivescProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for PrivescProvider {
    fn name(&self) -> &str {
        "privesc"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        vec![Arc::new(PrivescSecurityCheck {
            min_risk: self.min_risk,
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check for privilege escalation detection
struct PrivescSecurityCheck {
    min_risk: RiskLevel,
}

impl SecurityCheck for PrivescSecurityCheck {
    fn id(&self) -> &str {
        "privesc-scan"
    }

    fn name(&self) -> &str {
        "Privilege Escalation Path Finder"
    }

    fn description(&self) -> &str {
        "Scans for potential privilege escalation vectors"
    }

    fn category(&self) -> &str {
        "privesc"
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
        let entries = scan_privesc();
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

            let title = format!("{}: {}", entry.privesc_type.as_str(), entry.name);

            let description = if entry.risk_reasons.is_empty() {
                entry.description.clone()
            } else {
                format!("{}\nReasons: {}", entry.description, entry.risk_reasons.join(", "))
            };

            let source = FindingSource::PrivilegeEscalation {
                vector_type: entry.privesc_type.to_string(),
            };

            let mut finding = Finding::new(
                format!("privesc-{}", entry.privesc_type.as_str()),
                title,
                description,
                severity,
                source,
            );

            if let Some(ref mitre) = entry.mitre_id {
                finding.references.push(format!(
                    "https://attack.mitre.org/techniques/{}/",
                    mitre
                ));
            }

            if let Some(ref rem) = entry.remediation {
                finding.remediation = Some(rem.clone());
            }

            findings.push(finding);
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }
}
