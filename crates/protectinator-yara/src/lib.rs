//! YARA-like Pattern Scanning for Protectinator
//!
//! Provides pattern-based file scanning similar to YARA rules.
//! Uses a simplified rule format for portability (no external YARA library needed).
//!
//! # Features
//!
//! - Pattern-based file scanning
//! - String and hex pattern matching
//! - Rule conditions
//! - Parallel scanning
//!
//! # Example
//!
//! ```no_run
//! use protectinator_yara::{YaraScanner, Rule};
//!
//! let scanner = YaraScanner::new();
//! // Add rules and scan files
//! ```

mod rules;
mod scanner;

pub use rules::{Condition, Pattern, PatternType, Rule, RuleSet};
pub use scanner::{Match, ScanResult, YaraScanner};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource, Result, SecurityCheck,
    Severity,
};
use std::path::PathBuf;
use std::sync::Arc;

/// YARA scanning check provider
pub struct YaraProvider {
    rule_paths: Vec<PathBuf>,
    scan_paths: Vec<PathBuf>,
}

impl YaraProvider {
    /// Create a new YARA provider
    pub fn new() -> Self {
        Self {
            rule_paths: Vec::new(),
            scan_paths: Vec::new(),
        }
    }

    /// Add rule paths
    pub fn with_rules(mut self, paths: Vec<PathBuf>) -> Self {
        self.rule_paths = paths;
        self
    }

    /// Add scan paths
    pub fn with_scan_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.scan_paths = paths;
        self
    }
}

impl Default for YaraProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for YaraProvider {
    fn name(&self) -> &str {
        "yara"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        vec![Arc::new(YaraSecurityCheck {
            rule_paths: self.rule_paths.clone(),
            scan_paths: self.scan_paths.clone(),
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check for YARA scanning
struct YaraSecurityCheck {
    rule_paths: Vec<PathBuf>,
    scan_paths: Vec<PathBuf>,
}

impl SecurityCheck for YaraSecurityCheck {
    fn id(&self) -> &str {
        "yara-scan"
    }

    fn name(&self) -> &str {
        "YARA Pattern Scanner"
    }

    fn description(&self) -> &str {
        "Scans files for malware patterns using YARA-like rules"
    }

    fn category(&self) -> &str {
        "malware"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        if self.rule_paths.is_empty() {
            Applicability::NotApplicable("No YARA rules configured".to_string())
        } else if self.scan_paths.is_empty() {
            Applicability::NotApplicable("No scan paths configured".to_string())
        } else {
            Applicability::Applicable
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Load rules
        let mut scanner = YaraScanner::new();
        for path in &self.rule_paths {
            if let Ok(rules) = RuleSet::from_file(path) {
                scanner.add_rules(rules);
            }
        }

        // Scan files
        for path in &self.scan_paths {
            let results = scanner.scan_path(path);
            for result in results {
                for m in &result.matches {
                    let severity = match m.rule.severity.as_deref() {
                        Some("critical") => Severity::Critical,
                        Some("high") => Severity::High,
                        Some("medium") => Severity::Medium,
                        _ => Severity::Low,
                    };

                    let source = FindingSource::Yara {
                        rule_name: m.rule.name.clone(),
                        rule_file: m.rule.source_file.clone(),
                    };

                    findings.push(Finding::new(
                        format!("yara-{}", m.rule.name),
                        format!("YARA match: {}", m.rule.name),
                        format!(
                            "File {} matched rule: {}",
                            result.path.display(),
                            m.rule.description.as_deref().unwrap_or(&m.rule.name)
                        ),
                        severity,
                        source,
                    ));
                }
            }
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }
}
