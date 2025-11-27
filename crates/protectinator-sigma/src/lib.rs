//! Sigma Rules Engine for Protectinator
//!
//! Provides Sigma rule parsing, log source adapters, and rule evaluation.
//!
//! # Features
//!
//! - Load Sigma rules from YAML files or directories
//! - Multiple log source adapters (syslog, journald, macOS unified logs, JSON files)
//! - Parallel rule evaluation with rayon
//! - Integration with protectinator-core SecurityCheck trait
//!
//! # Example
//!
//! ```no_run
//! use protectinator_sigma::{RuleSet, LogEvent, SigmaEngine};
//! use std::path::Path;
//!
//! // Load rules from a directory
//! let rules = RuleSet::from_directory(Path::new("/path/to/rules")).unwrap();
//! println!("Loaded {} rules", rules.len());
//!
//! // Create engine and scan events
//! let engine = SigmaEngine::new(rules);
//! let event = LogEvent::from_json(r#"{"EventID": 4625, "LogonType": 3}"#).unwrap();
//! let matches = engine.check_event(&event);
//! ```

pub mod error;
pub mod event;
pub mod logsource;
pub mod rule;
pub mod engine;

pub use error::{SigmaError, SigmaResult};
pub use event::LogEvent;
pub use logsource::{LogSource, LogSourceConfig, LogSourceType};
pub use rule::{RuleSet, SigmaRule, RuleMetadata, RuleSeverity};
pub use engine::{SigmaEngine, ScanResult, MatchedRule};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource, Result, SecurityCheck,
    Severity,
};
use std::path::PathBuf;
use std::sync::Arc;

/// Sigma rules check provider
pub struct SigmaProvider {
    rule_paths: Vec<PathBuf>,
    rules: Option<RuleSet>,
}

impl SigmaProvider {
    /// Create a new Sigma provider
    pub fn new() -> Self {
        Self {
            rule_paths: Vec::new(),
            rules: None,
        }
    }

    /// Add a rule path (file or directory)
    pub fn with_rule_path(mut self, path: PathBuf) -> Self {
        self.rule_paths.push(path);
        self
    }

    /// Add multiple rule paths
    pub fn with_rule_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.rule_paths.extend(paths);
        self
    }

    /// Load rules from configured paths
    pub fn load_rules(&mut self) -> SigmaResult<usize> {
        let mut ruleset = RuleSet::new();

        for path in &self.rule_paths {
            if path.is_dir() {
                let loaded = RuleSet::from_directory(path)?;
                ruleset.merge(loaded);
            } else if path.is_file() {
                if let Ok(rule) = SigmaRule::from_file(path) {
                    ruleset.add(rule);
                }
            }
        }

        let count = ruleset.len();
        self.rules = Some(ruleset);
        Ok(count)
    }

    /// Get the loaded rules
    pub fn rules(&self) -> Option<&RuleSet> {
        self.rules.as_ref()
    }
}

impl Default for SigmaProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for SigmaProvider {
    fn name(&self) -> &str {
        "sigma"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        let mut checks: Vec<Arc<dyn SecurityCheck>> = Vec::new();

        if let Some(rules) = &self.rules {
            if !rules.is_empty() {
                checks.push(Arc::new(SigmaSecurityCheck {
                    rules: rules.clone(),
                }));
            }
        }

        checks
    }

    fn refresh(&mut self) -> Result<()> {
        self.load_rules()
            .map_err(|e| protectinator_core::ProtectinatorError::Config(e.to_string()))?;
        Ok(())
    }
}

/// Security check that evaluates Sigma rules against system logs
struct SigmaSecurityCheck {
    rules: RuleSet,
}

impl SecurityCheck for SigmaSecurityCheck {
    fn id(&self) -> &str {
        "sigma-rules"
    }

    fn name(&self) -> &str {
        "Sigma Rules Detection"
    }

    fn description(&self) -> &str {
        "Evaluates Sigma detection rules against system logs to identify suspicious activity"
    }

    fn category(&self) -> &str {
        "detection"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        if self.rules.is_empty() {
            Applicability::NotApplicable("No Sigma rules loaded".to_string())
        } else {
            Applicability::Applicable
        }
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let engine = SigmaEngine::new(self.rules.clone());

        // Try to get events from available log sources
        let events = collect_system_events()?;

        let scan_results = engine.scan_events(&events);

        let findings: Vec<Finding> = scan_results
            .iter()
            .flat_map(|result| {
                result.matches.iter().map(|matched| {
                    let severity = match matched.rule.metadata.level {
                        RuleSeverity::Critical => Severity::Critical,
                        RuleSeverity::High => Severity::High,
                        RuleSeverity::Medium => Severity::Medium,
                        RuleSeverity::Low => Severity::Low,
                        RuleSeverity::Informational => Severity::Info,
                    };

                    Finding::new(
                        &format!("sigma-{}", matched.rule.id),
                        &matched.rule.metadata.title,
                        matched
                            .rule
                            .metadata
                            .description
                            .clone()
                            .unwrap_or_else(|| "Sigma rule matched".to_string()),
                        severity,
                        FindingSource::LogAnalysis {
                            log_source: result.event.source.clone().unwrap_or_default(),
                            rule_id: matched.rule.id.clone(),
                        },
                    )
                })
            })
            .collect();

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(30)
    }
}

/// Collect events from available system log sources
fn collect_system_events() -> Result<Vec<LogEvent>> {
    let mut events = Vec::new();

    // Try syslog on Linux
    #[cfg(target_os = "linux")]
    {
        if let Ok(syslog_events) = logsource::linux::read_syslog(100) {
            events.extend(syslog_events);
        }

        if let Ok(auth_events) = logsource::linux::read_auth_log(100) {
            events.extend(auth_events);
        }
    }

    // Try macOS unified log
    #[cfg(target_os = "macos")]
    {
        if let Ok(log_events) = logsource::macos::read_unified_log(100) {
            events.extend(log_events);
        }
    }

    Ok(events)
}
