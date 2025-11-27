//! Sigma rule matching engine

use crate::event::LogEvent;
use crate::rule::{RuleSet, RuleSeverity, SigmaRule};
use rayon::prelude::*;
use std::sync::Arc;

/// Result of scanning events against rules
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// The event that was scanned
    pub event: LogEvent,

    /// Rules that matched this event
    pub matches: Vec<MatchedRule>,
}

impl ScanResult {
    /// Check if any rules matched
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }

    /// Get the highest severity among matched rules
    pub fn max_severity(&self) -> Option<RuleSeverity> {
        self.matches
            .iter()
            .map(|m| m.rule.metadata.level)
            .max_by_key(|s| *s as u8)
    }

    /// Get count of matches by severity
    pub fn count_by_severity(&self) -> SeverityCounts {
        let mut counts = SeverityCounts::default();
        for m in &self.matches {
            match m.rule.metadata.level {
                RuleSeverity::Critical => counts.critical += 1,
                RuleSeverity::High => counts.high += 1,
                RuleSeverity::Medium => counts.medium += 1,
                RuleSeverity::Low => counts.low += 1,
                RuleSeverity::Informational => counts.informational += 1,
            }
        }
        counts
    }
}

/// Counts of matches by severity
#[derive(Debug, Clone, Default)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

impl SeverityCounts {
    pub fn total(&self) -> usize {
        self.critical + self.high + self.medium + self.low + self.informational
    }
}

/// A rule that matched an event
#[derive(Debug, Clone)]
pub struct MatchedRule {
    /// The rule that matched
    pub rule: Arc<SigmaRule>,

    /// Optional match details/context
    pub context: Option<String>,
}

/// Sigma rule matching engine
#[derive(Clone)]
pub struct SigmaEngine {
    rules: RuleSet,
    /// Minimum severity level to report
    min_severity: RuleSeverity,
    /// Use parallel scanning
    parallel: bool,
}

impl SigmaEngine {
    /// Create a new engine with a rule set
    pub fn new(rules: RuleSet) -> Self {
        Self {
            rules,
            min_severity: RuleSeverity::Informational,
            parallel: true,
        }
    }

    /// Set minimum severity to report
    pub fn with_min_severity(mut self, severity: RuleSeverity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Enable or disable parallel scanning
    pub fn parallel(mut self, parallel: bool) -> Self {
        self.parallel = parallel;
        self
    }

    /// Get the number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Get the loaded rules
    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    /// Check a single event against all rules
    pub fn check_event(&self, event: &LogEvent) -> Vec<MatchedRule> {
        let mut matches = Vec::new();

        // Get the sigma event representation once
        let sigma_event = event.to_sigma_event();

        for rule in self.rules.iter() {
            // Check if rule applies to this event's log source
            if !rule.applies_to(
                event.category.as_deref(),
                event.product.as_deref(),
                event.service.as_deref(),
            ) {
                continue;
            }

            // Check severity filter
            if (rule.metadata.level as u8) < (self.min_severity as u8) {
                continue;
            }

            // Check if rule matches
            if rule.compiled.is_match(&sigma_event) {
                matches.push(MatchedRule {
                    rule: Arc::new(rule.clone()),
                    context: None,
                });
            }
        }

        matches
    }

    /// Scan multiple events against all rules
    pub fn scan_events(&self, events: &[LogEvent]) -> Vec<ScanResult> {
        if self.parallel && events.len() > 10 {
            self.scan_events_parallel(events)
        } else {
            self.scan_events_sequential(events)
        }
    }

    /// Scan events sequentially
    fn scan_events_sequential(&self, events: &[LogEvent]) -> Vec<ScanResult> {
        events
            .iter()
            .map(|event| ScanResult {
                event: event.clone(),
                matches: self.check_event(event),
            })
            .filter(|r| r.has_matches())
            .collect()
    }

    /// Scan events in parallel
    fn scan_events_parallel(&self, events: &[LogEvent]) -> Vec<ScanResult> {
        events
            .par_iter()
            .map(|event| ScanResult {
                event: event.clone(),
                matches: self.check_event(event),
            })
            .filter(|r| r.has_matches())
            .collect()
    }

    /// Get a summary of scan results
    pub fn summarize(results: &[ScanResult]) -> ScanSummary {
        let mut summary = ScanSummary::default();

        summary.events_scanned = results.len();

        for result in results {
            if result.has_matches() {
                summary.events_matched += 1;
            }

            for matched in &result.matches {
                summary.total_matches += 1;
                match matched.rule.metadata.level {
                    RuleSeverity::Critical => summary.severity_counts.critical += 1,
                    RuleSeverity::High => summary.severity_counts.high += 1,
                    RuleSeverity::Medium => summary.severity_counts.medium += 1,
                    RuleSeverity::Low => summary.severity_counts.low += 1,
                    RuleSeverity::Informational => summary.severity_counts.informational += 1,
                }

                // Track unique rules
                if !summary.matched_rules.contains(&matched.rule.id) {
                    summary.matched_rules.push(matched.rule.id.clone());
                }
            }
        }

        summary
    }
}

/// Summary of scan results
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    /// Total events scanned
    pub events_scanned: usize,
    /// Events that matched at least one rule
    pub events_matched: usize,
    /// Total rule matches (one event can match multiple rules)
    pub total_matches: usize,
    /// Matches by severity
    pub severity_counts: SeverityCounts,
    /// Unique rule IDs that matched
    pub matched_rules: Vec<String>,
}

impl ScanSummary {
    /// Check if any matches were found
    pub fn has_matches(&self) -> bool {
        self.total_matches > 0
    }

    /// Get the number of unique rules that matched
    pub fn unique_rules_matched(&self) -> usize {
        self.matched_rules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::SigmaRule;

    const TEST_RULE: &str = r#"
title: Test Powershell Detection
id: test-rule-001
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'powershell'
    condition: selection
"#;

    #[test]
    fn test_engine_matching() {
        let rule = SigmaRule::from_yaml(TEST_RULE).unwrap();
        let mut ruleset = RuleSet::new();
        ruleset.add(rule);

        let engine = SigmaEngine::new(ruleset);

        // Should match
        let event = LogEvent::from_json(r#"{"CommandLine": "powershell.exe -enc base64"}"#)
            .unwrap()
            .with_category("process_creation")
            .with_product("windows");
        let matches = engine.check_event(&event);
        assert_eq!(matches.len(), 1);

        // Should not match (no powershell)
        let event = LogEvent::from_json(r#"{"CommandLine": "cmd.exe /c dir"}"#)
            .unwrap()
            .with_category("process_creation")
            .with_product("windows");
        let matches = engine.check_event(&event);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_scan_summary() {
        let rule = SigmaRule::from_yaml(TEST_RULE).unwrap();
        let mut ruleset = RuleSet::new();
        ruleset.add(rule);

        let engine = SigmaEngine::new(ruleset);

        let events = vec![
            LogEvent::from_json(r#"{"CommandLine": "powershell.exe"}"#)
                .unwrap()
                .with_category("process_creation")
                .with_product("windows"),
            LogEvent::from_json(r#"{"CommandLine": "cmd.exe"}"#)
                .unwrap()
                .with_category("process_creation")
                .with_product("windows"),
            LogEvent::from_json(r#"{"CommandLine": "powershell -nop"}"#)
                .unwrap()
                .with_category("process_creation")
                .with_product("windows"),
        ];

        let results = engine.scan_events(&events);
        let summary = SigmaEngine::summarize(&results);

        assert_eq!(summary.events_matched, 2);
        assert_eq!(summary.total_matches, 2);
        assert_eq!(summary.severity_counts.high, 2);
    }
}
