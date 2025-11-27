//! Sigma rule loading and parsing

use crate::error::{SigmaError, SigmaResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;

/// A Sigma detection rule
#[derive(Debug, Clone)]
pub struct SigmaRule {
    /// Unique rule identifier
    pub id: String,

    /// Rule metadata
    pub metadata: RuleMetadata,

    /// Log source specification
    pub logsource: LogSource,

    /// The compiled sigma-rust rule for evaluation (wrapped in Arc since Rule doesn't impl Clone)
    pub(crate) compiled: Arc<sigma_rust::Rule>,

    /// Original YAML content
    pub yaml: String,
}

impl SigmaRule {
    /// Load a rule from a YAML string
    pub fn from_yaml(yaml: &str) -> SigmaResult<Self> {
        // Parse metadata first
        let metadata: RuleYaml = serde_yaml::from_str(yaml)?;

        // Compile the rule using sigma-rust
        let compiled = sigma_rust::rule_from_yaml(yaml)
            .map_err(|e| SigmaError::ParseError(format!("{:?}", e)))?;

        Ok(Self {
            id: metadata.id.unwrap_or_else(|| uuid_from_title(&metadata.title)),
            metadata: RuleMetadata {
                title: metadata.title,
                description: metadata.description,
                author: metadata.author,
                date: metadata.date,
                modified: metadata.modified,
                status: metadata.status.map(|s| s.parse().unwrap_or_default()),
                level: metadata
                    .level
                    .map(|l| l.parse().unwrap_or_default())
                    .unwrap_or_default(),
                references: metadata.references.unwrap_or_default(),
                tags: metadata.tags.unwrap_or_default(),
                falsepositives: metadata.falsepositives.unwrap_or_default(),
            },
            logsource: LogSource {
                category: metadata.logsource.category,
                product: metadata.logsource.product,
                service: metadata.logsource.service,
            },
            compiled: Arc::new(compiled),
            yaml: yaml.to_string(),
        })
    }

    /// Load a rule from a file
    pub fn from_file(path: &Path) -> SigmaResult<Self> {
        let yaml = std::fs::read_to_string(path)?;
        Self::from_yaml(&yaml).map_err(|e| {
            SigmaError::ParseError(format!("{}: {}", path.display(), e))
        })
    }

    /// Check if this rule matches an event
    pub fn matches(&self, event: &crate::LogEvent) -> bool {
        let sigma_event = event.to_sigma_event();
        self.compiled.is_match(&sigma_event)
    }

    /// Check if this rule applies to the given log source
    pub fn applies_to(&self, category: Option<&str>, product: Option<&str>, service: Option<&str>) -> bool {
        // If the rule has a category requirement, check it
        if let Some(rule_cat) = &self.logsource.category {
            if let Some(event_cat) = category {
                if !rule_cat.eq_ignore_ascii_case(event_cat) {
                    return false;
                }
            }
        }

        // If the rule has a product requirement, check it
        if let Some(rule_prod) = &self.logsource.product {
            if let Some(event_prod) = product {
                if !rule_prod.eq_ignore_ascii_case(event_prod) {
                    return false;
                }
            }
        }

        // If the rule has a service requirement, check it
        if let Some(rule_svc) = &self.logsource.service {
            if let Some(event_svc) = service {
                if !rule_svc.eq_ignore_ascii_case(event_svc) {
                    return false;
                }
            }
        }

        true
    }
}

/// Rule metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetadata {
    /// Rule title
    pub title: String,

    /// Rule description
    pub description: Option<String>,

    /// Rule author
    pub author: Option<String>,

    /// Creation date
    pub date: Option<String>,

    /// Last modified date
    pub modified: Option<String>,

    /// Rule status
    pub status: Option<RuleStatus>,

    /// Rule severity level
    pub level: RuleSeverity,

    /// External references
    pub references: Vec<String>,

    /// MITRE ATT&CK tags and other tags
    pub tags: Vec<String>,

    /// Known false positives
    pub falsepositives: Vec<String>,
}

/// Log source specification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogSource {
    /// Log category (e.g., "process_creation", "network_connection")
    pub category: Option<String>,

    /// Product (e.g., "windows", "linux", "macos")
    pub product: Option<String>,

    /// Service (e.g., "sysmon", "security", "audit")
    pub service: Option<String>,
}

/// Rule status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    /// Stable rule
    Stable,
    /// Test rule
    Test,
    /// Experimental rule
    #[default]
    Experimental,
    /// Deprecated rule
    Deprecated,
    /// Unsupported rule
    Unsupported,
}

impl std::str::FromStr for RuleStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "stable" => Ok(RuleStatus::Stable),
            "test" => Ok(RuleStatus::Test),
            "experimental" => Ok(RuleStatus::Experimental),
            "deprecated" => Ok(RuleStatus::Deprecated),
            "unsupported" => Ok(RuleStatus::Unsupported),
            _ => Ok(RuleStatus::Experimental),
        }
    }
}

impl std::fmt::Display for RuleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleStatus::Stable => write!(f, "stable"),
            RuleStatus::Test => write!(f, "test"),
            RuleStatus::Experimental => write!(f, "experimental"),
            RuleStatus::Deprecated => write!(f, "deprecated"),
            RuleStatus::Unsupported => write!(f, "unsupported"),
        }
    }
}

/// Rule severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleSeverity {
    /// Informational only
    Informational,
    /// Low severity
    #[default]
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

impl std::str::FromStr for RuleSeverity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "informational" | "info" => Ok(RuleSeverity::Informational),
            "low" => Ok(RuleSeverity::Low),
            "medium" => Ok(RuleSeverity::Medium),
            "high" => Ok(RuleSeverity::High),
            "critical" => Ok(RuleSeverity::Critical),
            _ => Ok(RuleSeverity::Low),
        }
    }
}

impl std::fmt::Display for RuleSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleSeverity::Informational => write!(f, "informational"),
            RuleSeverity::Low => write!(f, "low"),
            RuleSeverity::Medium => write!(f, "medium"),
            RuleSeverity::High => write!(f, "high"),
            RuleSeverity::Critical => write!(f, "critical"),
        }
    }
}

/// A collection of Sigma rules
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<SigmaRule>,
    by_id: HashMap<String, usize>,
}

impl RuleSet {
    /// Create a new empty rule set
    pub fn new() -> Self {
        Self::default()
    }

    /// Load rules from a directory
    pub fn from_directory(path: &Path) -> SigmaResult<Self> {
        let mut ruleset = Self::new();

        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "yml" || ext == "yaml" {
                        match SigmaRule::from_file(path) {
                            Ok(rule) => {
                                ruleset.add(rule);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to load rule {}: {}", path.display(), e);
                            }
                        }
                    }
                }
            }
        }

        Ok(ruleset)
    }

    /// Add a rule to the set
    pub fn add(&mut self, rule: SigmaRule) {
        let index = self.rules.len();
        self.by_id.insert(rule.id.clone(), index);
        self.rules.push(rule);
    }

    /// Merge another rule set into this one
    pub fn merge(&mut self, other: RuleSet) {
        for rule in other.rules {
            self.add(rule);
        }
    }

    /// Get a rule by ID
    pub fn get(&self, id: &str) -> Option<&SigmaRule> {
        self.by_id.get(id).map(|&idx| &self.rules[idx])
    }

    /// Get all rules
    pub fn rules(&self) -> &[SigmaRule] {
        &self.rules
    }

    /// Get the number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate over rules
    pub fn iter(&self) -> impl Iterator<Item = &SigmaRule> {
        self.rules.iter()
    }

    /// Filter rules by log source
    pub fn filter_by_logsource(
        &self,
        category: Option<&str>,
        product: Option<&str>,
        service: Option<&str>,
    ) -> Vec<&SigmaRule> {
        self.rules
            .iter()
            .filter(|r| r.applies_to(category, product, service))
            .collect()
    }

    /// Filter rules by severity
    pub fn filter_by_severity(&self, min_level: RuleSeverity) -> Vec<&SigmaRule> {
        self.rules
            .iter()
            .filter(|r| r.metadata.level as u8 >= min_level as u8)
            .collect()
    }

    /// Filter rules by status
    pub fn filter_by_status(&self, status: RuleStatus) -> Vec<&SigmaRule> {
        self.rules
            .iter()
            .filter(|r| r.metadata.status == Some(status))
            .collect()
    }

    /// Get rules by tag (case-insensitive)
    pub fn filter_by_tag(&self, tag: &str) -> Vec<&SigmaRule> {
        let tag_lower = tag.to_lowercase();
        self.rules
            .iter()
            .filter(|r| {
                r.metadata
                    .tags
                    .iter()
                    .any(|t| t.to_lowercase().contains(&tag_lower))
            })
            .collect()
    }
}

/// Internal struct for parsing rule YAML
#[derive(Debug, Deserialize)]
struct RuleYaml {
    #[serde(default)]
    id: Option<String>,
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    references: Option<Vec<String>>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    falsepositives: Option<Vec<String>>,
    logsource: LogSourceYaml,
}

#[derive(Debug, Deserialize)]
struct LogSourceYaml {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    service: Option<String>,
}

/// Generate a deterministic UUID-like ID from a title
fn uuid_from_title(title: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    title.hash(&mut hasher);
    let hash = hasher.finish();

    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RULE: &str = r#"
title: Test Rule - Suspicious Process Creation
id: 12345678-1234-1234-1234-123456789012
status: test
level: high
description: Detects suspicious process creation
author: Test Author
date: 2024/01/01
references:
    - https://example.com/ref1
tags:
    - attack.execution
    - attack.t1059
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'powershell'
            - 'cmd.exe'
    condition: selection
falsepositives:
    - Legitimate admin activity
"#;

    #[test]
    fn test_parse_rule() {
        let rule = SigmaRule::from_yaml(TEST_RULE).unwrap();
        assert_eq!(rule.id, "12345678-1234-1234-1234-123456789012");
        assert_eq!(rule.metadata.title, "Test Rule - Suspicious Process Creation");
        assert_eq!(rule.metadata.level, RuleSeverity::High);
        assert_eq!(rule.metadata.status, Some(RuleStatus::Test));
        assert!(rule.metadata.tags.contains(&"attack.execution".to_string()));
    }

    #[test]
    fn test_rule_matching() {
        let rule = SigmaRule::from_yaml(TEST_RULE).unwrap();

        let event = crate::LogEvent::from_json(r#"{"CommandLine": "powershell.exe -enc"}"#).unwrap();
        assert!(rule.matches(&event));

        let event = crate::LogEvent::from_json(r#"{"CommandLine": "notepad.exe"}"#).unwrap();
        assert!(!rule.matches(&event));
    }
}
