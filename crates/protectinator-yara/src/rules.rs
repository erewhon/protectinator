//! YARA rule definitions

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuleError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    Parse(String),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
}

/// Pattern type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PatternType {
    /// Plain text string
    String,
    /// Hex bytes (e.g., "48 65 6C 6C 6F")
    Hex,
    /// Regular expression
    Regex,
}

impl Default for PatternType {
    fn default() -> Self {
        PatternType::String
    }
}

/// A pattern to match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pattern {
    /// Pattern identifier (e.g., "$a")
    pub id: String,
    /// Pattern value
    pub value: String,
    /// Pattern type
    #[serde(default)]
    pub pattern_type: PatternType,
    /// Case insensitive
    #[serde(default)]
    pub nocase: bool,
    /// Match wide strings (UTF-16)
    #[serde(default)]
    pub wide: bool,
    /// Match ASCII strings
    #[serde(default = "default_true")]
    pub ascii: bool,
}

fn default_true() -> bool {
    true
}

impl Pattern {
    pub fn new(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            value: value.into(),
            pattern_type: PatternType::String,
            nocase: false,
            wide: false,
            ascii: true,
        }
    }

    pub fn hex(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            value: value.into(),
            pattern_type: PatternType::Hex,
            nocase: false,
            wide: false,
            ascii: true,
        }
    }

    pub fn regex(id: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            value: value.into(),
            pattern_type: PatternType::Regex,
            nocase: false,
            wide: false,
            ascii: true,
        }
    }

    /// Convert pattern to bytes for matching
    pub fn to_bytes(&self) -> Result<Vec<u8>, RuleError> {
        match self.pattern_type {
            PatternType::String => Ok(self.value.as_bytes().to_vec()),
            PatternType::Hex => parse_hex_pattern(&self.value),
            PatternType::Regex => Ok(self.value.as_bytes().to_vec()),
        }
    }
}

fn parse_hex_pattern(hex: &str) -> Result<Vec<u8>, RuleError> {
    let hex = hex.replace([' ', '\n', '\r', '\t'], "");
    let mut bytes = Vec::new();

    let mut chars = hex.chars().peekable();
    while let Some(c1) = chars.next() {
        if c1 == '?' {
            // Wildcard
            if chars.peek() == Some(&'?') {
                chars.next();
            }
            bytes.push(0x00); // Placeholder for wildcard
            continue;
        }

        let c2 = chars.next().ok_or_else(|| {
            RuleError::InvalidPattern("Incomplete hex byte".to_string())
        })?;

        let byte = u8::from_str_radix(&format!("{}{}", c1, c2), 16)
            .map_err(|_| RuleError::InvalidPattern(format!("Invalid hex: {}{}", c1, c2)))?;

        bytes.push(byte);
    }

    Ok(bytes)
}

/// Rule condition
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Condition {
    /// All patterns must match
    All,
    /// Any pattern must match
    Any,
    /// Specific number of patterns must match
    Count(usize),
    /// Custom expression (simplified)
    Expr(String),
}

impl Default for Condition {
    fn default() -> Self {
        Condition::Any
    }
}

/// A YARA-like rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Rule name
    pub name: String,
    /// Rule description
    pub description: Option<String>,
    /// Rule author
    pub author: Option<String>,
    /// Rule severity
    pub severity: Option<String>,
    /// Tags
    #[serde(default)]
    pub tags: Vec<String>,
    /// Patterns to match
    #[serde(default)]
    pub patterns: Vec<Pattern>,
    /// Condition for matching
    #[serde(default)]
    pub condition: Condition,
    /// Source file
    #[serde(skip)]
    pub source_file: Option<String>,
}

impl Rule {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            author: None,
            severity: None,
            tags: Vec::new(),
            patterns: Vec::new(),
            condition: Condition::Any,
            source_file: None,
        }
    }

    pub fn with_pattern(mut self, pattern: Pattern) -> Self {
        self.patterns.push(pattern);
        self
    }

    pub fn with_condition(mut self, condition: Condition) -> Self {
        self.condition = condition;
        self
    }
}

/// A set of rules
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleSet {
    /// Rules in this set
    pub rules: Vec<Rule>,
    /// Name of the ruleset
    pub name: Option<String>,
}

impl RuleSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load rules from a YAML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, RuleError> {
        let content = fs::read_to_string(path.as_ref())?;
        let mut ruleset: RuleSet =
            serde_yaml::from_str(&content).map_err(|e| RuleError::Parse(e.to_string()))?;

        // Set source file for all rules
        let source = path.as_ref().to_string_lossy().to_string();
        for rule in &mut ruleset.rules {
            rule.source_file = Some(source.clone());
        }

        Ok(ruleset)
    }

    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}
