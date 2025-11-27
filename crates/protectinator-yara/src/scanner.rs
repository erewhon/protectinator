//! YARA-like pattern scanner

use crate::rules::{Condition, Pattern, PatternType, Rule, RuleSet};
use rayon::prelude::*;
use regex::bytes::Regex as BytesRegex;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// A pattern match in a file
#[derive(Debug, Clone)]
pub struct Match {
    /// Rule that matched
    pub rule: Rule,
    /// Pattern IDs that matched
    pub matched_patterns: Vec<String>,
    /// Offset where match was found
    pub offset: Option<usize>,
}

/// Result of scanning a file
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path to the scanned file
    pub path: PathBuf,
    /// Size of the file
    pub size: u64,
    /// Matches found
    pub matches: Vec<Match>,
    /// Any errors during scanning
    pub error: Option<String>,
}

impl ScanResult {
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }
}

/// YARA-like scanner
pub struct YaraScanner {
    rules: Vec<Rule>,
    max_file_size: u64,
}

impl YaraScanner {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            max_file_size: 50 * 1024 * 1024, // 50 MB
        }
    }

    /// Set maximum file size to scan
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Add a ruleset
    pub fn add_rules(&mut self, ruleset: RuleSet) {
        self.rules.extend(ruleset.rules);
    }

    /// Add a single rule
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Get number of loaded rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Scan a single file
    pub fn scan_file(&self, path: impl AsRef<Path>) -> ScanResult {
        let path = path.as_ref();

        // Check file size
        let metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e) => {
                return ScanResult {
                    path: path.to_path_buf(),
                    size: 0,
                    matches: Vec::new(),
                    error: Some(e.to_string()),
                };
            }
        };

        if metadata.len() > self.max_file_size {
            return ScanResult {
                path: path.to_path_buf(),
                size: metadata.len(),
                matches: Vec::new(),
                error: Some("File too large".to_string()),
            };
        }

        // Read file content
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(e) => {
                return ScanResult {
                    path: path.to_path_buf(),
                    size: metadata.len(),
                    matches: Vec::new(),
                    error: Some(e.to_string()),
                };
            }
        };

        // Check each rule
        let mut matches = Vec::new();

        for rule in &self.rules {
            if let Some(m) = self.check_rule(rule, &content) {
                matches.push(m);
            }
        }

        ScanResult {
            path: path.to_path_buf(),
            size: metadata.len(),
            matches,
            error: None,
        }
    }

    /// Scan a directory recursively
    pub fn scan_path(&self, path: impl AsRef<Path>) -> Vec<ScanResult> {
        let path = path.as_ref();

        if path.is_file() {
            return vec![self.scan_file(path)];
        }

        // Collect files to scan
        let files: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect();

        // Scan in parallel
        files
            .par_iter()
            .map(|f| self.scan_file(f))
            .filter(|r| r.has_matches() || r.error.is_some())
            .collect()
    }

    fn check_rule(&self, rule: &Rule, content: &[u8]) -> Option<Match> {
        if rule.patterns.is_empty() {
            return None;
        }

        let mut matched_patterns = Vec::new();
        let mut first_offset = None;

        for pattern in &rule.patterns {
            if let Some(offset) = self.match_pattern(pattern, content) {
                matched_patterns.push(pattern.id.clone());
                if first_offset.is_none() {
                    first_offset = Some(offset);
                }
            }
        }

        // Check condition
        let matches = match &rule.condition {
            Condition::All => matched_patterns.len() == rule.patterns.len(),
            Condition::Any => !matched_patterns.is_empty(),
            Condition::Count(n) => matched_patterns.len() >= *n,
            Condition::Expr(_) => !matched_patterns.is_empty(), // Simplified
        };

        if matches {
            Some(Match {
                rule: rule.clone(),
                matched_patterns,
                offset: first_offset,
            })
        } else {
            None
        }
    }

    fn match_pattern(&self, pattern: &Pattern, content: &[u8]) -> Option<usize> {
        match pattern.pattern_type {
            PatternType::String => {
                let search = if pattern.nocase {
                    let content_lower = content
                        .iter()
                        .map(|b| b.to_ascii_lowercase())
                        .collect::<Vec<_>>();
                    let pattern_lower = pattern.value.to_lowercase();
                    find_bytes(&content_lower, pattern_lower.as_bytes())
                } else {
                    find_bytes(content, pattern.value.as_bytes())
                };
                search
            }
            PatternType::Hex => {
                if let Ok(bytes) = pattern.to_bytes() {
                    find_bytes(content, &bytes)
                } else {
                    None
                }
            }
            PatternType::Regex => {
                if let Ok(re) = BytesRegex::new(&pattern.value) {
                    re.find(content).map(|m| m.start())
                } else {
                    None
                }
            }
        }
    }
}

impl Default for YaraScanner {
    fn default() -> Self {
        Self::new()
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }

    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Create common malware detection rules
pub fn get_builtin_rules() -> RuleSet {
    let mut ruleset = RuleSet::new();
    ruleset.name = Some("builtin".to_string());

    // Suspicious script patterns
    ruleset.add_rule(
        Rule::new("suspicious_powershell")
            .with_pattern(Pattern::new("$a", "-enc"))
            .with_pattern(Pattern::new("$b", "-EncodedCommand"))
            .with_pattern(Pattern::new("$c", "IEX("))
            .with_pattern(Pattern::new("$d", "Invoke-Expression"))
            .with_condition(Condition::Any),
    );

    // Common malware strings
    ruleset.add_rule(
        Rule::new("reverse_shell_indicator")
            .with_pattern(Pattern::new("$a", "/dev/tcp/"))
            .with_pattern(Pattern::new("$b", "bash -i"))
            .with_pattern(Pattern::new("$c", "nc -e"))
            .with_pattern(Pattern::new("$d", "python -c"))
            .with_condition(Condition::Any),
    );

    // Cryptominer indicators
    ruleset.add_rule(
        Rule::new("cryptominer")
            .with_pattern(Pattern::new("$a", "stratum+tcp://"))
            .with_pattern(Pattern::new("$b", "xmrig"))
            .with_pattern(Pattern::new("$c", "minerd"))
            .with_pattern(Pattern::new("$d", "cpuminer"))
            .with_condition(Condition::Any),
    );

    ruleset
}
