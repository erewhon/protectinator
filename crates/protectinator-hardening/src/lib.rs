//! System Hardening Checks for Protectinator
//!
//! Provides security configuration checks for Linux and macOS based on
//! CIS Benchmarks and security best practices.
//!
//! # Features
//!
//! - SSH configuration checks
//! - Kernel security settings (ASLR, ptrace, etc.)
//! - Network hardening (firewall, IP forwarding)
//! - Filesystem security (SUID audit, permissions)
//! - macOS-specific checks (SIP, Gatekeeper, FileVault)
//!
//! # Example
//!
//! ```no_run
//! use protectinator_hardening::checks::{get_platform_checks, CheckCategory};
//!
//! // Get all checks for current platform
//! let registry = get_platform_checks();
//! println!("Loaded {} hardening checks", registry.len());
//!
//! // Run all checks
//! for check in registry.checks() {
//!     let result = check.run();
//!     println!("{}: {:?}", check.definition().name, result);
//! }
//! ```

pub mod checks;

pub use checks::{
    get_categories, get_platform_checks, CheckCategory, CheckRegistry, CheckResult,
    HardeningCheck, RunnableCheck,
};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, Result, SecurityCheck, Severity,
};
use std::sync::Arc;

/// System hardening check provider
pub struct HardeningProvider {
    categories: Vec<CheckCategory>,
    skip_checks: Vec<String>,
    min_severity: Severity,
    registry: CheckRegistry,
}

impl HardeningProvider {
    /// Create a new hardening provider
    pub fn new() -> Self {
        Self {
            categories: Vec::new(),
            skip_checks: Vec::new(),
            min_severity: Severity::Low,
            registry: get_platform_checks(),
        }
    }

    /// Filter by categories
    pub fn with_categories(mut self, categories: Vec<CheckCategory>) -> Self {
        self.categories = categories;
        self
    }

    /// Skip specific checks by ID
    pub fn skip(mut self, checks: Vec<String>) -> Self {
        self.skip_checks = checks;
        self
    }

    /// Set minimum severity to report
    pub fn with_min_severity(mut self, severity: Severity) -> Self {
        self.min_severity = severity;
        self
    }

    /// Get the check registry
    pub fn registry(&self) -> &CheckRegistry {
        &self.registry
    }

    /// Run all applicable checks and return findings
    pub fn run_checks(&self) -> Vec<(String, CheckResult, Option<Finding>)> {
        let mut results = Vec::new();

        for check in self.registry.checks() {
            let def = check.definition();

            // Skip if check is in skip list
            if self.skip_checks.contains(&def.id) {
                continue;
            }

            // Skip if category doesn't match filter
            if !self.categories.is_empty() && !self.categories.contains(&def.category) {
                continue;
            }

            // Skip if not applicable
            if !check.is_applicable() {
                results.push((
                    def.id.clone(),
                    CheckResult::skipped("Not applicable on this system"),
                    None,
                ));
                continue;
            }

            // Run the check
            let result = check.run();

            // Convert to finding if it's a failure
            let finding = def.to_finding(&result);

            // Filter by severity
            if let Some(ref f) = finding {
                if (f.severity as u8) < (self.min_severity as u8) {
                    continue;
                }
            }

            results.push((def.id.clone(), result, finding));
        }

        results
    }
}

impl Default for HardeningProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for HardeningProvider {
    fn name(&self) -> &str {
        "hardening"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        vec![Arc::new(HardeningSecurityCheck {
            categories: self.categories.clone(),
            skip_checks: self.skip_checks.clone(),
            min_severity: self.min_severity,
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        self.registry = get_platform_checks();
        Ok(())
    }
}

/// Security check that runs all hardening checks
struct HardeningSecurityCheck {
    categories: Vec<CheckCategory>,
    skip_checks: Vec<String>,
    min_severity: Severity,
}

impl SecurityCheck for HardeningSecurityCheck {
    fn id(&self) -> &str {
        "system-hardening"
    }

    fn name(&self) -> &str {
        "System Hardening Checks"
    }

    fn description(&self) -> &str {
        "Evaluates system security configuration against hardening best practices"
    }

    fn category(&self) -> &str {
        "hardening"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        Applicability::Applicable
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let provider = HardeningProvider::new()
            .with_categories(self.categories.clone())
            .skip(self.skip_checks.clone())
            .with_min_severity(self.min_severity);

        let results = provider.run_checks();

        let findings: Vec<Finding> = results
            .into_iter()
            .filter_map(|(_, _, finding)| finding)
            .collect();

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(10)
    }
}

/// Summary of hardening check results
#[derive(Debug, Clone, Default)]
pub struct HardeningSummary {
    pub total_checks: usize,
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub errors: usize,
    pub critical_failures: usize,
    pub high_failures: usize,
    pub medium_failures: usize,
    pub low_failures: usize,
}

impl HardeningSummary {
    /// Create summary from check results
    pub fn from_results(results: &[(String, CheckResult, Option<Finding>)]) -> Self {
        let mut summary = Self::default();

        for (_, result, finding) in results {
            summary.total_checks += 1;

            match result {
                CheckResult::Pass { .. } => summary.passed += 1,
                CheckResult::Fail { severity, .. } => {
                    summary.failed += 1;
                    match severity {
                        Severity::Critical => summary.critical_failures += 1,
                        Severity::High => summary.high_failures += 1,
                        Severity::Medium => summary.medium_failures += 1,
                        Severity::Low | Severity::Info => summary.low_failures += 1,
                    }
                }
                CheckResult::Skipped { .. } => summary.skipped += 1,
                CheckResult::Error { .. } => summary.errors += 1,
            }

            // Also count from findings for consistency
            if let Some(f) = finding {
                match f.severity {
                    Severity::Critical => {}
                    Severity::High => {}
                    Severity::Medium => {}
                    Severity::Low | Severity::Info => {}
                }
            }
        }

        summary
    }

    /// Check if any critical or high severity issues were found
    pub fn has_critical_issues(&self) -> bool {
        self.critical_failures > 0 || self.high_failures > 0
    }

    /// Get a score (0-100) based on passed checks
    pub fn score(&self) -> u32 {
        if self.total_checks == 0 {
            return 100;
        }
        let applicable = self.total_checks - self.skipped;
        if applicable == 0 {
            return 100;
        }
        ((self.passed as f64 / applicable as f64) * 100.0) as u32
    }
}
