//! Scan runner that orchestrates security checks

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, NullProgressReporter,
    ProgressReporter, Result, ScanResults, SecurityCheck,
};
use protectinator_platform::{get_system_info, DefaultCheckContext};
use rayon::prelude::*;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

/// Configuration for the scan runner
#[derive(Debug, Clone)]
pub struct RunnerConfig {
    /// Run checks in parallel
    pub parallel: bool,
    /// Continue on error
    pub continue_on_error: bool,
    /// Only run applicable checks
    pub skip_non_applicable: bool,
}

impl Default for RunnerConfig {
    fn default() -> Self {
        Self {
            parallel: true,
            continue_on_error: true,
            skip_non_applicable: true,
        }
    }
}

/// Main scan runner that orchestrates all security checks
pub struct ScanRunner {
    providers: Vec<Box<dyn CheckProvider>>,
    config: RunnerConfig,
    progress: Arc<dyn ProgressReporter>,
}

impl ScanRunner {
    /// Create a new scan runner
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            config: RunnerConfig::default(),
            progress: Arc::new(NullProgressReporter),
        }
    }

    /// Set the runner configuration
    pub fn with_config(mut self, config: RunnerConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the progress reporter
    pub fn with_progress(mut self, progress: Arc<dyn ProgressReporter>) -> Self {
        self.progress = progress;
        self
    }

    /// Add a check provider
    pub fn add_provider(&mut self, provider: Box<dyn CheckProvider>) {
        self.providers.push(provider);
    }

    /// Run all checks and return results
    pub fn run(&self, ctx: &dyn CheckContext) -> Result<ScanResults> {
        let mut results = ScanResults::new(get_system_info());

        info!("Starting security scan with {} providers", self.providers.len());

        for provider in &self.providers {
            let provider_name = provider.name();
            debug!("Running checks from provider: {}", provider_name);

            let checks = provider.checks();
            let applicable_checks: Vec<_> = if self.config.skip_non_applicable {
                checks
                    .into_iter()
                    .filter(|c| matches!(c.applicability(ctx), Applicability::Applicable))
                    .collect()
            } else {
                checks
            };

            self.progress.phase_started(provider_name, applicable_checks.len());

            let findings = if self.config.parallel {
                self.run_checks_parallel(&applicable_checks, ctx, &mut results)
            } else {
                self.run_checks_sequential(&applicable_checks, ctx, &mut results)
            };

            for finding in findings {
                results.add_finding(finding);
            }

            self.progress.phase_completed(provider_name);
        }

        results.complete();
        info!(
            "Scan completed: {} findings, {} errors",
            results.findings.len(),
            results.errors.len()
        );

        Ok(results)
    }

    fn run_checks_sequential(
        &self,
        checks: &[Arc<dyn SecurityCheck>],
        ctx: &dyn CheckContext,
        results: &mut ScanResults,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (i, check) in checks.iter().enumerate() {
            self.progress.progress(i + 1, check.name());

            match check.execute(ctx) {
                Ok(check_findings) => {
                    for finding in &check_findings {
                        self.progress.finding_discovered(finding);
                    }
                    findings.extend(check_findings);
                    results.summary.checks_passed += 1;
                }
                Err(e) => {
                    let msg = format!("Check {} failed: {}", check.id(), e);
                    warn!("{}", msg);
                    self.progress.error(check.id(), &msg);
                    results.add_error(check.id(), msg, self.config.continue_on_error);
                    results.summary.checks_failed += 1;

                    if !self.config.continue_on_error {
                        break;
                    }
                }
            }
        }

        findings
    }

    fn run_checks_parallel(
        &self,
        checks: &[Arc<dyn SecurityCheck>],
        ctx: &dyn CheckContext,
        results: &mut ScanResults,
    ) -> Vec<Finding> {
        let findings = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let progress_counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        checks.par_iter().for_each(|check| {
            let count = progress_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            // Note: Progress reporting in parallel mode may be out of order
            // This is acceptable for the progress bar use case

            match check.execute(ctx) {
                Ok(check_findings) => {
                    for finding in &check_findings {
                        self.progress.finding_discovered(finding);
                    }
                    findings.lock().unwrap().extend(check_findings);
                }
                Err(e) => {
                    let msg = format!("Check {} failed: {}", check.id(), e);
                    warn!("{}", msg);
                    self.progress.error(check.id(), &msg);
                    errors.lock().unwrap().push((check.id().to_string(), msg));
                }
            }
        });

        // Transfer errors to results
        for (id, msg) in errors.lock().unwrap().drain(..) {
            results.add_error(id, msg, true);
            results.summary.checks_failed += 1;
        }

        results.summary.checks_passed = checks.len() - results.summary.checks_failed;

        Arc::try_unwrap(findings)
            .map(|mutex| mutex.into_inner().unwrap())
            .unwrap_or_else(|arc| arc.lock().unwrap().clone())
    }
}

impl Default for ScanRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for creating configured scan runners
pub struct ScanRunnerBuilder {
    runner: ScanRunner,
    ctx_config: protectinator_core::CheckConfig,
}

impl ScanRunnerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            runner: ScanRunner::new(),
            ctx_config: Default::default(),
        }
    }

    /// Set parallel execution
    pub fn parallel(mut self, parallel: bool) -> Self {
        self.runner.config.parallel = parallel;
        self
    }

    /// Set continue on error
    pub fn continue_on_error(mut self, continue_on_error: bool) -> Self {
        self.runner.config.continue_on_error = continue_on_error;
        self
    }

    /// Set progress reporter
    pub fn progress(mut self, progress: Arc<dyn ProgressReporter>) -> Self {
        self.runner.progress = progress;
        self
    }

    /// Add a provider
    pub fn provider(mut self, provider: Box<dyn CheckProvider>) -> Self {
        self.runner.providers.push(provider);
        self
    }

    /// Add exclude paths
    pub fn exclude_paths(mut self, paths: Vec<String>) -> Self {
        self.ctx_config.exclude_paths = paths;
        self
    }

    /// Build and run the scan
    pub fn run(self) -> Result<ScanResults> {
        let ctx = DefaultCheckContext::new(self.ctx_config);
        self.runner.run(&ctx)
    }

    /// Build the runner without running
    pub fn build(self) -> (ScanRunner, DefaultCheckContext) {
        let ctx = DefaultCheckContext::new(self.ctx_config);
        (self.runner, ctx)
    }
}

impl Default for ScanRunnerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
