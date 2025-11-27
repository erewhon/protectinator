//! Full scan command
//!
//! Runs comprehensive security scans including:
//! - File integrity monitoring
//! - System hardening checks
//! - Sigma rule evaluation
//! - Persistence mechanism detection
//! - Privilege escalation path finding

use clap::{Args, ValueEnum};
use protectinator_core::{Finding, ProgressReporter, Severity};
use protectinator_engine::{format_json, format_text, ScanRunnerBuilder};
#[cfg(feature = "fim")]
use protectinator_fim::FimProvider;
#[cfg(feature = "hardening")]
use protectinator_hardening::HardeningProvider;
#[cfg(feature = "persistence")]
use protectinator_persistence::PersistenceProvider;
#[cfg(feature = "privesc")]
use protectinator_privesc::PrivescProvider;
#[cfg(feature = "sigma")]
use protectinator_sigma::SigmaProvider;
use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Scan profile presets
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ScanProfile {
    /// Quick scan - essential checks only (hardening, high-risk persistence)
    Quick,
    /// Standard scan - most checks (default)
    #[default]
    Standard,
    /// Full scan - all checks including low-priority items
    Full,
    /// Audit mode - comprehensive scan for compliance
    Audit,
}

/// Minimum severity to report
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum MinSeverity {
    /// Report all findings including info
    Info,
    /// Report low severity and above
    #[default]
    Low,
    /// Report medium severity and above
    Medium,
    /// Report high severity and above
    High,
    /// Report only critical findings
    Critical,
}

impl From<MinSeverity> for Severity {
    fn from(s: MinSeverity) -> Self {
        match s {
            MinSeverity::Info => Severity::Info,
            MinSeverity::Low => Severity::Low,
            MinSeverity::Medium => Severity::Medium,
            MinSeverity::High => Severity::High,
            MinSeverity::Critical => Severity::Critical,
        }
    }
}

#[derive(Args)]
pub struct ScanArgs {
    /// Scan profile preset
    #[arg(long, short = 'p', value_enum, default_value_t = ScanProfile::Standard)]
    profile: ScanProfile,

    /// Minimum severity to report
    #[arg(long, value_enum, default_value_t = MinSeverity::Low)]
    min_severity: MinSeverity,

    /// Skip file integrity checks
    #[arg(long)]
    skip_fim: bool,

    /// Skip Sigma rule checks
    #[arg(long)]
    skip_sigma: bool,

    /// Skip hardening checks
    #[arg(long)]
    skip_hardening: bool,

    /// Skip persistence mechanism scan
    #[arg(long)]
    skip_persistence: bool,

    /// Skip privilege escalation scan
    #[arg(long)]
    skip_privesc: bool,

    /// Paths to exclude from scan
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Quiet mode - only show summary (for CI/CD)
    #[arg(short, long)]
    quiet: bool,

    /// Exit with non-zero code on any finding at or above this severity
    #[arg(long, value_enum)]
    fail_on: Option<MinSeverity>,

    /// Show progress indicator during scan
    #[arg(long)]
    progress: bool,
}

/// Simple CLI progress reporter
struct CliProgress {
    quiet: bool,
    findings: AtomicUsize,
}

impl CliProgress {
    fn new(quiet: bool) -> Self {
        Self {
            quiet,
            findings: AtomicUsize::new(0),
        }
    }
}

impl ProgressReporter for CliProgress {
    fn phase_started(&self, name: &str, _total_items: usize) {
        if !self.quiet {
            print!("\r\x1b[K  [*] {} ", name);
            let _ = io::stdout().flush();
        }
    }

    fn progress(&self, _current: usize, _message: &str) {
        // Minimal progress output
    }

    fn phase_completed(&self, name: &str) {
        if !self.quiet {
            println!("\r\x1b[K  [+] {} \x1b[32m✓\x1b[0m", name);
        }
    }

    fn finding_discovered(&self, finding: &Finding) {
        self.findings.fetch_add(1, Ordering::SeqCst);
        if !self.quiet && finding.severity >= Severity::High {
            println!(
                "      \x1b[93m!\x1b[0m {} ({})",
                finding.title,
                finding.severity.to_string().to_uppercase()
            );
        }
    }

    fn error(&self, module: &str, message: &str) {
        if !self.quiet {
            eprintln!("      \x1b[91mError\x1b[0m [{}]: {}", module, message);
        }
    }
}

pub fn run(args: ScanArgs, format: &str) -> anyhow::Result<()> {
    let start = Instant::now();
    let is_json = format == "json";
    let show_progress = args.progress && !args.quiet && !is_json;

    if !args.quiet && !is_json {
        println!("Protectinator Security Scan");
        println!("═══════════════════════════════════════════════════════════════\n");
        println!("Profile: {:?}", args.profile);
        println!();
    }

    let mut builder = ScanRunnerBuilder::new()
        .parallel(true)
        .continue_on_error(true);

    // Add progress reporter if requested
    if show_progress {
        let progress = Arc::new(CliProgress::new(false));
        builder = builder.progress(progress);
    }

    if !args.exclude.is_empty() {
        builder = builder.exclude_paths(args.exclude.clone());
    }

    // Determine which checks to run based on profile
    let (run_fim, run_sigma, run_hardening, run_persistence, run_privesc) = match args.profile {
        ScanProfile::Quick => (false, false, true, true, false),
        ScanProfile::Standard => (true, true, true, true, true),
        ScanProfile::Full => (true, true, true, true, true),
        ScanProfile::Audit => (true, true, true, true, true),
    };

    // Apply skip flags
    let run_fim = run_fim && !args.skip_fim;
    let run_sigma = run_sigma && !args.skip_sigma;
    let run_hardening = run_hardening && !args.skip_hardening;
    let run_persistence = run_persistence && !args.skip_persistence;
    let run_privesc = run_privesc && !args.skip_privesc;

    // Add providers based on configuration and feature flags
    #[cfg(feature = "fim")]
    if run_fim {
        if !args.quiet && !is_json && !show_progress {
            println!("  [+] File integrity monitoring");
        }
        builder = builder.provider(Box::new(FimProvider::new()));
    }

    #[cfg(feature = "sigma")]
    if run_sigma {
        if !args.quiet && !is_json && !show_progress {
            println!("  [+] Sigma rule evaluation");
        }
        builder = builder.provider(Box::new(SigmaProvider::new()));
    }

    #[cfg(feature = "hardening")]
    if run_hardening {
        if !args.quiet && !is_json && !show_progress {
            println!("  [+] System hardening checks");
        }
        builder = builder.provider(Box::new(HardeningProvider::new()));
    }

    #[cfg(feature = "persistence")]
    if run_persistence {
        if !args.quiet && !is_json && !show_progress {
            println!("  [+] Persistence mechanism scan");
        }
        builder = builder.provider(Box::new(PersistenceProvider::new()));
    }

    #[cfg(feature = "privesc")]
    if run_privesc {
        if !args.quiet && !is_json && !show_progress {
            println!("  [+] Privilege escalation scan");
        }
        builder = builder.provider(Box::new(PrivescProvider::new()));
    }

    if !args.quiet && !is_json && !show_progress {
        println!("\nScanning...\n");
    }

    let results = builder.run()?;
    let duration = start.elapsed();

    // Filter findings by minimum severity
    let min_severity: Severity = args.min_severity.into();
    let filtered_count = results.findings.iter().filter(|f| f.severity >= min_severity).count();

    // Output results
    match format {
        "json" => {
            let json = format_json(&results, true)?;
            println!("{}", json);
        }
        _ => {
            if !args.quiet {
                let text = format_text(&results, matches!(args.min_severity, MinSeverity::Info));
                println!("{}", text);
            } else {
                // Quiet mode - just summary
                print_quiet_summary(&results, duration);
            }
        }
    }

    // Determine exit code
    let fail_severity: Severity = args.fail_on.unwrap_or(MinSeverity::Critical).into();
    let should_fail = results.findings.iter().any(|f| f.severity >= fail_severity);

    if should_fail {
        let count = results.findings.iter().filter(|f| f.severity >= fail_severity).count();
        if !is_json {
            eprintln!(
                "\n\x1b[91mFailed:\x1b[0m {} finding(s) at {} severity or above",
                count,
                fail_severity.to_string().to_uppercase()
            );
        }
        std::process::exit(1);
    }

    Ok(())
}

fn print_quiet_summary(results: &protectinator_core::ScanResults, duration: std::time::Duration) {
    let critical = results.summary.findings_by_severity.get(&Severity::Critical).unwrap_or(&0);
    let high = results.summary.findings_by_severity.get(&Severity::High).unwrap_or(&0);
    let medium = results.summary.findings_by_severity.get(&Severity::Medium).unwrap_or(&0);
    let low = results.summary.findings_by_severity.get(&Severity::Low).unwrap_or(&0);

    println!(
        "protectinator: {} findings (C:{} H:{} M:{} L:{}) in {:?}",
        results.findings.len(),
        critical,
        high,
        medium,
        low,
        duration
    );
}
