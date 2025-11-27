//! System hardening commands

use clap::{Args, Subcommand};
use protectinator_core::Severity;
use protectinator_hardening::{
    get_categories, get_platform_checks, CheckCategory, CheckResult, HardeningProvider,
    HardeningSummary,
};
use std::time::Instant;

#[derive(Subcommand)]
pub enum HardenCommands {
    /// Run hardening checks
    Scan(HardenScanArgs),

    /// List available hardening checks
    List(ListArgs),

    /// Show available categories
    Categories,
}

#[derive(Args)]
pub struct HardenScanArgs {
    /// Check categories to run (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    categories: Vec<String>,

    /// Checks to skip (comma-separated IDs)
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,

    /// Minimum severity to report (info, low, medium, high, critical)
    #[arg(long, default_value = "low")]
    min_severity: String,

    /// Show passed checks too
    #[arg(long)]
    show_passed: bool,

    /// Show skipped checks
    #[arg(long)]
    show_skipped: bool,

    /// Quiet mode - only show failures
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Filter by category
    #[arg(short, long)]
    category: Option<String>,

    /// Show verbose check details
    #[arg(short, long)]
    verbose: bool,
}

pub fn run(cmd: HardenCommands) -> anyhow::Result<()> {
    match cmd {
        HardenCommands::Scan(args) => run_scan(args),
        HardenCommands::List(args) => list_checks(args),
        HardenCommands::Categories => show_categories(),
    }
}

fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "info" => Severity::Info,
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Low,
    }
}

fn parse_categories(cats: &[String]) -> Vec<CheckCategory> {
    cats.iter()
        .filter_map(|c| c.parse().ok())
        .collect()
}

fn run_scan(args: HardenScanArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    if !args.quiet {
        println!("Running system hardening checks...\n");
    }

    let categories = parse_categories(&args.categories);
    let min_severity = parse_severity(&args.min_severity);

    let mut provider = HardeningProvider::new().with_min_severity(min_severity);

    if !categories.is_empty() {
        provider = provider.with_categories(categories);
    }

    if !args.skip.is_empty() {
        provider = provider.skip(args.skip.clone());
    }

    let results = provider.run_checks();
    let summary = HardeningSummary::from_results(&results);

    // Display results
    if !args.quiet {
        println!("═══════════════════════════════════════════════════════════════");
        println!("Hardening Check Results");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    // Group results by category
    let registry = get_platform_checks();
    let mut by_category: std::collections::HashMap<CheckCategory, Vec<_>> =
        std::collections::HashMap::new();

    for (id, result, finding) in &results {
        if let Some(check) = registry.filter_by_id(id) {
            let cat = check.definition().category;
            by_category.entry(cat).or_default().push((check, result, finding));
        }
    }

    // Display by category
    for category in get_categories() {
        if let Some(checks) = by_category.get(&category) {
            let has_visible = checks.iter().any(|(_, result, _)| {
                match result {
                    CheckResult::Pass { .. } => args.show_passed,
                    CheckResult::Skipped { .. } => args.show_skipped,
                    _ => true,
                }
            });

            if !has_visible {
                continue;
            }

            println!("┌─ {} ─────────────────────────────────────────", category.to_string().to_uppercase());

            for (check, result, _finding) in checks {
                let def = check.definition();

                match result {
                    CheckResult::Pass { message } => {
                        if args.show_passed && !args.quiet {
                            println!("│ \x1b[32m✓\x1b[0m {}", def.name);
                            println!("│   {}", message);
                        }
                    }
                    CheckResult::Fail {
                        message,
                        severity,
                        remediation,
                    } => {
                        let color = match severity {
                            Severity::Critical => "\x1b[91m",
                            Severity::High => "\x1b[93m",
                            Severity::Medium => "\x1b[33m",
                            Severity::Low => "\x1b[36m",
                            Severity::Info => "\x1b[37m",
                        };
                        let reset = "\x1b[0m";

                        println!(
                            "│ {}✗{} [{}{}{}] {}",
                            color, reset, color, severity, reset, def.name
                        );
                        println!("│   {}", message);
                        if let Some(rem) = remediation {
                            println!("│   \x1b[90mFix: {}\x1b[0m", rem);
                        } else if let Some(rem) = &def.remediation {
                            println!("│   \x1b[90mFix: {}\x1b[0m", rem);
                        }
                        if let Some(cis) = &def.cis_reference {
                            println!("│   \x1b[90mRef: {}\x1b[0m", cis);
                        }
                    }
                    CheckResult::Skipped { reason } => {
                        if args.show_skipped && !args.quiet {
                            println!("│ \x1b[90m─\x1b[0m {} (skipped: {})", def.name, reason);
                        }
                    }
                    CheckResult::Error { message } => {
                        println!("│ \x1b[91m!\x1b[0m {} (error: {})", def.name, message);
                    }
                }
            }

            println!("└───────────────────────────────────────────────────────────────\n");
        }
    }

    // Summary
    let duration = start.elapsed();

    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!(
        "  Score: {}% ({}/{} passed)",
        summary.score(),
        summary.passed,
        summary.total_checks - summary.skipped
    );
    println!();
    println!("  Total checks:  {}", summary.total_checks);
    println!("  \x1b[32mPassed:\x1b[0m        {}", summary.passed);
    println!("  \x1b[31mFailed:\x1b[0m        {}", summary.failed);
    println!("  \x1b[90mSkipped:\x1b[0m       {}", summary.skipped);
    if summary.errors > 0 {
        println!("  Errors:        {}", summary.errors);
    }
    println!();
    println!("  Failures by severity:");
    println!("    \x1b[91mCritical:\x1b[0m {}", summary.critical_failures);
    println!("    \x1b[93mHigh:\x1b[0m     {}", summary.high_failures);
    println!("    \x1b[33mMedium:\x1b[0m   {}", summary.medium_failures);
    println!("    \x1b[36mLow:\x1b[0m      {}", summary.low_failures);
    println!();
    println!("  Completed in {:?}", duration);

    // Exit code based on critical issues
    if summary.has_critical_issues() {
        std::process::exit(1);
    }

    Ok(())
}

fn list_checks(args: ListArgs) -> anyhow::Result<()> {
    let registry = get_platform_checks();

    println!("Available Hardening Checks ({} total)\n", registry.len());

    let filter_category: Option<CheckCategory> = args
        .category
        .as_ref()
        .and_then(|c| c.parse().ok());

    for category in get_categories() {
        if let Some(ref filter) = filter_category {
            if *filter != category {
                continue;
            }
        }

        let checks = registry.filter_by_category(category);
        if checks.is_empty() {
            continue;
        }

        println!("┌─ {} ({} checks) ─────────────────────────",
            category.to_string().to_uppercase(),
            checks.len()
        );

        for check in checks {
            let def = check.definition();
            let severity_color = match def.default_severity {
                Severity::Critical => "\x1b[91m",
                Severity::High => "\x1b[93m",
                Severity::Medium => "\x1b[33m",
                Severity::Low => "\x1b[36m",
                Severity::Info => "\x1b[37m",
            };
            let reset = "\x1b[0m";

            println!(
                "│ [{}{}{}] {}",
                severity_color, def.default_severity, reset, def.name
            );

            if args.verbose {
                println!("│   ID: {}", def.id);
                println!("│   {}", def.description);
                if let Some(cis) = &def.cis_reference {
                    println!("│   CIS: {}", cis);
                }
                if let Some(rem) = &def.remediation {
                    println!("│   Fix: {}", rem);
                }
                println!("│");
            }
        }

        println!("└─────────────────────────────────────────────────────\n");
    }

    Ok(())
}

fn show_categories() -> anyhow::Result<()> {
    println!("Available Check Categories:\n");

    let registry = get_platform_checks();

    for category in get_categories() {
        let count = registry.filter_by_category(category).len();
        if count > 0 {
            println!("  {:15} - {} checks", category.to_string(), count);
        }
    }

    println!("\nUse --categories <name> to filter by category");
    println!("Example: protectinator harden scan --categories network,authentication");

    Ok(())
}
