//! Sigma rules commands

use clap::{Args, Subcommand};
use protectinator_sigma::{
    LogEvent, LogSourceConfig, LogSourceType, RuleSet, RuleSeverity, SigmaEngine,
};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum SigmaCommands {
    /// Scan logs with Sigma rules
    Scan(SigmaScanArgs),

    /// Validate Sigma rules
    Validate(ValidateArgs),

    /// List loaded Sigma rules
    List(SigmaListArgs),

    /// Show available log sources
    Sources,
}

#[derive(Args)]
pub struct SigmaScanArgs {
    /// Rule paths (files or directories)
    #[arg(short, long, required = true)]
    rules: Vec<PathBuf>,

    /// Log source type (json, jsonl, syslog, auth, journald, unified)
    #[arg(short = 's', long, default_value = "json")]
    source: String,

    /// Path to log file or directory
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Maximum number of events to scan
    #[arg(short = 'n', long, default_value = "10000")]
    limit: usize,

    /// Minimum severity level (info, low, medium, high, critical)
    #[arg(long, default_value = "low")]
    min_severity: String,

    /// Use parallel scanning
    #[arg(long, short = 'P', default_value = "true")]
    parallel: bool,

    /// Output only matching events (quiet mode)
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Args)]
pub struct ValidateArgs {
    /// Rule paths to validate
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Show verbose validation info
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args)]
pub struct SigmaListArgs {
    /// Rule paths (files or directories)
    #[arg(short, long, required = true)]
    rules: Vec<PathBuf>,

    /// Filter by severity level
    #[arg(long)]
    severity: Option<String>,

    /// Filter by tag (e.g., "attack.execution")
    #[arg(short, long)]
    tag: Option<String>,

    /// Filter by category
    #[arg(short, long)]
    category: Option<String>,

    /// Show full rule details
    #[arg(short, long)]
    verbose: bool,
}

pub fn run(cmd: SigmaCommands) -> anyhow::Result<()> {
    match cmd {
        SigmaCommands::Scan(args) => scan_logs(args),
        SigmaCommands::Validate(args) => validate_rules(args),
        SigmaCommands::List(args) => list_rules(args),
        SigmaCommands::Sources => show_sources(),
    }
}

fn parse_severity(s: &str) -> RuleSeverity {
    match s.to_lowercase().as_str() {
        "info" | "informational" => RuleSeverity::Informational,
        "low" => RuleSeverity::Low,
        "medium" => RuleSeverity::Medium,
        "high" => RuleSeverity::High,
        "critical" => RuleSeverity::Critical,
        _ => RuleSeverity::Low,
    }
}

fn parse_log_source_type(s: &str) -> LogSourceType {
    match s.to_lowercase().as_str() {
        "json" => LogSourceType::JsonFile,
        "jsonl" | "ndjson" => LogSourceType::JsonLines,
        "syslog" => LogSourceType::Syslog,
        "auth" | "authlog" => LogSourceType::AuthLog,
        "journald" | "journal" => LogSourceType::Journald,
        "unified" | "unifiedlog" => LogSourceType::UnifiedLog,
        _ => LogSourceType::JsonFile,
    }
}

fn scan_logs(args: SigmaScanArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    // Load rules
    println!("Loading Sigma rules...");
    let rule_start = Instant::now();
    let mut ruleset = RuleSet::new();
    let mut load_errors = 0;

    for path in &args.rules {
        if path.is_dir() {
            match RuleSet::from_directory(path) {
                Ok(rules) => {
                    println!("  Loaded {} rules from {}", rules.len(), path.display());
                    ruleset.merge(rules);
                }
                Err(e) => {
                    eprintln!("  Error loading rules from {}: {}", path.display(), e);
                    load_errors += 1;
                }
            }
        } else if path.is_file() {
            match protectinator_sigma::SigmaRule::from_file(path) {
                Ok(rule) => {
                    ruleset.add(rule);
                }
                Err(e) => {
                    eprintln!("  Error loading {}: {}", path.display(), e);
                    load_errors += 1;
                }
            }
        } else {
            eprintln!("  Path not found: {}", path.display());
        }
    }

    if ruleset.is_empty() {
        anyhow::bail!("No valid rules loaded");
    }

    println!(
        "Loaded {} rules in {:?} ({} errors)",
        ruleset.len(),
        rule_start.elapsed(),
        load_errors
    );

    // Load events
    println!("\nLoading events...");
    let event_start = Instant::now();
    let source_type = parse_log_source_type(&args.source);
    let config = LogSourceConfig::new(source_type.clone())
        .with_limit(args.limit);

    let config = if let Some(path) = &args.input {
        config.with_path(path.clone())
    } else {
        config
    };

    let source = protectinator_sigma::logsource::create_log_source(&config);

    if !source.is_available() {
        anyhow::bail!("Log source '{}' is not available on this system", args.source);
    }

    let events = source.read_events(&config)?;
    println!(
        "Loaded {} events from {} in {:?}",
        events.len(),
        source.description(),
        event_start.elapsed()
    );

    if events.is_empty() {
        println!("\nNo events to scan.");
        return Ok(());
    }

    // Create engine and scan
    println!("\nScanning events...");
    let scan_start = Instant::now();
    let min_severity = parse_severity(&args.min_severity);
    let engine = SigmaEngine::new(ruleset)
        .with_min_severity(min_severity)
        .parallel(args.parallel);

    let results = engine.scan_events(&events);
    let scan_duration = scan_start.elapsed();

    // Display results
    let summary = SigmaEngine::summarize(&results);

    if !args.quiet {
        println!("\n═══════════════════════════════════════════");
        println!("Scan Results");
        println!("═══════════════════════════════════════════");
        println!("  Events scanned: {}", events.len());
        println!("  Events matched: {}", summary.events_matched);
        println!("  Total matches:  {}", summary.total_matches);
        println!("  Unique rules:   {}", summary.unique_rules_matched());
        println!();
        println!("By Severity:");
        println!("  Critical: {}", summary.severity_counts.critical);
        println!("  High:     {}", summary.severity_counts.high);
        println!("  Medium:   {}", summary.severity_counts.medium);
        println!("  Low:      {}", summary.severity_counts.low);
        println!("  Info:     {}", summary.severity_counts.informational);
    }

    if !results.is_empty() {
        println!("\nMatches:");
        println!("─────────────────────────────────────────────");

        for result in &results {
            for matched in &result.matches {
                let severity_color = match matched.rule.metadata.level {
                    RuleSeverity::Critical => "\x1b[91m", // Red
                    RuleSeverity::High => "\x1b[93m",     // Yellow
                    RuleSeverity::Medium => "\x1b[33m",   // Orange
                    RuleSeverity::Low => "\x1b[36m",      // Cyan
                    RuleSeverity::Informational => "\x1b[37m", // White
                };
                let reset = "\x1b[0m";

                println!(
                    "  [{}{}{}] {}",
                    severity_color,
                    matched.rule.metadata.level.to_string().to_uppercase(),
                    reset,
                    matched.rule.metadata.title
                );
                println!("    Rule ID: {}", matched.rule.id);

                if let Some(desc) = &matched.rule.metadata.description {
                    // Truncate long descriptions
                    let desc = if desc.len() > 100 {
                        format!("{}...", &desc[..100])
                    } else {
                        desc.clone()
                    };
                    println!("    Description: {}", desc);
                }

                if !matched.rule.metadata.tags.is_empty() {
                    println!("    Tags: {}", matched.rule.metadata.tags.join(", "));
                }

                // Show some event context
                let event_json = result.event.to_json();
                let preview = if event_json.len() > 200 {
                    format!("{}...", &event_json[..200])
                } else {
                    event_json
                };
                println!("    Event: {}", preview);
                println!();
            }
        }
    }

    let total_duration = start.elapsed();
    println!("─────────────────────────────────────────────");
    println!(
        "Scan completed in {:?} ({:.0} events/sec)",
        total_duration,
        events.len() as f64 / scan_duration.as_secs_f64()
    );

    // Exit with error code if critical/high findings
    if summary.severity_counts.critical > 0 || summary.severity_counts.high > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn validate_rules(args: ValidateArgs) -> anyhow::Result<()> {
    let mut total = 0;
    let mut valid = 0;
    let mut invalid = 0;

    for path in &args.paths {
        if path.is_dir() {
            for entry in walkdir::WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                let entry_path = entry.path();
                if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        if ext == "yml" || ext == "yaml" {
                            total += 1;
                            match protectinator_sigma::SigmaRule::from_file(entry_path) {
                                Ok(rule) => {
                                    valid += 1;
                                    if args.verbose {
                                        println!("✓ {} - {}", entry_path.display(), rule.metadata.title);
                                    }
                                }
                                Err(e) => {
                                    invalid += 1;
                                    println!("✗ {} - {}", entry_path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        } else if path.is_file() {
            total += 1;
            match protectinator_sigma::SigmaRule::from_file(path) {
                Ok(rule) => {
                    valid += 1;
                    if args.verbose {
                        println!("✓ {} - {}", path.display(), rule.metadata.title);
                    }
                }
                Err(e) => {
                    invalid += 1;
                    println!("✗ {} - {}", path.display(), e);
                }
            }
        }
    }

    println!();
    println!("Validation Summary:");
    println!("  Total:   {}", total);
    println!("  Valid:   {}", valid);
    println!("  Invalid: {}", invalid);

    if invalid > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn list_rules(args: SigmaListArgs) -> anyhow::Result<()> {
    let mut ruleset = RuleSet::new();

    for path in &args.rules {
        if path.is_dir() {
            if let Ok(rules) = RuleSet::from_directory(path) {
                ruleset.merge(rules);
            }
        } else if path.is_file() {
            if let Ok(rule) = protectinator_sigma::SigmaRule::from_file(path) {
                ruleset.add(rule);
            }
        }
    }

    println!("Loaded {} rules\n", ruleset.len());

    // Apply filters
    let rules: Vec<_> = ruleset
        .iter()
        .filter(|r| {
            if let Some(sev) = &args.severity {
                let target = parse_severity(sev);
                if (r.metadata.level as u8) < (target as u8) {
                    return false;
                }
            }
            if let Some(tag) = &args.tag {
                let tag_lower = tag.to_lowercase();
                if !r.metadata.tags.iter().any(|t| t.to_lowercase().contains(&tag_lower)) {
                    return false;
                }
            }
            if let Some(cat) = &args.category {
                if let Some(rule_cat) = &r.logsource.category {
                    if !rule_cat.eq_ignore_ascii_case(cat) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
            true
        })
        .collect();

    println!("Showing {} rules (after filters)\n", rules.len());

    for rule in rules {
        let severity_color = match rule.metadata.level {
            RuleSeverity::Critical => "\x1b[91m",
            RuleSeverity::High => "\x1b[93m",
            RuleSeverity::Medium => "\x1b[33m",
            RuleSeverity::Low => "\x1b[36m",
            RuleSeverity::Informational => "\x1b[37m",
        };
        let reset = "\x1b[0m";

        println!(
            "[{}{}{}] {}",
            severity_color,
            rule.metadata.level.to_string().to_uppercase(),
            reset,
            rule.metadata.title
        );

        if args.verbose {
            println!("  ID: {}", rule.id);
            if let Some(desc) = &rule.metadata.description {
                println!("  Description: {}", desc);
            }
            if let Some(author) = &rule.metadata.author {
                println!("  Author: {}", author);
            }
            if let Some(status) = &rule.metadata.status {
                println!("  Status: {}", status);
            }
            if let Some(cat) = &rule.logsource.category {
                println!("  Category: {}", cat);
            }
            if let Some(prod) = &rule.logsource.product {
                println!("  Product: {}", prod);
            }
            if !rule.metadata.tags.is_empty() {
                println!("  Tags: {}", rule.metadata.tags.join(", "));
            }
            println!();
        }
    }

    Ok(())
}

fn show_sources() -> anyhow::Result<()> {
    println!("Available Log Sources:\n");

    let sources = protectinator_sigma::logsource::detect_available_sources();

    println!("Detected on this system:");
    for source in &sources {
        println!("  ✓ {}", source);
    }

    println!("\nAll supported sources:");
    println!("  json     - JSON file or directory");
    println!("  jsonl    - JSON Lines format (one event per line)");
    #[cfg(target_os = "linux")]
    {
        println!("  syslog   - Linux syslog (/var/log/syslog or /var/log/messages)");
        println!("  auth     - Linux auth log (/var/log/auth.log or /var/log/secure)");
        println!("  journald - Linux systemd journal");
    }
    #[cfg(target_os = "macos")]
    {
        println!("  unified  - macOS Unified Log");
    }

    Ok(())
}
