//! Persistence mechanism scanner commands

use clap::{Args, Subcommand, ValueEnum};
use protectinator_persistence::{
    get_persistence_locations, scan_persistence, PersistenceEntry, PersistenceSummary, RiskLevel,
};
use serde::Serialize;
use std::time::Instant;

#[derive(Subcommand)]
pub enum PersistenceCommands {
    /// Scan for persistence mechanisms
    Scan(ScanArgs),

    /// List known persistence locations
    List(ListArgs),
}

/// Output format for persistence results
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output
    Json,
}

#[derive(Args)]
pub struct ScanArgs {
    /// Minimum risk level to report (low, medium, high, critical)
    #[arg(long, default_value = "low")]
    min_risk: String,

    /// Show only high-risk findings
    #[arg(short, long)]
    suspicious_only: bool,

    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Exit with non-zero code if high-risk findings are found
    #[arg(long)]
    fail_on_high: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

/// JSON output structure for scan results
#[derive(Serialize)]
struct ScanOutput {
    entries: Vec<PersistenceEntry>,
    summary: PersistenceSummary,
    duration_ms: u64,
}

pub fn run(cmd: PersistenceCommands) -> anyhow::Result<()> {
    match cmd {
        PersistenceCommands::Scan(args) => run_scan(args),
        PersistenceCommands::List(args) => list_locations(args),
    }
}

fn parse_risk(s: &str) -> RiskLevel {
    match s.to_lowercase().as_str() {
        "critical" => RiskLevel::Critical,
        "high" => RiskLevel::High,
        "medium" => RiskLevel::Medium,
        _ => RiskLevel::Low,
    }
}

fn run_scan(args: ScanArgs) -> anyhow::Result<()> {
    let start = Instant::now();
    let is_json = matches!(args.output, OutputFormat::Json);

    if !is_json && !args.quiet {
        println!("Persistence Mechanism Scanner");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    let min_risk = if args.suspicious_only {
        RiskLevel::High
    } else {
        parse_risk(&args.min_risk)
    };

    let entries = scan_persistence();
    let filtered: Vec<_> = entries.iter().filter(|e| e.risk >= min_risk).cloned().collect();
    let summary = PersistenceSummary::from_entries(&entries);
    let duration = start.elapsed();

    // JSON output
    if is_json {
        let output = ScanOutput {
            entries: filtered,
            summary: summary.clone(),
            duration_ms: duration.as_millis() as u64,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);

        if args.fail_on_high && summary.has_critical_findings() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Text output
    if !args.quiet {
        let mut current_type = None;

        for entry in &filtered {
            if current_type != Some(entry.persistence_type) {
                if current_type.is_some() {
                    println!("└───────────────────────────────────────────────────────────────\n");
                }
                current_type = Some(entry.persistence_type);
                println!(
                    "┌─ {} ─────────────────────────────────────────",
                    entry.persistence_type.as_str().to_uppercase()
                );
            }

            let (color, symbol) = match entry.risk {
                RiskLevel::Critical => ("\x1b[91m", "!"),
                RiskLevel::High => ("\x1b[93m", "!"),
                RiskLevel::Medium => ("\x1b[33m", "?"),
                RiskLevel::Low => ("\x1b[37m", "-"),
            };
            let reset = "\x1b[0m";

            println!(
                "│ {}{}{}  {} \x1b[90m({})\x1b[0m",
                color,
                symbol,
                reset,
                entry.name,
                entry.path.display()
            );

            if let Some(ref cmd) = entry.command {
                if !cmd.is_empty() && cmd.len() < 80 {
                    println!("│     Command: {}", cmd);
                }
            }

            if !entry.risk_reasons.is_empty() {
                for reason in &entry.risk_reasons {
                    println!("│     \x1b[90m- {}\x1b[0m", reason);
                }
            }
        }

        if current_type.is_some() {
            println!("└───────────────────────────────────────────────────────────────\n");
        }
    }

    // Summary
    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Total mechanisms: {}", summary.total_entries);
    println!("  \x1b[91mCritical:\x1b[0m  {}", summary.critical_count);
    println!("  \x1b[93mHigh:\x1b[0m      {}", summary.high_count);
    println!("  \x1b[33mMedium:\x1b[0m    {}", summary.medium_count);
    println!("  \x1b[37mLow:\x1b[0m       {}", summary.low_count);
    println!();
    println!("  Completed in {:?}", duration);

    if summary.has_critical_findings() {
        println!(
            "\n\x1b[93mWarning:\x1b[0m {} high-risk persistence mechanisms found.",
            summary.critical_count + summary.high_count
        );
        if args.fail_on_high {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn list_locations(args: ListArgs) -> anyhow::Result<()> {
    let locations = get_persistence_locations();

    if matches!(args.output, OutputFormat::Json) {
        let json_locations: Vec<_> = locations
            .iter()
            .map(|(path, ptype)| {
                serde_json::json!({
                    "path": path,
                    "type": ptype.as_str(),
                    "mitre_id": ptype.mitre_id()
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_locations)?);
        return Ok(());
    }

    println!("Persistence Locations Checked");
    println!("═══════════════════════════════════════════════════════════════\n");

    let mut current_type = None;

    for (path, ptype) in &locations {
        if current_type != Some(*ptype) {
            if current_type.is_some() {
                println!();
            }
            current_type = Some(*ptype);
            println!("{}:", ptype.as_str().to_uppercase());
        }
        println!("  - {}", path);
    }

    println!("\nMITRE ATT&CK Reference:");
    println!("  - Cron: T1053.003");
    println!("  - Systemd: T1543.002");
    println!("  - Shell Profile: T1546.004");
    println!("  - LD_PRELOAD: T1574.006");
    println!("  - LaunchAgent: T1543.001");
    println!("  - LaunchDaemon: T1543.004");

    Ok(())
}
