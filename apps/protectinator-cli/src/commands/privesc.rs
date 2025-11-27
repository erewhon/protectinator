//! Privilege escalation finder commands

use clap::{Args, Subcommand, ValueEnum};
use protectinator_privesc::{scan_privesc, PrivescEntry, PrivescSummary, RiskLevel};
use serde::Serialize;
use std::time::Instant;

#[derive(Subcommand)]
pub enum PrivescCommands {
    /// Scan for privilege escalation vectors
    Scan(ScanArgs),

    /// List known privesc techniques
    List(ListArgs),
}

/// Output format for privesc results
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
    #[arg(long, default_value = "medium")]
    min_risk: String,

    /// Show only exploitable findings
    #[arg(short, long)]
    exploitable_only: bool,

    /// Quiet mode - only show summary
    #[arg(short, long)]
    quiet: bool,

    /// Output format (text or json)
    #[arg(long = "output", value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,

    /// Exit with non-zero code if critical findings are found
    #[arg(long)]
    fail_on_critical: bool,
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
    entries: Vec<PrivescEntry>,
    summary: PrivescSummary,
    duration_ms: u64,
}

pub fn run(cmd: PrivescCommands) -> anyhow::Result<()> {
    match cmd {
        PrivescCommands::Scan(args) => run_scan(args),
        PrivescCommands::List(args) => list_techniques(args),
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
        println!("Privilege Escalation Path Finder");
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    let min_risk = if args.exploitable_only {
        RiskLevel::High
    } else {
        parse_risk(&args.min_risk)
    };

    let entries = scan_privesc();
    let filtered: Vec<_> = entries.iter().filter(|e| e.risk >= min_risk).cloned().collect();
    let summary = PrivescSummary::from_entries(&entries);
    let duration = start.elapsed();

    // JSON output
    if is_json {
        let output = ScanOutput {
            entries: filtered,
            summary: summary.clone(),
            duration_ms: duration.as_millis() as u64,
        };
        println!("{}", serde_json::to_string_pretty(&output)?);

        if args.fail_on_critical && summary.has_critical() {
            std::process::exit(1);
        }
        return Ok(());
    }

    // Text output
    if !args.quiet {
        let mut current_type = None;

        for entry in &filtered {
            if current_type != Some(entry.privesc_type) {
                if current_type.is_some() {
                    println!("└───────────────────────────────────────────────────────────────\n");
                }
                current_type = Some(entry.privesc_type);
                println!(
                    "┌─ {} ─────────────────────────────────────────",
                    entry.privesc_type.as_str().to_uppercase()
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

            if let Some(ref perms) = entry.permissions {
                println!("│     Permissions: {}", perms);
            }

            for reason in &entry.risk_reasons {
                println!("│     \x1b[90m- {}\x1b[0m", reason);
            }

            if let Some(ref rem) = entry.remediation {
                println!("│     \x1b[36mFix: {}\x1b[0m", rem);
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
    println!("  Total findings: {}", summary.total_findings);
    println!("  \x1b[91mCritical:\x1b[0m  {}", summary.critical_count);
    println!("  \x1b[93mHigh:\x1b[0m      {}", summary.high_count);
    println!("  \x1b[33mMedium:\x1b[0m    {}", summary.medium_count);
    println!("  \x1b[37mLow:\x1b[0m       {}", summary.low_count);
    println!();
    println!("  Completed in {:?}", duration);

    if summary.has_critical() {
        println!(
            "\n\x1b[91mWarning:\x1b[0m {} exploitable privilege escalation vectors found!",
            summary.critical_count + summary.high_count
        );
        if args.fail_on_critical {
            std::process::exit(1);
        }
    }

    Ok(())
}

fn list_techniques(args: ListArgs) -> anyhow::Result<()> {
    let techniques = vec![
        serde_json::json!({
            "name": "SUID/SGID Binaries",
            "mitre_id": "T1548.001",
            "description": "Scans for binaries with SUID/SGID bits set. Checks against GTFOBins list for exploitable binaries.",
            "reference": "https://gtfobins.github.io/"
        }),
        serde_json::json!({
            "name": "Linux Capabilities",
            "mitre_id": "T1548.001",
            "description": "Files with dangerous capabilities (cap_setuid, cap_sys_admin, etc.)"
        }),
        serde_json::json!({
            "name": "Sudo Misconfigurations",
            "mitre_id": "T1548.003",
            "description": "NOPASSWD rules and dangerous command allowances"
        }),
        serde_json::json!({
            "name": "PATH Hijacking",
            "mitre_id": "T1574.007",
            "description": "Writable directories in PATH that could allow binary hijacking"
        }),
        serde_json::json!({
            "name": "World-Writable Files",
            "mitre_id": "T1222.002",
            "description": "World-writable files in sensitive locations (/etc, /usr/lib, etc.)"
        }),
    ];

    if matches!(args.output, OutputFormat::Json) {
        println!("{}", serde_json::to_string_pretty(&techniques)?);
        return Ok(());
    }

    println!("Privilege Escalation Techniques Checked");
    println!("═══════════════════════════════════════════════════════════════\n");

    println!("SUID/SGID Binaries (T1548.001):");
    println!("  - Scans for binaries with SUID/SGID bits set");
    println!("  - Checks against GTFOBins list for exploitable binaries");
    println!();

    println!("Linux Capabilities (T1548.001):");
    println!("  - Files with dangerous capabilities (cap_setuid, cap_sys_admin, etc.)");
    println!();

    println!("Sudo Misconfigurations (T1548.003):");
    println!("  - NOPASSWD rules");
    println!("  - Dangerous command allowances");
    println!();

    println!("PATH Hijacking (T1574.007):");
    println!("  - Writable directories in PATH");
    println!();

    println!("World-Writable Files (T1222.002):");
    println!("  - World-writable files in /etc, /usr/lib, etc.");
    println!();

    println!("Reference: https://gtfobins.github.io/");

    Ok(())
}
