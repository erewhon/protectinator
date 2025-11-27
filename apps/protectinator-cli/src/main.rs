//! Protectinator CLI
//!
//! A portable, zero-config security monitoring tool for Linux and macOS.
//!
//! # Features
//!
//! - **File Integrity Monitoring**: Track changes to critical system files
//! - **System Hardening**: Check for security misconfigurations
//! - **Sigma Rules**: Detect threats using community detection rules
//! - **Persistence Detection**: Find malware persistence mechanisms
//! - **Privilege Escalation**: Identify privesc vectors (GTFOBins, etc.)
//! - **Process Monitoring**: Monitor running processes and connections
//! - **YARA Scanning**: Custom pattern matching for malware detection
//!
//! # Quick Start
//!
//! ```sh
//! # Run a full security scan
//! protectinator scan
//!
//! # Quick scan (faster, fewer checks)
//! protectinator scan --profile quick
//!
//! # JSON output for CI/CD
//! protectinator scan --format json --quiet
//!
//! # Fail if any high severity findings
//! protectinator scan --fail-on high
//! ```

mod commands;

use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Output format for results
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum OutputFormat {
    /// Human-readable text output
    #[default]
    Text,
    /// JSON output for machine parsing
    Json,
}

/// Protectinator - A portable security monitoring tool
///
/// Run comprehensive security scans on Linux and macOS systems.
/// Zero configuration required - just run 'protectinator scan'.
#[derive(Parser)]
#[command(name = "protectinator")]
#[command(author = "Protectinator Team")]
#[command(version)]
#[command(about = "Portable, zero-config security monitoring for Linux and macOS")]
#[command(long_about = "Protectinator is a comprehensive security monitoring tool that runs \
on Linux and macOS without requiring any configuration. It includes file integrity monitoring, \
system hardening checks, Sigma rule detection, persistence mechanism scanning, and privilege \
escalation path finding.

EXAMPLES:
    protectinator scan                    Run a standard security scan
    protectinator scan -p quick           Run a quick scan (essential checks only)
    protectinator scan -p full            Run a full scan (all checks)
    protectinator scan -f json -q         JSON output for CI/CD pipelines
    protectinator harden scan             Check system hardening
    protectinator persistence scan        Find persistence mechanisms
    protectinator privesc scan            Find privilege escalation vectors
    protectinator info                    Show system information

EXIT CODES:
    0    No critical findings
    1    Critical findings detected (or --fail-on threshold exceeded)
    2    Error during execution
")]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose/debug output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format
    #[arg(short, long, global = true, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a comprehensive security scan
    ///
    /// Combines multiple security checks into a single scan:
    /// - File integrity monitoring
    /// - System hardening checks
    /// - Sigma rule evaluation
    /// - Persistence mechanism detection
    /// - Privilege escalation scanning
    Scan(commands::scan::ScanArgs),

    /// File integrity monitoring
    ///
    /// Track changes to critical system files and directories.
    /// Create baselines and detect modifications.
    #[cfg(feature = "fim")]
    #[command(subcommand)]
    Fim(commands::fim::FimCommands),

    /// Sigma rule detection
    ///
    /// Evaluate logs against Sigma detection rules.
    /// Supports custom rules and built-in detection.
    #[cfg(feature = "sigma")]
    #[command(subcommand)]
    Sigma(commands::sigma::SigmaCommands),

    /// System hardening checks
    ///
    /// Check for security misconfigurations based on
    /// CIS benchmarks and best practices.
    #[cfg(feature = "hardening")]
    #[command(subcommand)]
    Harden(commands::harden::HardenCommands),

    /// OS file verification
    ///
    /// Verify system files against package manager manifests
    /// to detect unauthorized modifications.
    #[cfg(feature = "osverify")]
    #[command(subcommand)]
    Verify(commands::verify::VerifyCommands),

    /// Persistence mechanism scanner
    ///
    /// Find malware persistence mechanisms:
    /// - Cron jobs, systemd services (Linux)
    /// - LaunchAgents, LaunchDaemons (macOS)
    /// - Shell profiles, SSH keys, etc.
    #[cfg(feature = "persistence")]
    #[command(subcommand)]
    Persistence(commands::persistence::PersistenceCommands),

    /// Process and connection monitor
    ///
    /// Monitor running processes and network connections.
    /// Identify suspicious activity patterns.
    #[cfg(feature = "procmon")]
    #[command(subcommand)]
    Procmon(commands::procmon::ProcmonCommands),

    /// YARA pattern scanning
    ///
    /// Scan files using YARA-like pattern rules
    /// for malware detection.
    #[cfg(feature = "yara")]
    #[command(subcommand)]
    Yara(commands::yara::YaraCommands),

    /// Privilege escalation finder
    ///
    /// Find potential privilege escalation vectors:
    /// - SUID/SGID binaries (GTFOBins)
    /// - Linux capabilities
    /// - Sudo misconfigurations
    /// - Writable PATH directories
    #[cfg(feature = "privesc")]
    #[command(subcommand)]
    Privesc(commands::privesc::PrivescCommands),

    /// Show system information
    ///
    /// Display information about the current system
    /// including OS, architecture, and user context.
    Info,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).without_time())
        .with(filter)
        .init();

    let format_str = match cli.format {
        OutputFormat::Text => "text",
        OutputFormat::Json => "json",
    };

    let result = match cli.command {
        Commands::Scan(args) => commands::scan::run(args, format_str),
        #[cfg(feature = "fim")]
        Commands::Fim(cmd) => commands::fim::run(cmd),
        #[cfg(feature = "sigma")]
        Commands::Sigma(cmd) => commands::sigma::run(cmd),
        #[cfg(feature = "hardening")]
        Commands::Harden(cmd) => commands::harden::run(cmd),
        #[cfg(feature = "osverify")]
        Commands::Verify(cmd) => commands::verify::run(cmd),
        #[cfg(feature = "persistence")]
        Commands::Persistence(cmd) => commands::persistence::run(cmd),
        #[cfg(feature = "procmon")]
        Commands::Procmon(cmd) => commands::procmon::run(cmd),
        #[cfg(feature = "yara")]
        Commands::Yara(cmd) => commands::yara::run(cmd),
        #[cfg(feature = "privesc")]
        Commands::Privesc(cmd) => commands::privesc::run(cmd),
        Commands::Info => commands::info::run(),
    };

    // Exit code 2 for errors
    if let Err(ref e) = result {
        eprintln!("\x1b[91mError:\x1b[0m {}", e);
        std::process::exit(2);
    }

    result
}
