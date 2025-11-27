//! Protectinator CLI
//!
//! A portable, zero-config security monitoring tool.

mod commands;

use clap::{Parser, Subcommand};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Protectinator - A portable security monitoring tool
#[derive(Parser)]
#[command(name = "protectinator")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Output format (text, json)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a full security scan
    Scan(commands::scan::ScanArgs),

    /// File integrity monitoring commands
    #[command(subcommand)]
    Fim(commands::fim::FimCommands),

    /// Sigma rules commands
    #[command(subcommand)]
    Sigma(commands::sigma::SigmaCommands),

    /// System hardening checks
    #[command(subcommand)]
    Harden(commands::harden::HardenCommands),

    /// OS file verification
    #[command(subcommand)]
    Verify(commands::verify::VerifyCommands),

    /// Persistence mechanism scanner
    #[command(subcommand)]
    Persistence(commands::persistence::PersistenceCommands),

    /// Process and connection monitor
    #[command(subcommand)]
    Procmon(commands::procmon::ProcmonCommands),

    /// YARA scanning
    #[command(subcommand)]
    Yara(commands::yara::YaraCommands),

    /// Privilege escalation finder
    #[command(subcommand)]
    Privesc(commands::privesc::PrivescCommands),

    /// Show system information
    Info,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(filter)
        .init();

    match cli.command {
        Commands::Scan(args) => commands::scan::run(args, &cli.format),
        Commands::Fim(cmd) => commands::fim::run(cmd),
        Commands::Sigma(cmd) => commands::sigma::run(cmd),
        Commands::Harden(cmd) => commands::harden::run(cmd),
        Commands::Verify(cmd) => commands::verify::run(cmd),
        Commands::Persistence(cmd) => commands::persistence::run(cmd),
        Commands::Procmon(cmd) => commands::procmon::run(cmd),
        Commands::Yara(cmd) => commands::yara::run(cmd),
        Commands::Privesc(cmd) => commands::privesc::run(cmd),
        Commands::Info => commands::info::run(),
    }
}
