//! System hardening commands

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum HardenCommands {
    /// Run hardening checks
    Scan(HardenScanArgs),

    /// List available hardening checks
    List,
}

#[derive(Args)]
pub struct HardenScanArgs {
    /// Check categories to run
    #[arg(short, long, value_delimiter = ',')]
    categories: Vec<String>,

    /// Checks to skip
    #[arg(long, value_delimiter = ',')]
    skip: Vec<String>,

    /// Minimum severity to report
    #[arg(long, default_value = "low")]
    min_severity: String,
}

pub fn run(cmd: HardenCommands) -> anyhow::Result<()> {
    match cmd {
        HardenCommands::Scan(args) => {
            println!("System hardening scan will be implemented in Phase 3");
            if !args.categories.is_empty() {
                println!("  Categories: {:?}", args.categories);
            }
            if !args.skip.is_empty() {
                println!("  Skipping: {:?}", args.skip);
            }
            println!("  Min severity: {}", args.min_severity);
            Ok(())
        }
        HardenCommands::List => {
            println!("Hardening check list will be implemented in Phase 3");
            Ok(())
        }
    }
}
