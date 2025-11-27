//! Process and connection monitor commands

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub enum ProcmonCommands {
    /// List running processes
    List(ProcListArgs),

    /// Show network connections
    Connections,
}

#[derive(Args)]
pub struct ProcListArgs {
    /// Show network connections for each process
    #[arg(long)]
    connections: bool,

    /// Show command line arguments
    #[arg(long)]
    cmdline: bool,

    /// Filter by process name
    #[arg(short, long)]
    filter: Option<String>,
}

pub fn run(cmd: ProcmonCommands) -> anyhow::Result<()> {
    match cmd {
        ProcmonCommands::List(args) => {
            println!("Process listing will be implemented in Phase 6b");
            println!("  Show connections: {}", args.connections);
            println!("  Show cmdline: {}", args.cmdline);
            if let Some(filter) = args.filter {
                println!("  Filter: {}", filter);
            }
            Ok(())
        }
        ProcmonCommands::Connections => {
            println!("Connection listing will be implemented in Phase 6b");
            Ok(())
        }
    }
}
