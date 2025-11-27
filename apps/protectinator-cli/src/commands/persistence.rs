//! Persistence mechanism scanner commands

use clap::Subcommand;

#[derive(Subcommand)]
pub enum PersistenceCommands {
    /// Scan for persistence mechanisms
    Scan,

    /// List known persistence locations
    List,
}

pub fn run(cmd: PersistenceCommands) -> anyhow::Result<()> {
    match cmd {
        PersistenceCommands::Scan => {
            println!("Persistence scanning will be implemented in Phase 6a");

            #[cfg(target_os = "linux")]
            {
                println!("\nLinux persistence locations to check:");
                println!("  - /etc/cron.*");
                println!("  - /etc/systemd/system/");
                println!("  - ~/.bashrc, ~/.profile");
                println!("  - /etc/ld.so.preload");
            }

            #[cfg(target_os = "macos")]
            {
                println!("\nmacOS persistence locations to check:");
                println!("  - /Library/LaunchAgents/");
                println!("  - /Library/LaunchDaemons/");
                println!("  - ~/Library/LaunchAgents/");
                println!("  - Login Items");
            }

            Ok(())
        }
        PersistenceCommands::List => {
            println!("Persistence location listing will be implemented in Phase 6a");
            Ok(())
        }
    }
}
