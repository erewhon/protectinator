//! Full scan command

use clap::Args;
use protectinator_engine::{format_json, format_text, ScanRunnerBuilder};
use protectinator_fim::FimProvider;
use protectinator_hardening::HardeningProvider;
use protectinator_sigma::SigmaProvider;

#[derive(Args)]
pub struct ScanArgs {
    /// Skip file integrity checks
    #[arg(long)]
    skip_fim: bool,

    /// Skip Sigma rule checks
    #[arg(long)]
    skip_sigma: bool,

    /// Skip hardening checks
    #[arg(long)]
    skip_hardening: bool,

    /// Paths to exclude from scan
    #[arg(long, value_delimiter = ',')]
    exclude: Vec<String>,
}

pub fn run(args: ScanArgs, format: &str) -> anyhow::Result<()> {
    println!("Protectinator Security Scan");
    println!("===========================\n");

    let mut builder = ScanRunnerBuilder::new()
        .parallel(true)
        .continue_on_error(true);

    if !args.exclude.is_empty() {
        builder = builder.exclude_paths(args.exclude);
    }

    // Add providers based on flags
    if !args.skip_fim {
        builder = builder.provider(Box::new(FimProvider::new()));
    }

    if !args.skip_sigma {
        builder = builder.provider(Box::new(SigmaProvider::new()));
    }

    if !args.skip_hardening {
        builder = builder.provider(Box::new(HardeningProvider::new()));
    }

    let results = builder.run()?;

    // Output results
    match format {
        "json" => {
            let json = format_json(&results, true)?;
            println!("{}", json);
        }
        _ => {
            let text = format_text(&results, false);
            println!("{}", text);
        }
    }

    // Exit with error code if critical findings
    if results.has_critical_findings() {
        std::process::exit(1);
    }

    Ok(())
}
