//! File integrity monitoring commands

use clap::{Args, Subcommand};
use protectinator_fim::{BaselineDatabase, BaselineVerifier, FileScanner, HashAlgorithm};
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum FimCommands {
    /// Create a baseline of file hashes
    Baseline(BaselineArgs),

    /// Verify files against a baseline
    Verify(VerifyArgs),
}

#[derive(Args)]
pub struct BaselineArgs {
    /// Directory to scan
    path: PathBuf,

    /// Output database file
    #[arg(short, long, default_value = "baseline.db")]
    output: PathBuf,

    /// Hash algorithm (sha256, sha512, blake3)
    #[arg(short = 'a', long, default_value = "sha256")]
    algorithm: String,

    /// Patterns to exclude (glob)
    #[arg(short, long, value_delimiter = ',')]
    exclude: Vec<String>,

    /// Follow symbolic links
    #[arg(long)]
    follow_symlinks: bool,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Baseline database file
    baseline: PathBuf,

    /// Hash algorithm (must match baseline)
    #[arg(short = 'a', long, default_value = "sha256")]
    algorithm: String,
}

pub fn run(cmd: FimCommands) -> anyhow::Result<()> {
    match cmd {
        FimCommands::Baseline(args) => create_baseline(args),
        FimCommands::Verify(args) => verify_baseline(args),
    }
}

fn create_baseline(args: BaselineArgs) -> anyhow::Result<()> {
    println!("Creating baseline for: {}", args.path.display());

    let algorithm: HashAlgorithm = args.algorithm.parse()?;

    let scanner = FileScanner::new(algorithm)
        .with_excludes(&args.exclude)?
        .follow_symlinks(args.follow_symlinks);

    println!("Scanning files...");
    let entries = scanner.scan(&args.path)?;
    println!("Found {} files", entries.len());

    println!("Creating database: {}", args.output.display());
    let mut db = BaselineDatabase::create(&args.output)?;

    db.set_metadata("algorithm", &args.algorithm)?;
    db.set_metadata("root_path", &args.path.to_string_lossy())?;
    db.set_metadata(
        "created_at",
        &chrono::Utc::now().to_rfc3339(),
    )?;

    println!("Storing file hashes...");
    db.add_files(&entries)?;

    println!("Baseline created successfully!");
    println!("  Files: {}", db.file_count()?);
    println!("  Algorithm: {}", args.algorithm);
    println!("  Output: {}", args.output.display());

    Ok(())
}

fn verify_baseline(args: VerifyArgs) -> anyhow::Result<()> {
    println!("Verifying against baseline: {}", args.baseline.display());

    let db = BaselineDatabase::open(&args.baseline)?;

    // Get stored algorithm
    let stored_algorithm = db
        .get_metadata("algorithm")?
        .unwrap_or_else(|| "sha256".to_string());

    if stored_algorithm != args.algorithm {
        println!(
            "Warning: Using algorithm '{}' but baseline was created with '{}'",
            args.algorithm, stored_algorithm
        );
    }

    let algorithm: HashAlgorithm = stored_algorithm.parse()?;
    let verifier = BaselineVerifier::new(algorithm);

    println!("Verifying files...");
    let results = verifier.verify(&db)?;

    let summary = BaselineVerifier::summarize(&results);

    println!("\nVerification Results:");
    println!("---------------------");
    println!("  Matched: {}", summary.matched);
    println!("  Modified: {}", summary.modified);
    println!("  Deleted: {}", summary.deleted);
    println!("  Permissions Changed: {}", summary.permissions_changed);
    println!("  Errors: {}", summary.errors);

    if summary.total_changes() > 0 {
        println!("\nChanges Detected:");
        for result in &results {
            match &result.result {
                protectinator_fim::verifier::VerificationResult::Modified { expected, actual } => {
                    println!("  [MODIFIED] {}", result.path);
                    println!("    Expected: {}", expected);
                    println!("    Actual:   {}", actual);
                }
                protectinator_fim::verifier::VerificationResult::Deleted => {
                    println!("  [DELETED] {}", result.path);
                }
                protectinator_fim::verifier::VerificationResult::PermissionsChanged {
                    expected,
                    actual,
                } => {
                    println!("  [PERMS] {} ({:o} -> {:o})", result.path, expected, actual);
                }
                protectinator_fim::verifier::VerificationResult::Error(e) => {
                    println!("  [ERROR] {}: {}", result.path, e);
                }
                _ => {}
            }
        }

        std::process::exit(1);
    } else {
        println!("\nAll files match baseline!");
    }

    Ok(())
}
