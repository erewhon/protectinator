//! File integrity monitoring commands

use clap::{Args, Subcommand};
use protectinator_fim::{
    diff_baselines, format_size, BaselineDatabase, BaselineVerifier, DiffType, FileScanner,
    HashAlgorithm, VerificationResult,
};
use std::path::PathBuf;
use std::time::Instant;

#[derive(Subcommand)]
pub enum FimCommands {
    /// Create a baseline of file hashes
    Baseline(BaselineArgs),

    /// Verify files against a baseline
    Verify(VerifyArgs),

    /// Compare two baselines
    Diff(DiffArgs),

    /// Show baseline statistics
    Stats(StatsArgs),
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

    /// Use parallel hashing (faster for many files)
    #[arg(long, short = 'P', default_value = "true")]
    parallel: bool,

    /// Exclude hidden files (starting with .)
    #[arg(long)]
    exclude_hidden: bool,

    /// Maximum recursion depth
    #[arg(long)]
    max_depth: Option<usize>,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// Baseline database file
    baseline: PathBuf,

    /// Hash algorithm (must match baseline)
    #[arg(short = 'a', long, default_value = "sha256")]
    algorithm: String,

    /// Use parallel verification
    #[arg(long, short = 'P', default_value = "true")]
    parallel: bool,

    /// Only show changes (hide matched files)
    #[arg(long, short = 'c')]
    changes_only: bool,
}

#[derive(Args)]
pub struct DiffArgs {
    /// First baseline database
    baseline1: PathBuf,

    /// Second baseline database
    baseline2: PathBuf,
}

#[derive(Args)]
pub struct StatsArgs {
    /// Baseline database file
    baseline: PathBuf,
}

pub fn run(cmd: FimCommands) -> anyhow::Result<()> {
    match cmd {
        FimCommands::Baseline(args) => create_baseline(args),
        FimCommands::Verify(args) => verify_baseline(args),
        FimCommands::Diff(args) => diff_baselines_cmd(args),
        FimCommands::Stats(args) => show_stats(args),
    }
}

fn create_baseline(args: BaselineArgs) -> anyhow::Result<()> {
    println!("Creating baseline for: {}", args.path.display());

    let algorithm: HashAlgorithm = args.algorithm.parse()?;
    println!("  Algorithm: {}", algorithm);

    let mut scanner = FileScanner::new(algorithm)
        .follow_symlinks(args.follow_symlinks)
        .include_hidden(!args.exclude_hidden);

    if !args.exclude.is_empty() {
        scanner = scanner.with_excludes(&args.exclude)?;
        println!("  Excluding: {:?}", args.exclude);
    }

    if let Some(depth) = args.max_depth {
        scanner = scanner.max_depth(depth);
        println!("  Max depth: {}", depth);
    }

    let start = Instant::now();

    println!("\nScanning files...");
    let entries = if args.parallel {
        scanner.scan_parallel(&args.path)?
    } else {
        scanner.scan(&args.path)?
    };

    let scan_duration = start.elapsed();
    let total_size: u64 = entries.iter().map(|e| e.size).sum();

    println!("Found {} files ({}) in {:?}", entries.len(), format_size(total_size), scan_duration);

    println!("\nCreating database: {}", args.output.display());
    let mut db = BaselineDatabase::create(&args.output)?;

    db.set_metadata("algorithm", &args.algorithm)?;
    db.set_metadata("root_path", &args.path.to_string_lossy())?;
    db.set_metadata("created_at", &chrono::Utc::now().to_rfc3339())?;
    db.set_metadata("file_count", &entries.len().to_string())?;
    db.set_metadata("total_size", &total_size.to_string())?;

    println!("Storing file hashes...");
    let store_start = Instant::now();
    db.add_files(&entries)?;
    let store_duration = store_start.elapsed();

    let total_duration = start.elapsed();

    println!("\nBaseline created successfully!");
    println!("  Files: {}", db.file_count()?);
    println!("  Total size: {}", format_size(total_size));
    println!("  Algorithm: {}", args.algorithm);
    println!("  Output: {}", args.output.display());
    println!("  Scan time: {:?}", scan_duration);
    println!("  Store time: {:?}", store_duration);
    println!("  Total time: {:?}", total_duration);

    if args.parallel && entries.len() > 100 {
        let rate = entries.len() as f64 / scan_duration.as_secs_f64();
        println!("  Hash rate: {:.0} files/sec", rate);
    }

    Ok(())
}

fn verify_baseline(args: VerifyArgs) -> anyhow::Result<()> {
    println!("Verifying against baseline: {}", args.baseline.display());

    let db = BaselineDatabase::open(&args.baseline)?;

    // Get stored metadata
    let stored_algorithm = db
        .get_metadata("algorithm")?
        .unwrap_or_else(|| "sha256".to_string());

    let root_path = db.get_metadata("root_path")?.unwrap_or_default();
    let created_at = db.get_metadata("created_at")?.unwrap_or_default();

    println!("  Baseline path: {}", root_path);
    println!("  Created: {}", created_at);
    println!("  Algorithm: {}", stored_algorithm);
    println!("  Files in baseline: {}", db.file_count()?);

    if stored_algorithm != args.algorithm {
        println!(
            "\nWarning: Using algorithm '{}' but baseline was created with '{}'",
            args.algorithm, stored_algorithm
        );
    }

    let algorithm: HashAlgorithm = stored_algorithm.parse()?;

    let config = protectinator_fim::VerifierConfig {
        check_permissions: true,
        check_ownership: true,
        quick_check: true,
        parallel: args.parallel,
    };

    let verifier = BaselineVerifier::with_config(algorithm, config);

    println!("\nVerifying files...");
    let start = Instant::now();
    let results = verifier.verify(&db)?;
    let duration = start.elapsed();

    let summary = BaselineVerifier::summarize(&results);

    println!("\nVerification Results ({:?}):", duration);
    println!("─────────────────────────────");
    println!("  Matched: {}", summary.matched);
    println!("  Modified: {}", summary.modified);
    println!("  Deleted: {}", summary.deleted);
    println!("  Size changed: {}", summary.size_changed);
    println!("  Permissions changed: {}", summary.permissions_changed);
    println!("  Ownership changed: {}", summary.ownership_changed);
    println!("  Errors: {}", summary.errors);

    if summary.total_changes() > 0 || summary.errors > 0 {
        println!("\nChanges Detected:");
        println!("─────────────────");

        let mut changes: Vec<_> = results
            .iter()
            .filter(|r| r.result.is_change())
            .collect();

        // Sort by severity
        changes.sort_by(|a, b| b.result.severity().cmp(&a.result.severity()));

        for result in changes {
            match &result.result {
                VerificationResult::Modified { expected, actual } => {
                    println!("  [MODIFIED] {}", result.path);
                    println!("    Expected: {}...", &expected[..std::cmp::min(16, expected.len())]);
                    println!("    Actual:   {}...", &actual[..std::cmp::min(16, actual.len())]);
                }
                VerificationResult::Deleted => {
                    println!("  [DELETED] {}", result.path);
                }
                VerificationResult::SizeChanged { expected, actual } => {
                    println!(
                        "  [SIZE] {} ({} -> {})",
                        result.path,
                        format_size(*expected),
                        format_size(*actual)
                    );
                }
                VerificationResult::PermissionsChanged { expected, actual } => {
                    println!(
                        "  [PERMS] {} ({:o} -> {:o})",
                        result.path, expected, actual
                    );
                }
                VerificationResult::OwnerChanged {
                    expected_uid,
                    expected_gid,
                    actual_uid,
                    actual_gid,
                } => {
                    println!(
                        "  [OWNER] {} ({:?}:{:?} -> {}:{})",
                        result.path, expected_uid, expected_gid, actual_uid, actual_gid
                    );
                }
                VerificationResult::Error(e) => {
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

fn diff_baselines_cmd(args: DiffArgs) -> anyhow::Result<()> {
    println!("Comparing baselines:");
    println!("  Base: {}", args.baseline1.display());
    println!("  New:  {}", args.baseline2.display());

    let db1 = BaselineDatabase::open(&args.baseline1)?;
    let db2 = BaselineDatabase::open(&args.baseline2)?;

    let count1 = db1.file_count()?;
    let count2 = db2.file_count()?;

    println!("\n  Base files: {}", count1);
    println!("  New files:  {}", count2);

    println!("\nComparing...");
    let diffs = diff_baselines(&db1, &db2)?;

    if diffs.is_empty() {
        println!("\nNo differences found!");
        return Ok(());
    }

    let added = diffs.iter().filter(|d| matches!(d.diff_type, DiffType::Added)).count();
    let removed = diffs.iter().filter(|d| matches!(d.diff_type, DiffType::Removed)).count();
    let modified = diffs.iter().filter(|d| matches!(d.diff_type, DiffType::Modified { .. })).count();

    println!("\nDifferences found: {} total", diffs.len());
    println!("  Added: {}", added);
    println!("  Removed: {}", removed);
    println!("  Modified: {}", modified);

    println!("\nDetails:");
    println!("─────────");

    for diff in &diffs {
        match &diff.diff_type {
            DiffType::Added => {
                println!("  [+] {}", diff.path);
            }
            DiffType::Removed => {
                println!("  [-] {}", diff.path);
            }
            DiffType::Modified {
                old_size, new_size, ..
            } => {
                let size_change = if new_size > old_size {
                    format!("+{}", format_size(new_size - old_size))
                } else {
                    format!("-{}", format_size(old_size - new_size))
                };
                println!("  [M] {} ({})", diff.path, size_change);
            }
        }
    }

    Ok(())
}

fn show_stats(args: StatsArgs) -> anyhow::Result<()> {
    let db = BaselineDatabase::open(&args.baseline)?;

    println!("Baseline Statistics: {}", args.baseline.display());
    println!("═══════════════════════════════════════════");

    // Metadata
    if let Some(root) = db.get_metadata("root_path")? {
        println!("Root path: {}", root);
    }
    if let Some(created) = db.get_metadata("created_at")? {
        println!("Created: {}", created);
    }
    if let Some(algo) = db.get_metadata("algorithm")? {
        println!("Algorithm: {}", algo);
    }

    println!();

    let file_count = db.file_count()?;
    let total_size = db.total_size()?;

    println!("Files: {}", file_count);
    println!("Total size: {}", format_size(total_size));

    if file_count > 0 {
        let avg_size = total_size / file_count as u64;
        println!("Average file size: {}", format_size(avg_size));
    }

    Ok(())
}
