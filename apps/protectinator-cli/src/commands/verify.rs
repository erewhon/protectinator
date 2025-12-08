//! OS file verification commands

use clap::{Args, Subcommand};
use protectinator_osverify::{
    detect_package_manager, get_package_manager, FileStatus, Manifest, PackageManagerType,
    ProgressInfo, VerificationEngine, VerificationMode, VerifyConfig,
};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Subcommand)]
pub enum VerifyCommands {
    /// Verify OS files using package manager
    Os(OsVerifyArgs),

    /// Verify using specific manifest
    Manifest(ManifestVerifyArgs),

    /// Verify specific packages
    Package(PackageVerifyArgs),

    /// Show package manager info
    Info,
}

#[derive(Args)]
pub struct OsVerifyArgs {
    /// Specific packages to verify (comma-separated)
    #[arg(short, long, value_delimiter = ',')]
    packages: Vec<String>,

    /// Skip configuration files
    #[arg(long, default_value = "true")]
    skip_config: bool,

    /// Show only problems (hide OK files)
    #[arg(short, long)]
    quiet: bool,

    /// Show all checked files
    #[arg(short, long)]
    verbose: bool,

    /// Include permission changes
    #[arg(long)]
    permissions: bool,

    /// Show cumulative progress (files and bytes checked)
    #[arg(long)]
    progress: bool,
}

#[derive(Args)]
pub struct ManifestVerifyArgs {
    /// Manifest file (JSON format)
    manifest: PathBuf,

    /// Paths to verify (if empty, verify all in manifest)
    #[arg(short, long)]
    paths: Vec<PathBuf>,

    /// Skip configuration files
    #[arg(long, default_value = "true")]
    skip_config: bool,
}

#[derive(Args)]
pub struct PackageVerifyArgs {
    /// Package name to verify
    package: String,

    /// Show all files, not just problems
    #[arg(short, long)]
    verbose: bool,
}

pub fn run(cmd: VerifyCommands) -> anyhow::Result<()> {
    match cmd {
        VerifyCommands::Os(args) => run_os_verify(args),
        VerifyCommands::Manifest(args) => run_manifest_verify(args),
        VerifyCommands::Package(args) => run_package_verify(args),
        VerifyCommands::Info => show_info(),
    }
}

/// Format bytes in human-readable form
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn run_os_verify(args: OsVerifyArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    println!("OS File Verification");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Show package manager info
    let pm_type = detect_package_manager();
    println!("Package manager: {}", pm_type.as_str());

    if pm_type == PackageManagerType::Unknown {
        println!("\n\x1b[91mError:\x1b[0m No supported package manager found.");
        println!("Supported: dpkg (Debian/Ubuntu), rpm (RHEL/Fedora), pacman (Arch), pkgutil (macOS)");
        std::process::exit(1);
    }

    // Set up progress callback if --progress flag is set
    let progress_callback = if args.progress {
        Some(Arc::new(move |info: ProgressInfo| {
            let pkg_progress = if let Some(total) = info.total_packages {
                format!("{}/{}", info.packages_checked, total)
            } else {
                format!("{}", info.packages_checked)
            };

            // Calculate MB/s rate
            let elapsed_secs = info.elapsed.as_secs_f64();
            let rate = if elapsed_secs > 0.0 {
                let mb_checked = info.bytes_checked as f64 / (1024.0 * 1024.0);
                format!("{:.1} MB/s", mb_checked / elapsed_secs)
            } else {
                "-- MB/s".to_string()
            };

            print!(
                "\r\x1b[KProgress: {} files, {} ({}) [{} packages]",
                info.files_checked,
                format_bytes(info.bytes_checked),
                rate,
                pkg_progress
            );
            let _ = io::stdout().flush();
        }) as Arc<dyn Fn(ProgressInfo) + Send + Sync>)
    } else {
        None
    };

    let config = VerifyConfig {
        mode: VerificationMode::PackageManager,
        skip_config: args.skip_config,
        check_permissions: args.permissions,
        packages: args.packages,
        show_progress: true,
        progress_callback,
        ..Default::default()
    };

    println!("Mode: Package manager verification");
    if !config.packages.is_empty() {
        println!("Packages: {}", config.packages.join(", "));
    } else {
        println!("Packages: All installed");
    }
    println!();

    let engine = VerificationEngine::new(config);
    let summary = engine.verify().map_err(|e| anyhow::anyhow!("{}", e))?;

    // Clear progress line if it was shown
    if args.progress {
        println!("\r\x1b[K");
    }

    // Display issues
    if !summary.issues.is_empty() {
        println!("┌─ Issues Found ─────────────────────────────────────────────────");
        for issue in &summary.issues {
            let (color, symbol) = match issue.status {
                FileStatus::Modified => ("\x1b[91m", "M"),
                FileStatus::Missing => ("\x1b[93m", "?"),
                FileStatus::Replaced => ("\x1b[91m", "R"),
                FileStatus::PermissionsChanged => ("\x1b[33m", "P"),
                FileStatus::SizeChanged => ("\x1b[33m", "S"),
                _ => ("\x1b[37m", "-"),
            };
            let reset = "\x1b[0m";

            print!("│ {}{}{}  {}", color, symbol, reset, issue.path);
            if let Some(ref pkg) = issue.package {
                print!(" \x1b[90m({})\x1b[0m", pkg);
            }
            println!();
        }
        println!("└───────────────────────────────────────────────────────────────\n");
    }

    // Summary
    let duration = start.elapsed();

    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Score: {}%", summary.score());
    println!();
    println!("  Packages checked:   {}", summary.total_packages);
    println!("  Files verified:     {}", summary.total_files);
    println!("  \x1b[32mOK:\x1b[0m                {}", summary.files_ok);
    println!("  \x1b[91mModified:\x1b[0m          {}", summary.files_modified);
    println!("  \x1b[93mMissing:\x1b[0m           {}", summary.files_missing);
    if args.permissions {
        println!("  \x1b[33mPermissions:\x1b[0m       {}", summary.permissions_changed);
    }
    println!("  \x1b[90mConfig (skipped):\x1b[0m  {}", summary.config_modified);
    println!("  \x1b[90mSkipped:\x1b[0m           {}", summary.files_skipped);
    if summary.errors > 0 {
        println!("  Errors:            {}", summary.errors);
    }
    println!();
    println!("  Completed in {:?}", duration);

    // Exit with error if critical issues found
    if !summary.passed() {
        println!(
            "\n\x1b[91mWarning:\x1b[0m {} modified or missing files detected.",
            summary.files_modified + summary.files_missing
        );
        std::process::exit(1);
    } else {
        println!("\n\x1b[32mAll verified files are intact.\x1b[0m");
    }

    Ok(())
}

fn run_manifest_verify(args: ManifestVerifyArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    println!("Manifest Verification");
    println!("═══════════════════════════════════════════════════════════════\n");

    // Load manifest
    let manifest = Manifest::from_json_file(&args.manifest)
        .map_err(|e| anyhow::anyhow!("Failed to load manifest: {}", e))?;

    println!("Manifest: {}", args.manifest.display());
    if let Some(ref desc) = manifest.description {
        println!("Description: {}", desc);
    }
    if let Some(ref os) = manifest.os {
        println!("OS: {}", os);
    }
    println!("Files in manifest: {}", manifest.len());
    println!();

    let config = VerifyConfig {
        mode: VerificationMode::Manifest,
        skip_config: args.skip_config,
        ..Default::default()
    };

    let engine = VerificationEngine::new(config).with_manifest(manifest);
    let summary = engine.verify().map_err(|e| anyhow::anyhow!("{}", e))?;

    // Display issues
    if !summary.issues.is_empty() {
        println!("┌─ Issues Found ─────────────────────────────────────────────────");
        for issue in &summary.issues {
            let (color, symbol) = match issue.status {
                FileStatus::Modified => ("\x1b[91m", "M"),
                FileStatus::Missing => ("\x1b[93m", "?"),
                _ => ("\x1b[37m", "-"),
            };
            let reset = "\x1b[0m";

            println!("│ {}{}{}  {}", color, symbol, reset, issue.path);
            if let Some(ref expected) = issue.expected {
                println!("│     Expected: {}", expected);
            }
            if let Some(ref actual) = issue.actual {
                println!("│     Actual:   {}", actual);
            }
        }
        println!("└───────────────────────────────────────────────────────────────\n");
    }

    // Summary
    let duration = start.elapsed();

    println!("═══════════════════════════════════════════════════════════════");
    println!("Summary");
    println!("═══════════════════════════════════════════════════════════════");
    println!("  Score: {}%", summary.score());
    println!();
    println!("  Files in manifest: {}", summary.total_files);
    println!("  \x1b[32mOK:\x1b[0m               {}", summary.files_ok);
    println!("  \x1b[91mModified:\x1b[0m         {}", summary.files_modified);
    println!("  \x1b[93mMissing:\x1b[0m          {}", summary.files_missing);
    println!();
    println!("  Completed in {:?}", duration);

    if !summary.passed() {
        std::process::exit(1);
    }

    Ok(())
}

fn run_package_verify(args: PackageVerifyArgs) -> anyhow::Result<()> {
    let start = Instant::now();

    println!("Package Verification: {}", args.package);
    println!("═══════════════════════════════════════════════════════════════\n");

    let pm = get_package_manager().map_err(|e| anyhow::anyhow!("{}", e))?;

    println!("Package manager: {}", pm.manager_type().as_str());
    println!();

    // Get package files
    let files = pm
        .get_package_files(&args.package)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("Files in package: {}", files.len());

    // Verify the package
    let results = pm
        .verify_package(&args.package)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if results.is_empty() && !args.verbose {
        println!("\n\x1b[32mAll files OK.\x1b[0m");
    } else {
        println!();
        let mut problem_count = 0;

        for result in &results {
            if result.status == FileStatus::Ok {
                if args.verbose {
                    println!("\x1b[32m✓\x1b[0m {}", result.path);
                }
            } else {
                problem_count += 1;
                let (color, symbol) = match result.status {
                    FileStatus::Modified => ("\x1b[91m", "M"),
                    FileStatus::Missing => ("\x1b[93m", "?"),
                    FileStatus::Config => ("\x1b[90m", "c"),
                    FileStatus::PermissionsChanged => ("\x1b[33m", "P"),
                    _ => ("\x1b[37m", "-"),
                };
                println!("{}{}  {}\x1b[0m", color, symbol, result.path);
            }
        }

        if problem_count == 0 && results.is_empty() {
            // Package manager didn't report issues
            println!("\x1b[32mNo issues reported by package manager.\x1b[0m");
        }
    }

    let duration = start.elapsed();
    println!("\nCompleted in {:?}", duration);

    Ok(())
}

fn show_info() -> anyhow::Result<()> {
    println!("OS File Verification - System Info");
    println!("═══════════════════════════════════════════════════════════════\n");

    let pm_type = detect_package_manager();

    println!("Detected package manager: {}", pm_type.as_str());

    match pm_type {
        PackageManagerType::Dpkg => {
            println!("  Type: Debian/Ubuntu dpkg");
            println!("  Verification: dpkg -V");
            println!("  Hash algorithm: MD5");
        }
        PackageManagerType::Rpm => {
            println!("  Type: Red Hat/Fedora RPM");
            println!("  Verification: rpm -V");
            println!("  Hash algorithm: SHA-256");
        }
        PackageManagerType::Pacman => {
            println!("  Type: Arch Linux pacman");
            println!("  Verification: pacman -Qkk");
            println!("  Hash algorithm: SHA-256");
        }
        PackageManagerType::Pkgutil => {
            println!("  Type: macOS pkgutil");
            println!("  Verification: pkgutil --verify");
            println!("  Hash algorithm: SHA-256");
        }
        PackageManagerType::Apk => {
            println!("  Type: Alpine APK");
            println!("  Note: APK verification not yet implemented");
        }
        PackageManagerType::Unknown => {
            println!("  \x1b[91mNo supported package manager found.\x1b[0m");
            println!();
            println!("Supported package managers:");
            println!("  - dpkg (Debian, Ubuntu, etc.)");
            println!("  - rpm (RHEL, Fedora, CentOS, etc.)");
            println!("  - pacman (Arch Linux, Manjaro, etc.)");
            println!("  - pkgutil (macOS)");
            return Ok(());
        }
    }

    println!();

    // Try to get package count
    if let Ok(pm) = get_package_manager() {
        if let Ok(packages) = pm.list_packages() {
            println!("Installed packages: {}", packages.len());
        }
    }

    println!();
    println!("Verification modes:");
    println!("  os       - Use package manager built-in verification");
    println!("  manifest - Verify against a hash manifest file");
    println!("  package  - Verify a specific package");

    Ok(())
}
