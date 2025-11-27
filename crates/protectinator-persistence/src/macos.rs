//! macOS persistence mechanism detection

use crate::types::{PersistenceEntry, PersistenceType, RiskLevel};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Scan all macOS persistence locations
pub fn scan_all() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    entries.extend(scan_launch_agents());
    entries.extend(scan_launch_daemons());
    entries.extend(scan_login_items());
    entries.extend(scan_periodic());
    entries.extend(scan_startup_items());
    entries.extend(scan_shell_profiles());
    entries.extend(scan_emond());

    // Assess risk for all entries
    for entry in &mut entries {
        assess_risk(entry);
    }

    entries
}

/// Scan LaunchAgents directories
pub fn scan_launch_agents() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let agent_dirs = [
        "/Library/LaunchAgents",
        "/System/Library/LaunchAgents",
    ];

    // User LaunchAgents
    if let Ok(home) = std::env::var("HOME") {
        let user_agents = format!("{}/Library/LaunchAgents", home);
        if Path::new(&user_agents).exists() {
            entries.extend(scan_launchd_dir(&user_agents, PersistenceType::LaunchAgent, true));
        }
    }

    for dir in &agent_dirs {
        entries.extend(scan_launchd_dir(dir, PersistenceType::LaunchAgent, false));
    }

    entries
}

/// Scan LaunchDaemons directories
pub fn scan_launch_daemons() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let daemon_dirs = [
        "/Library/LaunchDaemons",
        "/System/Library/LaunchDaemons",
    ];

    for dir in &daemon_dirs {
        entries.extend(scan_launchd_dir(dir, PersistenceType::LaunchDaemon, false));
    }

    entries
}

fn scan_launchd_dir(dir: &str, ptype: PersistenceType, user_level: bool) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let path = Path::new(dir);

    if !path.exists() {
        return entries;
    }

    if let Ok(dir_entries) = fs::read_dir(path) {
        for entry in dir_entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();

            // Only process .plist files
            if file_path.extension().and_then(|e| e.to_str()) != Some("plist") {
                continue;
            }

            let name = file_path
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let mut pe = PersistenceEntry::new(ptype, &file_path, name);

            // Try to parse plist to get Program/ProgramArguments
            if let Some(cmd) = parse_launchd_plist(&file_path) {
                pe.command = Some(cmd);
            }

            // Check if loaded
            pe.enabled = is_launchd_loaded(name);

            if user_level {
                pe.user = std::env::var("USER").ok();
            }

            // Apple-signed plists are lower risk
            if name.starts_with("com.apple.") {
                pe.risk = RiskLevel::Low;
            }

            entries.push(pe);
        }
    }

    entries
}

fn parse_launchd_plist(path: &Path) -> Option<String> {
    // Use plutil to convert plist to JSON
    let output = Command::new("plutil")
        .args(["-convert", "json", "-o", "-", path.to_str()?])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let content = String::from_utf8_lossy(&output.stdout);

    // Simple JSON parsing for Program or ProgramArguments
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
        // Try Program first
        if let Some(program) = json.get("Program").and_then(|v| v.as_str()) {
            return Some(program.to_string());
        }

        // Try ProgramArguments
        if let Some(args) = json.get("ProgramArguments").and_then(|v| v.as_array()) {
            let cmd: Vec<String> = args
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            if !cmd.is_empty() {
                return Some(cmd.join(" "));
            }
        }
    }

    None
}

fn is_launchd_loaded(label: &str) -> bool {
    Command::new("launchctl")
        .args(["list", label])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Scan Login Items
pub fn scan_login_items() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Use osascript to list login items
    let output = Command::new("osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get the name of every login item",
        ])
        .output();

    if let Ok(output) = output {
        if output.status.success() {
            let items = String::from_utf8_lossy(&output.stdout);
            for item in items.trim().split(", ") {
                if !item.is_empty() && item != "missing value" {
                    entries.push(
                        PersistenceEntry::new(
                            PersistenceType::LoginItem,
                            "/Library/Preferences/com.apple.loginitems.plist",
                            item,
                        )
                        .with_user(std::env::var("USER").unwrap_or_default()),
                    );
                }
            }
        }
    }

    entries
}

/// Scan periodic scripts
pub fn scan_periodic() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let periodic_dirs = [
        "/etc/periodic/daily",
        "/etc/periodic/weekly",
        "/etc/periodic/monthly",
        "/usr/local/etc/periodic/daily",
        "/usr/local/etc/periodic/weekly",
        "/usr/local/etc/periodic/monthly",
    ];

    for dir in &periodic_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if let Ok(dir_entries) = fs::read_dir(path) {
            for entry in dir_entries.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if file_path.is_file() {
                    let name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    entries.push(PersistenceEntry::new(
                        PersistenceType::Periodic,
                        &file_path,
                        name,
                    ));
                }
            }
        }
    }

    entries
}

/// Scan legacy StartupItems
pub fn scan_startup_items() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let startup_dirs = [
        "/Library/StartupItems",
        "/System/Library/StartupItems",
    ];

    for dir in &startup_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if let Ok(dir_entries) = fs::read_dir(path) {
            for entry in dir_entries.filter_map(|e| e.ok()) {
                let item_path = entry.path();
                if item_path.is_dir() {
                    let name = item_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    let mut pe = PersistenceEntry::new(
                        PersistenceType::StartupItem,
                        &item_path,
                        name,
                    );

                    // Startup items are deprecated, flag as suspicious
                    pe.risk = RiskLevel::Medium;
                    pe.risk_reasons
                        .push("StartupItems are deprecated and rarely used legitimately".to_string());

                    entries.push(pe);
                }
            }
        }
    }

    entries
}

/// Scan shell profiles
pub fn scan_shell_profiles() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let system_profiles = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/zshrc",
        "/etc/zprofile",
    ];

    for path_str in &system_profiles {
        let path = Path::new(path_str);
        if path.exists() {
            entries.push(PersistenceEntry::new(
                PersistenceType::ShellProfile,
                path,
                path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
            ));
        }
    }

    // User profiles
    if let Ok(home) = std::env::var("HOME") {
        let user_profiles = [
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zshrc",
            ".zprofile",
            ".zshenv",
            ".zlogin",
        ];

        for profile in &user_profiles {
            let path = PathBuf::from(&home).join(profile);
            if path.exists() {
                entries.push(
                    PersistenceEntry::new(PersistenceType::ShellProfile, &path, *profile)
                        .with_user(std::env::var("USER").unwrap_or_default()),
                );
            }
        }
    }

    entries
}

/// Scan emond rules
pub fn scan_emond() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let emond_dirs = [
        "/etc/emond.d/rules",
        "/private/var/db/emondClients",
    ];

    for dir in &emond_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if let Ok(dir_entries) = fs::read_dir(path) {
            for entry in dir_entries.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if file_path.extension().and_then(|e| e.to_str()) == Some("plist") {
                    let name = file_path
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    let mut pe = PersistenceEntry::new(
                        PersistenceType::Emond,
                        &file_path,
                        name,
                    );

                    // Emond rules are suspicious by default
                    pe.risk = RiskLevel::Medium;
                    pe.risk_reasons
                        .push("Emond rules are rarely used and can be used for persistence".to_string());

                    entries.push(pe);
                }
            }
        }
    }

    entries
}

/// Assess risk level for a persistence entry
fn assess_risk(entry: &mut PersistenceEntry) {
    let mut reasons = entry.risk_reasons.clone();
    let mut risk = entry.risk;

    // Check command for suspicious patterns
    if let Some(ref cmd) = entry.command {
        let cmd_lower = cmd.to_lowercase();

        let suspicious_patterns = [
            ("curl", "Downloads content from internet"),
            ("wget", "Downloads content from internet"),
            ("osascript", "AppleScript execution"),
            ("python", "Python script execution"),
            ("bash -c", "Shell command execution"),
            ("/tmp/", "Execution from /tmp"),
            ("/var/tmp", "Execution from temp directory"),
            ("base64", "Base64 encoding - potential obfuscation"),
        ];

        for (pattern, reason) in &suspicious_patterns {
            if cmd_lower.contains(pattern) {
                reasons.push(reason.to_string());
                risk = std::cmp::max(risk, RiskLevel::Medium);
            }
        }
    }

    // Non-Apple bundles are higher risk
    if !entry.name.starts_with("com.apple.") {
        match entry.persistence_type {
            PersistenceType::LaunchDaemon => {
                reasons.push("Third-party LaunchDaemon".to_string());
                risk = std::cmp::max(risk, RiskLevel::Medium);
            }
            PersistenceType::LaunchAgent if entry.user.is_none() => {
                reasons.push("System-level third-party LaunchAgent".to_string());
                risk = std::cmp::max(risk, RiskLevel::Medium);
            }
            _ => {}
        }
    }

    entry.risk = risk;
    entry.risk_reasons = reasons;
}

/// Get list of all persistence locations
pub fn get_persistence_locations() -> Vec<(&'static str, PersistenceType)> {
    vec![
        ("/Library/LaunchAgents/", PersistenceType::LaunchAgent),
        ("~/Library/LaunchAgents/", PersistenceType::LaunchAgent),
        ("/System/Library/LaunchAgents/", PersistenceType::LaunchAgent),
        ("/Library/LaunchDaemons/", PersistenceType::LaunchDaemon),
        ("/System/Library/LaunchDaemons/", PersistenceType::LaunchDaemon),
        ("Login Items", PersistenceType::LoginItem),
        ("/Library/StartupItems/", PersistenceType::StartupItem),
        ("/etc/periodic/", PersistenceType::Periodic),
        ("/etc/emond.d/rules/", PersistenceType::Emond),
        ("/etc/profile", PersistenceType::ShellProfile),
        ("~/.bashrc", PersistenceType::ShellProfile),
        ("~/.zshrc", PersistenceType::ShellProfile),
    ]
}
