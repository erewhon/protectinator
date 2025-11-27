//! Linux persistence mechanism detection

use crate::types::{PersistenceEntry, PersistenceType, RiskLevel};
use regex::Regex;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

/// Scan all Linux persistence locations
pub fn scan_all() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    entries.extend(scan_cron());
    entries.extend(scan_systemd());
    entries.extend(scan_shell_profiles());
    entries.extend(scan_ld_preload());
    entries.extend(scan_ssh_authorized_keys());
    entries.extend(scan_xdg_autostart());
    entries.extend(scan_init_scripts());
    entries.extend(scan_kernel_modules());

    // Assess risk for all entries
    for entry in &mut entries {
        assess_risk(entry);
    }

    entries
}

/// Scan cron directories and files
pub fn scan_cron() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let cron_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
    ];

    // System crontab
    if let Ok(content) = fs::read_to_string("/etc/crontab") {
        for line in content.lines() {
            if let Some(entry) = parse_crontab_line(line, "/etc/crontab") {
                entries.push(entry);
            }
        }
    }

    // Cron directories
    for dir in &cron_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if let Ok(dir_entries) = fs::read_dir(path) {
            for entry in dir_entries.filter_map(|e| e.ok()) {
                let file_path = entry.path();
                if file_path.is_file() {
                    if let Ok(content) = fs::read_to_string(&file_path) {
                        // For cron.d, parse as crontab
                        if dir.contains("cron.d") || dir.contains("crontabs") {
                            for line in content.lines() {
                                if let Some(entry) = parse_crontab_line(line, &file_path) {
                                    entries.push(entry);
                                }
                            }
                        } else {
                            // For cron.daily etc., the script itself runs
                            let name = file_path
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("unknown");

                            entries.push(
                                PersistenceEntry::new(PersistenceType::Cron, &file_path, name)
                                    .with_command(content.lines().next().unwrap_or("")),
                            );
                        }
                    }
                }
            }
        }
    }

    entries
}

fn parse_crontab_line(line: &str, source: impl Into<PathBuf>) -> Option<PersistenceEntry> {
    let line = line.trim();

    // Skip comments and empty lines
    if line.is_empty() || line.starts_with('#') {
        return None;
    }

    // Skip environment variables
    if line.contains('=') && !line.contains(' ') {
        return None;
    }

    // Parse cron format: min hour day month weekday [user] command
    static CRON_PATTERN: OnceLock<Regex> = OnceLock::new();
    let pattern = CRON_PATTERN.get_or_init(|| {
        Regex::new(r"^[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+[\d\*,/-]+\s+(.+)$")
            .unwrap()
    });

    if let Some(caps) = pattern.captures(line) {
        let command = caps.get(1)?.as_str();
        let name = command.split_whitespace().next().unwrap_or("unknown");

        return Some(
            PersistenceEntry::new(PersistenceType::Cron, source, name).with_command(command),
        );
    }

    None
}

/// Scan systemd unit files
pub fn scan_systemd() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let systemd_dirs = [
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/run/systemd/system",
    ];

    // Also check user systemd directories
    if let Ok(home) = std::env::var("HOME") {
        let user_systemd = format!("{}/.config/systemd/user", home);
        if Path::new(&user_systemd).exists() {
            entries.extend(scan_systemd_dir(&user_systemd, true));
        }
    }

    for dir in &systemd_dirs {
        entries.extend(scan_systemd_dir(dir, false));
    }

    entries
}

fn scan_systemd_dir(dir: &str, user_level: bool) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let path = Path::new(dir);

    if !path.exists() {
        return entries;
    }

    for entry in WalkDir::new(path).max_depth(2).into_iter().filter_map(|e| e.ok()) {
        let file_path = entry.path();
        let file_name = file_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Only process .service and .timer files
        if !file_name.ends_with(".service") && !file_name.ends_with(".timer") {
            continue;
        }

        if let Ok(content) = fs::read_to_string(file_path) {
            let mut pe = PersistenceEntry::new(PersistenceType::Systemd, file_path, file_name);

            // Extract ExecStart
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with("ExecStart=") {
                    pe.command = Some(line.strip_prefix("ExecStart=").unwrap_or("").to_string());
                }
                if line.starts_with("Description=") {
                    pe.description =
                        Some(line.strip_prefix("Description=").unwrap_or("").to_string());
                }
            }

            if user_level {
                pe.user = std::env::var("USER").ok();
            }

            // Check if enabled
            let enabled_path = Path::new("/etc/systemd/system/multi-user.target.wants")
                .join(file_name);
            pe.enabled = enabled_path.exists() || content.contains("[Install]");

            entries.push(pe);
        }
    }

    entries
}

/// Scan shell profile files
pub fn scan_shell_profiles() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let system_profiles = [
        "/etc/profile",
        "/etc/profile.d",
        "/etc/bash.bashrc",
        "/etc/bashrc",
        "/etc/zsh/zshenv",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
    ];

    // System profiles
    for path_str in &system_profiles {
        let path = Path::new(path_str);
        if path.is_file() {
            entries.push(PersistenceEntry::new(
                PersistenceType::ShellProfile,
                path,
                path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown"),
            ));
        } else if path.is_dir() {
            if let Ok(dir_entries) = fs::read_dir(path) {
                for entry in dir_entries.filter_map(|e| e.ok()) {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        let name = file_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");
                        entries.push(PersistenceEntry::new(
                            PersistenceType::ShellProfile,
                            &file_path,
                            name,
                        ));
                    }
                }
            }
        }
    }

    // User profiles
    if let Ok(home) = std::env::var("HOME") {
        let user_profiles = [
            ".bashrc",
            ".bash_profile",
            ".bash_login",
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

/// Scan for LD_PRELOAD persistence
pub fn scan_ld_preload() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Check /etc/ld.so.preload
    let preload_path = Path::new("/etc/ld.so.preload");
    if preload_path.exists() {
        if let Ok(content) = fs::read_to_string(preload_path) {
            for line in content.lines() {
                let line = line.trim();
                if !line.is_empty() && !line.starts_with('#') {
                    entries.push(
                        PersistenceEntry::new(PersistenceType::LdPreload, preload_path, line)
                            .with_command(line)
                            .with_risk(
                                RiskLevel::High,
                                vec!["LD_PRELOAD is commonly used for library injection".to_string()],
                            ),
                    );
                }
            }
        }
    }

    // Check environment for LD_PRELOAD
    if let Ok(ld_preload) = std::env::var("LD_PRELOAD") {
        if !ld_preload.is_empty() {
            entries.push(
                PersistenceEntry::new(
                    PersistenceType::LdPreload,
                    "/proc/self/environ",
                    "LD_PRELOAD env",
                )
                .with_command(&ld_preload)
                .with_risk(
                    RiskLevel::High,
                    vec!["LD_PRELOAD environment variable is set".to_string()],
                ),
            );
        }
    }

    entries
}

/// Scan SSH authorized_keys files
pub fn scan_ssh_authorized_keys() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Check common locations
    let ssh_dirs = ["/root/.ssh", "/home"];

    for dir in &ssh_dirs {
        let path = Path::new(dir);
        if !path.exists() {
            continue;
        }

        if *dir == "/home" {
            // Scan all user home directories
            if let Ok(users) = fs::read_dir(path) {
                for user in users.filter_map(|e| e.ok()) {
                    let auth_keys = user.path().join(".ssh/authorized_keys");
                    if auth_keys.exists() {
                        if let Ok(content) = fs::read_to_string(&auth_keys) {
                            let key_count = content
                                .lines()
                                .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
                                .count();

                            let user_name = user.file_name().to_string_lossy().to_string();
                            entries.push(
                                PersistenceEntry::new(
                                    PersistenceType::SshAuthorizedKeys,
                                    &auth_keys,
                                    format!("{} SSH keys", key_count),
                                )
                                .with_user(&user_name),
                            );
                        }
                    }
                }
            }
        } else {
            // Root's SSH keys
            let auth_keys = Path::new(dir).join("authorized_keys");
            if auth_keys.exists() {
                entries.push(
                    PersistenceEntry::new(
                        PersistenceType::SshAuthorizedKeys,
                        &auth_keys,
                        "root SSH keys",
                    )
                    .with_user("root"),
                );
            }
        }
    }

    entries
}

/// Scan XDG autostart directories
pub fn scan_xdg_autostart() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let autostart_dirs = ["/etc/xdg/autostart"];

    // User autostart
    if let Ok(home) = std::env::var("HOME") {
        let user_autostart = format!("{}/.config/autostart", home);
        if Path::new(&user_autostart).exists() {
            entries.extend(scan_desktop_files(&user_autostart, true));
        }
    }

    for dir in &autostart_dirs {
        entries.extend(scan_desktop_files(dir, false));
    }

    entries
}

fn scan_desktop_files(dir: &str, user_level: bool) -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();
    let path = Path::new(dir);

    if !path.exists() {
        return entries;
    }

    if let Ok(dir_entries) = fs::read_dir(path) {
        for entry in dir_entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            if file_path.extension().and_then(|e| e.to_str()) != Some("desktop") {
                continue;
            }

            if let Ok(content) = fs::read_to_string(&file_path) {
                let name = file_path
                    .file_stem()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                let mut pe = PersistenceEntry::new(PersistenceType::XdgAutostart, &file_path, name);

                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with("Exec=") {
                        pe.command = Some(line.strip_prefix("Exec=").unwrap_or("").to_string());
                    }
                    if line.starts_with("Name=") {
                        pe.description = Some(line.strip_prefix("Name=").unwrap_or("").to_string());
                    }
                    if line == "Hidden=true" || line == "X-GNOME-Autostart-enabled=false" {
                        pe.enabled = false;
                    }
                }

                if user_level {
                    pe.user = std::env::var("USER").ok();
                }

                entries.push(pe);
            }
        }
    }

    entries
}

/// Scan init scripts
pub fn scan_init_scripts() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    let init_dirs = ["/etc/init.d", "/etc/rc.local"];

    for dir in &init_dirs {
        let path = Path::new(dir);
        if path.is_file() {
            entries.push(PersistenceEntry::new(
                PersistenceType::InitScript,
                path,
                "rc.local",
            ));
        } else if path.is_dir() {
            if let Ok(dir_entries) = fs::read_dir(path) {
                for entry in dir_entries.filter_map(|e| e.ok()) {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        let name = file_path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("unknown");
                        entries.push(PersistenceEntry::new(
                            PersistenceType::InitScript,
                            &file_path,
                            name,
                        ));
                    }
                }
            }
        }
    }

    entries
}

/// Scan loaded kernel modules
pub fn scan_kernel_modules() -> Vec<PersistenceEntry> {
    let mut entries = Vec::new();

    // Check /etc/modules-load.d for auto-loaded modules
    if let Ok(dir_entries) = fs::read_dir("/etc/modules-load.d") {
        for entry in dir_entries.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            if file_path.is_file() {
                if let Ok(content) = fs::read_to_string(&file_path) {
                    for line in content.lines() {
                        let line = line.trim();
                        if !line.is_empty() && !line.starts_with('#') {
                            entries.push(PersistenceEntry::new(
                                PersistenceType::KernelModule,
                                &file_path,
                                line,
                            ));
                        }
                    }
                }
            }
        }
    }

    entries
}

/// Assess risk level for a persistence entry
fn assess_risk(entry: &mut PersistenceEntry) {
    let mut reasons = Vec::new();
    let mut risk = RiskLevel::Low;

    // Check command for suspicious patterns
    if let Some(ref cmd) = entry.command {
        let cmd_lower = cmd.to_lowercase();

        // Suspicious command patterns
        let suspicious_patterns = [
            ("curl", "Downloads content from internet"),
            ("wget", "Downloads content from internet"),
            ("nc ", "Netcat - potential reverse shell"),
            ("netcat", "Netcat - potential reverse shell"),
            ("bash -i", "Interactive shell - potential reverse shell"),
            ("/dev/tcp", "Bash network redirection"),
            ("python -c", "Inline Python execution"),
            ("perl -e", "Inline Perl execution"),
            ("base64", "Base64 encoding - potential obfuscation"),
            ("eval", "Dynamic code execution"),
            ("/tmp/", "Execution from /tmp"),
            ("/dev/shm", "Execution from shared memory"),
            ("chmod +x", "Making files executable"),
            ("0.0.0.0", "Binding to all interfaces"),
            ("&>/dev/null", "Hiding output"),
            ("2>/dev/null", "Hiding errors"),
        ];

        for (pattern, reason) in &suspicious_patterns {
            if cmd_lower.contains(pattern) {
                reasons.push(reason.to_string());
                risk = std::cmp::max(risk, RiskLevel::Medium);
            }
        }

        // High-risk patterns
        if cmd_lower.contains("reverse") || cmd_lower.contains("shell") || cmd_lower.contains("backdoor") {
            risk = RiskLevel::High;
            reasons.push("Command contains suspicious keywords".to_string());
        }
    }

    // Check path for suspicious locations
    let path_str = entry.path.to_string_lossy();
    if path_str.contains("/tmp/") || path_str.contains("/dev/shm") || path_str.contains("/var/tmp")
    {
        risk = std::cmp::max(risk, RiskLevel::High);
        reasons.push("File in temporary directory".to_string());
    }

    // Check for recently modified files
    if let Ok(metadata) = fs::metadata(&entry.path) {
        let modified = metadata.mtime();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Modified in last 24 hours
        if now - modified < 86400 {
            reasons.push("Recently modified (last 24 hours)".to_string());
            risk = std::cmp::max(risk, RiskLevel::Medium);
        }
    }

    // Type-specific risk assessment
    match entry.persistence_type {
        PersistenceType::LdPreload => {
            risk = RiskLevel::High;
            reasons.push("LD_PRELOAD is commonly used for malicious library injection".to_string());
        }
        PersistenceType::KernelModule => {
            risk = std::cmp::max(risk, RiskLevel::Medium);
            reasons.push("Kernel modules run with highest privileges".to_string());
        }
        _ => {}
    }

    entry.risk = risk;
    entry.risk_reasons = reasons;
}

/// Get list of all persistence locations
pub fn get_persistence_locations() -> Vec<(&'static str, PersistenceType)> {
    vec![
        ("/etc/crontab", PersistenceType::Cron),
        ("/etc/cron.d/", PersistenceType::Cron),
        ("/etc/cron.daily/", PersistenceType::Cron),
        ("/etc/cron.hourly/", PersistenceType::Cron),
        ("/etc/cron.weekly/", PersistenceType::Cron),
        ("/etc/cron.monthly/", PersistenceType::Cron),
        ("/var/spool/cron/crontabs/", PersistenceType::Cron),
        ("/etc/systemd/system/", PersistenceType::Systemd),
        ("/usr/lib/systemd/system/", PersistenceType::Systemd),
        ("~/.config/systemd/user/", PersistenceType::Systemd),
        ("/etc/profile", PersistenceType::ShellProfile),
        ("/etc/profile.d/", PersistenceType::ShellProfile),
        ("/etc/bash.bashrc", PersistenceType::ShellProfile),
        ("~/.bashrc", PersistenceType::ShellProfile),
        ("~/.bash_profile", PersistenceType::ShellProfile),
        ("~/.profile", PersistenceType::ShellProfile),
        ("/etc/ld.so.preload", PersistenceType::LdPreload),
        ("~/.ssh/authorized_keys", PersistenceType::SshAuthorizedKeys),
        ("/etc/xdg/autostart/", PersistenceType::XdgAutostart),
        ("~/.config/autostart/", PersistenceType::XdgAutostart),
        ("/etc/init.d/", PersistenceType::InitScript),
        ("/etc/rc.local", PersistenceType::InitScript),
        ("/etc/modules-load.d/", PersistenceType::KernelModule),
    ]
}
