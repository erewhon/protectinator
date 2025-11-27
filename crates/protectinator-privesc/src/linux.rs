//! Linux privilege escalation checks

use crate::types::{PrivescEntry, PrivescType, RiskLevel};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

/// Run all Linux privesc checks
pub fn scan_all() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    entries.extend(scan_suid_binaries());
    entries.extend(scan_sgid_binaries());
    entries.extend(scan_capabilities());
    entries.extend(scan_writable_paths());
    entries.extend(scan_sudo_config());
    entries.extend(scan_world_writable());

    entries
}

/// Scan for SUID binaries
pub fn scan_suid_binaries() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    let search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin"];

    for base_path in &search_paths {
        let path = Path::new(base_path);
        if !path.exists() {
            continue;
        }

        for entry in WalkDir::new(path)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if !file_path.is_file() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(file_path) {
                let mode = metadata.permissions().mode();
                // Check SUID bit (4000)
                if mode & 0o4000 != 0 {
                    let name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    let (risk, reasons) = assess_suid_risk(name, file_path);

                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::SuidBinary,
                        path: file_path.to_path_buf(),
                        name: name.to_string(),
                        description: format!("SUID binary: {}", name),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk,
                        risk_reasons: reasons,
                        mitre_id: Some("T1548.001".to_string()),
                        remediation: Some("Review if SUID is necessary; remove with chmod u-s".to_string()),
                    });
                }
            }
        }
    }

    entries
}

/// Scan for SGID binaries
pub fn scan_sgid_binaries() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    let search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"];

    for base_path in &search_paths {
        let path = Path::new(base_path);
        if !path.exists() {
            continue;
        }

        for entry in WalkDir::new(path)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if !file_path.is_file() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(file_path) {
                let mode = metadata.permissions().mode();
                // Check SGID bit (2000)
                if mode & 0o2000 != 0 {
                    let name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::SgidBinary,
                        path: file_path.to_path_buf(),
                        name: name.to_string(),
                        description: format!("SGID binary: {}", name),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk: RiskLevel::Low,
                        risk_reasons: vec!["SGID binary found".to_string()],
                        mitre_id: Some("T1548.001".to_string()),
                        remediation: Some("Review if SGID is necessary".to_string()),
                    });
                }
            }
        }
    }

    entries
}

/// Scan for files with capabilities
pub fn scan_capabilities() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    // Use getcap to find files with capabilities
    let output = match Command::new("getcap").args(["-r", "/usr"]).output() {
        Ok(o) => o,
        Err(_) => return entries,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        // Format: /path/to/file cap_xxx+ep
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            let path = Path::new(parts[0]);
            let caps = parts[1..].join(" ");

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            let (risk, reasons) = assess_capability_risk(name, &caps);

            entries.push(PrivescEntry {
                privesc_type: PrivescType::Capability,
                path: path.to_path_buf(),
                name: name.to_string(),
                description: format!("Capabilities: {}", caps),
                owner: None,
                permissions: None,
                risk,
                risk_reasons: reasons,
                mitre_id: Some("T1548.001".to_string()),
                remediation: Some("Review if capabilities are necessary".to_string()),
            });
        }
    }

    entries
}

/// Scan for writable directories in PATH
pub fn scan_writable_paths() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(path) {
                let mode = metadata.permissions().mode();
                // Check if world-writable or group-writable
                if mode & 0o002 != 0 || mode & 0o020 != 0 {
                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::WritablePath,
                        path: path.to_path_buf(),
                        name: dir.to_string(),
                        description: "Writable directory in PATH".to_string(),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk: RiskLevel::High,
                        risk_reasons: vec![
                            "Directory in PATH is writable".to_string(),
                            "Attacker could place malicious binaries".to_string(),
                        ],
                        mitre_id: Some("T1574.007".to_string()),
                        remediation: Some("Remove write permissions: chmod o-w".to_string()),
                    });
                }
            }
        }
    }

    entries
}

/// Check sudo configuration
pub fn scan_sudo_config() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    // Check /etc/sudoers for dangerous configurations
    if let Ok(content) = fs::read_to_string("/etc/sudoers") {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Check for NOPASSWD
            if line.contains("NOPASSWD") {
                let (risk, reasons) = assess_sudo_line_risk(line);
                entries.push(PrivescEntry {
                    privesc_type: PrivescType::SudoMisconfig,
                    path: "/etc/sudoers".into(),
                    name: "NOPASSWD rule".to_string(),
                    description: line.to_string(),
                    owner: None,
                    permissions: None,
                    risk,
                    risk_reasons: reasons,
                    mitre_id: Some("T1548.003".to_string()),
                    remediation: Some("Review NOPASSWD privileges".to_string()),
                });
            }

            // Check for dangerous wildcards
            if line.contains("ALL=(ALL)") || line.contains("ALL=(ALL:ALL)") {
                if line.contains("NOPASSWD") {
                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::SudoMisconfig,
                        path: "/etc/sudoers".into(),
                        name: "Full sudo without password".to_string(),
                        description: line.to_string(),
                        owner: None,
                        permissions: None,
                        risk: RiskLevel::Critical,
                        risk_reasons: vec![
                            "User can run any command as root without password".to_string(),
                        ],
                        mitre_id: Some("T1548.003".to_string()),
                        remediation: Some("Remove NOPASSWD or limit commands".to_string()),
                    });
                }
            }
        }
    }

    // Check /etc/sudoers.d/
    if let Ok(dir_entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in dir_entries.filter_map(|e| e.ok()) {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                for line in content.lines() {
                    let line = line.trim();
                    if line.contains("NOPASSWD") && !line.starts_with('#') {
                        entries.push(PrivescEntry {
                            privesc_type: PrivescType::SudoMisconfig,
                            path: entry.path(),
                            name: "NOPASSWD rule".to_string(),
                            description: line.to_string(),
                            owner: None,
                            permissions: None,
                            risk: RiskLevel::Medium,
                            risk_reasons: vec!["NOPASSWD sudo rule".to_string()],
                            mitre_id: Some("T1548.003".to_string()),
                            remediation: Some("Review sudo configuration".to_string()),
                        });
                    }
                }
            }
        }
    }

    entries
}

/// Scan for world-writable files in sensitive locations
pub fn scan_world_writable() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    let sensitive_dirs = ["/etc", "/usr/lib", "/lib"];

    for base_dir in &sensitive_dirs {
        let path = Path::new(base_dir);
        if !path.exists() {
            continue;
        }

        for entry in WalkDir::new(path)
            .max_depth(3)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let file_path = entry.path();
            if !file_path.is_file() {
                continue;
            }

            if let Ok(metadata) = fs::metadata(file_path) {
                let mode = metadata.permissions().mode();
                // World-writable
                if mode & 0o002 != 0 {
                    let name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::WorldWritable,
                        path: file_path.to_path_buf(),
                        name: name.to_string(),
                        description: "World-writable file in sensitive location".to_string(),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk: RiskLevel::High,
                        risk_reasons: vec![
                            "File is world-writable".to_string(),
                            format!("Located in {}", base_dir),
                        ],
                        mitre_id: Some("T1222.002".to_string()),
                        remediation: Some("Remove world-write permission: chmod o-w".to_string()),
                    });
                }
            }
        }
    }

    entries
}

fn get_owner(uid: u32) -> Option<String> {
    // Try to get username from /etc/passwd
    if let Ok(content) = fs::read_to_string("/etc/passwd") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 3 {
                if let Ok(file_uid) = parts[2].parse::<u32>() {
                    if file_uid == uid {
                        return Some(parts[0].to_string());
                    }
                }
            }
        }
    }
    Some(uid.to_string())
}

fn assess_suid_risk(name: &str, _path: &Path) -> (RiskLevel, Vec<String>) {
    let mut reasons = Vec::new();
    let mut risk = RiskLevel::Low;

    // GTFOBins - known exploitable SUID binaries
    let dangerous = [
        "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
        "python", "python2", "python3", "perl", "ruby", "php", "lua",
        "awk", "gawk", "nawk", "mawk",
        "vim", "vi", "nano", "ed", "less", "more", "most",
        "find", "xargs", "env", "time", "timeout", "nice", "ionice",
        "cp", "mv", "dd", "tar", "zip", "gzip", "bzip2", "xz",
        "base64", "xxd", "od", "hexdump",
        "nc", "netcat", "ncat", "socat",
        "wget", "curl", "fetch",
        "ssh", "scp", "rsync", "ftp",
        "ld.so", "docker", "lxc", "runc",
    ];

    for bin in &dangerous {
        if name == *bin {
            risk = RiskLevel::Critical;
            reasons.push(format!("{} is known exploitable with SUID (GTFOBins)", name));
            break;
        }
    }

    if risk == RiskLevel::Low {
        // Medium risk for less common SUID binaries
        let common_suid = [
            "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
            "ping", "ping6", "mount", "umount", "fusermount",
        ];

        if !common_suid.contains(&name) {
            risk = RiskLevel::Medium;
            reasons.push("Uncommon SUID binary".to_string());
        } else {
            reasons.push("Common system SUID binary".to_string());
        }
    }

    (risk, reasons)
}

fn assess_capability_risk(name: &str, caps: &str) -> (RiskLevel, Vec<String>) {
    let mut reasons = Vec::new();
    let mut risk = RiskLevel::Low;

    // Dangerous capabilities
    let dangerous_caps = [
        ("cap_setuid", "Can change UID - full privilege escalation"),
        ("cap_setgid", "Can change GID"),
        ("cap_net_raw", "Raw socket access - potential for packet sniffing"),
        ("cap_sys_admin", "Various privileged operations"),
        ("cap_sys_ptrace", "Can trace any process"),
        ("cap_dac_override", "Bypasses file permission checks"),
        ("cap_dac_read_search", "Bypasses read permission checks"),
        ("cap_fowner", "Bypasses ownership checks"),
    ];

    for (cap, desc) in &dangerous_caps {
        if caps.contains(cap) {
            risk = std::cmp::max(risk, RiskLevel::High);
            reasons.push(format!("{}: {}", cap, desc));
        }
    }

    if risk == RiskLevel::Low {
        reasons.push(format!("Capabilities: {}", caps));
    }

    (risk, reasons)
}

fn assess_sudo_line_risk(line: &str) -> (RiskLevel, Vec<String>) {
    let mut reasons = Vec::new();
    let mut risk = RiskLevel::Medium;

    if line.contains("ALL=(ALL)") || line.contains("ALL=(ALL:ALL)") {
        risk = RiskLevel::High;
        reasons.push("Allows running as any user".to_string());
    }

    // Check for dangerous commands
    let dangerous = ["bash", "sh", "python", "perl", "ruby", "vim", "less", "find"];
    for cmd in &dangerous {
        if line.contains(cmd) {
            risk = RiskLevel::High;
            reasons.push(format!("{} can be used to escape to shell", cmd));
            break;
        }
    }

    reasons.push("NOPASSWD allows passwordless sudo".to_string());

    (risk, reasons)
}

/// Get list of privilege escalation check locations
pub fn get_privesc_locations() -> Vec<(&'static str, PrivescType)> {
    vec![
        ("/usr/bin (SUID)", PrivescType::SuidBinary),
        ("/usr/sbin (SUID)", PrivescType::SuidBinary),
        ("Files with capabilities", PrivescType::Capability),
        ("/etc/sudoers", PrivescType::SudoMisconfig),
        ("/etc/sudoers.d/", PrivescType::SudoMisconfig),
        ("$PATH directories", PrivescType::WritablePath),
        ("/etc (world-writable)", PrivescType::WorldWritable),
    ]
}
