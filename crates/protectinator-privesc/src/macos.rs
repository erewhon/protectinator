//! macOS privilege escalation checks

use crate::types::{PrivescEntry, PrivescType, RiskLevel};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use walkdir::WalkDir;

/// Run all macOS privesc checks
pub fn scan_all() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    entries.extend(scan_suid_binaries());
    entries.extend(scan_writable_paths());
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

                    let (risk, reasons) = assess_suid_risk(name);

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
                        remediation: Some("Review if SUID is necessary".to_string()),
                    });
                }
            }
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
                if mode & 0o002 != 0 {
                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::WritablePath,
                        path: path.to_path_buf(),
                        name: dir.to_string(),
                        description: "Writable directory in PATH".to_string(),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk: RiskLevel::High,
                        risk_reasons: vec!["Directory in PATH is world-writable".to_string()],
                        mitre_id: Some("T1574.007".to_string()),
                        remediation: Some("Remove write permissions".to_string()),
                    });
                }
            }
        }
    }

    entries
}

/// Scan for world-writable files
pub fn scan_world_writable() -> Vec<PrivescEntry> {
    let mut entries = Vec::new();

    let sensitive_dirs = ["/etc", "/usr/local/bin"];

    for base_dir in &sensitive_dirs {
        let path = Path::new(base_dir);
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
                if mode & 0o002 != 0 {
                    let name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("unknown");

                    entries.push(PrivescEntry {
                        privesc_type: PrivescType::WorldWritable,
                        path: file_path.to_path_buf(),
                        name: name.to_string(),
                        description: "World-writable file".to_string(),
                        owner: get_owner(metadata.uid()),
                        permissions: Some(format!("{:o}", mode & 0o7777)),
                        risk: RiskLevel::High,
                        risk_reasons: vec!["File is world-writable".to_string()],
                        mitre_id: Some("T1222.002".to_string()),
                        remediation: Some("chmod o-w".to_string()),
                    });
                }
            }
        }
    }

    entries
}

fn get_owner(uid: u32) -> Option<String> {
    Some(uid.to_string())
}

fn assess_suid_risk(name: &str) -> (RiskLevel, Vec<String>) {
    let mut reasons = Vec::new();

    // Known exploitable binaries
    let dangerous = [
        "bash", "sh", "zsh", "python", "perl", "ruby",
        "vim", "less", "find", "env", "tar",
    ];

    for bin in &dangerous {
        if name == *bin {
            return (RiskLevel::Critical, vec![format!("{} is exploitable with SUID", name)]);
        }
    }

    let common_suid = ["sudo", "su", "passwd", "ping", "mount", "umount"];
    if !common_suid.contains(&name) {
        reasons.push("Uncommon SUID binary".to_string());
        return (RiskLevel::Medium, reasons);
    }

    reasons.push("Common system SUID binary".to_string());
    (RiskLevel::Low, reasons)
}

/// Get list of privesc check locations
pub fn get_privesc_locations() -> Vec<(&'static str, PrivescType)> {
    vec![
        ("/usr/bin (SUID)", PrivescType::SuidBinary),
        ("$PATH directories", PrivescType::WritablePath),
        ("/etc (world-writable)", PrivescType::WorldWritable),
    ]
}
