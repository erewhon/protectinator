//! Common utilities for hardening checks

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

/// Read a file and return its contents
pub fn read_file(path: &Path) -> Result<String, std::io::Error> {
    fs::read_to_string(path)
}

/// Check if a file exists
pub fn file_exists(path: &Path) -> bool {
    path.exists() && path.is_file()
}

/// Check if a directory exists
pub fn dir_exists(path: &Path) -> bool {
    path.exists() && path.is_dir()
}

/// Read a sysctl value
#[cfg(target_os = "linux")]
pub fn read_sysctl(key: &str) -> Option<String> {
    // Try reading from /proc/sys first
    let proc_path = format!("/proc/sys/{}", key.replace('.', "/"));
    if let Ok(content) = fs::read_to_string(&proc_path) {
        return Some(content.trim().to_string());
    }

    // Fall back to sysctl command
    let output = Command::new("sysctl")
        .arg("-n")
        .arg(key)
        .output()
        .ok()?;

    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Run a command and return stdout
pub fn run_command(cmd: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(cmd)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to run {}: {}", cmd, e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).trim().to_string())
    }
}

/// Check if a command exists
pub fn command_exists(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Parse a config file for a key=value pattern
pub fn parse_config_value(path: &Path, key: &str) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle key=value and key value formats
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim();
            if rest.starts_with('=') {
                return Some(rest[1..].trim().to_string());
            } else if rest.starts_with(char::is_whitespace) {
                return Some(rest.trim().to_string());
            }
        }
    }

    None
}

/// Check if a line exists in a file (with optional pattern)
pub fn file_contains_line(path: &Path, pattern: &str) -> bool {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();
        if line.contains(pattern) {
            return true;
        }
    }

    false
}

/// Get file permissions (Unix mode)
#[cfg(unix)]
pub fn get_file_mode(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).ok().map(|m| m.permissions().mode())
}

/// Get file owner UID
#[cfg(unix)]
pub fn get_file_owner(path: &Path) -> Option<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).ok().map(|m| (m.uid(), m.gid()))
}

/// Check if file has specific permission bits set
#[cfg(unix)]
pub fn check_file_permissions(path: &Path, required_mode: u32, mask: u32) -> bool {
    if let Some(mode) = get_file_mode(path) {
        (mode & mask) == required_mode
    } else {
        false
    }
}

/// Check if running as root
#[cfg(unix)]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Find files matching a glob pattern
pub fn find_files(pattern: &str) -> Vec<std::path::PathBuf> {
    glob::glob(pattern)
        .map(|paths| paths.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

/// Parse SSH config file and extract settings
pub fn parse_ssh_config(path: &Path) -> std::collections::HashMap<String, String> {
    let mut config = std::collections::HashMap::new();

    let file = match fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return config,
    };
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let line = line.trim();

        // Skip comments and empty lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Split on whitespace
        let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
        if parts.len() == 2 {
            config.insert(parts[0].to_lowercase(), parts[1].trim().to_string());
        }
    }

    config
}

/// Check systemd service status
#[cfg(target_os = "linux")]
pub fn is_service_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Check systemd service enabled status
#[cfg(target_os = "linux")]
pub fn is_service_enabled(service: &str) -> bool {
    Command::new("systemctl")
        .args(["is-enabled", "--quiet", service])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
