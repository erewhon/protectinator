//! Linux-specific platform utilities

use std::path::Path;

/// Check if systemd is available
pub fn has_systemd() -> bool {
    Path::new("/run/systemd/system").exists()
}

/// Check if auditd is running
pub fn has_auditd() -> bool {
    Path::new("/var/log/audit").exists()
        || std::process::Command::new("systemctl")
            .args(["is-active", "auditd"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
}

/// Check if SELinux is enabled
pub fn selinux_enabled() -> bool {
    if let Ok(content) = std::fs::read_to_string("/sys/fs/selinux/enforce") {
        content.trim() == "1"
    } else {
        false
    }
}

/// Check if AppArmor is enabled
pub fn apparmor_enabled() -> bool {
    Path::new("/sys/kernel/security/apparmor").exists()
}

/// Get the package manager type
pub fn detect_package_manager() -> Option<PackageManager> {
    if super::command_available("dpkg") {
        Some(PackageManager::Dpkg)
    } else if super::command_available("rpm") {
        Some(PackageManager::Rpm)
    } else if super::command_available("pacman") {
        Some(PackageManager::Pacman)
    } else {
        None
    }
}

/// Linux package manager types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Dpkg,
    Rpm,
    Pacman,
}

/// Read a sysctl value
pub fn read_sysctl(key: &str) -> Option<String> {
    let path = format!("/proc/sys/{}", key.replace('.', "/"));
    std::fs::read_to_string(&path).ok().map(|s| s.trim().to_string())
}

/// Get ASLR status (0=disabled, 1=conservative, 2=full)
pub fn aslr_status() -> Option<u8> {
    read_sysctl("kernel.randomize_va_space")
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sysctl_read() {
        // This should work on any Linux system
        let hostname = read_sysctl("kernel.hostname");
        // May or may not succeed depending on system
        if hostname.is_some() {
            assert!(!hostname.unwrap().is_empty());
        }
    }
}
