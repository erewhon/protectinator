//! macOS-specific platform utilities

use std::process::Command;

/// Check System Integrity Protection (SIP) status
pub fn sip_enabled() -> Option<bool> {
    let output = Command::new("csrutil")
        .arg("status")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.contains("enabled"))
}

/// Check Gatekeeper status
pub fn gatekeeper_enabled() -> Option<bool> {
    let output = Command::new("spctl")
        .arg("--status")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.contains("assessments enabled"))
}

/// Check FileVault status
pub fn filevault_enabled() -> Option<bool> {
    let output = Command::new("fdesetup")
        .arg("status")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.contains("FileVault is On"))
}

/// Check if the application firewall is enabled
pub fn firewall_enabled() -> Option<bool> {
    let output = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.contains("enabled"))
}

/// Check if remote login (SSH) is enabled
pub fn remote_login_enabled() -> Option<bool> {
    let output = Command::new("systemsetup")
        .args(["-getremotelogin"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.to_lowercase().contains("on"))
}

/// Get macOS version info
pub fn macos_version() -> Option<MacOsVersion> {
    let output = Command::new("sw_vers")
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut product_name = None;
    let mut product_version = None;
    let mut build_version = None;

    for line in stdout.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.trim() {
                "ProductName" => product_name = Some(value.to_string()),
                "ProductVersion" => product_version = Some(value.to_string()),
                "BuildVersion" => build_version = Some(value.to_string()),
                _ => {}
            }
        }
    }

    Some(MacOsVersion {
        product_name: product_name?,
        product_version: product_version?,
        build_version: build_version?,
    })
}

/// macOS version information
#[derive(Debug, Clone)]
pub struct MacOsVersion {
    pub product_name: String,
    pub product_version: String,
    pub build_version: String,
}

/// Common LaunchAgent/LaunchDaemon locations
pub fn launch_agent_paths() -> Vec<std::path::PathBuf> {
    let mut paths = vec![
        std::path::PathBuf::from("/Library/LaunchAgents"),
        std::path::PathBuf::from("/Library/LaunchDaemons"),
        std::path::PathBuf::from("/System/Library/LaunchAgents"),
        std::path::PathBuf::from("/System/Library/LaunchDaemons"),
    ];

    if let Some(home) = super::home_dir() {
        paths.push(home.join("Library/LaunchAgents"));
    }

    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "macos")]
    fn test_macos_version() {
        let version = macos_version();
        assert!(version.is_some());
        let version = version.unwrap();
        assert!(!version.product_version.is_empty());
    }
}
