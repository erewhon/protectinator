//! OS and platform detection utilities

use protectinator_core::{OsInfo, OsType};

/// Detect the current operating system
pub fn detect_os() -> OsInfo {
    let os_type = detect_os_type();
    let version = detect_os_version();
    let arch = std::env::consts::ARCH.to_string();
    let distribution = detect_distribution();

    OsInfo {
        os_type,
        version,
        arch,
        distribution,
    }
}

/// Detect the OS type
fn detect_os_type() -> OsType {
    match std::env::consts::OS {
        "linux" => OsType::Linux,
        "macos" => OsType::MacOS,
        "windows" => OsType::Windows,
        _ => OsType::Unknown,
    }
}

/// Detect OS version
fn detect_os_version() -> String {
    sysinfo::System::os_version().unwrap_or_else(|| "unknown".to_string())
}

/// Detect Linux distribution (if applicable)
fn detect_distribution() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // Try to read /etc/os-release
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if line.starts_with("PRETTY_NAME=") {
                    return Some(
                        line.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string(),
                    );
                }
            }
            for line in content.lines() {
                if line.starts_with("NAME=") {
                    return Some(
                        line.trim_start_matches("NAME=")
                            .trim_matches('"')
                            .to_string(),
                    );
                }
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Check if running with elevated privileges
pub fn is_elevated() -> bool {
    #[cfg(unix)]
    {
        // On Unix, check if running as root (uid 0)
        nix::unistd::geteuid().is_root()
    }

    #[cfg(windows)]
    {
        // On Windows, would check for admin privileges
        // For now, return false as Windows is not yet implemented
        false
    }

    #[cfg(not(any(unix, windows)))]
    {
        false
    }
}

/// Check if a specific command is available on the system
pub fn command_available(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Get the current user's home directory
pub fn home_dir() -> Option<std::path::PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME").ok().map(std::path::PathBuf::from)
    }

    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").ok().map(std::path::PathBuf::from)
    }

    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

/// Get the current username
pub fn current_user() -> Option<String> {
    #[cfg(unix)]
    {
        std::env::var("USER").ok()
    }

    #[cfg(windows)]
    {
        std::env::var("USERNAME").ok()
    }

    #[cfg(not(any(unix, windows)))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os() {
        let os = detect_os();
        assert!(!os.version.is_empty());
        assert!(!os.arch.is_empty());
    }

    #[test]
    fn test_os_type_display() {
        assert_eq!(OsType::Linux.to_string(), "Linux");
        assert_eq!(OsType::MacOS.to_string(), "macOS");
        assert_eq!(OsType::Windows.to_string(), "Windows");
    }
}
