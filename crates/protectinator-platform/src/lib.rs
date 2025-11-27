//! Platform abstraction layer for Protectinator
//!
//! Provides OS detection, capability checking, and platform-specific utilities.

mod detection;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;

pub use detection::*;

use protectinator_core::{
    Capabilities, CheckConfig, CheckContext, OsInfo, OsType,
};

/// Default implementation of CheckContext
pub struct DefaultCheckContext {
    os_info: OsInfo,
    capabilities: Capabilities,
    is_elevated: bool,
    config: CheckConfig,
}

impl DefaultCheckContext {
    /// Create a new check context with auto-detected system information
    pub fn new(config: CheckConfig) -> Self {
        let os_info = detect_os();
        let is_elevated = is_elevated();
        let capabilities = detect_capabilities(is_elevated);

        Self {
            os_info,
            capabilities,
            is_elevated,
            config,
        }
    }

    /// Create a new check context with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CheckConfig::default())
    }
}

impl CheckContext for DefaultCheckContext {
    fn os(&self) -> &OsInfo {
        &self.os_info
    }

    fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    fn is_elevated(&self) -> bool {
        self.is_elevated
    }

    fn config(&self) -> &CheckConfig {
        &self.config
    }
}

/// Detect system capabilities based on privileges and OS
fn detect_capabilities(is_elevated: bool) -> Capabilities {
    Capabilities {
        can_read_logs: is_elevated || cfg!(target_os = "macos"),
        can_access_network: true,
        can_read_all_files: is_elevated,
        can_access_processes: true,
    }
}

/// Get system information for scan results
pub fn get_system_info() -> protectinator_core::SystemInfo {
    let os_info = detect_os();

    protectinator_core::SystemInfo {
        os_name: os_info.os_type.to_string(),
        os_version: os_info.version.clone(),
        hostname: hostname(),
        architecture: os_info.arch.clone(),
        is_elevated: is_elevated(),
        kernel_version: kernel_version(),
    }
}

/// Get the hostname
fn hostname() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "unknown".to_string())
}

/// Get kernel version if available
fn kernel_version() -> Option<String> {
    sysinfo::System::kernel_version()
}
