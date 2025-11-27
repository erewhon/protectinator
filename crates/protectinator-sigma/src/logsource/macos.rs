//! macOS-specific log sources (Unified Log)

use crate::error::{SigmaError, SigmaResult};
use crate::event::LogEvent;
use crate::logsource::{LogSource, LogSourceConfig, LogSourceType};
use std::process::Command;

/// macOS Unified Log source (uses `log` command)
pub struct UnifiedLogSource;

impl UnifiedLogSource {
    pub fn new() -> Self {
        Self
    }
}

impl Default for UnifiedLogSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSource for UnifiedLogSource {
    fn source_type(&self) -> LogSourceType {
        LogSourceType::UnifiedLog
    }

    fn is_available(&self) -> bool {
        Command::new("log")
            .arg("--help")
            .output()
            .is_ok()
    }

    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let limit = config.limit.unwrap_or(1000);

        let mut cmd = Command::new("log");
        cmd.arg("show")
            .arg("--style")
            .arg("json")
            .arg("--last")
            .arg("1h"); // Default to last hour

        // Add predicate filters
        let mut predicates = Vec::new();

        if let Some(filter) = &config.process_filter {
            predicates.push(format!("process == \"{}\"", filter));
        }

        if let Some(since) = &config.since {
            cmd.arg("--start")
                .arg(since.format("%Y-%m-%d %H:%M:%S").to_string());
        }

        if let Some(until) = &config.until {
            cmd.arg("--end")
                .arg(until.format("%Y-%m-%d %H:%M:%S").to_string());
        }

        if !predicates.is_empty() {
            cmd.arg("--predicate").arg(predicates.join(" AND "));
        }

        let output = cmd.output().map_err(|e| {
            SigmaError::LogSourceUnavailable(format!("Failed to run log command: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // The log command sometimes returns non-zero even with valid output
            if output.stdout.is_empty() {
                return Err(SigmaError::LogSourceUnavailable(format!(
                    "log command failed: {}",
                    stderr
                )));
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse the JSON array output
        let events = parse_unified_log_output(&stdout, config, limit)?;

        Ok(events)
    }

    fn description(&self) -> &str {
        "macOS Unified Log (log show command)"
    }
}

/// Parse the output from `log show --style json`
fn parse_unified_log_output(
    output: &str,
    config: &LogSourceConfig,
    limit: usize,
) -> SigmaResult<Vec<LogEvent>> {
    let mut events = Vec::new();

    // The output is a JSON array
    let value: serde_json::Value = serde_json::from_str(output).map_err(|e| {
        SigmaError::EventParseError(format!("Failed to parse unified log JSON: {}", e))
    })?;

    if let serde_json::Value::Array(arr) = value {
        for item in arr.into_iter().take(limit) {
            let mut event = LogEvent::new(item)
                .with_source("unified_log")
                .with_product("macos");

            if let Some(cat) = &config.category {
                event = event.with_category(cat);
            }
            if let Some(svc) = &config.service {
                event = event.with_service(svc);
            }

            events.push(event);
        }
    }

    Ok(events)
}

/// Read unified log events (convenience function)
pub fn read_unified_log(limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let source = UnifiedLogSource::new();
    let config = LogSourceConfig::new(LogSourceType::UnifiedLog).with_limit(limit);
    source.read_events(&config)
}

/// Read unified log events with a process filter
pub fn read_unified_log_for_process(process: &str, limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let source = UnifiedLogSource::new();
    let config = LogSourceConfig::new(LogSourceType::UnifiedLog)
        .with_limit(limit)
        .with_process_filter(process);
    source.read_events(&config)
}

/// Query specific subsystem logs
pub fn read_subsystem_log(subsystem: &str, limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let mut cmd = Command::new("log");
    cmd.arg("show")
        .arg("--style")
        .arg("json")
        .arg("--last")
        .arg("1h")
        .arg("--predicate")
        .arg(format!("subsystem == \"{}\"", subsystem));

    let output = cmd.output().map_err(|e| {
        SigmaError::LogSourceUnavailable(format!("Failed to run log command: {}", e))
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let config = LogSourceConfig::new(LogSourceType::UnifiedLog);
    parse_unified_log_output(&stdout, &config, limit)
}

/// Common macOS security-relevant subsystems
pub mod subsystems {
    /// Security subsystem
    pub const SECURITY: &str = "com.apple.securityd";
    /// Authorization subsystem
    pub const AUTHORIZATION: &str = "com.apple.Authorization";
    /// Keychain subsystem
    pub const KEYCHAIN: &str = "com.apple.securityd.keychain";
    /// Firewall subsystem
    pub const FIREWALL: &str = "com.apple.alf";
    /// XProtect (malware protection)
    pub const XPROTECT: &str = "com.apple.XProtect";
    /// Gatekeeper
    pub const GATEKEEPER: &str = "com.apple.syspolicy";
    /// System Policy Security
    pub const SYSPOLICY: &str = "com.apple.syspolicy.exec";
    /// SSH
    pub const SSH: &str = "com.openssh.sshd";
    /// Sudo
    pub const SUDO: &str = "com.apple.sudo";
    /// Login
    pub const LOGIN: &str = "com.apple.loginwindow";
}
