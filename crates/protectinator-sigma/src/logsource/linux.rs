//! Linux-specific log sources (syslog, auth.log, journald)

use crate::error::{SigmaError, SigmaResult};
use crate::event::{LogEvent, LogEventBuilder};
use crate::logsource::{LogSource, LogSourceConfig, LogSourceType};
use chrono::{DateTime, NaiveDateTime, Utc};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

/// Syslog log source
pub struct SyslogSource;

impl SyslogSource {
    pub fn new() -> Self {
        Self
    }

    fn get_syslog_path(&self) -> Option<&'static Path> {
        let paths = [
            Path::new("/var/log/syslog"),
            Path::new("/var/log/messages"),
        ];

        paths.into_iter().find(|p| p.exists())
    }
}

impl Default for SyslogSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSource for SyslogSource {
    fn source_type(&self) -> LogSourceType {
        LogSourceType::Syslog
    }

    fn is_available(&self) -> bool {
        self.get_syslog_path().is_some()
    }

    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let path = config.path.as_ref().map(|p| p.as_path()).or_else(|| self.get_syslog_path());

        let path = path.ok_or_else(|| {
            SigmaError::LogSourceUnavailable("Syslog file not found".to_string())
        })?;

        parse_syslog_file(path, config, "syslog")
    }

    fn description(&self) -> &str {
        "Linux syslog (/var/log/syslog or /var/log/messages)"
    }
}

/// Auth log source
pub struct AuthLogSource;

impl AuthLogSource {
    pub fn new() -> Self {
        Self
    }

    fn get_auth_log_path(&self) -> Option<&'static Path> {
        let paths = [
            Path::new("/var/log/auth.log"),
            Path::new("/var/log/secure"),
        ];

        paths.into_iter().find(|p| p.exists())
    }
}

impl Default for AuthLogSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSource for AuthLogSource {
    fn source_type(&self) -> LogSourceType {
        LogSourceType::AuthLog
    }

    fn is_available(&self) -> bool {
        self.get_auth_log_path().is_some()
    }

    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let path = config.path.as_ref().map(|p| p.as_path()).or_else(|| self.get_auth_log_path());

        let path = path.ok_or_else(|| {
            SigmaError::LogSourceUnavailable("Auth log file not found".to_string())
        })?;

        parse_syslog_file(path, config, "auth")
    }

    fn description(&self) -> &str {
        "Linux authentication log (/var/log/auth.log or /var/log/secure)"
    }
}

/// Parse a syslog-format file
fn parse_syslog_file(path: &Path, config: &LogSourceConfig, service: &str) -> SigmaResult<Vec<LogEvent>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();

    let mut reader = BufReader::new(file);

    // If the file is large, seek to near the end to get recent events
    let limit = config.limit.unwrap_or(1000);
    if file_size > 1_000_000 {
        // Estimate bytes to read based on average line length (~200 bytes)
        let bytes_to_read = (limit * 200) as u64;
        let seek_pos = file_size.saturating_sub(bytes_to_read);
        reader.seek(SeekFrom::Start(seek_pos))?;

        // Skip partial first line
        let mut discard = String::new();
        let _ = reader.read_line(&mut discard);
    }

    let mut events = Vec::new();
    let current_year = chrono::Utc::now().year();

    for line in reader.lines() {
        if events.len() >= limit {
            break;
        }

        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if let Some(event) = parse_syslog_line(&line, current_year, service, config) {
            // Apply process filter if specified
            if let Some(filter) = &config.process_filter {
                if let Some(proc) = event.get_string("process") {
                    if !proc.to_lowercase().contains(&filter.to_lowercase()) {
                        continue;
                    }
                }
            }

            // Apply time filters
            if let Some(since) = &config.since {
                if event.timestamp < *since {
                    continue;
                }
            }
            if let Some(until) = &config.until {
                if event.timestamp > *until {
                    continue;
                }
            }

            events.push(event);
        }
    }

    Ok(events)
}

/// Parse a single syslog line
/// Format: "Mon DD HH:MM:SS hostname process[pid]: message"
fn parse_syslog_line(line: &str, current_year: i32, service: &str, config: &LogSourceConfig) -> Option<LogEvent> {
    // Minimum valid line length
    if line.len() < 16 {
        return None;
    }

    // Parse timestamp (first 15 characters: "Mon DD HH:MM:SS")
    let timestamp_str = &line[..15];
    let timestamp = parse_syslog_timestamp(timestamp_str, current_year)?;

    // Find hostname and rest
    let rest = &line[16..];
    let mut parts = rest.splitn(2, ' ');
    let hostname = parts.next()?;
    let rest = parts.next()?;

    // Parse process and message
    let (process, pid, message) = if let Some(bracket_pos) = rest.find('[') {
        if let Some(colon_pos) = rest.find("]: ") {
            let process = &rest[..bracket_pos];
            let pid_str = &rest[bracket_pos + 1..colon_pos];
            let pid: Option<u32> = pid_str.parse().ok();
            let message = &rest[colon_pos + 3..];
            (process, pid, message)
        } else {
            parse_simple_process_message(rest)?
        }
    } else {
        parse_simple_process_message(rest)?
    };

    let mut builder = LogEventBuilder::new()
        .timestamp(timestamp)
        .source("syslog")
        .service(service)
        .product("linux")
        .field("hostname", hostname)
        .field("process", process)
        .field("message", message)
        .field("raw", line);

    if let Some(pid) = pid {
        builder = builder.field_i64("pid", pid as i64);
    }

    if let Some(cat) = &config.category {
        builder = builder.category(cat);
    }

    Some(builder.build())
}

/// Parse simple "process: message" format
fn parse_simple_process_message(s: &str) -> Option<(&str, Option<u32>, &str)> {
    let colon_pos = s.find(": ")?;
    let process = &s[..colon_pos];
    let message = &s[colon_pos + 2..];
    Some((process, None, message))
}

/// Parse syslog timestamp format "Mon DD HH:MM:SS"
fn parse_syslog_timestamp(s: &str, current_year: i32) -> Option<DateTime<Utc>> {
    // Add the year to the timestamp string
    let with_year = format!("{} {}", current_year, s);

    NaiveDateTime::parse_from_str(&with_year, "%Y %b %d %H:%M:%S")
        .ok()
        .map(|dt| DateTime::from_naive_utc_and_offset(dt, Utc))
}

/// Journald log source (uses journalctl command)
pub struct JournaldSource;

impl JournaldSource {
    pub fn new() -> Self {
        Self
    }
}

impl Default for JournaldSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSource for JournaldSource {
    fn source_type(&self) -> LogSourceType {
        LogSourceType::Journald
    }

    fn is_available(&self) -> bool {
        Path::new("/run/systemd/journal").exists()
            || Command::new("journalctl")
                .arg("--version")
                .output()
                .is_ok()
    }

    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let limit = config.limit.unwrap_or(1000);

        let mut cmd = Command::new("journalctl");
        cmd.arg("--output=json")
            .arg("--no-pager")
            .arg(format!("--lines={}", limit));

        // Add time filters
        if let Some(since) = &config.since {
            cmd.arg(format!("--since={}", since.format("%Y-%m-%d %H:%M:%S")));
        }
        if let Some(until) = &config.until {
            cmd.arg(format!("--until={}", until.format("%Y-%m-%d %H:%M:%S")));
        }

        // Add unit/process filter
        if let Some(filter) = &config.process_filter {
            cmd.arg(format!("--unit={}", filter));
        }

        let output = cmd.output().map_err(|e| {
            SigmaError::LogSourceUnavailable(format!("Failed to run journalctl: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SigmaError::LogSourceUnavailable(format!(
                "journalctl failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut events = Vec::new();

        for line in stdout.lines() {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<serde_json::Value>(line) {
                Ok(value) => {
                    let mut event = LogEvent::new(value)
                        .with_source("journald")
                        .with_product("linux")
                        .with_service("journald");

                    if let Some(cat) = &config.category {
                        event = event.with_category(cat);
                    }

                    events.push(event);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse journald JSON: {}", e);
                }
            }
        }

        Ok(events)
    }

    fn description(&self) -> &str {
        "Linux systemd journal (journalctl)"
    }
}

/// Read syslog events (convenience function)
pub fn read_syslog(limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let source = SyslogSource::new();
    let config = LogSourceConfig::new(LogSourceType::Syslog).with_limit(limit);
    source.read_events(&config)
}

/// Read auth log events (convenience function)
pub fn read_auth_log(limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let source = AuthLogSource::new();
    let config = LogSourceConfig::new(LogSourceType::AuthLog).with_limit(limit);
    source.read_events(&config)
}

/// Read journald events (convenience function)
pub fn read_journald(limit: usize) -> SigmaResult<Vec<LogEvent>> {
    let source = JournaldSource::new();
    let config = LogSourceConfig::new(LogSourceType::Journald).with_limit(limit);
    source.read_events(&config)
}

use chrono::Datelike;
