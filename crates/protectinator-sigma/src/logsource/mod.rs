//! Log source adapters for reading events from various sources

pub mod file;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use crate::event::LogEvent;
use crate::error::SigmaResult;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Types of log sources
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogSourceType {
    /// JSON file or directory of JSON files
    JsonFile,
    /// JSON Lines format (one JSON object per line)
    JsonLines,
    /// Syslog file (Linux/Unix)
    Syslog,
    /// Auth log (Linux)
    AuthLog,
    /// Journald (Linux systemd)
    Journald,
    /// macOS Unified Log
    UnifiedLog,
    /// Windows Event Log
    WindowsEventLog,
    /// Generic text log with custom parsing
    TextLog,
}

impl std::fmt::Display for LogSourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSourceType::JsonFile => write!(f, "json_file"),
            LogSourceType::JsonLines => write!(f, "json_lines"),
            LogSourceType::Syslog => write!(f, "syslog"),
            LogSourceType::AuthLog => write!(f, "auth_log"),
            LogSourceType::Journald => write!(f, "journald"),
            LogSourceType::UnifiedLog => write!(f, "unified_log"),
            LogSourceType::WindowsEventLog => write!(f, "windows_event_log"),
            LogSourceType::TextLog => write!(f, "text_log"),
        }
    }
}

/// Configuration for a log source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSourceConfig {
    /// Type of log source
    pub source_type: LogSourceType,

    /// Path to log file or directory (for file-based sources)
    pub path: Option<PathBuf>,

    /// Maximum number of events to read
    pub limit: Option<usize>,

    /// Time range filter (events after this time)
    pub since: Option<chrono::DateTime<chrono::Utc>>,

    /// Time range filter (events before this time)
    pub until: Option<chrono::DateTime<chrono::Utc>>,

    /// Filter by process/service name
    pub process_filter: Option<String>,

    /// Sigma logsource category to assign to events
    pub category: Option<String>,

    /// Sigma logsource product to assign to events
    pub product: Option<String>,

    /// Sigma logsource service to assign to events
    pub service: Option<String>,
}

impl LogSourceConfig {
    /// Create a new log source configuration
    pub fn new(source_type: LogSourceType) -> Self {
        Self {
            source_type,
            path: None,
            limit: None,
            since: None,
            until: None,
            process_filter: None,
            category: None,
            product: None,
            service: None,
        }
    }

    /// Set the path
    pub fn with_path(mut self, path: PathBuf) -> Self {
        self.path = Some(path);
        self
    }

    /// Set the limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set the since filter
    pub fn since(mut self, since: chrono::DateTime<chrono::Utc>) -> Self {
        self.since = Some(since);
        self
    }

    /// Set the until filter
    pub fn until(mut self, until: chrono::DateTime<chrono::Utc>) -> Self {
        self.until = Some(until);
        self
    }

    /// Set a process filter
    pub fn with_process_filter(mut self, filter: impl Into<String>) -> Self {
        self.process_filter = Some(filter.into());
        self
    }

    /// Set the category
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set the product
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Set the service
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }
}

/// Trait for log sources that can provide events
pub trait LogSource: Send + Sync {
    /// Get the log source type
    fn source_type(&self) -> LogSourceType;

    /// Check if this log source is available
    fn is_available(&self) -> bool;

    /// Read events from the log source
    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>>;

    /// Get a human-readable description
    fn description(&self) -> &str;
}

/// Create a log source from configuration
pub fn create_log_source(config: &LogSourceConfig) -> Box<dyn LogSource> {
    match config.source_type {
        LogSourceType::JsonFile | LogSourceType::JsonLines => {
            Box::new(file::JsonFileSource::new())
        }
        #[cfg(target_os = "linux")]
        LogSourceType::Syslog => Box::new(linux::SyslogSource::new()),
        #[cfg(target_os = "linux")]
        LogSourceType::AuthLog => Box::new(linux::AuthLogSource::new()),
        #[cfg(target_os = "linux")]
        LogSourceType::Journald => Box::new(linux::JournaldSource::new()),
        #[cfg(target_os = "macos")]
        LogSourceType::UnifiedLog => Box::new(macos::UnifiedLogSource::new()),
        _ => Box::new(file::JsonFileSource::new()),
    }
}

/// Detect available log sources on the current system
pub fn detect_available_sources() -> Vec<LogSourceType> {
    let mut sources = Vec::new();

    // JSON files are always available
    sources.push(LogSourceType::JsonFile);
    sources.push(LogSourceType::JsonLines);

    #[cfg(target_os = "linux")]
    {
        if std::path::Path::new("/var/log/syslog").exists()
            || std::path::Path::new("/var/log/messages").exists()
        {
            sources.push(LogSourceType::Syslog);
        }

        if std::path::Path::new("/var/log/auth.log").exists()
            || std::path::Path::new("/var/log/secure").exists()
        {
            sources.push(LogSourceType::AuthLog);
        }

        // Check for journald
        if std::path::Path::new("/run/systemd/journal").exists() {
            sources.push(LogSourceType::Journald);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Unified log is always available on macOS
        sources.push(LogSourceType::UnifiedLog);
    }

    sources
}
