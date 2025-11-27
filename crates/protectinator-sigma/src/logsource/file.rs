//! File-based log sources (JSON, JSON Lines)

use crate::error::{SigmaError, SigmaResult};
use crate::event::LogEvent;
use crate::logsource::{LogSource, LogSourceConfig, LogSourceType};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::WalkDir;

/// JSON file log source
pub struct JsonFileSource;

impl JsonFileSource {
    pub fn new() -> Self {
        Self
    }

    /// Read events from a JSON file
    fn read_json_file(&self, path: &Path, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let content = std::fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&content)?;

        let mut events = match value {
            serde_json::Value::Array(arr) => arr
                .into_iter()
                .map(|v| {
                    let mut event = LogEvent::new(v);
                    if let Some(cat) = &config.category {
                        event = event.with_category(cat);
                    }
                    if let Some(prod) = &config.product {
                        event = event.with_product(prod);
                    }
                    if let Some(svc) = &config.service {
                        event = event.with_service(svc);
                    }
                    event = event.with_source(path.display().to_string());
                    event
                })
                .collect(),
            serde_json::Value::Object(_) => {
                let mut event = LogEvent::new(value);
                if let Some(cat) = &config.category {
                    event = event.with_category(cat);
                }
                if let Some(prod) = &config.product {
                    event = event.with_product(prod);
                }
                if let Some(svc) = &config.service {
                    event = event.with_service(svc);
                }
                event = event.with_source(path.display().to_string());
                vec![event]
            }
            _ => return Err(SigmaError::EventParseError("Expected JSON object or array".to_string())),
        };

        // Apply limit
        if let Some(limit) = config.limit {
            events.truncate(limit);
        }

        Ok(events)
    }

    /// Read events from a JSON Lines file
    fn read_jsonl_file(&self, path: &Path, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();
        let limit = config.limit.unwrap_or(usize::MAX);

        for line in reader.lines() {
            if events.len() >= limit {
                break;
            }

            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<serde_json::Value>(&line) {
                Ok(value) => {
                    let mut event = LogEvent::new(value);
                    if let Some(cat) = &config.category {
                        event = event.with_category(cat);
                    }
                    if let Some(prod) = &config.product {
                        event = event.with_product(prod);
                    }
                    if let Some(svc) = &config.service {
                        event = event.with_service(svc);
                    }
                    event = event.with_source(path.display().to_string());
                    events.push(event);
                }
                Err(e) => {
                    tracing::warn!("Failed to parse JSON line: {}", e);
                }
            }
        }

        Ok(events)
    }
}

impl Default for JsonFileSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LogSource for JsonFileSource {
    fn source_type(&self) -> LogSourceType {
        LogSourceType::JsonFile
    }

    fn is_available(&self) -> bool {
        true
    }

    fn read_events(&self, config: &LogSourceConfig) -> SigmaResult<Vec<LogEvent>> {
        let path = config.path.as_ref().ok_or_else(|| {
            SigmaError::InvalidLogSource("No path specified for JSON file source".to_string())
        })?;

        if !path.exists() {
            return Err(SigmaError::IoError(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Path not found: {}", path.display()),
            )));
        }

        let mut all_events = Vec::new();
        let limit = config.limit.unwrap_or(usize::MAX);

        if path.is_file() {
            let events = if config.source_type == LogSourceType::JsonLines {
                self.read_jsonl_file(path, config)?
            } else {
                self.read_json_file(path, config)?
            };
            all_events.extend(events);
        } else if path.is_dir() {
            for entry in WalkDir::new(path)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
            {
                if all_events.len() >= limit {
                    break;
                }

                let entry_path = entry.path();
                if entry_path.is_file() {
                    let ext = entry_path.extension().and_then(|e| e.to_str());
                    let is_json = ext == Some("json");
                    let is_jsonl = ext == Some("jsonl") || ext == Some("ndjson");

                    if is_json {
                        if let Ok(events) = self.read_json_file(entry_path, config) {
                            all_events.extend(events);
                        }
                    } else if is_jsonl || config.source_type == LogSourceType::JsonLines {
                        if let Ok(events) = self.read_jsonl_file(entry_path, config) {
                            all_events.extend(events);
                        }
                    }
                }
            }
        }

        // Apply final limit
        if all_events.len() > limit {
            all_events.truncate(limit);
        }

        Ok(all_events)
    }

    fn description(&self) -> &str {
        "JSON or JSON Lines file source"
    }
}
