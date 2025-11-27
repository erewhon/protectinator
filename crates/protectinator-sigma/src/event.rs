//! Log event representation

use crate::error::{SigmaError, SigmaResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// A log event that can be matched against Sigma rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    /// Event timestamp
    #[serde(default = "Utc::now")]
    pub timestamp: DateTime<Utc>,

    /// Source of the event (e.g., "syslog", "journald", "windows-security")
    #[serde(default)]
    pub source: Option<String>,

    /// Event category (maps to Sigma logsource.category)
    #[serde(default)]
    pub category: Option<String>,

    /// Event product (maps to Sigma logsource.product)
    #[serde(default)]
    pub product: Option<String>,

    /// Event service (maps to Sigma logsource.service)
    #[serde(default)]
    pub service: Option<String>,

    /// Raw event data as JSON value
    pub data: Value,

    /// Flattened field map for efficient lookup
    #[serde(skip)]
    field_cache: Option<HashMap<String, Value>>,
}

impl LogEvent {
    /// Create a new log event from JSON data
    pub fn new(data: Value) -> Self {
        Self {
            timestamp: Utc::now(),
            source: None,
            category: None,
            product: None,
            service: None,
            data,
            field_cache: None,
        }
    }

    /// Parse a log event from JSON string
    pub fn from_json(json: &str) -> SigmaResult<Self> {
        let data: Value = serde_json::from_str(json)?;
        Ok(Self::new(data))
    }

    /// Parse multiple log events from JSON array
    pub fn from_json_array(json: &str) -> SigmaResult<Vec<Self>> {
        let data: Value = serde_json::from_str(json)?;
        match data {
            Value::Array(arr) => arr.into_iter().map(|v| Ok(Self::new(v))).collect(),
            _ => Err(SigmaError::EventParseError(
                "Expected JSON array".to_string(),
            )),
        }
    }

    /// Set the event source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Set the event category
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set the event product
    pub fn with_product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Set the event service
    pub fn with_service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the timestamp
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Get a field value by path (supports dot notation for nested fields)
    pub fn get_field(&self, path: &str) -> Option<&Value> {
        get_nested_value(&self.data, path)
    }

    /// Get a field as string
    pub fn get_string(&self, path: &str) -> Option<String> {
        self.get_field(path).and_then(|v| match v {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(b.to_string()),
            _ => None,
        })
    }

    /// Get a field as i64
    pub fn get_i64(&self, path: &str) -> Option<i64> {
        self.get_field(path).and_then(|v| v.as_i64())
    }

    /// Get a field as u64
    pub fn get_u64(&self, path: &str) -> Option<u64> {
        self.get_field(path).and_then(|v| v.as_u64())
    }

    /// Get a field as bool
    pub fn get_bool(&self, path: &str) -> Option<bool> {
        self.get_field(path).and_then(|v| v.as_bool())
    }

    /// Convert to sigma_rust::Event for rule evaluation
    pub fn to_sigma_event(&self) -> sigma_rust::Event {
        sigma_rust::event_from_json(&self.data.to_string())
            .unwrap_or_else(|_| sigma_rust::event_from_json("{}").unwrap())
    }

    /// Get the raw JSON string
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.data).unwrap_or_default()
    }

    /// Check if the event has a specific field
    pub fn has_field(&self, path: &str) -> bool {
        self.get_field(path).is_some()
    }
}

/// Get a nested value from a JSON Value using dot notation
fn get_nested_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;

    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            Value::Array(arr) => {
                let index: usize = part.parse().ok()?;
                current = arr.get(index)?;
            }
            _ => return None,
        }
    }

    Some(current)
}

/// Builder for creating log events
pub struct LogEventBuilder {
    data: HashMap<String, Value>,
    source: Option<String>,
    category: Option<String>,
    product: Option<String>,
    service: Option<String>,
    timestamp: DateTime<Utc>,
}

impl LogEventBuilder {
    /// Create a new event builder
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            source: None,
            category: None,
            product: None,
            service: None,
            timestamp: Utc::now(),
        }
    }

    /// Add a string field
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.data.insert(key.into(), Value::String(value.into()));
        self
    }

    /// Add an integer field
    pub fn field_i64(mut self, key: impl Into<String>, value: i64) -> Self {
        self.data
            .insert(key.into(), Value::Number(value.into()));
        self
    }

    /// Add a boolean field
    pub fn field_bool(mut self, key: impl Into<String>, value: bool) -> Self {
        self.data.insert(key.into(), Value::Bool(value));
        self
    }

    /// Add a JSON value field
    pub fn field_value(mut self, key: impl Into<String>, value: Value) -> Self {
        self.data.insert(key.into(), value);
        self
    }

    /// Set source
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Set category
    pub fn category(mut self, category: impl Into<String>) -> Self {
        self.category = Some(category.into());
        self
    }

    /// Set product
    pub fn product(mut self, product: impl Into<String>) -> Self {
        self.product = Some(product.into());
        self
    }

    /// Set service
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set timestamp
    pub fn timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Build the log event
    pub fn build(self) -> LogEvent {
        let data = Value::Object(self.data.into_iter().collect());
        LogEvent {
            timestamp: self.timestamp,
            source: self.source,
            category: self.category,
            product: self.product,
            service: self.service,
            data,
            field_cache: None,
        }
    }
}

impl Default for LogEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_from_json() {
        let event = LogEvent::from_json(r#"{"EventID": 4625, "LogonType": 3}"#).unwrap();
        assert_eq!(event.get_i64("EventID"), Some(4625));
        assert_eq!(event.get_i64("LogonType"), Some(3));
    }

    #[test]
    fn test_nested_field_access() {
        let event =
            LogEvent::from_json(r#"{"Event": {"System": {"EventID": 1234}}}"#).unwrap();
        assert_eq!(event.get_i64("Event.System.EventID"), Some(1234));
    }

    #[test]
    fn test_event_builder() {
        let event = LogEventBuilder::new()
            .field("CommandLine", "powershell.exe -enc")
            .field_i64("ProcessId", 1234)
            .field_bool("Elevated", true)
            .source("sysmon")
            .category("process_creation")
            .build();

        assert_eq!(event.get_string("CommandLine"), Some("powershell.exe -enc".to_string()));
        assert_eq!(event.get_i64("ProcessId"), Some(1234));
        assert_eq!(event.get_bool("Elevated"), Some(true));
        assert_eq!(event.source, Some("sysmon".to_string()));
        assert_eq!(event.category, Some("process_creation".to_string()));
    }
}
