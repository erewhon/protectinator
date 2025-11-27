//! Error types for the Sigma engine

use thiserror::Error;

/// Result type for Sigma operations
pub type SigmaResult<T> = std::result::Result<T, SigmaError>;

/// Errors that can occur during Sigma rule processing
#[derive(Debug, Error)]
pub enum SigmaError {
    /// Failed to parse a Sigma rule
    #[error("Failed to parse rule: {0}")]
    ParseError(String),

    /// Failed to parse YAML
    #[error("YAML parse error: {0}")]
    YamlError(#[from] serde_yaml::Error),

    /// Failed to parse JSON
    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Rule validation failed
    #[error("Rule validation failed: {0}")]
    ValidationError(String),

    /// Invalid log source
    #[error("Invalid log source: {0}")]
    InvalidLogSource(String),

    /// Log source not available
    #[error("Log source not available: {0}")]
    LogSourceUnavailable(String),

    /// Event parsing error
    #[error("Failed to parse event: {0}")]
    EventParseError(String),

    /// Rule file not found
    #[error("Rule file not found: {0}")]
    RuleNotFound(String),

    /// Condition evaluation error
    #[error("Condition evaluation error: {0}")]
    ConditionError(String),

    /// Unsupported feature
    #[error("Unsupported feature: {0}")]
    Unsupported(String),
}

impl From<walkdir::Error> for SigmaError {
    fn from(e: walkdir::Error) -> Self {
        SigmaError::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            e.to_string(),
        ))
    }
}
