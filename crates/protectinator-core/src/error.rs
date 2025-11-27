//! Error types for Protectinator

use thiserror::Error;

/// Main error type for Protectinator operations
#[derive(Error, Debug)]
pub enum ProtectinatorError {
    /// I/O error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Parse error with context
    #[error("Parse error in {context}: {message}")]
    Parse { context: String, message: String },

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Platform not supported for this operation
    #[error("Platform not supported: {0}")]
    UnsupportedPlatform(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Network error
    #[error("Network error: {0}")]
    Network(String),

    /// Hash mismatch during verification
    #[error("Hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    /// Sigma rule error
    #[error("Sigma rule error: {0}")]
    SigmaRule(String),

    /// Database error
    #[error("Database error: {0}")]
    Database(String),

    /// Timeout error
    #[error("Timeout after {0:?}")]
    Timeout(std::time::Duration),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Generic error with message
    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for ProtectinatorError {
    fn from(err: serde_json::Error) -> Self {
        ProtectinatorError::Serialization(err.to_string())
    }
}

/// Result type alias for Protectinator operations
pub type Result<T> = std::result::Result<T, ProtectinatorError>;
