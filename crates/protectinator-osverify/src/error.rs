//! Error types for OS verification

use thiserror::Error;

/// OS verification error types
#[derive(Error, Debug)]
pub enum OsVerifyError {
    #[error("Package manager not found: {0}")]
    PackageManagerNotFound(String),

    #[error("Package manager error: {0}")]
    PackageManagerError(String),

    #[error("Manifest parse error: {0}")]
    ManifestParseError(String),

    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Verification failed: {count} files modified")]
    VerificationFailed { count: usize },
}

pub type Result<T> = std::result::Result<T, OsVerifyError>;
