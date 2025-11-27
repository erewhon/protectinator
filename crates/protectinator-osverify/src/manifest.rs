//! File manifest structures for OS verification

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::{OsVerifyError, Result};

/// Hash algorithm used for verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Blake3,
    Md5,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            HashAlgorithm::Sha256 => "sha256",
            HashAlgorithm::Blake3 => "blake3",
            HashAlgorithm::Md5 => "md5",
        }
    }
}

/// File entry in a manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    /// File path (absolute or relative to root)
    pub path: String,

    /// Expected hash value
    pub hash: String,

    /// Hash algorithm used
    #[serde(default)]
    pub algorithm: HashAlgorithm,

    /// Expected file size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,

    /// Expected file mode (Unix permissions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

    /// Package this file belongs to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,

    /// Configuration file (may be modified by user)
    #[serde(default)]
    pub config: bool,
}

impl FileEntry {
    pub fn new(path: impl Into<String>, hash: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            hash: hash.into(),
            algorithm: HashAlgorithm::default(),
            size: None,
            mode: None,
            package: None,
            config: false,
        }
    }

    pub fn with_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    pub fn with_package(mut self, package: impl Into<String>) -> Self {
        self.package = Some(package.into());
        self
    }

    pub fn as_config(mut self) -> Self {
        self.config = true;
        self
    }
}

/// A manifest containing file hashes for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Manifest version
    #[serde(default = "default_version")]
    pub version: String,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// OS/distribution this manifest is for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// OS version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// Creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,

    /// File entries indexed by path
    #[serde(default)]
    pub files: HashMap<String, FileEntry>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl Default for Manifest {
    fn default() -> Self {
        Self {
            version: default_version(),
            description: None,
            os: None,
            os_version: None,
            created: None,
            files: HashMap::new(),
        }
    }
}

impl Manifest {
    /// Create a new empty manifest
    pub fn new() -> Self {
        Self::default()
    }

    /// Load manifest from a JSON file
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())?;
        Self::from_json(&content)
    }

    /// Parse manifest from JSON string
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| OsVerifyError::ManifestParseError(e.to_string()))
    }

    /// Add a file entry
    pub fn add_file(&mut self, entry: FileEntry) {
        self.files.insert(entry.path.clone(), entry);
    }

    /// Get a file entry by path
    pub fn get_file(&self, path: &str) -> Option<&FileEntry> {
        self.files.get(path)
    }

    /// Number of files in manifest
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Check if manifest is empty
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Merge another manifest into this one
    pub fn merge(&mut self, other: Manifest) {
        self.files.extend(other.files);
    }

    /// Export to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| OsVerifyError::ManifestParseError(e.to_string()))
    }
}

/// Result of parsing package manager output
#[derive(Debug, Clone)]
pub struct PackageFile {
    pub path: String,
    pub package: String,
    pub hash: Option<String>,
    pub algorithm: HashAlgorithm,
    pub config: bool,
}

impl PackageFile {
    pub fn new(path: impl Into<String>, package: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            package: package.into(),
            hash: None,
            algorithm: HashAlgorithm::Sha256,
            config: false,
        }
    }

    pub fn with_hash(mut self, hash: impl Into<String>, algorithm: HashAlgorithm) -> Self {
        self.hash = Some(hash.into());
        self.algorithm = algorithm;
        self
    }

    pub fn as_config(mut self) -> Self {
        self.config = true;
        self
    }

    /// Convert to FileEntry
    pub fn into_entry(self) -> Option<FileEntry> {
        self.hash.map(|hash| {
            FileEntry {
                path: self.path,
                hash,
                algorithm: self.algorithm,
                size: None,
                mode: None,
                package: Some(self.package),
                config: self.config,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_json() {
        let mut manifest = Manifest::new();
        manifest.add_file(
            FileEntry::new("/usr/bin/ls", "abc123")
                .with_package("coreutils")
                .with_algorithm(HashAlgorithm::Sha256),
        );

        let json = manifest.to_json().unwrap();
        let parsed = Manifest::from_json(&json).unwrap();
        assert_eq!(parsed.files.len(), 1);
        assert!(parsed.files.contains_key("/usr/bin/ls"));
    }
}
