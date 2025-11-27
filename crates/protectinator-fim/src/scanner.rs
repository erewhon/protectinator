//! File system scanner for FIM

use crate::hasher::{HashAlgorithm, Hasher};
use protectinator_core::Result;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// File metadata with hash
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: std::time::SystemTime,
    pub permissions: u32,
}

/// File scanner for creating baselines
pub struct FileScanner {
    hasher: Hasher,
    exclude_patterns: Vec<glob::Pattern>,
    follow_symlinks: bool,
    max_depth: Option<usize>,
}

impl FileScanner {
    /// Create a new file scanner
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            hasher: Hasher::new(algorithm),
            exclude_patterns: Vec::new(),
            follow_symlinks: false,
            max_depth: None,
        }
    }

    /// Add exclude patterns
    pub fn with_excludes(mut self, patterns: &[String]) -> Result<Self> {
        for pattern in patterns {
            let pat = glob::Pattern::new(pattern).map_err(|e| {
                protectinator_core::ProtectinatorError::Config(format!(
                    "Invalid glob pattern '{}': {}",
                    pattern, e
                ))
            })?;
            self.exclude_patterns.push(pat);
        }
        Ok(self)
    }

    /// Set whether to follow symbolic links
    pub fn follow_symlinks(mut self, follow: bool) -> Self {
        self.follow_symlinks = follow;
        self
    }

    /// Set maximum recursion depth
    pub fn max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Scan a directory and return file entries
    pub fn scan(&self, root: &Path) -> Result<Vec<FileEntry>> {
        let mut entries = Vec::new();

        let mut walker = WalkDir::new(root).follow_links(self.follow_symlinks);

        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker {
            let entry = entry.map_err(|e| {
                protectinator_core::ProtectinatorError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            let path = entry.path();

            // Skip directories
            if entry.file_type().is_dir() {
                continue;
            }

            // Check exclusions
            if self.is_excluded(path) {
                continue;
            }

            // Get metadata
            let metadata = entry.metadata().map_err(|e| {
                protectinator_core::ProtectinatorError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    e.to_string(),
                ))
            })?;

            // Hash the file
            let hash = self.hasher.hash_file(path)?;

            #[cfg(unix)]
            let permissions = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode()
            };

            #[cfg(not(unix))]
            let permissions = 0u32;

            entries.push(FileEntry {
                path: path.to_path_buf(),
                hash,
                size: metadata.len(),
                modified: metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH),
                permissions,
            });
        }

        Ok(entries)
    }

    /// Check if a path should be excluded
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.exclude_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
        }
        false
    }
}

impl Default for FileScanner {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}
