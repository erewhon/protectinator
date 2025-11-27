//! File system scanner for FIM

use crate::hasher::{HashAlgorithm, Hasher};
use protectinator_core::{ProgressReporter, Result};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

/// File metadata with hash
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub hash: String,
    pub size: u64,
    pub modified: u64,       // Unix timestamp
    pub permissions: u32,
    #[cfg(unix)]
    pub uid: u32,
    #[cfg(unix)]
    pub gid: u32,
    pub file_type: FileType,
    pub is_symlink: bool,
    pub symlink_target: Option<PathBuf>,
}

/// Type of file
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileType {
    Regular,
    Symlink,
    Other,
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub bytes_processed: u64,
    pub errors: usize,
    pub duration: std::time::Duration,
}

/// File scanner for creating baselines with parallel hashing
pub struct FileScanner {
    algorithm: HashAlgorithm,
    exclude_patterns: Vec<glob::Pattern>,
    follow_symlinks: bool,
    max_depth: Option<usize>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    include_hidden: bool,
}

impl FileScanner {
    /// Create a new file scanner
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self {
            algorithm,
            exclude_patterns: Vec::new(),
            follow_symlinks: false,
            max_depth: None,
            min_size: None,
            max_size: None,
            include_hidden: true,
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

    /// Set minimum file size to include
    pub fn min_size(mut self, size: u64) -> Self {
        self.min_size = Some(size);
        self
    }

    /// Set maximum file size to include
    pub fn max_size(mut self, size: u64) -> Self {
        self.max_size = Some(size);
        self
    }

    /// Set whether to include hidden files
    pub fn include_hidden(mut self, include: bool) -> Self {
        self.include_hidden = include;
        self
    }

    /// Scan a directory and return file entries (sequential)
    pub fn scan(&self, root: &Path) -> Result<Vec<FileEntry>> {
        self.scan_with_progress(root, None)
    }

    /// Scan a directory with progress reporting
    pub fn scan_with_progress(
        &self,
        root: &Path,
        progress: Option<&dyn ProgressReporter>,
    ) -> Result<Vec<FileEntry>> {
        let start_time = std::time::Instant::now();

        // First, collect all file paths
        let file_paths = self.collect_file_paths(root)?;
        let total_files = file_paths.len();

        if let Some(p) = progress {
            p.phase_started("Hashing files", total_files);
        }

        let hasher = Hasher::new(self.algorithm);
        let counter = AtomicUsize::new(0);
        let mut entries = Vec::new();

        // Sequential hashing with progress
        for path in file_paths {
            let current = counter.fetch_add(1, Ordering::SeqCst);

            if let Some(p) = progress {
                p.progress(current + 1, &path.to_string_lossy());
            }

            match self.process_file(&path, &hasher) {
                Ok(entry) => entries.push(entry),
                Err(e) => {
                    if let Some(p) = progress {
                        p.error("fim", &format!("Error processing {}: {}", path.display(), e));
                    }
                }
            }
        }

        if let Some(p) = progress {
            p.phase_completed("Hashing files");
        }

        Ok(entries)
    }

    /// Scan a directory with parallel hashing
    pub fn scan_parallel(&self, root: &Path) -> Result<Vec<FileEntry>> {
        self.scan_parallel_with_progress(root, None)
    }

    /// Scan a directory with parallel hashing and progress reporting
    pub fn scan_parallel_with_progress(
        &self,
        root: &Path,
        progress: Option<Arc<dyn ProgressReporter>>,
    ) -> Result<Vec<FileEntry>> {
        // First, collect all file paths
        let file_paths = self.collect_file_paths(root)?;
        let total_files = file_paths.len();

        if let Some(ref p) = progress {
            p.phase_started("Hashing files (parallel)", total_files);
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let algorithm = self.algorithm;

        // Parallel hashing with rayon
        let entries: Vec<FileEntry> = file_paths
            .par_iter()
            .filter_map(|path| {
                let current = counter.fetch_add(1, Ordering::SeqCst);

                if let Some(ref p) = progress {
                    // Only report progress every 100 files to avoid contention
                    if current % 100 == 0 {
                        p.progress(current, &path.to_string_lossy());
                    }
                }

                let hasher = Hasher::new(algorithm);
                match self.process_file(path, &hasher) {
                    Ok(entry) => Some(entry),
                    Err(e) => {
                        if let Some(ref p) = progress {
                            p.error("fim", &format!("Error processing {}: {}", path.display(), e));
                        }
                        None
                    }
                }
            })
            .collect();

        if let Some(ref p) = progress {
            p.phase_completed("Hashing files (parallel)");
        }

        Ok(entries)
    }

    /// Collect all file paths to scan
    fn collect_file_paths(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();

        let mut walker = WalkDir::new(root).follow_links(self.follow_symlinks);

        if let Some(depth) = self.max_depth {
            walker = walker.max_depth(depth);
        }

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!("Error walking directory: {}", e);
                    continue;
                }
            };

            let path = entry.path();

            // Skip directories
            if entry.file_type().is_dir() {
                continue;
            }

            // Check hidden files
            if !self.include_hidden && is_hidden(path) {
                continue;
            }

            // Check exclusions
            if self.is_excluded(path) {
                continue;
            }

            // Check file size
            if let Ok(metadata) = entry.metadata() {
                let size = metadata.len();

                if let Some(min) = self.min_size {
                    if size < min {
                        continue;
                    }
                }

                if let Some(max) = self.max_size {
                    if size > max {
                        continue;
                    }
                }
            }

            paths.push(path.to_path_buf());
        }

        Ok(paths)
    }

    /// Process a single file and create a FileEntry
    fn process_file(&self, path: &Path, hasher: &Hasher) -> Result<FileEntry> {
        let metadata = std::fs::metadata(path)?;
        let symlink_metadata = std::fs::symlink_metadata(path)?;

        let is_symlink = symlink_metadata.file_type().is_symlink();
        let symlink_target = if is_symlink {
            std::fs::read_link(path).ok()
        } else {
            None
        };

        let file_type = if symlink_metadata.file_type().is_symlink() {
            FileType::Symlink
        } else if metadata.is_file() {
            FileType::Regular
        } else {
            FileType::Other
        };

        // Hash the file
        let hash = hasher.hash_file(path)?;

        let modified = metadata
            .modified()
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        #[cfg(unix)]
        let (permissions, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.mode(), metadata.uid(), metadata.gid())
        };

        #[cfg(not(unix))]
        let (permissions, uid, gid) = (0u32, 0u32, 0u32);

        Ok(FileEntry {
            path: path.to_path_buf(),
            hash,
            size: metadata.len(),
            modified,
            permissions,
            #[cfg(unix)]
            uid,
            #[cfg(unix)]
            gid,
            file_type,
            is_symlink,
            symlink_target,
        })
    }

    /// Check if a path should be excluded
    fn is_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();

        // Check against exclude patterns
        for pattern in &self.exclude_patterns {
            if pattern.matches(&path_str) {
                return true;
            }
            // Also check just the filename
            if let Some(filename) = path.file_name() {
                if pattern.matches(&filename.to_string_lossy()) {
                    return true;
                }
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

/// Check if a path is hidden (starts with .)
fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.starts_with('.'))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_scan_directory() {
        let dir = tempdir().unwrap();

        // Create test files
        let file1 = dir.path().join("file1.txt");
        let file2 = dir.path().join("file2.txt");

        File::create(&file1).unwrap().write_all(b"content1").unwrap();
        File::create(&file2).unwrap().write_all(b"content2").unwrap();

        let scanner = FileScanner::new(HashAlgorithm::Sha256);
        let entries = scanner.scan(dir.path()).unwrap();

        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_exclude_pattern() {
        let dir = tempdir().unwrap();

        let file1 = dir.path().join("file.txt");
        let file2 = dir.path().join("file.log");

        File::create(&file1).unwrap().write_all(b"content").unwrap();
        File::create(&file2).unwrap().write_all(b"log").unwrap();

        let scanner = FileScanner::new(HashAlgorithm::Sha256)
            .with_excludes(&["*.log".to_string()])
            .unwrap();

        let entries = scanner.scan(dir.path()).unwrap();

        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.to_string_lossy().contains("file.txt"));
    }

    #[test]
    fn test_parallel_scan() {
        let dir = tempdir().unwrap();

        // Create multiple test files
        for i in 0..10 {
            let file = dir.path().join(format!("file{}.txt", i));
            File::create(&file).unwrap().write_all(format!("content{}", i).as_bytes()).unwrap();
        }

        let scanner = FileScanner::new(HashAlgorithm::Blake3);
        let entries = scanner.scan_parallel(dir.path()).unwrap();

        assert_eq!(entries.len(), 10);
    }
}
