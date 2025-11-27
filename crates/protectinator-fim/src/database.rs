//! SQLite database for storing file baselines

use crate::scanner::{FileEntry, FileType};
use protectinator_core::{ProtectinatorError, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

/// Baseline database for storing file hashes
pub struct BaselineDatabase {
    conn: Connection,
}

impl BaselineDatabase {
    /// Create a new baseline database
    pub fn create(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).map_err(|e| {
            ProtectinatorError::Database(format!("Failed to create database: {}", e))
        })?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                path TEXT NOT NULL UNIQUE,
                hash TEXT NOT NULL,
                size INTEGER NOT NULL,
                modified INTEGER NOT NULL,
                permissions INTEGER NOT NULL,
                uid INTEGER,
                gid INTEGER,
                file_type TEXT NOT NULL DEFAULT 'regular',
                is_symlink INTEGER NOT NULL DEFAULT 0,
                symlink_target TEXT,
                scan_time INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
            CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);
            ",
        )
        .map_err(|e| ProtectinatorError::Database(format!("Failed to create tables: {}", e)))?;

        Ok(Self { conn })
    }

    /// Open an existing baseline database
    pub fn open(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(ProtectinatorError::NotFound(format!(
                "Database not found: {}",
                path.display()
            )));
        }

        let conn = Connection::open(path).map_err(|e| {
            ProtectinatorError::Database(format!("Failed to open database: {}", e))
        })?;

        Ok(Self { conn })
    }

    /// Set metadata
    pub fn set_metadata(&self, key: &str, value: &str) -> Result<()> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?1, ?2)",
                params![key, value],
            )
            .map_err(|e| ProtectinatorError::Database(format!("Failed to set metadata: {}", e)))?;
        Ok(())
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &str) -> Result<Option<String>> {
        let result = self
            .conn
            .query_row(
                "SELECT value FROM metadata WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| ProtectinatorError::Database(format!("Failed to get metadata: {}", e)))?;

        Ok(result)
    }

    /// Add a file entry to the baseline
    pub fn add_file(&self, entry: &FileEntry) -> Result<()> {
        let scan_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let file_type_str = match entry.file_type {
            FileType::Regular => "regular",
            FileType::Symlink => "symlink",
            FileType::Other => "other",
        };

        #[cfg(unix)]
        let (uid, gid) = (Some(entry.uid as i64), Some(entry.gid as i64));
        #[cfg(not(unix))]
        let (uid, gid): (Option<i64>, Option<i64>) = (None, None);

        self.conn
            .execute(
                "INSERT OR REPLACE INTO files (path, hash, size, modified, permissions, uid, gid, file_type, is_symlink, symlink_target, scan_time)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    entry.path.to_string_lossy(),
                    entry.hash,
                    entry.size as i64,
                    entry.modified as i64,
                    entry.permissions as i64,
                    uid,
                    gid,
                    file_type_str,
                    entry.is_symlink,
                    entry.symlink_target.as_ref().map(|p| p.to_string_lossy().to_string()),
                    scan_time
                ],
            )
            .map_err(|e| ProtectinatorError::Database(format!("Failed to add file: {}", e)))?;
        Ok(())
    }

    /// Add multiple file entries in a transaction
    pub fn add_files(&mut self, entries: &[FileEntry]) -> Result<()> {
        let tx = self.conn.transaction().map_err(|e| {
            ProtectinatorError::Database(format!("Failed to start transaction: {}", e))
        })?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT OR REPLACE INTO files (path, hash, size, modified, permissions, uid, gid, file_type, is_symlink, symlink_target, scan_time)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                )
                .map_err(|e| {
                    ProtectinatorError::Database(format!("Failed to prepare statement: {}", e))
                })?;

            let scan_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            for entry in entries {
                let file_type_str = match entry.file_type {
                    FileType::Regular => "regular",
                    FileType::Symlink => "symlink",
                    FileType::Other => "other",
                };

                #[cfg(unix)]
                let (uid, gid) = (Some(entry.uid as i64), Some(entry.gid as i64));
                #[cfg(not(unix))]
                let (uid, gid): (Option<i64>, Option<i64>) = (None, None);

                stmt.execute(params![
                    entry.path.to_string_lossy(),
                    entry.hash,
                    entry.size as i64,
                    entry.modified as i64,
                    entry.permissions as i64,
                    uid,
                    gid,
                    file_type_str,
                    entry.is_symlink,
                    entry.symlink_target.as_ref().map(|p| p.to_string_lossy().to_string()),
                    scan_time
                ])
                .map_err(|e| {
                    ProtectinatorError::Database(format!("Failed to insert file: {}", e))
                })?;
            }
        }

        tx.commit().map_err(|e| {
            ProtectinatorError::Database(format!("Failed to commit transaction: {}", e))
        })?;

        Ok(())
    }

    /// Get all file entries
    pub fn get_all_files(&self) -> Result<Vec<StoredFileEntry>> {
        let mut stmt = self
            .conn
            .prepare("SELECT path, hash, size, modified, permissions, uid, gid, file_type, is_symlink, symlink_target FROM files")
            .map_err(|e| {
                ProtectinatorError::Database(format!("Failed to prepare statement: {}", e))
            })?;

        let entries = stmt
            .query_map([], |row| {
                let file_type_str: String = row.get(7)?;
                let file_type = match file_type_str.as_str() {
                    "symlink" => FileType::Symlink,
                    "other" => FileType::Other,
                    _ => FileType::Regular,
                };

                Ok(StoredFileEntry {
                    path: row.get(0)?,
                    hash: row.get(1)?,
                    size: row.get::<_, i64>(2)? as u64,
                    modified: row.get::<_, i64>(3)? as u64,
                    permissions: row.get::<_, i64>(4)? as u32,
                    uid: row.get::<_, Option<i64>>(5)?.map(|v| v as u32),
                    gid: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
                    file_type,
                    is_symlink: row.get(8)?,
                    symlink_target: row.get(9)?,
                })
            })
            .map_err(|e| ProtectinatorError::Database(format!("Failed to query files: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ProtectinatorError::Database(format!("Failed to collect files: {}", e)))?;

        Ok(entries)
    }

    /// Get a specific file entry by path
    pub fn get_file(&self, path: &str) -> Result<Option<StoredFileEntry>> {
        let result = self
            .conn
            .query_row(
                "SELECT path, hash, size, modified, permissions, uid, gid, file_type, is_symlink, symlink_target FROM files WHERE path = ?1",
                params![path],
                |row| {
                    let file_type_str: String = row.get(7)?;
                    let file_type = match file_type_str.as_str() {
                        "symlink" => FileType::Symlink,
                        "other" => FileType::Other,
                        _ => FileType::Regular,
                    };

                    Ok(StoredFileEntry {
                        path: row.get(0)?,
                        hash: row.get(1)?,
                        size: row.get::<_, i64>(2)? as u64,
                        modified: row.get::<_, i64>(3)? as u64,
                        permissions: row.get::<_, i64>(4)? as u32,
                        uid: row.get::<_, Option<i64>>(5)?.map(|v| v as u32),
                        gid: row.get::<_, Option<i64>>(6)?.map(|v| v as u32),
                        file_type,
                        is_symlink: row.get(8)?,
                        symlink_target: row.get(9)?,
                    })
                },
            )
            .optional()
            .map_err(|e| ProtectinatorError::Database(format!("Failed to get file: {}", e)))?;

        Ok(result)
    }

    /// Get file count
    pub fn file_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(|e| ProtectinatorError::Database(format!("Failed to count files: {}", e)))?;
        Ok(count as usize)
    }

    /// Get total size of all files
    pub fn total_size(&self) -> Result<u64> {
        let size: i64 = self
            .conn
            .query_row("SELECT COALESCE(SUM(size), 0) FROM files", [], |row| row.get(0))
            .map_err(|e| ProtectinatorError::Database(format!("Failed to sum sizes: {}", e)))?;
        Ok(size as u64)
    }

    /// Delete a file entry
    pub fn delete_file(&self, path: &str) -> Result<bool> {
        let rows = self
            .conn
            .execute("DELETE FROM files WHERE path = ?1", params![path])
            .map_err(|e| ProtectinatorError::Database(format!("Failed to delete file: {}", e)))?;
        Ok(rows > 0)
    }

    /// Clear all file entries
    pub fn clear(&self) -> Result<()> {
        self.conn
            .execute("DELETE FROM files", [])
            .map_err(|e| ProtectinatorError::Database(format!("Failed to clear files: {}", e)))?;
        Ok(())
    }
}

/// Stored file entry from database
#[derive(Debug, Clone)]
pub struct StoredFileEntry {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub modified: u64,
    pub permissions: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub file_type: FileType,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

impl StoredFileEntry {
    /// Convert to a path for comparison
    pub fn path_buf(&self) -> std::path::PathBuf {
        std::path::PathBuf::from(&self.path)
    }
}
