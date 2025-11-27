//! SQLite database for storing file baselines

use crate::scanner::FileEntry;
use protectinator_core::{ProtectinatorError, Result};
use rusqlite::{params, Connection};
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
            );

        match result {
            Ok(value) => Ok(Some(value)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(ProtectinatorError::Database(format!(
                "Failed to get metadata: {}",
                e
            ))),
        }
    }

    /// Add a file entry to the baseline
    pub fn add_file(&self, entry: &FileEntry) -> Result<()> {
        let modified = entry
            .modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let scan_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn
            .execute(
                "INSERT OR REPLACE INTO files (path, hash, size, modified, permissions, scan_time)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    entry.path.to_string_lossy(),
                    entry.hash,
                    entry.size as i64,
                    modified,
                    entry.permissions as i64,
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
                    "INSERT OR REPLACE INTO files (path, hash, size, modified, permissions, scan_time)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| {
                    ProtectinatorError::Database(format!("Failed to prepare statement: {}", e))
                })?;

            let scan_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;

            for entry in entries {
                let modified = entry
                    .modified
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;

                stmt.execute(params![
                    entry.path.to_string_lossy(),
                    entry.hash,
                    entry.size as i64,
                    modified,
                    entry.permissions as i64,
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
            .prepare("SELECT path, hash, size, modified, permissions FROM files")
            .map_err(|e| {
                ProtectinatorError::Database(format!("Failed to prepare statement: {}", e))
            })?;

        let entries = stmt
            .query_map([], |row| {
                Ok(StoredFileEntry {
                    path: row.get(0)?,
                    hash: row.get(1)?,
                    size: row.get::<_, i64>(2)? as u64,
                    modified: row.get::<_, i64>(3)? as u64,
                    permissions: row.get::<_, i64>(4)? as u32,
                })
            })
            .map_err(|e| ProtectinatorError::Database(format!("Failed to query files: {}", e)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| ProtectinatorError::Database(format!("Failed to collect files: {}", e)))?;

        Ok(entries)
    }

    /// Get file count
    pub fn file_count(&self) -> Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM files", [], |row| row.get(0))
            .map_err(|e| ProtectinatorError::Database(format!("Failed to count files: {}", e)))?;
        Ok(count as usize)
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
}
