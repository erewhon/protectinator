//! File hashing utilities

use protectinator_core::{ProtectinatorError, Result};
use sha2::{Digest, Sha256, Sha512};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
    Blake3,
}

impl std::str::FromStr for HashAlgorithm {
    type Err = ProtectinatorError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "sha256" | "sha-256" => Ok(HashAlgorithm::Sha256),
            "sha512" | "sha-512" => Ok(HashAlgorithm::Sha512),
            "blake3" => Ok(HashAlgorithm::Blake3),
            _ => Err(ProtectinatorError::Config(format!("Unknown hash algorithm: {}", s))),
        }
    }
}

impl std::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
            HashAlgorithm::Blake3 => write!(f, "blake3"),
        }
    }
}

/// File hasher
pub struct Hasher {
    algorithm: HashAlgorithm,
}

impl Hasher {
    /// Create a new hasher with the specified algorithm
    pub fn new(algorithm: HashAlgorithm) -> Self {
        Self { algorithm }
    }

    /// Get the algorithm name
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Hash a file at the given path
    pub fn hash_file(&self, path: &Path) -> Result<String> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                Ok(hex::encode(hasher.finalize()))
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                Ok(hex::encode(hasher.finalize()))
            }
            HashAlgorithm::Blake3 => {
                let mut hasher = blake3::Hasher::new();
                let mut buffer = [0u8; 8192];
                loop {
                    let bytes_read = reader.read(&mut buffer)?;
                    if bytes_read == 0 {
                        break;
                    }
                    hasher.update(&buffer[..bytes_read]);
                }
                Ok(hasher.finalize().to_hex().to_string())
            }
        }
    }

    /// Hash bytes directly
    pub fn hash_bytes(&self, data: &[u8]) -> String {
        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            HashAlgorithm::Blake3 => {
                let hasher = blake3::hash(data);
                hasher.to_hex().to_string()
            }
        }
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new(HashAlgorithm::Sha256)
    }
}

// Simple hex encoding (to avoid adding hex crate dependency)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_bytes() {
        let hasher = Hasher::new(HashAlgorithm::Sha256);
        let hash = hasher.hash_bytes(b"hello world");
        assert_eq!(hash, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    }

    #[test]
    fn test_blake3_bytes() {
        let hasher = Hasher::new(HashAlgorithm::Blake3);
        let hash = hasher.hash_bytes(b"hello world");
        assert_eq!(hash.len(), 64); // BLAKE3 produces 256-bit hash = 64 hex chars
    }
}
