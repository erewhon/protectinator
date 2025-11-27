//! Process and Connection Monitor for Protectinator
//!
//! Monitors running processes and network connections.

use protectinator_core::{CheckProvider, Result, SecurityCheck};
use std::sync::Arc;

pub mod processes;
pub mod connections;

/// Process monitor check provider
pub struct ProcMonProvider;

impl ProcMonProvider {
    /// Create a new process monitor provider
    pub fn new() -> Self {
        Self
    }
}

impl Default for ProcMonProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckProvider for ProcMonProvider {
    fn name(&self) -> &str {
        "procmon"
    }

    fn checks(&self) -> Vec<Arc<dyn SecurityCheck>> {
        // Process monitor checks will be added in Phase 6b
        Vec::new()
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}
