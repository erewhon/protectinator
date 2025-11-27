//! Process and Connection Monitor for Protectinator
//!
//! Monitors running processes and network connections for suspicious activity.
//!
//! # Features
//!
//! - List running processes with command lines
//! - Process risk assessment (suspicious commands, execution locations)
//! - Network connection monitoring
//! - Listening port enumeration
//! - External connection detection
//!
//! # Example
//!
//! ```no_run
//! use protectinator_procmon::{get_processes, get_connections, ProcessSummary};
//!
//! let processes = get_processes();
//! let summary = ProcessSummary::from_processes(&processes);
//!
//! println!("Total processes: {}", summary.total_processes);
//! if summary.has_suspicious() {
//!     println!("Warning: {} suspicious processes", summary.high_risk);
//! }
//! ```

pub mod connections;
pub mod processes;

pub use connections::{
    get_connections, get_external_connections, get_listening_ports, ConnectionInfo,
    ConnectionState, ConnectionSummary, Protocol,
};
pub use processes::{get_process, get_processes, get_process_tree, ProcessInfo, ProcessRisk, ProcessSummary};

use protectinator_core::{
    Applicability, CheckContext, CheckProvider, Finding, FindingSource,
    Result, SecurityCheck, Severity,
};
use std::sync::Arc;

/// Process monitor check provider
pub struct ProcMonProvider {
    check_connections: bool,
    min_risk: ProcessRisk,
}

impl ProcMonProvider {
    /// Create a new process monitor provider
    pub fn new() -> Self {
        Self {
            check_connections: true,
            min_risk: ProcessRisk::Medium,
        }
    }

    /// Enable/disable connection monitoring
    pub fn with_connections(mut self, check: bool) -> Self {
        self.check_connections = check;
        self
    }

    /// Set minimum risk level to report
    pub fn with_min_risk(mut self, risk: ProcessRisk) -> Self {
        self.min_risk = risk;
        self
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
        vec![Arc::new(ProcMonSecurityCheck {
            check_connections: self.check_connections,
            min_risk: self.min_risk,
        })]
    }

    fn refresh(&mut self) -> Result<()> {
        Ok(())
    }
}

/// Security check for process monitoring
struct ProcMonSecurityCheck {
    check_connections: bool,
    min_risk: ProcessRisk,
}

impl SecurityCheck for ProcMonSecurityCheck {
    fn id(&self) -> &str {
        "process-monitor"
    }

    fn name(&self) -> &str {
        "Process and Connection Monitor"
    }

    fn description(&self) -> &str {
        "Monitors running processes and network connections for suspicious activity"
    }

    fn category(&self) -> &str {
        "runtime"
    }

    fn applicability(&self, _ctx: &dyn CheckContext) -> Applicability {
        Applicability::Applicable
    }

    fn execute(&self, _ctx: &dyn CheckContext) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        // Check processes
        let processes = get_processes();
        for proc in &processes {
            if proc.risk < self.min_risk {
                continue;
            }

            let severity = match proc.risk {
                ProcessRisk::Critical => Severity::Critical,
                ProcessRisk::High => Severity::High,
                ProcessRisk::Medium => Severity::Medium,
                ProcessRisk::Low => Severity::Low,
            };

            let title = format!("Suspicious process: {} (PID {})", proc.name, proc.pid);
            let description = if proc.risk_reasons.is_empty() {
                format!("Command: {}", proc.cmdline)
            } else {
                format!(
                    "Command: {}\nReasons: {}",
                    proc.cmdline,
                    proc.risk_reasons.join(", ")
                )
            };

            let source = FindingSource::ProcessMonitor {
                pid: proc.pid,
                process_name: proc.name.clone(),
            };

            findings.push(Finding::new(
                "suspicious-process",
                title,
                description,
                severity,
                source,
            ));
        }

        // Check connections
        if self.check_connections {
            let connections = get_external_connections();
            for conn in &connections {
                let title = format!(
                    "External connection: {}:{} -> {}:{}",
                    conn.local_addr, conn.local_port, conn.remote_addr, conn.remote_port
                );

                let description = format!(
                    "Process: {} (PID {})",
                    conn.process_name.as_deref().unwrap_or("unknown"),
                    conn.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".to_string())
                );

                let source = FindingSource::ProcessMonitor {
                    pid: conn.pid.unwrap_or(0),
                    process_name: conn.process_name.clone().unwrap_or_default(),
                };

                findings.push(Finding::new(
                    "external-connection",
                    title,
                    description,
                    Severity::Info,
                    source,
                ));
            }
        }

        Ok(findings)
    }

    fn estimated_duration(&self) -> std::time::Duration {
        std::time::Duration::from_secs(2)
    }
}
