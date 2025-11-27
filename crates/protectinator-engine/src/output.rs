//! Output formatting for scan results

use protectinator_core::{OutputFormat, OutputHandler, Result, ScanResults, Severity};
use std::io::Write;

/// Text output handler
pub struct TextOutputHandler<W: Write> {
    writer: W,
    show_info: bool,
}

impl<W: Write> TextOutputHandler<W> {
    /// Create a new text output handler
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            show_info: false,
        }
    }

    /// Include informational findings
    pub fn with_info(mut self, show_info: bool) -> Self {
        self.show_info = show_info;
        self
    }
}

impl<W: Write + Send + Sync> OutputHandler for TextOutputHandler<W> {
    fn handle(&self, results: &ScanResults) -> Result<()> {
        // Note: For thread safety, we'd need interior mutability
        // For now, this is a simplified implementation
        Ok(())
    }
}

/// JSON output handler
pub struct JsonOutputHandler<W: Write> {
    writer: W,
    pretty: bool,
}

impl<W: Write> JsonOutputHandler<W> {
    /// Create a new JSON output handler
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            pretty: false,
        }
    }

    /// Use pretty printing
    pub fn pretty(mut self, pretty: bool) -> Self {
        self.pretty = pretty;
        self
    }
}

impl<W: Write + Send + Sync> OutputHandler for JsonOutputHandler<W> {
    fn handle(&self, results: &ScanResults) -> Result<()> {
        Ok(())
    }
}

/// Format scan results as text
pub fn format_text(results: &ScanResults, show_info: bool) -> String {
    let mut output = String::new();

    // Header
    output.push_str(&format!(
        "Protectinator Security Scan Report\n{}\n\n",
        "=".repeat(35)
    ));

    // System info
    output.push_str(&format!("System: {} {}\n", results.system_info.os_name, results.system_info.os_version));
    output.push_str(&format!("Host: {}\n", results.system_info.hostname));
    output.push_str(&format!("Architecture: {}\n", results.system_info.architecture));
    output.push_str(&format!("Elevated: {}\n", if results.system_info.is_elevated { "Yes" } else { "No" }));
    output.push_str(&format!("Scan Duration: {:?}\n\n", results.completed_at - results.started_at));

    // Summary
    output.push_str("Summary\n-------\n");
    output.push_str(&format!("Total Checks: {}\n", results.summary.total_checks));
    output.push_str(&format!("Passed: {}\n", results.summary.checks_passed));
    output.push_str(&format!("Failed: {}\n", results.summary.checks_failed));
    output.push_str(&format!("Skipped: {}\n\n", results.summary.checks_skipped));

    // Findings by severity
    output.push_str("Findings by Severity\n--------------------\n");
    for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low, Severity::Info] {
        let count = results.summary.findings_by_severity.get(&severity).unwrap_or(&0);
        if *count > 0 || severity != Severity::Info || show_info {
            output.push_str(&format!("{:?}: {}\n", severity, count));
        }
    }
    output.push('\n');

    // Detailed findings
    if !results.findings.is_empty() {
        output.push_str("Findings\n--------\n\n");

        for finding in &results.findings {
            if finding.severity == Severity::Info && !show_info {
                continue;
            }

            output.push_str(&format!("[{}] {}\n", finding.severity.to_string().to_uppercase(), finding.title));
            output.push_str(&format!("ID: {}\n", finding.id));
            output.push_str(&format!("Description: {}\n", finding.description));

            if let Some(resource) = &finding.resource {
                output.push_str(&format!("Resource: {}\n", resource));
            }

            if let Some(remediation) = &finding.remediation {
                output.push_str(&format!("Remediation: {}\n", remediation));
            }

            if !finding.references.is_empty() {
                output.push_str("References:\n");
                for reference in &finding.references {
                    output.push_str(&format!("  - {}\n", reference));
                }
            }

            output.push('\n');
        }
    }

    // Errors
    if !results.errors.is_empty() {
        output.push_str("Errors\n------\n");
        for error in &results.errors {
            output.push_str(&format!("[{}] {}\n", error.module, error.message));
        }
    }

    output
}

/// Format scan results as JSON
pub fn format_json(results: &ScanResults, pretty: bool) -> Result<String> {
    if pretty {
        serde_json::to_string_pretty(results).map_err(Into::into)
    } else {
        serde_json::to_string(results).map_err(Into::into)
    }
}
