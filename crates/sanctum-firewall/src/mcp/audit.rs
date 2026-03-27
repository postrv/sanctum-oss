//! MCP audit log.
//!
//! Records all MCP tool invocations for post-hoc security review. Each entry
//! captures the tool name, arguments, timestamp, and the policy decision that
//! was applied.

use std::io::Write;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::hooks::protocol::HookDecision;

/// A single MCP audit log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the tool invocation occurred.
    pub timestamp: DateTime<Utc>,
    /// The name of the MCP tool that was invoked.
    pub tool_name: String,
    /// The arguments passed to the tool (may be redacted).
    pub arguments: serde_json::Value,
    /// The policy decision that was applied.
    pub decision: HookDecision,
    /// Optional reason for the decision.
    pub reason: Option<String>,
}

/// An append-only audit log for MCP tool invocations.
#[derive(Debug, Default)]
pub struct McpAuditLog {
    entries: Vec<AuditEntry>,
}

impl McpAuditLog {
    /// Create a new, empty audit log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record a new audit entry.
    pub fn record(
        &mut self,
        tool_name: impl Into<String>,
        arguments: serde_json::Value,
        decision: HookDecision,
        reason: Option<String>,
    ) {
        self.entries.push(AuditEntry {
            timestamp: Utc::now(),
            tool_name: tool_name.into(),
            arguments,
            decision,
            reason,
        });
    }

    /// Return all recorded entries.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Write the audit log to a file as newline-delimited JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written to.
    pub fn write_to_file(&self, path: &Path) -> Result<(), std::io::Error> {
        let mut file = std::fs::File::create(path)?;
        for entry in &self.entries {
            // Serialisation of our well-known types should never fail, but we
            // handle the error gracefully rather than panicking.
            if let Ok(json) = serde_json::to_string(entry) {
                writeln!(file, "{json}")?;
            }
        }
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn new_log_is_empty() {
        let log = McpAuditLog::new();
        assert!(log.entries().is_empty());
    }

    #[test]
    fn record_adds_entry() {
        let mut log = McpAuditLog::new();
        log.record("test_tool", json!({"key": "value"}), HookDecision::Allow, None);
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.entries()[0].tool_name, "test_tool");
        assert_eq!(log.entries()[0].decision, HookDecision::Allow);
    }

    #[test]
    fn record_multiple_entries() {
        let mut log = McpAuditLog::new();
        log.record("tool_a", json!({}), HookDecision::Allow, None);
        log.record("tool_b", json!({}), HookDecision::Block, Some("blocked".to_owned()));
        log.record("tool_c", json!({}), HookDecision::Warn, Some("warned".to_owned()));
        assert_eq!(log.entries().len(), 3);
    }

    #[test]
    fn write_to_file_creates_ndjson() -> Result<(), Box<dyn std::error::Error>> {
        let mut log = McpAuditLog::new();
        log.record("tool_x", json!({"arg": 1}), HookDecision::Allow, None);
        log.record("tool_y", json!({"arg": 2}), HookDecision::Block, Some("reason".to_owned()));

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.ndjson");

        log.write_to_file(&path)?;

        let contents = std::fs::read_to_string(&path)?;
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON
        for line in &lines {
            let _entry: AuditEntry = serde_json::from_str(line)?;
        }

        Ok(())
    }

    #[test]
    fn entries_preserve_reason() {
        let mut log = McpAuditLog::new();
        log.record(
            "restricted_tool",
            json!({}),
            HookDecision::Block,
            Some("path restriction violated".to_owned()),
        );
        let entry = &log.entries()[0];
        assert_eq!(
            entry.reason.as_deref(),
            Some("path restriction violated")
        );
    }
}
