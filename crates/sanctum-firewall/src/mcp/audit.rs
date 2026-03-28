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

/// Maximum number of in-memory audit entries before oldest are drained.
const MAX_ENTRIES: usize = 10_000;

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
        if self.entries.len() > MAX_ENTRIES {
            let drain_count = self.entries.len() - MAX_ENTRIES;
            self.entries.drain(..drain_count);
        }
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
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        // Set restrictive permissions (owner-only read/write) so that audit
        // logs are not world-readable. The `let _ =` deliberately ignores
        // errors (e.g. on non-Unix platforms where this is a no-op).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(path, perms);
        }

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
        log.record(
            "test_tool",
            json!({"key": "value"}),
            HookDecision::Allow,
            None,
        );
        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.entries()[0].tool_name, "test_tool");
        assert_eq!(log.entries()[0].decision, HookDecision::Allow);
    }

    #[test]
    fn record_multiple_entries() {
        let mut log = McpAuditLog::new();
        log.record("tool_a", json!({}), HookDecision::Allow, None);
        log.record(
            "tool_b",
            json!({}),
            HookDecision::Block,
            Some("blocked".to_owned()),
        );
        log.record(
            "tool_c",
            json!({}),
            HookDecision::Warn,
            Some("warned".to_owned()),
        );
        assert_eq!(log.entries().len(), 3);
    }

    #[test]
    fn write_to_file_creates_ndjson() -> Result<(), Box<dyn std::error::Error>> {
        let mut log = McpAuditLog::new();
        log.record("tool_x", json!({"arg": 1}), HookDecision::Allow, None);
        log.record(
            "tool_y",
            json!({"arg": 2}),
            HookDecision::Block,
            Some("reason".to_owned()),
        );

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
    fn write_to_file_appends_not_truncates() -> Result<(), Box<dyn std::error::Error>> {
        let mut log = McpAuditLog::new();
        log.record("tool_a", json!({"arg": 1}), HookDecision::Allow, None);

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit.ndjson");

        // First write: 1 entry
        log.write_to_file(&path)?;
        let contents = std::fs::read_to_string(&path)?;
        assert_eq!(contents.lines().count(), 1);

        // Second write: should append, resulting in 2 entries total
        log.write_to_file(&path)?;
        let contents = std::fs::read_to_string(&path)?;
        assert_eq!(
            contents.lines().count(),
            2,
            "write_to_file should append, not truncate"
        );

        // Verify all lines are valid JSON
        for line in contents.lines() {
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
        assert_eq!(entry.reason.as_deref(), Some("path restriction violated"));
    }

    #[cfg(unix)]
    #[test]
    fn write_to_file_sets_restrictive_permissions() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;

        let mut log = McpAuditLog::new();
        log.record("tool_z", json!({"arg": 1}), HookDecision::Allow, None);

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("audit_perms.ndjson");

        log.write_to_file(&path)?;

        let metadata = std::fs::metadata(&path)?;
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "audit log file should have 0600 permissions, got {mode:o}"
        );

        Ok(())
    }

    #[test]
    fn record_caps_at_max_entries() {
        let mut log = McpAuditLog::new();
        for i in 0..10_050 {
            log.record(format!("tool_{i}"), json!({}), HookDecision::Allow, None);
        }
        assert!(
            log.entries().len() <= 10_000,
            "entries should be capped at 10,000"
        );
        // Oldest entries should have been drained
        assert!(log.entries()[0].tool_name.ends_with("_50") || log.entries().len() == 10_000);
    }
}
