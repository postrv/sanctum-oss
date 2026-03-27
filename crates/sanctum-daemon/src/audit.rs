//! Audit log persistence for threat events.
//!
//! Appends `ThreatEvent` entries as NDJSON (one JSON object per line) to the
//! audit log file, which can be queried via `sanctum audit`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use sanctum_types::threat::ThreatEvent;

/// Append a threat event to the NDJSON audit log.
///
/// Creates the parent directory and file if they don't exist.
/// Sets file permissions to 0o600 on Unix.
/// Errors are logged via tracing but never propagated — audit logging
/// must not crash the daemon.
pub fn append_audit_event(event: &ThreatEvent, audit_path: &Path) {
    if let Err(e) = append_audit_event_inner(event, audit_path) {
        tracing::warn!("failed to write audit log entry: {e}");
    }
}

fn append_audit_event_inner(
    event: &ThreatEvent,
    audit_path: &Path,
) -> Result<(), std::io::Error> {
    // Ensure parent directory exists
    if let Some(parent) = audit_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Open in append mode, create if needed
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_path)?;

    // Set restrictive permissions on first creation
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(audit_path, perms)?;
    }

    // Serialize as single JSON line
    let json = serde_json::to_string(event)
        .map_err(std::io::Error::other)?;

    writeln!(file, "{json}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_types::threat::{Action, ThreatCategory, ThreatLevel};
    use std::io::BufRead;
    use std::path::PathBuf;

    fn make_test_event() -> ThreatEvent {
        ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: ThreatLevel::Critical,
            category: ThreatCategory::PthInjection,
            description: "test threat".to_string(),
            source_path: PathBuf::from("/test/evil.pth"),
            creator_pid: Some(1234),
            creator_exe: None,
            action_taken: Action::Quarantined,
        }
    }

    #[test]
    fn appends_valid_ndjson() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        let content = std::fs::read_to_string(&log_path).expect("read audit log");
        let parsed: ThreatEvent =
            serde_json::from_str(content.trim()).expect("parse NDJSON line");

        assert_eq!(parsed.level, ThreatLevel::Critical);
        assert_eq!(parsed.category, ThreatCategory::PthInjection);
        assert_eq!(parsed.description, "test threat");
    }

    #[test]
    fn multiple_events_produce_multiple_lines() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event1 = make_test_event();
        let mut event2 = make_test_event();
        event2.level = ThreatLevel::Warning;
        event2.description = "second threat".to_string();

        append_audit_event(&event1, &log_path);
        append_audit_event(&event2, &log_path);

        let file = std::fs::File::open(&log_path).expect("open audit log");
        let reader = std::io::BufReader::new(file);
        let lines: Vec<String> = reader
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .expect("read lines");

        assert_eq!(lines.len(), 2);

        let parsed1: ThreatEvent =
            serde_json::from_str(&lines[0]).expect("parse first line");
        let parsed2: ThreatEvent =
            serde_json::from_str(&lines[1]).expect("parse second line");

        assert_eq!(parsed1.level, ThreatLevel::Critical);
        assert_eq!(parsed2.level, ThreatLevel::Warning);
        assert_eq!(parsed2.description, "second threat");
    }

    #[test]
    #[cfg(unix)]
    fn audit_file_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        let metadata = std::fs::metadata(&log_path).expect("read file metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit log should have 0600 permissions");
    }

    #[test]
    fn creates_parent_directory() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("nested").join("subdir").join("audit.log");

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        assert!(log_path.exists(), "audit log should be created");
        let content = std::fs::read_to_string(&log_path).expect("read audit log");
        let parsed: ThreatEvent =
            serde_json::from_str(content.trim()).expect("parse NDJSON line");
        assert_eq!(parsed.level, ThreatLevel::Critical);
    }
}
