//! Audit log persistence for threat events.
//!
//! Appends `ThreatEvent` entries as NDJSON (one JSON object per line) to the
//! audit log file, which can be queried via `sanctum audit`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use sanctum_types::threat::ThreatEvent;

/// Maximum audit log file size before rotation (50 MB).
const MAX_AUDIT_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Append a threat event to the NDJSON audit log.
///
/// Creates the parent directory and file if they don't exist.
/// Sets file permissions to 0o600 on Unix.
/// Rotates the log file if it exceeds `MAX_AUDIT_LOG_BYTES`.
/// Errors are logged via tracing but never propagated — audit logging
/// must not crash the daemon.
pub fn append_audit_event(event: &ThreatEvent, audit_path: &Path) {
    if let Err(e) = maybe_rotate(audit_path) {
        tracing::warn!("failed to rotate audit log: {e}");
    }
    if let Err(e) = append_audit_event_inner(event, audit_path) {
        tracing::warn!("failed to write audit log entry: {e}");
    }
}

/// Rotate the audit log if it exceeds the size threshold.
///
/// Renames the current log to `audit.log.1` (removing any existing `.1` file),
/// so that subsequent writes go to a fresh `audit.log`.
fn maybe_rotate(audit_path: &Path) -> Result<(), std::io::Error> {
    let metadata = match fs::metadata(audit_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };

    if metadata.len() < MAX_AUDIT_LOG_BYTES {
        return Ok(());
    }

    let mut rotated = audit_path.as_os_str().to_os_string();
    rotated.push(".1");
    let rotated_path = std::path::PathBuf::from(rotated);

    // Rename current log to .1 — on POSIX, rename() atomically replaces the target
    fs::rename(audit_path, &rotated_path)?;

    tracing::info!("rotated audit log (exceeded {} bytes)", MAX_AUDIT_LOG_BYTES);

    Ok(())
}

fn append_audit_event_inner(
    event: &ThreatEvent,
    audit_path: &Path,
) -> Result<(), std::io::Error> {
    // Ensure parent directory exists with secure permissions
    if let Some(parent) = audit_path.parent() {
        // Create parent directories (grandparents etc.) first
        if let Some(grandparent) = parent.parent() {
            fs::create_dir_all(grandparent)?;
        }
        // Create the final directory with restricted permissions atomically
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(parent) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(parent)?;
        }
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
    fn rotates_audit_log_when_exceeding_threshold() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");

        // Create a file that exceeds the rotation threshold
        {
            let mut file = std::fs::File::create(&log_path).expect("create audit log");
            // Write enough bytes to exceed MAX_AUDIT_LOG_BYTES
            let chunk = vec![b'x'; 1024];
            let iterations = (MAX_AUDIT_LOG_BYTES / 1024) + 1;
            for _ in 0..iterations {
                file.write_all(&chunk).expect("write chunk");
            }
            file.sync_all().expect("sync");
        }

        // Verify file exceeds threshold
        let size_before = std::fs::metadata(&log_path).expect("metadata").len();
        assert!(size_before >= MAX_AUDIT_LOG_BYTES);

        // Append an event, which should trigger rotation
        let event = make_test_event();
        append_audit_event(&event, &log_path);

        // The old large file should now be at .1
        assert!(rotated_path.exists(), "rotated file should exist");
        let rotated_size = std::fs::metadata(&rotated_path).expect("rotated metadata").len();
        assert!(rotated_size >= MAX_AUDIT_LOG_BYTES, "rotated file should contain the old data");

        // The new audit.log should contain only the freshly appended event
        assert!(log_path.exists(), "new audit log should exist");
        let new_content = std::fs::read_to_string(&log_path).expect("read new audit log");
        let lines: Vec<&str> = new_content.lines().collect();
        assert_eq!(lines.len(), 1, "new audit log should have exactly 1 line");
        let parsed: ThreatEvent =
            serde_json::from_str(lines[0]).expect("parse new audit entry");
        assert_eq!(parsed.description, "test threat");
    }

    #[test]
    fn rotation_replaces_existing_rotated_file() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");

        // Create an existing .1 file with known content
        std::fs::write(&rotated_path, "old-rotated-data").expect("write old rotated");

        // Create a file that exceeds the rotation threshold
        {
            let mut file = std::fs::File::create(&log_path).expect("create audit log");
            let chunk = vec![b'y'; 1024];
            let iterations = (MAX_AUDIT_LOG_BYTES / 1024) + 1;
            for _ in 0..iterations {
                file.write_all(&chunk).expect("write chunk");
            }
            file.sync_all().expect("sync");
        }

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        // The old .1 file should have been replaced
        let rotated_content = std::fs::read(&rotated_path).expect("read rotated");
        assert_ne!(
            rotated_content, b"old-rotated-data",
            "old rotated file should have been replaced"
        );
    }

    #[test]
    fn no_rotation_when_under_threshold() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");
        let rotated_path = dir.path().join("audit.log.1");

        // Write a small audit log
        let event = make_test_event();
        append_audit_event(&event, &log_path);

        // Should NOT trigger rotation
        assert!(!rotated_path.exists(), "no rotation should occur for small files");

        // Original file should still have the event
        let content = std::fs::read_to_string(&log_path).expect("read audit log");
        assert_eq!(content.lines().count(), 1);
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
