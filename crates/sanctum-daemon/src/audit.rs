//! Audit log persistence for threat events.
//!
//! Delegates to `sanctum_types::audit` for the shared implementation.
//! This module re-exports the shared `append_audit_event` function so that
//! existing daemon code does not need to change its import paths.

use std::path::Path;

use sanctum_types::threat::ThreatEvent;

/// Append a threat event to the NDJSON audit log.
///
/// Delegates to the shared implementation in `sanctum_types::audit`.
/// See that module for full documentation of safety invariants.
pub fn append_audit_event(event: &ThreatEvent, audit_path: &Path) {
    sanctum_types::audit::append_audit_event(event, audit_path);
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_types::threat::{Action, ThreatCategory, ThreatLevel};
    use std::io::BufRead;
    use std::io::Write;
    use std::path::PathBuf;

    /// Maximum audit log file size before rotation (50 MB).
    /// Mirrors the constant in `sanctum_types::audit` for test assertions.
    const MAX_AUDIT_LOG_BYTES: u64 = 50 * 1024 * 1024;

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
    fn delegates_to_shared_module() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        let content = std::fs::read_to_string(&log_path).expect("read audit log");
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse NDJSON line");

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

        let parsed1: ThreatEvent = serde_json::from_str(&lines[0]).expect("parse first line");
        let parsed2: ThreatEvent = serde_json::from_str(&lines[1]).expect("parse second line");

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
        let rotated_size = std::fs::metadata(&rotated_path)
            .expect("rotated metadata")
            .len();
        assert!(
            rotated_size >= MAX_AUDIT_LOG_BYTES,
            "rotated file should contain the old data"
        );

        // The new audit.log should contain only the freshly appended event
        assert!(log_path.exists(), "new audit log should exist");
        let new_content = std::fs::read_to_string(&log_path).expect("read new audit log");
        let lines: Vec<&str> = new_content.lines().collect();
        assert_eq!(lines.len(), 1, "new audit log should have exactly 1 line");
        let parsed: ThreatEvent = serde_json::from_str(lines[0]).expect("parse new audit entry");
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
        assert!(
            !rotated_path.exists(),
            "no rotation should occur for small files"
        );

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
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse NDJSON line");
        assert_eq!(parsed.level, ThreatLevel::Critical);
    }
}
