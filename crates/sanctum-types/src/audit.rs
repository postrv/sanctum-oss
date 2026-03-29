//! Audit log persistence for threat events.
//!
//! Appends `ThreatEvent` entries as NDJSON (one JSON object per line) to the
//! audit log file. This module is shared between the daemon and CLI so that
//! both can write to the same audit log without circular dependencies.
//!
//! # Safety invariants
//!
//! - File permissions: 0o600 on Unix (owner read/write only).
//! - Directory permissions: 0o700 on Unix.
//! - Writes use `O_APPEND` for POSIX-guaranteed atomicity under `PIPE_BUF`.
//! - All errors in `append_audit_event` are swallowed — audit logging must
//!   never crash the caller.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::threat::ThreatEvent;

/// Maximum audit log file size before rotation (50 MB).
const MAX_AUDIT_LOG_BYTES: u64 = 50 * 1024 * 1024;

/// Maximum audit events per second before throttling.
const MAX_AUDIT_EVENTS_PER_SEC: u64 = 50;

/// Sliding-window rate limiter state (second boundary + count).
static AUDIT_WINDOW_START: AtomicU64 = AtomicU64::new(0);
static AUDIT_WINDOW_COUNT: AtomicU64 = AtomicU64::new(0);

/// Check whether the audit write rate limit is exceeded.
///
/// Uses a simple per-second sliding window. Returns `true` if the event
/// should be dropped.
fn should_throttle_audit() -> bool {
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let window_start = AUDIT_WINDOW_START.load(Ordering::Acquire);
    if now_secs != window_start {
        // New second — reset counter. Race is benign (worst case: one
        // extra event slips through).
        AUDIT_WINDOW_START.store(now_secs, Ordering::Release);
        AUDIT_WINDOW_COUNT.store(1, Ordering::Release);
        return false;
    }

    let count = AUDIT_WINDOW_COUNT.fetch_add(1, Ordering::AcqRel);
    count >= MAX_AUDIT_EVENTS_PER_SEC
}

/// Append a threat event to the NDJSON audit log.
///
/// Creates the parent directory and file if they don't exist.
/// Sets file permissions to 0o600 on Unix.
/// Rotates the log file if it exceeds `MAX_AUDIT_LOG_BYTES`.
/// Rate-limited to [`MAX_AUDIT_EVENTS_PER_SEC`] events per second.
///
/// **Errors are swallowed**: failures are logged via `tracing::warn` but
/// never propagated. This ensures audit logging cannot crash the daemon
/// or cause a hook to change its allow/block decision.
pub fn append_audit_event(event: &ThreatEvent, audit_path: &Path) {
    if should_throttle_audit() {
        tracing::warn!("audit log write rate limit exceeded, dropping event");
        return;
    }
    if let Err(e) = maybe_rotate(audit_path) {
        tracing::warn!("failed to rotate audit log: {e}");
    }
    if let Err(e) = append_audit_event_inner(event, audit_path) {
        tracing::warn!("failed to write audit log entry: {e}");
    }
}

/// Try to append a threat event, returning any error for the caller to handle.
///
/// This is the fallible counterpart of [`append_audit_event`]. Use this when
/// you need to know whether the write succeeded (e.g., in tests or when the
/// caller has its own error-handling strategy). In production hook/daemon code,
/// prefer [`append_audit_event`] which swallows errors.
///
/// # Errors
///
/// Returns `std::io::Error` if directory creation, file open, serialization,
/// or write fails.
pub fn try_append_audit_event(
    event: &ThreatEvent,
    audit_path: &Path,
) -> Result<(), std::io::Error> {
    maybe_rotate(audit_path)?;
    append_audit_event_inner(event, audit_path)
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

fn append_audit_event_inner(event: &ThreatEvent, audit_path: &Path) -> Result<(), std::io::Error> {
    // Ensure parent directory exists with secure permissions
    if let Some(parent) = audit_path.parent() {
        // Create parent directories (grandparents etc.) first
        if let Some(grandparent) = parent.parent() {
            fs::create_dir_all(grandparent)?;
        }
        // Create the final directory with restricted permissions atomically
        crate::fs_safety::ensure_secure_dir(parent)?;
    }

    // Open in append mode with O_NOFOLLOW + fchmod (symlink-safe, TOCTOU-safe)
    let mut file = crate::fs_safety::safe_append_open(audit_path)?;

    // Serialize as single JSON line
    let json = serde_json::to_string(event).map_err(std::io::Error::other)?;

    writeln!(file, "{json}")?;
    // sync_data() flushes file data without metadata (faster than sync_all).
    // This is called from the hook path where latency matters.
    file.sync_data()?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::threat::{Action, ThreatCategory, ThreatLevel};
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

    #[test]
    fn try_append_returns_ok_on_success() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let event = make_test_event();
        let result = try_append_audit_event(&event, &log_path);
        assert!(result.is_ok(), "try_append should succeed");

        let content = std::fs::read_to_string(&log_path).expect("read");
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse");
        assert_eq!(parsed.category, ThreatCategory::PthInjection);
    }

    #[test]
    fn append_audit_event_swallows_errors() {
        // Writing to an impossible path should not panic
        let bad_path = std::path::Path::new("/nonexistent/deeply/nested/impossible/audit.log");
        let event = make_test_event();
        // This should NOT panic — errors are swallowed
        append_audit_event(&event, bad_path);
    }

    #[test]
    fn all_threat_categories_serialise_to_audit() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("audit.log");

        let categories = [
            ThreatCategory::PthInjection,
            ThreatCategory::SiteCustomize,
            ThreatCategory::CredentialAccess,
            ThreatCategory::NetworkAnomaly,
            ThreatCategory::McpViolation,
            ThreatCategory::BudgetOverrun,
            ThreatCategory::NpmLifecycleAttack,
        ];

        for cat in &categories {
            let event = ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: ThreatLevel::Warning,
                category: *cat,
                description: format!("{cat:?} test"),
                source_path: PathBuf::from("/test"),
                creator_pid: None,
                creator_exe: None,
                action_taken: Action::Logged,
            };
            let result = try_append_audit_event(&event, &log_path);
            assert!(result.is_ok(), "failed to write {cat:?} event");
        }

        // Verify all 7 lines are present and parseable
        let content = std::fs::read_to_string(&log_path).expect("read");
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 7, "should have one line per category");

        for line in &lines {
            let parsed: ThreatEvent = serde_json::from_str(line).expect("parse line");
            assert_eq!(parsed.level, ThreatLevel::Warning);
        }
    }

    #[test]
    #[cfg(unix)]
    fn parent_directory_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir for test");
        let log_path = dir.path().join("secure_dir").join("audit.log");

        let event = make_test_event();
        append_audit_event(&event, &log_path);

        let parent_meta =
            std::fs::metadata(dir.path().join("secure_dir")).expect("parent metadata");
        let mode = parent_meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "parent directory should have 0700 permissions");
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlink_at_audit_path() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let target = dir.path().join("real.log");
        let link = dir.path().join("audit.log");

        // Create a real file and a symlink pointing to it
        std::fs::write(&target, "original content").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let event = make_test_event();
        // Should swallow the error (ELOOP) without writing to target
        append_audit_event(&event, &link);

        // Target file should be unmodified
        let content = std::fs::read_to_string(&target).expect("read target");
        assert_eq!(content, "original content");
    }

    #[test]
    #[cfg(unix)]
    fn try_append_returns_err_for_symlink() {
        let dir = tempfile::tempdir().expect("tempdir for test");
        let target = dir.path().join("real.log");
        let link = dir.path().join("audit.log");

        std::fs::write(&target, "original").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let event = make_test_event();
        let result = try_append_audit_event(&event, &link);
        assert!(result.is_err(), "should fail for symlink path");
    }
}
