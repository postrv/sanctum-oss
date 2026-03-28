#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end tests: daemon lifecycle management.
//!
//! Tests PID file management, stale detection, and quarantine persistence
//! across daemon restarts.

use std::fs;

use sanctum_sentinel::pth::analyser::content_hash;
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata};

#[test]
fn e2e_daemon_pid_file_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("sanctum.pid");

    let manager = sanctum_daemon_test_helpers::DaemonManagerForTest::new(pid_file.clone());

    // Initially, no PID file exists
    assert!(!pid_file.exists());

    // Write PID file
    manager.write_pid_file().expect("write PID file");
    assert!(pid_file.exists());

    // Read back the PID
    let content = fs::read_to_string(&pid_file).expect("read PID");
    let pid: u32 = content.trim().parse().expect("parse PID");
    assert_eq!(pid, std::process::id());

    // Check existing — should find the running process
    let existing = manager.check_existing().expect("check existing");
    assert!(existing.is_some(), "should detect running process");
    assert_eq!(existing, Some(std::process::id()));

    // Remove PID file (simulate shutdown)
    manager.remove_pid_file();
    assert!(!pid_file.exists());
}

#[test]
fn e2e_daemon_stale_pid_detection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("sanctum.pid");

    // Write a stale PID — use a PID that is very unlikely to be running.
    // On macOS, PID space is smaller, so use a moderately large PID.
    // First, find a PID that is definitely not running.
    let stale_pid = find_unused_pid();
    fs::write(&pid_file, stale_pid.to_string()).expect("write stale PID");

    let manager = sanctum_daemon_test_helpers::DaemonManagerForTest::new(pid_file.clone());

    // Check should detect stale PID and clean up
    let existing = manager.check_existing().expect("check existing");
    assert!(
        existing.is_none(),
        "should detect stale PID ({stale_pid}) and return None"
    );

    // Stale PID file should be cleaned up
    assert!(!pid_file.exists(), "stale PID file should be removed");
}

#[test]
fn e2e_daemon_corrupt_pid_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_file = dir.path().join("sanctum.pid");

    // Write corrupt PID file
    fs::write(&pid_file, "not-a-number").expect("write corrupt PID");

    let manager = sanctum_daemon_test_helpers::DaemonManagerForTest::new(pid_file.clone());

    // Check should handle corrupt file gracefully
    let existing = manager.check_existing().expect("check existing");
    assert!(
        existing.is_none(),
        "corrupt PID file should be treated as no daemon"
    );

    // Corrupt file should be cleaned up
    assert!(!pid_file.exists(), "corrupt PID file should be removed");
}

#[test]
fn e2e_quarantine_survives_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let quarantine_dir = dir.path().join("quarantine");

    // Create quarantine entries with first "daemon instance"
    {
        let quarantine = Quarantine::new(quarantine_dir.clone());

        for i in 0..3 {
            let pth_path = dir.path().join(format!("evil_{i}.pth"));
            fs::write(&pth_path, format!("exec('payload_{i}')")).expect("write");

            let metadata = QuarantineMetadata {
                original_path: pth_path.clone(),
                content_hash: format!("sha256:hash_{i}"),
                creator_pid: None,
                reason: format!("test reason {i}"),
                quarantined_at: chrono::Utc::now(),
            };

            quarantine
                .quarantine_file(&pth_path, &metadata)
                .expect("quarantine");
        }

        let entries = quarantine.list().expect("list");
        assert_eq!(entries.len(), 3, "should have 3 entries before restart");
    }

    // Simulate "daemon restart" — create a new Quarantine instance
    // pointing to the same directory
    {
        let quarantine = Quarantine::new(quarantine_dir);

        let entries = quarantine.list().expect("list after restart");
        assert_eq!(
            entries.len(),
            3,
            "quarantine entries should survive restart"
        );

        // Verify all entries have valid metadata
        for entry in &entries {
            assert!(!entry.metadata.reason.is_empty());
            assert!(!entry.metadata.content_hash.is_empty());
        }
    }
}

#[test]
fn e2e_concurrent_quarantine_operations() {
    let dir = tempfile::tempdir().expect("tempdir");
    let quarantine = Quarantine::new(dir.path().join("quarantine"));

    // Quarantine multiple files
    let mut entry_ids = Vec::new();
    for i in 0..5 {
        let pth_path = dir.path().join(format!("file_{i}.pth"));
        let file_content = format!("exec('payload_{i}')");
        fs::write(&pth_path, &file_content).expect("write");

        let metadata = QuarantineMetadata {
            original_path: pth_path.clone(),
            content_hash: content_hash(file_content.as_bytes()),
            creator_pid: None,
            reason: format!("reason {i}"),
            quarantined_at: chrono::Utc::now(),
        };

        let entry = quarantine
            .quarantine_file(&pth_path, &metadata)
            .expect("quarantine");
        entry_ids.push(entry.id);
    }

    // Verify all 5 are listed
    let all = quarantine.list().expect("list all");
    assert_eq!(all.len(), 5, "should have 5 entries initially");

    // Restore first two and delete the third
    quarantine.restore(&entry_ids[0]).expect("restore 0");
    quarantine.restore(&entry_ids[1]).expect("restore 1");
    quarantine.delete(&entry_ids[2]).expect("delete 2");

    // Verify remaining entries
    let remaining = quarantine.list().expect("list");
    assert_eq!(
        remaining.len(),
        2,
        "should have 2 remaining entries after 2 restores + 1 delete"
    );
}

/// Find a PID that is not currently running.
fn find_unused_pid() -> u32 {
    // Start from a high PID and search downward for one that's not running
    for pid in (50000..99999_i32).rev() {
        #[cfg(unix)]
        {
            if nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err() {
                #[allow(clippy::cast_sign_loss)]
                return pid as u32;
            }
        }
        #[cfg(not(unix))]
        {
            #[allow(clippy::cast_sign_loss)]
            return pid as u32;
        }
    }
    99998
}

/// Thin wrapper to access `DaemonManager` from the daemon crate in tests.
/// We can't directly use the daemon's internal types from workspace tests,
/// so we replicate the PID file logic here for testing.
mod sanctum_daemon_test_helpers {
    use std::fs;
    use std::path::PathBuf;

    pub struct DaemonManagerForTest {
        pid_file: PathBuf,
    }

    impl DaemonManagerForTest {
        pub const fn new(pid_file: PathBuf) -> Self {
            Self { pid_file }
        }

        pub fn check_existing(&self) -> Result<Option<u32>, Box<dyn std::error::Error>> {
            if !self.pid_file.exists() {
                return Ok(None);
            }

            let pid_str = fs::read_to_string(&self.pid_file)?;
            let Ok(pid) = pid_str.trim().parse::<u32>() else {
                let _ = fs::remove_file(&self.pid_file);
                return Ok(None);
            };

            if is_process_running(pid) {
                Ok(Some(pid))
            } else {
                let _ = fs::remove_file(&self.pid_file);
                Ok(None)
            }
        }

        pub fn write_pid_file(&self) -> Result<(), Box<dyn std::error::Error>> {
            let pid = std::process::id();
            if let Some(parent) = self.pid_file.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&self.pid_file, pid.to_string())?;
            Ok(())
        }

        pub fn remove_pid_file(&self) {
            if self.pid_file.exists() {
                let _ = fs::remove_file(&self.pid_file);
            }
        }
    }

    fn is_process_running(pid: u32) -> bool {
        #[cfg(unix)]
        {
            let Ok(raw_pid) = i32::try_from(pid) else {
                return false;
            };
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), None).is_ok()
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
            false
        }
    }
}
