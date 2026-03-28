//! Daemon lifecycle management: start, stop, reload, PID file handling.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sanctum_types::errors::DaemonError;

/// Manages the daemon's lifecycle: PID file, start/stop, stale detection.
pub struct DaemonManager {
    pid_file: PathBuf,
}

impl DaemonManager {
    /// Create a new daemon manager.
    #[must_use]
    pub const fn new(pid_file: PathBuf) -> Self {
        Self { pid_file }
    }

    /// Check if a daemon is already running.
    ///
    /// Returns `Some(pid)` if a running daemon is detected,
    /// `None` if no daemon is running (cleans stale PID files).
    ///
    /// # Errors
    ///
    /// Returns an error on I/O failures.
    pub fn check_existing(&self) -> Result<Option<u32>, DaemonError> {
        let pid_str = match fs::read_to_string(&self.pid_file) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => {
                return Err(DaemonError::PidFile {
                    path: self.pid_file.clone(),
                    source: e,
                });
            }
        };

        let pid: u32 = if let Ok(p) = pid_str.trim().parse() {
            p
        } else {
            // Corrupt PID file — remove it
            tracing::warn!("corrupt PID file, removing");
            let _ = fs::remove_file(&self.pid_file);
            return Ok(None);
        };

        // Check if the process is actually running
        if is_process_running(pid) {
            Ok(Some(pid))
        } else {
            // Stale PID file — clean it up
            tracing::info!(pid, "stale PID file detected, cleaning up");
            let _ = fs::remove_file(&self.pid_file);
            Ok(None)
        }
    }

    /// Atomically create and write the PID file using exclusive creation.
    ///
    /// Uses `O_CREAT | O_EXCL` semantics (`create_new`) to prevent TOCTOU races
    /// between checking for an existing daemon and writing the PID file.
    /// If the file already exists, checks whether the recorded PID is still alive:
    /// - If alive, returns `DaemonError::AlreadyRunning`.
    /// - If dead (stale), removes the stale file and retries the exclusive create.
    ///
    /// # Errors
    ///
    /// Returns `DaemonError::AlreadyRunning` if another daemon holds the PID file,
    /// or `DaemonError::PidFile` on I/O failures.
    pub fn write_pid_file(&self) -> Result<(), DaemonError> {
        let pid = std::process::id();

        // Ensure parent directory exists with secure permissions
        if let Some(parent) = self.pid_file.parent() {
            // Create parent directories (grandparents etc.) first
            if let Some(grandparent) = parent.parent() {
                fs::create_dir_all(grandparent).map_err(|e| DaemonError::PidFile {
                    path: self.pid_file.clone(),
                    source: e,
                })?;
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
                    Err(e) => {
                        return Err(DaemonError::PidFile {
                            path: self.pid_file.clone(),
                            source: e,
                        });
                    }
                }
            }
            #[cfg(not(unix))]
            {
                fs::create_dir_all(parent).map_err(|e| DaemonError::PidFile {
                    path: self.pid_file.clone(),
                    source: e,
                })?;
            }
        }

        // First attempt: exclusive create
        match self.try_exclusive_create(pid) {
            Ok(()) => return Ok(()),
            Err(e) => {
                // If not "already exists", propagate the error
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(DaemonError::PidFile {
                        path: self.pid_file.clone(),
                        source: e,
                    });
                }
            }
        }

        // File already exists — check if the recorded PID is still alive
        let existing_pid = self.read_existing_pid();
        if let Some(existing) = existing_pid {
            if is_process_running(existing) {
                return Err(DaemonError::AlreadyRunning(existing));
            }
            tracing::info!(pid = existing, "stale PID file detected, removing");
        } else {
            tracing::warn!("corrupt or empty PID file detected, removing");
        }

        // Remove the stale/corrupt file and retry
        fs::remove_file(&self.pid_file).map_err(|e| DaemonError::PidFile {
            path: self.pid_file.clone(),
            source: e,
        })?;

        self.try_exclusive_create(pid)
            .map_err(|e| DaemonError::PidFile {
                path: self.pid_file.clone(),
                source: e,
            })
    }

    /// Attempt to exclusively create the PID file and write the given PID.
    ///
    /// Returns `Ok(())` on success, or the raw `io::Error` on failure.
    fn try_exclusive_create(&self, pid: u32) -> Result<(), std::io::Error> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.pid_file)?;

        file.write_all(pid.to_string().as_bytes())?;
        file.sync_all()?;

        // Set owner-only permissions via fchmod on the fd (TOCTOU-safe)
        if let Err(e) = sanctum_types::fs_safety::fchmod_600(&file) {
            tracing::warn!(
                path = %self.pid_file.display(),
                %e,
                "failed to set PID file permissions"
            );
        }

        tracing::info!(pid, path = %self.pid_file.display(), "PID file written");
        Ok(())
    }

    /// Read and parse the PID from an existing PID file.
    ///
    /// Returns `None` if the file cannot be read or contains invalid data.
    fn read_existing_pid(&self) -> Option<u32> {
        let content = fs::read_to_string(&self.pid_file).ok()?;
        content.trim().parse().ok()
    }

    /// Remove the PID file (called on shutdown).
    pub fn remove_pid_file(&self) {
        match fs::remove_file(&self.pid_file) {
            Ok(()) => {
                tracing::info!("PID file removed");
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Already gone — nothing to do
            }
            Err(e) => {
                tracing::warn!(
                    path = %self.pid_file.display(),
                    %e,
                    "failed to remove PID file"
                );
            }
        }
    }
}

impl Drop for DaemonManager {
    fn drop(&mut self) {
        self.remove_pid_file();
    }
}

/// Check if a process with the given PID is running.
fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let Ok(raw_pid) = i32::try_from(pid) else {
            return false;
        };
        // Signal 0 checks process existence without actually sending a signal
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw_pid), None).is_ok()
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn check_existing_returns_none_for_nonexistent_pid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("nonexistent.pid");
        let manager = DaemonManager::new(pid_file);

        let result = manager.check_existing().expect("should not error");
        assert!(
            result.is_none(),
            "should return None when PID file does not exist"
        );

        // Prevent Drop from trying to remove the non-existent file (no-op anyway)
        std::mem::forget(manager);
    }

    #[test]
    fn check_existing_returns_none_for_stale_pid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("stale.pid");
        // Write a PID that definitely isn't running (PID 999999999)
        fs::write(&pid_file, "999999999").expect("write pid");

        let manager = DaemonManager::new(pid_file);
        let result = manager.check_existing().expect("should not error");
        assert!(result.is_none(), "should return None for stale PID");

        std::mem::forget(manager);
    }

    #[test]
    fn remove_pid_file_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pid_file = dir.path().join("test.pid");
        fs::write(&pid_file, "12345").expect("write pid");

        let manager = DaemonManager::new(pid_file.clone());

        // First remove should succeed
        manager.remove_pid_file();
        assert!(!pid_file.exists());

        // Second remove should not panic (NotFound is ignored)
        manager.remove_pid_file();

        std::mem::forget(manager);
    }
}
