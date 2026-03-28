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
        if !self.pid_file.exists() {
            return Ok(None);
        }

        let pid_str = fs::read_to_string(&self.pid_file).map_err(|e| {
            DaemonError::PidFile {
                path: self.pid_file.clone(),
                source: e,
            }
        })?;

        let pid: u32 = if let Ok(p) = pid_str.trim().parse() { p } else {
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

        // Ensure parent directory exists
        if let Some(parent) = self.pid_file.parent() {
            fs::create_dir_all(parent).map_err(|e| DaemonError::PidFile {
                path: self.pid_file.clone(),
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
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

        self.try_exclusive_create(pid).map_err(|e| DaemonError::PidFile {
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

        // Set owner-only permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(
                &self.pid_file,
                fs::Permissions::from_mode(0o600),
            ) {
                tracing::warn!(
                    path = %self.pid_file.display(),
                    %e,
                    "failed to set PID file permissions"
                );
            }
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
        if self.pid_file.exists() {
            let _ = fs::remove_file(&self.pid_file);
            tracing::info!("PID file removed");
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
        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(raw_pid),
            None,
        )
        .is_ok()
    }

    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}
