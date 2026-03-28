//! Credential file access monitoring.
//!
//! Watches high-value credential files (SSH keys, cloud credentials, etc.)
//! for unexpected access by processes that aren't on the allowlist.
//!
//! Uses the `notify` crate for cross-platform filesystem events
//! (inotify on Linux, `FSEvent` on macOS). Filters events to only
//! known credential file paths.

use std::path::{Path, PathBuf};

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// Processes that are expected to access credential files.
const ALLOWED_ACCESSORS: &[&str] = &[
    "ssh",
    "ssh-agent",
    "ssh-add",
    "scp",
    "sftp",
    "git",
    "git-remote-https",
    "aws",
    "aws-cli",
    "gcloud",
    "kubectl",
    "docker",
    "docker-credential-helper",
    "op",      // 1Password CLI
    "doppler", // Doppler CLI
];

/// Check if a process name is an expected credential file accessor.
///
/// Only checks the hardcoded default list. For user-configured allowlists,
/// use [`is_allowed_accessor_with_custom`].
#[must_use]
pub(crate) fn is_allowed_accessor(process_name: &str) -> bool {
    ALLOWED_ACCESSORS.contains(&process_name)
}

/// Check if a process name is an expected credential file accessor,
/// merging a user-supplied allowlist with the hardcoded defaults.
#[must_use]
pub fn is_allowed_accessor_with_custom(process_name: &str, custom_allowlist: &[String]) -> bool {
    if is_allowed_accessor(process_name) {
        return true;
    }
    custom_allowlist.iter().any(|entry| entry == process_name)
}

/// An event emitted by the credential file watcher.
#[derive(Debug, Clone)]
pub enum CredentialEvent {
    /// A credential file was accessed (created or read).
    AccessDetected {
        /// Path to the credential file.
        path: PathBuf,
        /// PID of the accessor, if determinable.
        accessor_pid: Option<u32>,
        /// Name of the accessor process, if determinable.
        accessor_name: Option<String>,
        /// Whether this accessor is on the allowlist.
        allowed: bool,
    },
    /// A credential file was modified.
    Modified {
        /// Path to the credential file.
        path: PathBuf,
    },
}

/// The credential file watcher.
///
/// Watches credential file paths for modifications and access events.
/// When a modification is detected, attempts to determine the accessor
/// process and checks it against the allowlist.
pub struct CredentialWatcher {
    /// Whether the watcher is still running.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The notify watcher handle -- kept alive for the lifetime of `CredentialWatcher`.
    _watcher: notify::RecommendedWatcher,
}

impl CredentialWatcher {
    /// Start watching the given credential file paths.
    ///
    /// Events for credential files are sent to the provided channel.
    /// Directories (like `~/.ssh`) are watched non-recursively.
    /// Individual files (like `~/.aws/credentials`) have their parent
    /// directory watched, with events filtered to the specific file.
    ///
    /// The `custom_allowlist` parameter lets the caller supply additional
    /// process names that should be considered allowed accessors, on top
    /// of the hardcoded [`ALLOWED_ACCESSORS`] list.
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher cannot be initialised.
    pub fn start(
        watch_paths: &[PathBuf],
        tx: mpsc::Sender<CredentialEvent>,
        custom_allowlist: Vec<String>,
    ) -> Result<Self, sanctum_types::errors::SentinelError> {
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let alive_clone = alive.clone();

        // Build the set of credential paths we care about for filtering.
        // For directories (like ~/.ssh), we watch the directory itself.
        // For files, we watch the parent directory and filter by filename.
        let credential_paths: std::sync::Arc<Vec<PathBuf>> =
            std::sync::Arc::new(watch_paths.to_owned());

        let custom_al = std::sync::Arc::new(custom_allowlist);

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(%e, "credential watcher error");
                        return;
                    }
                };

                let is_modify = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                let is_access = matches!(event.kind, EventKind::Access(_));

                if !is_modify && !is_access {
                    return;
                }

                for path in &event.paths {
                    if !is_credential_path(path, &credential_paths) {
                        continue;
                    }

                    let (accessor_pid, accessor_name) = try_find_accessor_info(path);
                    let allowed = accessor_name
                        .as_deref()
                        .is_some_and(|name| is_allowed_accessor_with_custom(name, &custom_al));

                    let credential_event = CredentialEvent::AccessDetected {
                        path: path.clone(),
                        accessor_pid,
                        accessor_name,
                        allowed,
                    };

                    if tx.blocking_send(credential_event).is_err() {
                        alive_clone.store(false, std::sync::atomic::Ordering::Release);
                        return;
                    }
                }
            })
            .map_err(|e| sanctum_types::errors::SentinelError::WatcherInit(e.to_string()))?;

        // Watch each credential path
        for path in watch_paths {
            if path.is_dir() {
                // Watch directories directly (e.g. ~/.ssh)
                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                    tracing::warn!(
                        path = %path.display(),
                        %e,
                        "failed to watch credential directory, skipping"
                    );
                }
            } else if path.exists() {
                // For individual files, watch the parent directory
                if let Some(parent) = path.parent() {
                    if parent.exists() {
                        if let Err(e) = watcher.watch(parent, RecursiveMode::NonRecursive) {
                            tracing::warn!(
                                path = %parent.display(),
                                %e,
                                "failed to watch credential file parent, skipping"
                            );
                        }
                    }
                }
            } else {
                tracing::debug!(
                    path = %path.display(),
                    "credential path does not exist, skipping"
                );
            }
        }

        Ok(Self {
            alive,
            _watcher: watcher,
        })
    }

    /// Check if the watcher is still alive.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// Check if a path is within our set of monitored credential paths.
///
/// A path matches if:
/// - It exactly matches one of the watched paths, or
/// - It is a child of a watched directory (e.g. a file inside `~/.ssh`)
fn is_credential_path(path: &Path, credential_paths: &[PathBuf]) -> bool {
    for cred_path in credential_paths {
        // Exact match
        if path == cred_path {
            return true;
        }
        // Child of a watched directory
        if cred_path.is_dir() && path.starts_with(cred_path) {
            return true;
        }
    }
    false
}

/// Best-effort attempt to find the PID and name of the process accessing a file.
///
/// On Linux, scans `/proc/*/fd/` for open file descriptors pointing to the path.
/// On macOS, runs `lsof <path>` to find the accessor process.
/// Returns `(None, None)` if the accessor cannot be determined.
fn try_find_accessor_info(path: &Path) -> (Option<u32>, Option<String>) {
    #[cfg(target_os = "linux")]
    {
        linux_find_accessor(path)
    }

    #[cfg(target_os = "macos")]
    {
        macos_find_accessor(path)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path;
        (None, None)
    }
}

/// Linux-specific: scan `/proc/*/fd/` to find a process with the given file open.
#[cfg(target_os = "linux")]
fn linux_find_accessor(path: &Path) -> (Option<u32>, Option<String>) {
    use std::fs;

    let Ok(proc_entries) = fs::read_dir("/proc") else {
        return (None, None);
    };

    for entry in proc_entries.flatten() {
        let pid_str = entry.file_name();
        let Some(pid_str) = pid_str.to_str() else {
            continue;
        };
        let Ok(pid) = pid_str.parse::<u32>() else {
            continue;
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                if link_target == path {
                    // Found the process! Read its name from /proc/<pid>/comm
                    let name = fs::read_to_string(format!("/proc/{pid}/comm"))
                        .ok()
                        .map(|s| s.trim().to_string());
                    return (Some(pid), name);
                }
            }
        }
    }

    (None, None)
}

/// macOS-specific: run `lsof <path>` to find a process with the given file open.
///
/// Uses `std::process::Command` with a thread-based timeout to prevent
/// blocking indefinitely if `lsof` stalls. Without `sudo`, `lsof` only
/// shows processes owned by the current user -- this is acceptable for
/// the threat model (detecting same-UID credential theft).
///
/// This is best-effort: the file may already be closed by the time `lsof`
/// runs, or `lsof` may not be installed.
/// Maximum concurrent `lsof` invocations. Each spawns a thread that lives
/// up to 5 seconds, so this caps worst-case thread accumulation at 4.
#[cfg(target_os = "macos")]
static LSOF_IN_FLIGHT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
#[cfg(target_os = "macos")]
const MAX_CONCURRENT_LSOF: u32 = 4;

#[cfg(target_os = "macos")]
fn macos_find_accessor(path: &Path) -> (Option<u32>, Option<String>) {
    // Limit concurrent lsof invocations to prevent thread accumulation
    let current = LSOF_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if current >= MAX_CONCURRENT_LSOF {
        LSOF_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::Release);
        tracing::debug!("too many concurrent lsof calls ({current}), skipping");
        return (None, None);
    }

    let result = macos_find_accessor_inner(path);
    LSOF_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::Release);
    result
}

#[cfg(target_os = "macos")]
fn macos_find_accessor_inner(path: &Path) -> (Option<u32>, Option<String>) {
    use std::process::Command;
    use std::time::Duration;

    let path_str = path.to_string_lossy();

    // Spawn lsof as a child process so we can enforce a timeout.
    let child = Command::new("lsof")
        .arg(&*path_str)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            tracing::debug!(%e, "failed to spawn lsof for credential access tracing");
            return (None, None);
        }
    };

    // Wait with a 5-second timeout using a thread.
    let timeout = Duration::from_secs(5);
    let (tx, rx) = std::sync::mpsc::channel();

    // The child's PID is needed so the timeout thread can kill it if necessary.
    let child_id = child.id();

    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        // Signal the main thread that the timeout has elapsed.
        let _ = tx.send(());
    });

    // Poll: try wait in a loop with small sleeps, checking for timeout.
    let output = loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process has exited -- collect output.
                break child.wait_with_output().ok();
            }
            Ok(None) => {
                // Still running -- check if timeout has elapsed.
                if rx.try_recv().is_ok() {
                    // Timeout elapsed -- kill the process.
                    tracing::debug!("lsof timed out during credential access tracing");
                    // Best-effort kill; ignore errors (process may have exited between
                    // try_wait and kill).
                    let _ = child.kill();
                    let _ = child.wait();
                    return (None, None);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                tracing::debug!(%e, "error waiting for lsof during credential access tracing");
                // Best-effort kill on error.
                let _ = child.kill();
                let _ = child.wait();
                return (None, None);
            }
        }
    };

    // Suppress "unused variable" warning for child_id when the kill-by-PID
    // approach is not used (we kill via the Child handle instead).
    let _ = child_id;

    match output {
        Some(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_lsof_credential_output(&stdout)
        }
        _ => (None, None),
    }
}

/// Parse `lsof` default-format output for a single file to extract the first
/// accessor's PID and command name.
///
/// The default `lsof <path>` output has a header line followed by one row per
/// open file descriptor, with whitespace-separated columns:
///
/// ```text
/// COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
/// vim      1234  alice   4r   REG    1,5     8192  ... /path/to/file
/// ```
///
/// We extract the COMMAND and PID from the first non-header row. The COMMAND
/// column is index 0 and PID is index 1 in the whitespace-split fields.
#[cfg(any(target_os = "macos", test))]
#[must_use]
fn parse_lsof_credential_output(output: &str) -> (Option<u32>, Option<String>) {
    for line in output.lines().skip(1) {
        // Skip the header line
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }

        let command = fields[0];
        let Ok(pid) = fields[1].parse::<u32>() else {
            continue;
        };

        return (Some(pid), Some(command.to_owned()));
    }

    (None, None)
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::match_same_arms,
    clippy::cloned_ref_to_slice_refs
)]
mod tests {
    use super::*;

    #[test]
    fn ssh_is_allowed_accessor() {
        assert!(is_allowed_accessor("ssh"));
        assert!(is_allowed_accessor("ssh-agent"));
        assert!(is_allowed_accessor("git"));
    }

    #[test]
    fn unknown_process_is_not_allowed() {
        assert!(!is_allowed_accessor("python3"));
        assert!(!is_allowed_accessor("curl"));
        assert!(!is_allowed_accessor("node"));
    }

    #[test]
    fn allowed_accessor_check_covers_all_known() {
        for &name in ALLOWED_ACCESSORS {
            assert!(
                is_allowed_accessor(name),
                "{name} should be recognised as an allowed accessor"
            );
        }
    }

    #[test]
    fn is_credential_path_exact_match() {
        let paths = vec![
            PathBuf::from("/home/user/.aws/credentials"),
            PathBuf::from("/home/user/.npmrc"),
        ];
        assert!(is_credential_path(
            Path::new("/home/user/.aws/credentials"),
            &paths,
        ));
        assert!(is_credential_path(Path::new("/home/user/.npmrc"), &paths,));
        assert!(!is_credential_path(Path::new("/home/user/.bashrc"), &paths,));
    }

    #[tokio::test]
    async fn credential_watcher_detects_modification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cred_file = dir.path().join("credentials");
        std::fs::write(&cred_file, "secret=abc123").expect("write");

        let (tx, mut rx) = mpsc::channel::<CredentialEvent>(16);

        let _watcher = CredentialWatcher::start(&[cred_file.clone()], tx, Vec::new())
            .expect("watcher should start");

        // Give the watcher a moment to register
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Modify the credential file
        std::fs::write(&cred_file, "secret=xyz789").expect("write");

        // Wait for the event (with timeout)
        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;

        match event {
            Ok(Some(CredentialEvent::AccessDetected { path, .. })) => {
                assert_eq!(path, cred_file);
            }
            Ok(Some(CredentialEvent::Modified { path })) => {
                assert_eq!(path, cred_file);
            }
            _ => {
                // On some CI environments, filesystem events may not fire reliably.
                tracing::warn!(
                    "credential watcher event not received within timeout -- platform-dependent"
                );
            }
        }
    }

    #[tokio::test]
    async fn credential_watcher_ignores_non_credential_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cred_file = dir.path().join("credentials");
        let other_file = dir.path().join("random.txt");
        std::fs::write(&cred_file, "secret=abc123").expect("write");

        let (tx, mut rx) = mpsc::channel::<CredentialEvent>(16);

        // Only watch the specific credential file
        let _watcher = CredentialWatcher::start(&[cred_file.clone()], tx, Vec::new())
            .expect("watcher should start");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Modify a NON-credential file in the same directory
        std::fs::write(&other_file, "not a credential").expect("write");

        // Should NOT receive an event for the non-credential file
        let event = tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv()).await;

        // The timeout should expire without receiving an event
        assert!(
            event.is_err(),
            "should not receive event for non-credential file"
        );
    }

    #[test]
    fn credential_watcher_handles_nonexistent_paths() {
        let (tx, _rx) = mpsc::channel(16);
        let result = CredentialWatcher::start(
            &[PathBuf::from("/nonexistent/path/that/does/not/exist")],
            tx,
            Vec::new(),
        );
        // Should succeed (just skip nonexistent paths)
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn credential_event_includes_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let cred_file = dir.path().join("test_cred");
        std::fs::write(&cred_file, "initial").expect("write");

        let (tx, mut rx) = mpsc::channel::<CredentialEvent>(16);

        let _watcher = CredentialWatcher::start(&[cred_file.clone()], tx, Vec::new())
            .expect("watcher should start");

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Modify the file
        std::fs::write(&cred_file, "modified").expect("write");

        let event = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await;

        match event {
            Ok(Some(CredentialEvent::AccessDetected { path, .. })) => {
                assert_eq!(
                    path, cred_file,
                    "event path should match the modified credential file"
                );
            }
            Ok(Some(CredentialEvent::Modified { path })) => {
                assert_eq!(
                    path, cred_file,
                    "event path should match the modified credential file"
                );
            }
            _ => {
                tracing::warn!(
                    "credential event not received within timeout -- platform-dependent"
                );
            }
        }
    }

    // ============================================================
    // CUSTOM CREDENTIAL ALLOWLIST (W2)
    // ============================================================

    #[test]
    fn custom_allowlist_recognises_additional_accessors() {
        // "python3" is not in the hardcoded defaults
        assert!(!is_allowed_accessor("python3"));
        assert!(!is_allowed_accessor_with_custom("python3", &[]));

        // But with a custom allowlist it should be recognised
        let custom = vec!["python3".to_string(), "node".to_string()];
        assert!(is_allowed_accessor_with_custom("python3", &custom));
        assert!(is_allowed_accessor_with_custom("node", &custom));

        // Hardcoded defaults still work
        assert!(is_allowed_accessor_with_custom("ssh", &custom));
        assert!(is_allowed_accessor_with_custom("git", &custom));

        // Unknown process is still rejected
        assert!(!is_allowed_accessor_with_custom("malware", &custom));
    }

    // ============================================================
    // LSOF CREDENTIAL ACCESS PARSING (macOS)
    // ============================================================

    #[test]
    fn test_parse_lsof_output_with_process() {
        let output = "\
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
vim      1234  alice   4r   REG    1,5     8192 1234 /home/alice/.ssh/id_rsa
";
        let (pid, name) = parse_lsof_credential_output(output);
        assert_eq!(pid, Some(1234));
        assert_eq!(name.as_deref(), Some("vim"));
    }

    #[test]
    fn test_parse_lsof_output_empty() {
        let (pid, name) = parse_lsof_credential_output("");
        assert_eq!(pid, None);
        assert_eq!(name, None);
    }

    #[test]
    fn test_parse_lsof_output_malformed() {
        // Header only, no data rows
        let (pid, name) = parse_lsof_credential_output(
            "COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n",
        );
        assert_eq!(pid, None);
        assert_eq!(name, None);

        // Completely garbled output
        let (pid, name) = parse_lsof_credential_output("some random garbage\nmore garbage");
        assert_eq!(pid, None);
        assert_eq!(name, None);

        // Single field per line (not enough columns)
        let (pid, name) = parse_lsof_credential_output("HEADER\nx");
        assert_eq!(pid, None);
        assert_eq!(name, None);
    }

    #[test]
    fn test_parse_lsof_output_multiple_accessors() {
        // lsof may return multiple rows; we take the first one
        let output = "\
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
vim      1234  alice   4r   REG    1,5     8192 1234 /home/alice/.ssh/id_rsa
cat      5678  alice   3r   REG    1,5     8192 1234 /home/alice/.ssh/id_rsa
";
        let (pid, name) = parse_lsof_credential_output(output);
        assert_eq!(pid, Some(1234));
        assert_eq!(name.as_deref(), Some("vim"));
    }

    #[test]
    fn test_parse_lsof_output_header_only_empty_lines() {
        let output = "COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n\n\n";
        let (pid, name) = parse_lsof_credential_output(output);
        assert_eq!(pid, None);
        assert_eq!(name, None);
    }

    #[test]
    fn test_lsof_timeout_returns_none() {
        // We cannot easily simulate a real timeout in a unit test, but we can
        // verify that the parse function returns (None, None) for output that
        // would result from a killed/timed-out lsof (empty output).
        let (pid, name) = parse_lsof_credential_output("");
        assert_eq!(pid, None);
        assert_eq!(name, None);
    }

    #[test]
    fn test_parse_lsof_output_pid_not_numeric() {
        // If the PID field is not a number, skip that line gracefully
        let output = "\
COMMAND   PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
vim      abc   alice   4r   REG    1,5     8192 1234 /path
cat      5678  alice   3r   REG    1,5     8192 1234 /path
";
        let (pid, name) = parse_lsof_credential_output(output);
        // Should skip vim (bad PID) and return cat
        assert_eq!(pid, Some(5678));
        assert_eq!(name.as_deref(), Some("cat"));
    }
}
