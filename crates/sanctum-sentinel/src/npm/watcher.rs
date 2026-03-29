//! npm `node_modules` filesystem watcher.
//!
//! Monitors `node_modules` directories for changes to `package.json` files,
//! using two-phase debouncing to batch scan events during `npm install`.
//!
//! # Debouncing strategy
//!
//! npm/yarn/pnpm installs create many filesystem events in rapid succession.
//! To avoid scanning each package individually during install:
//!
//! 1. On first Create event, enter "install in progress" state.
//! 2. Start a 2-second inactivity timer, reset on each new event.
//! 3. After 2 seconds of silence, batch-scan all accumulated `package.json` files.
//! 4. Hard cap: 120 seconds max wait before forcing a scan.
//!
//! # Capacity bound
//!
//! The pending-path set is bounded to [`MAX_PENDING_PATHS`].  If a burst
//! of unique paths exceeds this limit during a single debounce window,
//! new paths are silently dropped and a warning is logged.  This prevents
//! unbounded memory growth from a malicious project generating millions
//! of unique package.json events.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Inactivity timeout before scanning accumulated files.
const DEBOUNCE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum wait time before forcing a scan of accumulated files.
const MAX_WAIT: Duration = Duration::from_secs(120);

/// Maximum number of unique paths the debouncer will hold in a single
/// window before refusing new entries.
const MAX_PENDING_PATHS: usize = 10_000;

/// Check if a path is a file we should watch inside `node_modules`.
///
/// Only matches `package.json` files.
#[must_use]
pub fn is_npm_watched_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name == "package.json")
}

/// Discover `node_modules` directories under the given project directories.
///
/// For each project directory, checks if a `node_modules` subdirectory exists
/// and returns it. Does not recurse into nested `node_modules`.
///
/// # Arguments
///
/// * `project_dirs` - List of project root directories to check.
///
/// # Returns
///
/// Paths to existing `node_modules` directories.
#[must_use]
pub fn discover_node_modules(project_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for dir in project_dirs {
        let nm_path = Path::new(dir).join("node_modules");
        if nm_path.is_dir() {
            result.push(nm_path);
        }
    }
    result
}

/// Tracks the debounce state for batching npm install events.
///
/// This struct manages the two-phase debouncing logic:
/// - Accumulates `package.json` paths as events arrive (bounded to [`MAX_PENDING_PATHS`])
/// - Tracks the inactivity timer and hard cap deadline
/// - Reports when it is time to scan
#[derive(Debug)]
pub struct NpmDebouncer {
    /// Paths accumulated during the current install window.
    pending_paths: HashSet<PathBuf>,
    /// When the install window started (first event). `None` if idle.
    window_start: Option<Instant>,
    /// When the last event was received.
    last_event: Option<Instant>,
}

impl Default for NpmDebouncer {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmDebouncer {
    /// Create a new idle debouncer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_paths: HashSet::new(),
            window_start: None,
            last_event: None,
        }
    }

    /// Record a new filesystem event for a `package.json` file.
    ///
    /// The path should be the directory containing `package.json` (the package
    /// directory), not the `package.json` file itself.
    ///
    /// If the pending set has reached [`MAX_PENDING_PATHS`], the event is
    /// silently dropped after logging a warning.
    pub fn record_event(&mut self, package_dir: PathBuf) {
        let now = Instant::now();
        if self.window_start.is_none() {
            self.window_start = Some(now);
        }
        self.last_event = Some(now);

        if self.pending_paths.len() >= MAX_PENDING_PATHS {
            tracing::warn!(
                max = MAX_PENDING_PATHS,
                "npm debouncer at capacity, dropping new path"
            );
            return;
        }
        self.pending_paths.insert(package_dir);
    }

    /// Check if the debouncer should trigger a scan.
    ///
    /// Returns `true` if either:
    /// - The inactivity timeout has elapsed since the last event, or
    /// - The hard cap has been reached since the first event.
    ///
    /// Returns `false` if:
    /// - No events have been recorded (idle state), or
    /// - Neither timeout has elapsed yet.
    #[must_use]
    pub fn should_scan(&self) -> bool {
        let Some(window_start) = self.window_start else {
            return false;
        };
        let Some(last_event) = self.last_event else {
            return false;
        };

        let now = Instant::now();

        // Hard cap: force scan after MAX_WAIT since first event
        if now.duration_since(window_start) >= MAX_WAIT {
            return true;
        }

        // Inactivity timeout: scan if DEBOUNCE_TIMEOUT has elapsed since last event
        now.duration_since(last_event) >= DEBOUNCE_TIMEOUT
    }

    /// Drain the accumulated paths, resetting the debouncer to idle state.
    ///
    /// Returns the set of package directories that need scanning.
    pub fn drain(&mut self) -> HashSet<PathBuf> {
        self.window_start = None;
        self.last_event = None;
        std::mem::take(&mut self.pending_paths)
    }

    /// Check if the debouncer has any pending events.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        !self.pending_paths.is_empty()
    }

    /// Time until the next check should occur.
    ///
    /// Returns `None` if idle (no pending events).
    #[must_use]
    pub fn time_until_check(&self) -> Option<Duration> {
        let last_event = self.last_event?;
        let elapsed = Instant::now().duration_since(last_event);
        if elapsed >= DEBOUNCE_TIMEOUT {
            Some(Duration::ZERO)
        } else {
            Some(DEBOUNCE_TIMEOUT.saturating_sub(elapsed))
        }
    }

    /// Return the maximum number of pending paths allowed.
    #[must_use]
    pub const fn capacity_limit() -> usize {
        MAX_PENDING_PATHS
    }
}

/// An npm filesystem event relevant to the watcher.
#[derive(Debug, Clone)]
pub struct NpmWatchEvent {
    /// The package directory containing the modified `package.json`.
    pub package_dir: PathBuf,
    /// Human-readable description of what was detected.
    pub description: String,
    /// The risk level from the scanner.
    pub risk: super::scanner::RiskLevel,
}

/// A raw `package.json` change event from the filesystem watcher.
///
/// Sent from the `NpmWatcher` to the daemon event loop, which manages
/// debouncing and scanning.
#[derive(Debug, Clone)]
pub struct NpmFileEvent {
    /// The directory containing the modified `package.json`.
    pub package_dir: PathBuf,
}

/// The npm `node_modules` filesystem watcher.
///
/// Watches one or more `node_modules` directories for changes to `package.json`
/// files, sending raw events through a channel. The consumer is responsible for
/// debouncing and scanning.
pub struct NpmWatcher {
    /// Whether the watcher is still running.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The notify watcher handle -- kept alive for the lifetime of `NpmWatcher`.
    _watcher: notify::RecommendedWatcher,
}

impl NpmWatcher {
    /// Start watching the given `node_modules` directories.
    ///
    /// Filesystem events for `package.json` files are sent to the provided channel
    /// as `NpmFileEvent`s. The consumer should use an `NpmDebouncer` to batch events.
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher cannot be initialised.
    pub fn start(
        watch_paths: &[PathBuf],
        tx: tokio::sync::mpsc::Sender<NpmFileEvent>,
    ) -> Result<Self, sanctum_types::errors::SentinelError> {
        use notify::{EventKind, RecursiveMode, Watcher};

        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let alive_clone = alive.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(%e, "npm filesystem watcher error");
                        return;
                    }
                };

                // Only process create/modify events
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {}
                    _ => return,
                }

                for path in event.paths {
                    if is_npm_watched_file(&path) {
                        // Send the parent directory (package dir) rather than the file itself
                        let package_dir = path.parent().map(Path::to_path_buf).unwrap_or(path);
                        let file_event = NpmFileEvent { package_dir };
                        if tx.blocking_send(file_event).is_err() {
                            alive_clone
                                .store(false, std::sync::atomic::Ordering::Release);
                            return;
                        }
                    }
                }
            })
            .map_err(|e| sanctum_types::errors::SentinelError::WatcherInit(e.to_string()))?;

        for path in watch_paths {
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::Recursive) {
                    tracing::warn!(
                        path = %path.display(),
                        %e,
                        "failed to watch node_modules directory, skipping"
                    );
                }
            } else {
                tracing::warn!(
                    path = %path.display(),
                    "node_modules path does not exist, skipping"
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

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unchecked_time_subtraction
)]
mod tests {
    use super::*;

    #[test]
    fn is_npm_watched_file_matches_package_json() {
        assert!(is_npm_watched_file(Path::new(
            "/project/node_modules/pkg/package.json"
        )));
        assert!(is_npm_watched_file(Path::new("package.json")));
        assert!(is_npm_watched_file(Path::new(
            "/deep/path/to/package.json"
        )));
    }

    #[test]
    fn is_npm_watched_file_rejects_other_files() {
        assert!(!is_npm_watched_file(Path::new("index.js")));
        assert!(!is_npm_watched_file(Path::new("package-lock.json")));
        assert!(!is_npm_watched_file(Path::new("yarn.lock")));
        assert!(!is_npm_watched_file(Path::new("README.md")));
        assert!(!is_npm_watched_file(Path::new("node_modules")));
        assert!(!is_npm_watched_file(Path::new("")));
    }

    #[test]
    fn discover_node_modules_finds_existing_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nm_dir = dir.path().join("node_modules");
        std::fs::create_dir(&nm_dir).expect("create node_modules");

        let result = discover_node_modules(&[dir.path().to_path_buf()]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], nm_dir);
    }

    #[test]
    fn discover_node_modules_skips_missing_directories() {
        let result = discover_node_modules(&[PathBuf::from("/nonexistent/project")]);
        assert!(result.is_empty());
    }

    #[test]
    fn discover_node_modules_handles_multiple_projects() {
        let dir1 = tempfile::tempdir().expect("tempdir");
        let dir2 = tempfile::tempdir().expect("tempdir");

        // Only dir1 has node_modules
        std::fs::create_dir(dir1.path().join("node_modules")).expect("create");

        let result =
            discover_node_modules(&[dir1.path().to_path_buf(), dir2.path().to_path_buf()]);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn debouncer_idle_should_not_scan() {
        let debouncer = NpmDebouncer::new();
        assert!(!debouncer.should_scan());
        assert!(!debouncer.has_pending());
        assert!(debouncer.time_until_check().is_none());
    }

    #[test]
    fn debouncer_records_events() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));
        assert!(debouncer.has_pending());
        assert!(!debouncer.should_scan()); // too soon
    }

    #[test]
    fn debouncer_drains_pending_paths() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg-a"));
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg-b"));
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg-a")); // duplicate

        let paths = debouncer.drain();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&PathBuf::from("/project/node_modules/pkg-a")));
        assert!(paths.contains(&PathBuf::from("/project/node_modules/pkg-b")));

        // After drain, debouncer is idle
        assert!(!debouncer.has_pending());
        assert!(!debouncer.should_scan());
    }

    #[test]
    fn debouncer_triggers_after_inactivity_timeout() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        // Simulate waiting for the debounce timeout
        debouncer.last_event = Some(Instant::now() - DEBOUNCE_TIMEOUT - Duration::from_millis(10));
        debouncer.window_start =
            Some(Instant::now() - DEBOUNCE_TIMEOUT - Duration::from_millis(10));

        assert!(debouncer.should_scan());
    }

    #[test]
    fn debouncer_triggers_after_hard_cap() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        // Simulate hard cap exceeded: window started MAX_WAIT ago, but last event was just now
        debouncer.window_start = Some(Instant::now() - MAX_WAIT - Duration::from_millis(10));
        debouncer.last_event = Some(Instant::now()); // recent event

        assert!(
            debouncer.should_scan(),
            "should trigger scan after hard cap even with recent events"
        );
    }

    #[test]
    fn debouncer_does_not_trigger_before_timeout() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        // Event was just recorded, neither timeout should have elapsed
        assert!(!debouncer.should_scan());
    }

    #[test]
    fn debouncer_time_until_check_returns_remaining() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        let remaining = debouncer.time_until_check();
        assert!(remaining.is_some());
        let remaining = remaining.unwrap();
        // Should be close to DEBOUNCE_TIMEOUT (within 100ms due to test execution time)
        assert!(remaining <= DEBOUNCE_TIMEOUT);
        assert!(remaining > Duration::from_millis(1800)); // at least 1.8s remaining
    }

    #[test]
    fn debouncer_time_until_check_zero_when_expired() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        // Simulate timeout expired
        debouncer.last_event = Some(Instant::now() - DEBOUNCE_TIMEOUT - Duration::from_millis(10));

        let remaining = debouncer.time_until_check();
        assert_eq!(remaining, Some(Duration::ZERO));
    }

    #[test]
    fn debouncer_real_timeout_with_simulated_time() {
        let mut debouncer = NpmDebouncer::new();
        debouncer.record_event(PathBuf::from("/project/node_modules/pkg"));

        // Should not scan immediately
        assert!(!debouncer.should_scan());

        // Override last_event to simulate passage of time (faster than sleeping 2s)
        debouncer.last_event = Some(Instant::now() - Duration::from_secs(3));
        debouncer.window_start = Some(Instant::now() - Duration::from_secs(3));

        assert!(debouncer.should_scan());
    }

    #[test]
    fn capacity_limit_is_correct() {
        assert_eq!(NpmDebouncer::capacity_limit(), MAX_PENDING_PATHS);
    }

    #[test]
    fn debouncer_respects_capacity_bound() {
        let mut debouncer = NpmDebouncer::new();
        for i in 0..MAX_PENDING_PATHS {
            debouncer.record_event(PathBuf::from(format!("/project/node_modules/pkg-{i}")));
        }
        // At capacity -- further events should be dropped
        debouncer.record_event(PathBuf::from("/project/node_modules/overflow"));
        let paths = debouncer.drain();
        assert_eq!(
            paths.len(),
            MAX_PENDING_PATHS,
            "should not exceed MAX_PENDING_PATHS"
        );
    }

    #[test]
    fn debouncer_drain_resets_capacity() {
        let mut debouncer = NpmDebouncer::new();
        for i in 0..MAX_PENDING_PATHS {
            debouncer.record_event(PathBuf::from(format!("/p/{i}")));
        }
        let drained = debouncer.drain();
        assert_eq!(drained.len(), MAX_PENDING_PATHS);
        assert!(!debouncer.has_pending());

        // After drain, new events should be accepted
        debouncer.record_event(PathBuf::from("/fresh/path"));
        assert!(debouncer.has_pending());
    }
}
