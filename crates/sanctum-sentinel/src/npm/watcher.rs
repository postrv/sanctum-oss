//! npm lockfile change debouncer.
//!
//! Collects filesystem events for package.json / lockfile changes and
//! batches them into periodic drain windows.  This avoids firing a
//! per-event scan when npm install writes many files in rapid
//! succession.
//!
//! # Capacity bound
//!
//! The pending-path set is bounded to [`MAX_PENDING_PATHS`].  If a burst
//! of unique paths exceeds this limit during a single debounce window,
//! new paths are rejected and a warning is logged.  This prevents
//! unbounded memory growth from a malicious project generating millions
//! of unique package.json events.

use std::collections::HashSet;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Maximum number of unique paths the debouncer will hold in a single
/// window before refusing new entries.
const MAX_PENDING_PATHS: usize = 10_000;

/// Default debounce quiet period.  If no new event arrives within this
/// duration the batch is ready to drain.
const DEFAULT_QUIET_PERIOD: Duration = Duration::from_secs(2);

/// Hard cap on the debounce window.  Even if events keep arriving the
/// batch will be drained after this duration.
const DEFAULT_HARD_CAP: Duration = Duration::from_secs(120);

/// Result of calling [`NpmDebouncer::record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordResult {
    /// The path was accepted into the pending set.
    Accepted,
    /// The pending set has reached its capacity limit.  The caller
    /// should trigger an immediate drain.
    AtCapacity,
}

/// Batching debouncer for npm-related filesystem events.
///
/// Accumulates unique [`PathBuf`] entries and exposes a time-based
/// drain policy:
///
/// 1. **Quiet period** -- if no new event has been recorded for
///    the configured quiet period, the batch is ready.
/// 2. **Hard cap** -- if events keep arriving, the batch is forced
///    out after the hard cap duration regardless.
/// 3. **Capacity** -- if the set reaches [`MAX_PENDING_PATHS`],
///    subsequent calls to [`record()`](NpmDebouncer::record) return
///    [`RecordResult::AtCapacity`] so the caller can drain immediately.
#[derive(Debug)]
pub struct NpmDebouncer {
    pending_paths: HashSet<PathBuf>,
    /// When the first event of the current batch was recorded.
    window_start: Option<Instant>,
    /// When the most recent event was recorded.
    last_event: Option<Instant>,
    quiet_period: Duration,
    hard_cap: Duration,
}

impl NpmDebouncer {
    /// Create a new debouncer with default timing parameters.
    #[must_use]
    pub fn new() -> Self {
        Self {
            pending_paths: HashSet::new(),
            window_start: None,
            last_event: None,
            quiet_period: DEFAULT_QUIET_PERIOD,
            hard_cap: DEFAULT_HARD_CAP,
        }
    }

    /// Create a debouncer with custom timing parameters.
    #[must_use]
    pub fn with_params(quiet_period: Duration, hard_cap: Duration) -> Self {
        Self {
            pending_paths: HashSet::new(),
            window_start: None,
            last_event: None,
            quiet_period,
            hard_cap,
        }
    }

    /// Record a filesystem event for the given path.
    ///
    /// Returns [`RecordResult::AtCapacity`] if the pending set has
    /// reached [`MAX_PENDING_PATHS`], signalling that the caller
    /// should trigger an immediate [`drain`](Self::drain).
    pub fn record(&mut self, path: PathBuf) -> RecordResult {
        let now = Instant::now();

        if self.window_start.is_none() {
            self.window_start = Some(now);
        }
        self.last_event = Some(now);

        if self.pending_paths.len() >= MAX_PENDING_PATHS {
            tracing::warn!(
                max = MAX_PENDING_PATHS,
                "npm debouncer at capacity, rejecting new path"
            );
            return RecordResult::AtCapacity;
        }

        self.pending_paths.insert(path);

        if self.pending_paths.len() >= MAX_PENDING_PATHS {
            RecordResult::AtCapacity
        } else {
            RecordResult::Accepted
        }
    }

    /// Check whether the batch is ready to drain based on timing.
    ///
    /// Returns `true` if:
    /// - There are pending paths **and** the quiet period has elapsed
    ///   since the last event, or
    /// - The hard cap duration has elapsed since the window opened.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        if self.pending_paths.is_empty() {
            return false;
        }

        let now = Instant::now();

        // Hard cap elapsed?
        if let Some(start) = self.window_start {
            if now.duration_since(start) >= self.hard_cap {
                return true;
            }
        }

        // Quiet period elapsed?
        if let Some(last) = self.last_event {
            if now.duration_since(last) >= self.quiet_period {
                return true;
            }
        }

        false
    }

    /// Drain all pending paths, resetting the debouncer for the next batch.
    pub fn drain(&mut self) -> Vec<PathBuf> {
        self.window_start = None;
        self.last_event = None;
        self.pending_paths.drain().collect()
    }

    /// Return the number of pending paths.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending_paths.len()
    }

    /// Return `true` if there are no pending paths.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending_paths.is_empty()
    }

    /// Return the maximum number of pending paths allowed.
    #[must_use]
    pub const fn capacity_limit() -> usize {
        MAX_PENDING_PATHS
    }
}

impl Default for NpmDebouncer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn new_debouncer_is_empty() {
        let d = NpmDebouncer::new();
        assert!(d.is_empty());
        assert_eq!(d.len(), 0);
        assert!(!d.is_ready());
    }

    #[test]
    fn record_accepts_paths() {
        let mut d = NpmDebouncer::new();
        let result = d.record(PathBuf::from("/tmp/project/pkg.json"));
        assert_eq!(result, RecordResult::Accepted);
        assert_eq!(d.len(), 1);
        assert!(!d.is_empty());
    }

    #[test]
    fn duplicate_paths_are_deduplicated() {
        let mut d = NpmDebouncer::new();
        d.record(PathBuf::from("/a/pkg.json"));
        d.record(PathBuf::from("/a/pkg.json"));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn drain_resets_state() {
        let mut d = NpmDebouncer::new();
        d.record(PathBuf::from("/a"));
        d.record(PathBuf::from("/b"));
        let drained = d.drain();
        assert_eq!(drained.len(), 2);
        assert!(d.is_empty());
        assert!(!d.is_ready());
    }

    #[test]
    fn at_capacity_after_max_pending_paths() {
        let mut d = NpmDebouncer::new();
        for i in 0..MAX_PENDING_PATHS - 1 {
            let result = d.record(PathBuf::from(format!("/project/{i}/pkg.json")));
            assert_eq!(
                result,
                RecordResult::Accepted,
                "path {i} should be accepted"
            );
        }
        assert_eq!(d.len(), MAX_PENDING_PATHS - 1);

        // The MAX_PENDING_PATHS-th insert should return AtCapacity
        let result = d.record(PathBuf::from("/project/final/pkg.json"));
        assert_eq!(result, RecordResult::AtCapacity);
        assert_eq!(d.len(), MAX_PENDING_PATHS);
    }

    #[test]
    fn rejects_beyond_capacity() {
        let mut d = NpmDebouncer::new();
        for i in 0..MAX_PENDING_PATHS {
            d.record(PathBuf::from(format!("/p/{i}")));
        }
        assert_eq!(d.len(), MAX_PENDING_PATHS);

        // Further inserts are rejected
        let result = d.record(PathBuf::from("/p/overflow"));
        assert_eq!(result, RecordResult::AtCapacity);
        // Size should not grow beyond limit
        assert_eq!(d.len(), MAX_PENDING_PATHS);
    }

    #[test]
    fn is_ready_after_quiet_period() {
        let mut d =
            NpmDebouncer::with_params(Duration::from_millis(10), Duration::from_secs(120));
        d.record(PathBuf::from("/a"));
        assert!(!d.is_ready());

        // Sleep past the quiet period
        std::thread::sleep(Duration::from_millis(15));
        assert!(d.is_ready());
    }

    #[test]
    fn is_ready_after_hard_cap() {
        let mut d =
            NpmDebouncer::with_params(Duration::from_secs(120), Duration::from_millis(10));
        d.record(PathBuf::from("/a"));

        // Sleep past the hard cap
        std::thread::sleep(Duration::from_millis(15));
        assert!(d.is_ready());
    }

    #[test]
    fn capacity_limit_is_correct() {
        assert_eq!(NpmDebouncer::capacity_limit(), MAX_PENDING_PATHS);
    }

    #[test]
    fn default_creates_new() {
        let d = NpmDebouncer::default();
        assert!(d.is_empty());
    }

    #[test]
    fn drain_after_capacity_allows_new_records() {
        let mut d = NpmDebouncer::new();
        for i in 0..MAX_PENDING_PATHS {
            d.record(PathBuf::from(format!("/p/{i}")));
        }
        assert_eq!(d.len(), MAX_PENDING_PATHS);

        // Drain and verify we can record again
        let drained = d.drain();
        assert_eq!(drained.len(), MAX_PENDING_PATHS);
        assert!(d.is_empty());

        let result = d.record(PathBuf::from("/fresh/path"));
        assert_eq!(result, RecordResult::Accepted);
        assert_eq!(d.len(), 1);
    }
}
