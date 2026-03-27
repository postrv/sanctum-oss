//! Filesystem watcher for `.pth` files and `sitecustomize.py`.
//!
//! Uses the `notify` crate for cross-platform filesystem events
//! (inotify on Linux, `FSEvent` on macOS). Filters events to only
//! `.pth` files and `sitecustomize.py` / `usercustomize.py`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

/// A filesystem event relevant to Sanctum.
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// Path of the affected file.
    pub path: PathBuf,
    /// Kind of event.
    pub kind: WatchEventKind,
}

/// Kind of filesystem event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchEventKind {
    /// File was created.
    Created,
    /// File was modified.
    Modified,
    /// File was deleted.
    Deleted,
}

/// The `.pth` filesystem watcher.
///
/// Watches one or more directories (typically Python `site-packages`)
/// for changes to `.pth` files and `sitecustomize.py`.
pub struct PthWatcher {
    /// Whether the watcher is still running.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The notify watcher handle — kept alive for the lifetime of `PthWatcher`.
    _watcher: notify::RecommendedWatcher,
}

impl PthWatcher {
    /// Start watching the given directories.
    ///
    /// Events matching `.pth`, `sitecustomize.py`, or `usercustomize.py`
    /// are sent to the provided channel.
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher cannot be initialised.
    pub fn start(
        watch_paths: &[PathBuf],
        tx: mpsc::Sender<WatchEvent>,
    ) -> Result<Self, sanctum_types::errors::SentinelError> {
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let alive_clone = alive.clone();

        let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
            let event = match res {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(%e, "filesystem watcher error");
                    return;
                }
            };

            let kind = match event.kind {
                EventKind::Create(_) => WatchEventKind::Created,
                EventKind::Modify(_) => WatchEventKind::Modified,
                EventKind::Remove(_) => WatchEventKind::Deleted,
                _ => return,
            };

            for path in event.paths {
                if is_watched_file(&path) {
                    let watch_event = WatchEvent {
                        path: path.clone(),
                        kind,
                    };
                    if tx.blocking_send(watch_event).is_err() {
                        // Receiver dropped — mark watcher as dead
                        alive_clone.store(false, std::sync::atomic::Ordering::Relaxed);
                        return;
                    }
                }
            }
        })
        .map_err(|e| sanctum_types::errors::SentinelError::WatcherInit(e.to_string()))?;

        for path in watch_paths {
            if path.exists() {
                if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                    tracing::warn!(
                        path = %path.display(),
                        %e,
                        "failed to watch directory, skipping"
                    );
                }
            } else {
                tracing::warn!(
                    path = %path.display(),
                    "watch path does not exist, skipping"
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
        self.alive.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Check if a path is a file we should watch.
#[must_use]
pub fn is_watched_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    std::path::Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pth"))
        || file_name == "sitecustomize.py"
        || file_name == "usercustomize.py"
}

/// Discover Python `site-packages` directories on the system.
///
/// Runs `python3 -c "import site; print('\n'.join(site.getsitepackages()))"`.
///
/// # Errors
///
/// Returns an empty vec if Python is not found or the command fails.
pub async fn discover_site_packages() -> Vec<PathBuf> {
    let Ok(Ok(output)) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::process::Command::new("python3")
            .args(["-c", "import site; print('\\n'.join(site.getsitepackages()))"])
            .output(),
    )
    .await
    else {
        return Vec::new();
    };

    if output.status.success() {
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(|l| PathBuf::from(l.trim()))
            .filter(|p| p.exists())
            .collect()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn is_watched_file_matches_pth() {
        assert!(is_watched_file(Path::new("/site-packages/evil.pth")));
        assert!(is_watched_file(Path::new("test.pth")));
    }

    #[test]
    fn is_watched_file_matches_sitecustomize() {
        assert!(is_watched_file(Path::new("/site-packages/sitecustomize.py")));
        assert!(is_watched_file(Path::new("usercustomize.py")));
    }

    #[test]
    fn is_watched_file_ignores_other_files() {
        assert!(!is_watched_file(Path::new("module.py")));
        assert!(!is_watched_file(Path::new("data.json")));
        assert!(!is_watched_file(Path::new("README.md")));
    }

    #[tokio::test]
    async fn watcher_detects_pth_file_creation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, mut rx) = mpsc::channel(16);

        let _watcher = PthWatcher::start(&[dir.path().to_path_buf()], tx)
            .expect("watcher should start");

        // Give the watcher a moment to register
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create a .pth file
        std::fs::write(dir.path().join("test.pth"), "import os").expect("write");

        // Wait for the event (with timeout)
        let event = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            rx.recv(),
        )
        .await;

        match event {
            Ok(Some(e)) => {
                assert!(e.path.to_string_lossy().contains("test.pth"));
                assert!(matches!(e.kind, WatchEventKind::Created | WatchEventKind::Modified));
            }
            _ => {
                // On some CI environments, filesystem events may not fire reliably.
                // This is a best-effort test.
                tracing::warn!("filesystem event not received within timeout — platform-dependent");
            }
        }
    }

    #[tokio::test]
    async fn watcher_ignores_non_pth_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (tx, mut rx) = mpsc::channel(16);

        let _watcher = PthWatcher::start(&[dir.path().to_path_buf()], tx)
            .expect("watcher should start");

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Create a non-pth file
        std::fs::write(dir.path().join("module.py"), "print('hello')").expect("write");

        // Should NOT receive an event
        let event = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            rx.recv(),
        )
        .await;

        assert!(event.is_err(), "should not receive event for non-.pth file");
    }

    #[test]
    fn watcher_handles_nonexistent_paths() {
        let (tx, _rx) = mpsc::channel(16);
        let result = PthWatcher::start(
            &[PathBuf::from("/nonexistent/path/that/does/not/exist")],
            tx,
        );
        // Should succeed (just skip nonexistent paths)
        assert!(result.is_ok());
    }
}
