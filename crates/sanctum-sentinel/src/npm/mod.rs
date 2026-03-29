//! npm lifecycle script monitoring.
//!
//! Watches `node_modules` directories for new package installations and
//! scans them for malicious lifecycle scripts (`preinstall`, `install`,
//! `postinstall`). Also monitors lockfile modifications.
//!
//! Uses the `notify` crate for cross-platform filesystem events
//! (inotify on Linux, `FSEvent` on macOS).

use std::path::PathBuf;

use notify::{EventKind, RecursiveMode, Watcher};
use tokio::sync::mpsc;

pub mod scanner;

/// Events emitted by the npm watcher.
#[derive(Debug)]
pub enum NpmEvent {
    /// A new package was installed or modified in `node_modules`.
    PackageChanged {
        /// The package directory that changed.
        package_dir: PathBuf,
        /// The risk assessment from scanning the package.
        risk: scanner::LifecycleRisk,
    },
    /// A lockfile was modified (potentially unexpectedly).
    LockfileModified {
        /// Path to the modified lockfile.
        path: PathBuf,
    },
}

/// Watches `node_modules` directories for new package installations.
///
/// When a filesystem event is detected inside a monitored `node_modules`
/// directory, the watcher scans the affected package for lifecycle script
/// threats and emits an [`NpmEvent`].
pub struct NpmWatcher {
    /// Whether the watcher is still running.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The notify watcher handle -- kept alive for the lifetime of `NpmWatcher`.
    _watcher: notify::RecommendedWatcher,
}

impl NpmWatcher {
    /// Start watching the given project directories for npm package changes.
    ///
    /// For each project directory, monitors:
    /// - `<project>/node_modules/` (recursively) for package installations
    /// - `<project>/` (non-recursively) for lockfile modifications
    ///
    /// # Errors
    ///
    /// Returns an error if the watcher cannot be initialised.
    pub fn start(
        project_dirs: &[PathBuf],
        tx: mpsc::Sender<NpmEvent>,
        allowlist: Vec<String>,
    ) -> Result<Self, sanctum_types::errors::SentinelError> {
        let alive = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let alive_clone = alive.clone();

        let allowlist = std::sync::Arc::new(allowlist);

        let mut watcher =
            notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
                let event = match res {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::warn!(%e, "npm watcher error");
                        return;
                    }
                };

                // Only care about creates and modifications
                let is_relevant = matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_));
                if !is_relevant {
                    return;
                }

                for path in &event.paths {
                    // Check for lockfile changes
                    if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                        if scanner::LOCKFILE_NAMES.contains(&file_name) {
                            let npm_event = NpmEvent::LockfileModified { path: path.clone() };
                            if tx.blocking_send(npm_event).is_err() {
                                alive_clone.store(false, std::sync::atomic::Ordering::Release);
                                return;
                            }
                            continue;
                        }
                    }

                    // Check for package.json changes inside node_modules
                    if is_node_modules_package_json(path) {
                        if let Some(package_dir) = path.parent() {
                            match scanner::scan_package(package_dir, &allowlist) {
                                Ok(risk) => {
                                    if !matches!(risk, scanner::LifecycleRisk::Clean) {
                                        let npm_event = NpmEvent::PackageChanged {
                                            package_dir: package_dir.to_path_buf(),
                                            risk,
                                        };
                                        if tx.blocking_send(npm_event).is_err() {
                                            alive_clone
                                                .store(false, std::sync::atomic::Ordering::Release);
                                            return;
                                        }
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        path = %package_dir.display(),
                                        %e,
                                        "failed to scan npm package"
                                    );
                                }
                            }
                        }
                    }
                }
            })
            .map_err(|e| sanctum_types::errors::SentinelError::WatcherInit(e.to_string()))?;

        for project_dir in project_dirs {
            let node_modules = project_dir.join("node_modules");

            // Watch node_modules recursively for new packages
            if node_modules.exists() {
                if let Err(e) = watcher.watch(&node_modules, RecursiveMode::Recursive) {
                    tracing::warn!(
                        path = %node_modules.display(),
                        %e,
                        "failed to watch node_modules, skipping"
                    );
                }
            } else {
                tracing::debug!(
                    path = %node_modules.display(),
                    "node_modules does not exist, skipping"
                );
            }

            // Watch the project root for lockfile changes
            if project_dir.exists() {
                if let Err(e) = watcher.watch(project_dir, RecursiveMode::NonRecursive) {
                    tracing::warn!(
                        path = %project_dir.display(),
                        %e,
                        "failed to watch project directory for lockfiles, skipping"
                    );
                }
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

/// Check if a path is a `package.json` inside a `node_modules` directory.
fn is_node_modules_package_json(path: &std::path::Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if file_name != "package.json" {
        return false;
    }

    // Walk up the path components to check for "node_modules"
    path.components().any(|c| {
        matches!(
            c,
            std::path::Component::Normal(s) if s.to_str().is_some_and(|s| s == "node_modules")
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ================================================================
    // NpmEvent Debug format
    // ================================================================

    #[test]
    fn npm_event_debug_format() {
        let event = NpmEvent::LockfileModified {
            path: PathBuf::from("/project/package-lock.json"),
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("LockfileModified"));
        assert!(debug.contains("package-lock.json"));

        let event = NpmEvent::PackageChanged {
            package_dir: PathBuf::from("/project/node_modules/evil"),
            risk: scanner::LifecycleRisk::Clean,
        };
        let debug = format!("{event:?}");
        assert!(debug.contains("PackageChanged"));
        assert!(debug.contains("Clean"));
    }

    // ================================================================
    // is_node_modules_package_json
    // ================================================================

    #[test]
    fn detects_package_json_in_node_modules() {
        assert!(is_node_modules_package_json(std::path::Path::new(
            "/project/node_modules/some-pkg/package.json"
        )));
        assert!(is_node_modules_package_json(std::path::Path::new(
            "/project/node_modules/@scope/pkg/package.json"
        )));
    }

    #[test]
    fn ignores_package_json_outside_node_modules() {
        assert!(!is_node_modules_package_json(std::path::Path::new(
            "/project/package.json"
        )));
        assert!(!is_node_modules_package_json(std::path::Path::new(
            "/project/src/package.json"
        )));
    }

    #[test]
    fn ignores_non_package_json_in_node_modules() {
        assert!(!is_node_modules_package_json(std::path::Path::new(
            "/project/node_modules/some-pkg/index.js"
        )));
        assert!(!is_node_modules_package_json(std::path::Path::new(
            "/project/node_modules/some-pkg/README.md"
        )));
    }

    // ================================================================
    // NpmWatcher handles nonexistent paths
    // ================================================================

    #[test]
    fn watcher_handles_nonexistent_paths() {
        let (tx, _rx) = mpsc::channel(16);
        let result = NpmWatcher::start(
            &[PathBuf::from("/nonexistent/project/that/does/not/exist")],
            tx,
            Vec::new(),
        );
        // Should succeed (just skip nonexistent paths)
        assert!(result.is_ok());
    }

    // ================================================================
    // NpmWatcher is_alive
    // ================================================================

    #[test]
    fn watcher_starts_alive() {
        let (tx, _rx) = mpsc::channel(16);
        let watcher = NpmWatcher::start(&[], tx, Vec::new()).expect("watcher should start");
        assert!(watcher.is_alive());
    }
}
