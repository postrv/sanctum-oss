//! Process lineage tracing via `/proc` (Linux) or `sysctl` (macOS).
//!
//! Traces the parent process chain to determine whether a file modification
//! originated from a legitimate package manager (pip, poetry, uv, etc.)
//! or from a suspicious source (e.g., Python startup executing `.pth` code).

use sanctum_types::errors::SentinelError;

/// Known package manager process names.
const KNOWN_PACKAGE_MANAGERS: &[&str] = &[
    "pip",
    "pip3",
    "poetry",
    "uv",
    "conda",
    "pdm",
    "pipx",
    "pip-compile",
    "pip-sync",
    "mamba",
    "micromamba",
];

/// Check if a process name is a known package manager.
#[must_use]
pub(crate) fn is_known_package_manager(name: &str) -> bool {
    KNOWN_PACKAGE_MANAGERS.contains(&name)
}

/// Assessment of a process lineage for `.pth` file creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineageAssessment {
    /// Root ancestor is a known package manager — expected behaviour.
    LegitimatePackageManager,
    /// Python interpreter creating `.pth` during startup — suspicious.
    SuspiciousPythonStartup,
    /// Unknown process creating `.pth` — needs investigation.
    UnknownCreator,
    /// Could not determine lineage (process already exited, etc.).
    Undetermined,
}

/// A single process in the lineage chain.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Process name (from /proc/<pid>/comm or equivalent).
    pub name: String,
    /// Executable path (from /proc/<pid>/exe or equivalent).
    pub exe: Option<std::path::PathBuf>,
    /// Parent PID.
    pub ppid: Option<u32>,
}

/// A complete process lineage from a given PID to init/root.
#[derive(Debug, Clone)]
pub struct ProcessLineage {
    /// The process chain, from the target process to the root ancestor.
    chain: Vec<ProcessInfo>,
}

impl ProcessLineage {
    /// Trace the process lineage for a given PID.
    ///
    /// Uses the provided `ProcSource` to read process information,
    /// allowing for testing with mock data.
    ///
    /// # Errors
    ///
    /// Returns `SentinelError::ProcessNotFound` if the PID doesn't exist.
    /// Terminates after 64 levels of depth to prevent infinite loops.
    #[allow(clippy::similar_names)]
    pub fn trace(pid: u32, source: &dyn ProcSource) -> Result<Self, SentinelError> {
        let mut chain = Vec::new();
        let mut current_pid = pid;
        let mut visited = std::collections::HashSet::new();
        let max_depth = 64;

        for _ in 0..max_depth {
            if visited.contains(&current_pid) {
                // Circular reference detected — stop traversal
                break;
            }
            visited.insert(current_pid);

            let info = source
                .get_process_info(current_pid)
                .ok_or(SentinelError::ProcessNotFound { pid: current_pid })?;

            let parent_pid = info.ppid;
            chain.push(info);

            match parent_pid {
                Some(parent) if parent != 0 && parent != current_pid => {
                    current_pid = parent;
                }
                _ => break,
            }
        }

        if chain.is_empty() {
            return Err(SentinelError::ProcessNotFound { pid });
        }

        Ok(Self { chain })
    }

    /// Check if any ancestor has the given name.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn has_ancestor_named(&self, name: &str) -> bool {
        self.chain.iter().any(|p| p.name == name)
    }

    /// Get the root ancestor (furthest from the target process).
    ///
    /// Returns `None` if the chain is empty (which should not happen
    /// with a validly-constructed `ProcessLineage`, but is safe against
    /// future changes).
    #[must_use]
    pub fn root_ancestor(&self) -> Option<&ProcessInfo> {
        self.chain.last()
    }

    /// Depth of the process chain.
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn depth(&self) -> usize {
        self.chain.len()
    }

    /// Assess whether this lineage is legitimate for `.pth` creation.
    #[must_use]
    pub fn assess_pth_creation(&self) -> LineageAssessment {
        // Check if any ancestor is a known package manager
        if self.chain.iter().any(|p| is_known_package_manager(&p.name)) {
            return LineageAssessment::LegitimatePackageManager;
        }

        // Check for Python startup context (Python creating .pth = suspicious)
        if let Some(creator) = self.chain.first() {
            if creator.name.starts_with("python") {
                // Python itself is creating the .pth — might be a .pth chain reaction
                return LineageAssessment::SuspiciousPythonStartup;
            }
        }

        LineageAssessment::UnknownCreator
    }
}

/// Trait for reading process information, enabling test mocking.
pub trait ProcSource {
    /// Get information about a process by PID.
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo>;
}

/// Mock `/proc` filesystem for testing.
#[cfg(test)]
#[derive(Default)]
pub struct MockProcFs {
    processes: std::collections::HashMap<u32, ProcessInfo>,
}

#[cfg(test)]
impl MockProcFs {
    /// Create a new empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a process to the mock.
    #[must_use]
    #[allow(clippy::similar_names)]
    pub fn process(mut self, pid: u32, name: &str, ppid: Option<u32>) -> Self {
        self.processes.insert(
            pid,
            ProcessInfo {
                pid,
                name: name.to_string(),
                exe: None,
                ppid,
            },
        );
        self
    }
}

#[cfg(test)]
impl ProcSource for MockProcFs {
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        self.processes.get(&pid).cloned()
    }
}

/// Real process information reader using platform-specific APIs.
///
/// On Linux, reads from `/proc/<pid>/status` and `/proc/<pid>/exe`.
/// On macOS, uses `sysctl` via the `nix` crate to query process info.
pub struct SystemProcSource;

impl ProcSource for SystemProcSource {
    fn get_process_info(&self, pid: u32) -> Option<ProcessInfo> {
        platform_get_process_info(pid)
    }
}

#[cfg(target_os = "linux")]
fn platform_get_process_info(pid: u32) -> Option<ProcessInfo> {
    use std::fs;
    use std::path::PathBuf;

    let proc_dir = PathBuf::from(format!("/proc/{pid}"));
    if !proc_dir.exists() {
        return None;
    }

    // Read process name from /proc/<pid>/comm
    let name = fs::read_to_string(proc_dir.join("comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if name.is_empty() {
        return None;
    }

    // Read PPID from /proc/<pid>/status
    let ppid = fs::read_to_string(proc_dir.join("status"))
        .ok()
        .and_then(|content| {
            for line in content.lines() {
                if let Some(val) = line.strip_prefix("PPid:") {
                    return val.trim().parse::<u32>().ok();
                }
            }
            None
        });

    // Read exe path from /proc/<pid>/exe symlink
    let exe = fs::read_link(proc_dir.join("exe")).ok();

    Some(ProcessInfo {
        pid,
        name,
        exe,
        ppid,
    })
}

#[cfg(target_os = "macos")]
fn platform_get_process_info(pid: u32) -> Option<ProcessInfo> {
    use std::path::PathBuf;

    // First check if the process exists via kill(pid, 0)
    let raw_pid = i32::try_from(pid).ok()?;
    let nix_pid = nix::unistd::Pid::from_raw(raw_pid);
    if nix::sys::signal::kill(nix_pid, None).is_err() {
        return None;
    }

    // NOTE: These `ps` calls use `std::process::Command::output()` which blocks
    // without a timeout. This is acceptable because:
    //   1. `ps` queries local kernel state and completes in <10ms.
    //   2. Lineage traversal is depth-limited to 64 iterations (see `trace()`).
    //   3. The caller runs in `spawn_blocking` or a bounded async context.
    // If `ps` were to hang (kernel bug, system under extreme load), the worst
    // case is a stalled lineage trace — the daemon's main event loop is not blocked.

    // Use two separate ps calls for reliable parsing:
    // 1. Get the process command (may contain spaces)
    let comm_output = std::process::Command::new("ps")
        .args(["-o", "comm=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    // 2. Get the parent PID
    let ppid_output = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &pid.to_string()])
        .output()
        .ok()?;

    if !comm_output.status.success() || !ppid_output.status.success() {
        return None;
    }

    let comm_full = String::from_utf8_lossy(&comm_output.stdout)
        .trim()
        .to_string();
    let ppid_str = String::from_utf8_lossy(&ppid_output.stdout)
        .trim()
        .to_string();

    if comm_full.is_empty() {
        return None;
    }

    // Extract just the binary name from a full path (e.g., /usr/bin/python3 -> python3)
    let name = comm_full
        .rsplit('/')
        .next()
        .unwrap_or(&comm_full)
        .to_string();

    let parent_pid = ppid_str.parse::<u32>().ok();

    // Try to get the executable path
    let exe = if comm_full.starts_with('/') {
        Some(PathBuf::from(&comm_full))
    } else {
        None
    };

    Some(ProcessInfo {
        pid,
        name,
        exe,
        ppid: parent_pid,
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_get_process_info(pid: u32) -> Option<ProcessInfo> {
    let _ = pid;
    None
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn lineage_identifies_pip_as_root_ancestor() {
        let mock =
            MockProcFs::new()
                .process(100, "pip", None)
                .process(101, "python3.12", Some(100));

        let lineage = ProcessLineage::trace(101, &mock).expect("lineage should succeed");
        assert!(lineage.has_ancestor_named("pip"));
        let root = lineage.root_ancestor().expect("root should exist");
        assert_eq!(root.name, "pip");
    }

    #[test]
    fn lineage_identifies_poetry_as_root_ancestor() {
        let mock = MockProcFs::new()
            .process(50, "poetry", None)
            .process(51, "python3", Some(50))
            .process(52, "pip", Some(51));

        let lineage = ProcessLineage::trace(52, &mock).expect("lineage should succeed");
        assert!(lineage.has_ancestor_named("poetry"));
    }

    #[test]
    fn lineage_flags_python_startup_creating_pth() {
        let mock = MockProcFs::new()
            .process(1, "zsh", None)
            .process(100, "python3.12", Some(1));

        let lineage = ProcessLineage::trace(100, &mock).expect("lineage should succeed");
        let assessment = lineage.assess_pth_creation();
        assert_eq!(assessment, LineageAssessment::SuspiciousPythonStartup);
    }

    #[test]
    fn lineage_handles_process_that_already_exited() {
        let mock = MockProcFs::new(); // empty — no processes
        let result = ProcessLineage::trace(99999, &mock);
        assert!(result.is_err());
    }

    #[test]
    fn lineage_handles_circular_parent_references() {
        let mock = MockProcFs::new()
            .process(100, "python3", Some(101))
            .process(101, "python3", Some(100));

        let lineage = ProcessLineage::trace(100, &mock).expect("should not infinite loop");
        assert!(lineage.depth() <= 64);
    }

    #[test]
    fn lineage_known_package_managers() {
        for name in &[
            "pip",
            "pip3",
            "poetry",
            "uv",
            "conda",
            "pdm",
            "pipx",
            "pip-compile",
            "pip-sync",
        ] {
            assert!(
                is_known_package_manager(name),
                "{name} should be recognised as a package manager"
            );
        }
    }

    #[test]
    fn lineage_unknown_process_not_recognised() {
        assert!(!is_known_package_manager("curl"));
        assert!(!is_known_package_manager("python3"));
        assert!(!is_known_package_manager("bash"));
    }

    #[test]
    fn root_ancestor_returns_last_in_chain() {
        let mock = MockProcFs::new()
            .process(1, "init", None)
            .process(50, "bash", Some(1))
            .process(100, "python3", Some(50));

        let lineage = ProcessLineage::trace(100, &mock).expect("lineage should succeed");

        let root = lineage.root_ancestor();
        assert!(
            root.is_some(),
            "root_ancestor should return Some for non-empty chain"
        );
        let root = root.expect("just checked");
        assert_eq!(root.name, "init");
        assert_eq!(root.pid, 1);
    }

    #[test]
    fn root_ancestor_single_process() {
        let mock = MockProcFs::new().process(42, "solo", None);

        let lineage = ProcessLineage::trace(42, &mock).expect("lineage should succeed");

        let root = lineage.root_ancestor();
        assert!(root.is_some());
        let root = root.expect("just checked");
        assert_eq!(root.name, "solo");
        assert_eq!(root.pid, 42);
    }

    #[test]
    fn system_proc_source_reads_current_process() {
        let source = SystemProcSource;
        let pid = std::process::id();
        let info = source.get_process_info(pid);
        // We should be able to read our own process info
        assert!(info.is_some(), "should be able to read own process info");
        if let Some(info) = info {
            assert_eq!(info.pid, pid);
            assert!(!info.name.is_empty());
        }
    }

    #[test]
    fn system_proc_source_returns_none_for_nonexistent_pid() {
        let source = SystemProcSource;
        // PID 0 or very large PIDs shouldn't resolve to a normal process
        let info = source.get_process_info(4_294_967_295);
        assert!(info.is_none());
    }
}
