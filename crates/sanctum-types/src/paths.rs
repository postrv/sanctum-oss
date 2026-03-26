//! Well-known filesystem paths used by Sanctum.
//!
//! Follows XDG Base Directory Specification on Linux and standard
//! `~/Library` conventions on macOS.

use std::path::PathBuf;

/// Well-known paths for credential files and Sanctum data.
#[derive(Debug, Clone)]
pub struct WellKnownPaths {
    /// SSH directory (~/.ssh).
    pub ssh_dir: PathBuf,
    /// Sanctum data directory (`XDG_DATA_HOME/sanctum` or ~/Library/Application Support/sanctum).
    pub data_dir: PathBuf,
    /// Sanctum configuration directory (`XDG_CONFIG_HOME/sanctum` or ~/Library/Application Support/sanctum).
    pub config_dir: PathBuf,
    /// Quarantine directory within the data dir.
    pub quarantine_dir: PathBuf,
    /// Audit log directory within the data dir.
    pub log_dir: PathBuf,
    /// PID file location.
    pub pid_file: PathBuf,
    /// IPC socket location.
    pub socket_path: PathBuf,
}

impl WellKnownPaths {
    /// Construct paths for the current platform, returning an error when `HOME`
    /// is not set.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `detect()` returns `None` (i.e. the `HOME` environment
    /// variable is missing).
    pub fn require() -> Result<Self, String> {
        Self::detect()
            .ok_or_else(|| "HOME environment variable not set — cannot determine safe paths".into())
    }

    /// Construct paths for the current platform, respecting XDG on Linux.
    ///
    /// # Errors
    ///
    /// Returns `None` if the home directory cannot be determined.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let home = home_dir()?;
        let ssh_dir = home.join(".ssh");

        let (data_dir, config_dir) = platform_dirs(&home);

        let quarantine_dir = data_dir.join("quarantine");
        let log_dir = data_dir.join("logs");
        let pid_file = data_dir.join("sanctum.pid");
        let socket_path = data_dir.join("sanctum.sock");

        Some(Self {
            ssh_dir,
            data_dir,
            config_dir,
            quarantine_dir,
            log_dir,
            pid_file,
            socket_path,
        })
    }
}

impl Default for WellKnownPaths {
    fn default() -> Self {
        Self::detect().unwrap_or_else(|| {
            // Fallback to /tmp if home dir unavailable (should not happen in practice)
            let fallback = PathBuf::from("/tmp/sanctum");
            Self {
                ssh_dir: PathBuf::from("/tmp/.ssh"),
                data_dir: fallback.clone(),
                config_dir: fallback.clone(),
                quarantine_dir: fallback.join("quarantine"),
                log_dir: fallback.join("logs"),
                pid_file: fallback.join("sanctum.pid"),
                socket_path: fallback.join("sanctum.sock"),
            }
        })
    }
}

/// Credential file paths that Sanctum monitors for unexpected access.
#[must_use]
pub fn credential_paths() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };

    vec![
        home.join(".ssh"),
        home.join(".aws/credentials"),
        home.join(".aws/config"),
        home.join(".config/gcloud"),
        home.join(".azure"),
        home.join(".npmrc"),
        home.join(".pypirc"),
        home.join(".docker/config.json"),
        home.join(".kube/config"),
    ]
}

/// Resolve the home directory.
fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Platform-specific data and config directories.
fn platform_dirs(home: &std::path::Path) -> (PathBuf, PathBuf) {
    #[cfg(target_os = "macos")]
    {
        let base = home.join("Library/Application Support/sanctum");
        (base.clone(), base)
    }

    #[cfg(target_os = "linux")]
    {
        let data = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("sanctum");

        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"))
            .join("sanctum");

        (data, config)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let base = home.join(".sanctum");
        (base.clone(), base)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    /// Run `require()` without HOME set in a child process so we don't
    /// poison the environment for concurrent tests.
    #[test]
    fn require_returns_err_when_home_unset() {
        let exe = std::env::current_exe().expect("current_exe should be available");
        let output = std::process::Command::new(exe)
            .env_remove("HOME")
            .args(["--exact", "paths::tests::require_returns_err_when_home_unset_inner", "--nocapture"])
            .output()
            .expect("failed to spawn subprocess");
        assert!(
            output.status.success(),
            "subprocess failed:\n{}",
            String::from_utf8_lossy(&output.stderr),
        );
    }

    /// Inner test executed only via the subprocess spawned above.
    #[test]
    #[ignore = "executed only via subprocess from require_returns_err_when_home_unset"]
    fn require_returns_err_when_home_unset_inner() {
        let result = WellKnownPaths::require();
        assert!(result.is_err(), "require() should fail without HOME");
        let msg = result.expect_err("already checked is_err");
        assert!(
            msg.contains("HOME environment variable not set"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn well_known_paths_are_platform_appropriate() {
        let paths = WellKnownPaths::default();
        assert!(paths.ssh_dir.ends_with(".ssh"));

        #[cfg(target_os = "linux")]
        assert!(
            paths
                .data_dir
                .to_string_lossy()
                .contains(".local/share/sanctum")
                || paths.data_dir.to_string_lossy().contains("sanctum")
        );

        #[cfg(target_os = "macos")]
        assert!(paths
            .data_dir
            .to_string_lossy()
            .contains("Library/Application Support/sanctum"));
    }

    #[test]
    fn credential_paths_are_not_empty() {
        // Should find paths if HOME is set (which it should be in test environments)
        if std::env::var_os("HOME").is_some() {
            let paths = credential_paths();
            assert!(!paths.is_empty());
        }
    }
}
