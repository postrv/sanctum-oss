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
            tracing::warn!(
                "HOME not set — falling back to user-specific /tmp directory with restricted permissions"
            );

            // Use a user-specific fallback to prevent symlink attacks on shared /tmp.
            // We use the real UID (not PID) so that the directory is stable across
            // process restarts and cannot be recycled by another user.
            #[cfg(unix)]
            let uid = std::process::Command::new("id")
                .arg("-u")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(|s| s.trim().parse::<u32>().ok())
                .unwrap_or_else(std::process::id);
            #[cfg(not(unix))]
            let uid = std::process::id();
            let fallback = PathBuf::from(format!("/tmp/sanctum-{uid}"));

            // Create the directory with restricted permissions (0o700) so other
            // users cannot plant symlinks or read contents.
            #[allow(clippy::let_underscore_must_use)]
            let _ = std::fs::create_dir_all(&fallback);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let perms = std::fs::Permissions::from_mode(0o700);
                #[allow(clippy::let_underscore_must_use)]
                let _ = std::fs::set_permissions(&fallback, perms);
            }

            Self {
                ssh_dir: fallback.join(".ssh"),
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
            .filter(|v| !v.is_empty())
            .map_or_else(|| home.join(".local/share"), PathBuf::from)
            .join("sanctum");

        let config = std::env::var_os("XDG_CONFIG_HOME")
            .filter(|v| !v.is_empty())
            .map_or_else(|| home.join(".config"), PathBuf::from)
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
            .args([
                "--exact",
                "paths::tests::require_returns_err_when_home_unset_inner",
                "--nocapture",
            ])
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

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_xdg_var_uses_default() {
        // When XDG_DATA_HOME is set to "" the code should fall back to the
        // default (~/.local/share) rather than producing a relative path.
        let home = std::env::var("HOME").expect("HOME should be set in test");
        std::env::set_var("XDG_DATA_HOME", "");
        std::env::set_var("XDG_CONFIG_HOME", "");
        let paths = WellKnownPaths::detect().expect("detect should succeed with HOME set");
        std::env::remove_var("XDG_DATA_HOME");
        std::env::remove_var("XDG_CONFIG_HOME");
        assert!(
            paths.data_dir.is_absolute(),
            "data_dir should be absolute, got: {}",
            paths.data_dir.display()
        );
        assert!(
            paths.config_dir.is_absolute(),
            "config_dir should be absolute, got: {}",
            paths.config_dir.display()
        );
        let expected_data = std::path::Path::new(&home).join(".local/share/sanctum");
        assert_eq!(paths.data_dir, expected_data);
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
