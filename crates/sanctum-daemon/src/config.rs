//! TOML configuration loading and validation for the daemon.

use std::fs;
use std::path::{Path, PathBuf};

use sanctum_types::config::SanctumConfig;
use sanctum_types::errors::DaemonError;

/// Load configuration from a TOML file.
///
/// Falls back to defaults if the file doesn't exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed.
pub fn load_config(path: &Path) -> Result<SanctumConfig, DaemonError> {
    if !path.exists() {
        tracing::info!(
            path = %path.display(),
            "config file not found, using defaults"
        );
        return Ok(SanctumConfig::default());
    }

    let content = fs::read_to_string(path).map_err(|e| {
        DaemonError::Config(format!("failed to read {}: {e}", path.display()))
    })?;

    toml::from_str(&content).map_err(|e| {
        DaemonError::Config(format!("failed to parse {}: {e}", path.display()))
    })
}

/// Find the configuration file path.
///
/// Searches in order:
/// 1. `.sanctum/config.toml` in the current directory
/// 2. `$XDG_CONFIG_HOME/sanctum/config.toml` (Linux)
/// 3. `~/Library/Application Support/sanctum/config.toml` (macOS)
/// 4. `~/.config/sanctum/config.toml` (fallback)
#[must_use]
pub fn find_config_path() -> Option<PathBuf> {
    // Check current directory first
    let local = PathBuf::from(".sanctum/config.toml");
    if local.exists() {
        return Some(local);
    }

    // Check platform-specific config directory
    let paths = sanctum_types::paths::WellKnownPaths::default();
    let global = paths.config_dir.join("config.toml");
    if global.exists() {
        return Some(global);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_config_returns_defaults_for_missing_file() {
        let config = load_config(Path::new("/nonexistent/config.toml"))
            .expect("should return defaults");
        assert!(config.sentinel.watch_pth);
    }

    #[test]
    fn load_config_parses_valid_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            r#"
            [sentinel]
            watch_pth = false
            pth_response = "alert"
            "#,
        )
        .expect("write");

        let config = load_config(&path).expect("should parse");
        assert!(!config.sentinel.watch_pth);
    }

    #[test]
    fn load_config_rejects_invalid_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, "this is not valid toml {{{").expect("write");

        let result = load_config(&path);
        assert!(result.is_err());
    }
}
