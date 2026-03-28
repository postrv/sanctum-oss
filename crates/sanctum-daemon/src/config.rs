//! TOML configuration loading and validation for the daemon.

use std::fs;
use std::path::{Path, PathBuf};

use sanctum_types::config::{PthResponse, SanctumConfig};
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

    let content = fs::read_to_string(path)
        .map_err(|e| DaemonError::Config(format!("failed to read {}: {e}", path.display())))?;

    toml::from_str(&content)
        .map_err(|e| DaemonError::Config(format!("failed to parse {}: {e}", path.display())))
}

/// Enforce a security floor on project-local configurations.
///
/// When `is_project_local` is `true`, certain security-critical fields
/// must not be weakened by the project config:
/// - `ai_firewall.claude_hooks` forced to `true`
/// - `ai_firewall.redact_credentials` forced to `true`
/// - `ai_firewall.mcp_audit` forced to `true`
/// - `sentinel.watch_pth` forced to `true`
/// - `sentinel.pth_response` cannot be downgraded from `Quarantine`
pub fn enforce_security_floor(config: &mut SanctumConfig, is_project_local: bool) {
    if !is_project_local {
        return;
    }

    if !config.ai_firewall.claude_hooks {
        tracing::warn!(
            "Project-local config cannot disable claude_hooks \u{2014} using global default"
        );
        config.ai_firewall.claude_hooks = true;
    }
    if !config.ai_firewall.redact_credentials {
        tracing::warn!(
            "Project-local config cannot disable redact_credentials \u{2014} using global default"
        );
        config.ai_firewall.redact_credentials = true;
    }
    if !config.sentinel.watch_pth {
        tracing::warn!(
            "Project-local config cannot disable watch_pth \u{2014} using global default"
        );
        config.sentinel.watch_pth = true;
    }
    // Prevent downgrading pth_response from Quarantine to a weaker action.
    if config.sentinel.pth_response != PthResponse::Quarantine {
        tracing::warn!(
            "Project-local config cannot downgrade pth_response from quarantine \u{2014} using global default"
        );
        config.sentinel.pth_response = PthResponse::Quarantine;
    }
    if !config.ai_firewall.mcp_audit {
        tracing::warn!(
            "Project-local config cannot disable mcp_audit \u{2014} using global default"
        );
        config.ai_firewall.mcp_audit = true;
    }
}

/// Find the configuration file path.
///
/// Searches in order:
/// 1. `.sanctum/config.toml` in the current directory
/// 2. `$XDG_CONFIG_HOME/sanctum/config.toml` (Linux)
/// 3. `~/Library/Application Support/sanctum/config.toml` (macOS)
/// 4. `~/.config/sanctum/config.toml` (fallback)
///
/// Returns the path and a boolean indicating whether the config is
/// project-local (`true`) or global (`false`).
#[must_use]
pub fn find_config_path() -> Option<(PathBuf, bool)> {
    // Check current directory first
    let local = PathBuf::from(".sanctum/config.toml");
    if local.exists() {
        tracing::warn!(
            path = %local.display(),
            "Loading project-local config from {} \u{2014} verify this file is trusted",
            local.display()
        );
        return Some((local, true));
    }

    // Check platform-specific config directory
    let paths = sanctum_types::paths::WellKnownPaths::default();
    let global = paths.config_dir.join("config.toml");
    if global.exists() {
        return Some((global, false));
    }

    None
}

/// Find config, load it, and enforce the security floor.
///
/// Combines `find_config_path`, `load_config`, and `enforce_security_floor`
/// into a single convenience function.
///
/// # Errors
///
/// Returns an error if the config file exists but cannot be read or parsed.
pub fn load_and_resolve() -> Result<SanctumConfig, DaemonError> {
    match find_config_path() {
        Some((path, is_project_local)) => {
            let mut config = load_config(&path)?;
            enforce_security_floor(&mut config, is_project_local);
            Ok(config)
        }
        None => Ok(SanctumConfig::default()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn load_config_returns_defaults_for_missing_file() {
        let config =
            load_config(Path::new("/nonexistent/config.toml")).expect("should return defaults");
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

    #[test]
    fn enforce_security_floor_forces_claude_hooks() {
        let mut config = SanctumConfig::default();
        config.ai_firewall.claude_hooks = false;
        enforce_security_floor(&mut config, true);
        assert!(config.ai_firewall.claude_hooks);
    }

    #[test]
    fn enforce_security_floor_forces_redact_credentials() {
        let mut config = SanctumConfig::default();
        config.ai_firewall.redact_credentials = false;
        enforce_security_floor(&mut config, true);
        assert!(config.ai_firewall.redact_credentials);
    }

    #[test]
    fn enforce_security_floor_forces_watch_pth() {
        let mut config = SanctumConfig::default();
        config.sentinel.watch_pth = false;
        enforce_security_floor(&mut config, true);
        assert!(config.sentinel.watch_pth);
    }

    #[test]
    fn enforce_security_floor_forces_mcp_audit() {
        let mut config = SanctumConfig::default();
        config.ai_firewall.mcp_audit = false;
        enforce_security_floor(&mut config, true);
        assert!(config.ai_firewall.mcp_audit);
    }

    #[test]
    fn enforce_security_floor_prevents_pth_response_downgrade() {
        let mut config = SanctumConfig::default();
        config.sentinel.pth_response = PthResponse::Log;
        enforce_security_floor(&mut config, true);
        assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);

        config.sentinel.pth_response = PthResponse::Alert;
        enforce_security_floor(&mut config, true);
        assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);
    }

    #[test]
    fn enforce_security_floor_noop_for_global_config() {
        let mut config = SanctumConfig::default();
        config.ai_firewall.claude_hooks = false;
        config.ai_firewall.redact_credentials = false;
        config.ai_firewall.mcp_audit = false;
        config.sentinel.watch_pth = false;
        config.sentinel.pth_response = PthResponse::Log;
        enforce_security_floor(&mut config, false);
        // Global config is not subject to the floor.
        assert!(!config.ai_firewall.claude_hooks);
        assert!(!config.ai_firewall.redact_credentials);
        assert!(!config.ai_firewall.mcp_audit);
        assert!(!config.sentinel.watch_pth);
        assert_eq!(config.sentinel.pth_response, PthResponse::Log);
    }

    #[test]
    fn enforce_security_floor_preserves_valid_settings() {
        let mut config = SanctumConfig::default();
        // All defaults are already secure; floor should be a no-op.
        let original = config.clone();
        enforce_security_floor(&mut config, true);
        assert_eq!(
            config.ai_firewall.claude_hooks,
            original.ai_firewall.claude_hooks
        );
        assert_eq!(
            config.ai_firewall.redact_credentials,
            original.ai_firewall.redact_credentials
        );
        assert_eq!(config.ai_firewall.mcp_audit, original.ai_firewall.mcp_audit);
        assert_eq!(config.sentinel.watch_pth, original.sentinel.watch_pth);
        assert_eq!(config.sentinel.pth_response, original.sentinel.pth_response);
    }
}
