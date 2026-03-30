//! TOML configuration loading and validation for the daemon.

use std::fs;
use std::path::{Path, PathBuf};

use sanctum_types::config::{McpDefaultPolicy, PthResponse, SanctumConfig};
use sanctum_types::errors::DaemonError;

/// Maximum config file size (1 MB).
const MAX_CONFIG_SIZE: u64 = 1_048_576;

/// Load configuration from a TOML file.
///
/// Falls back to defaults if the file doesn't exist.
///
/// # Errors
///
/// Returns an error if the file exists but cannot be parsed, or if the file
/// exceeds [`MAX_CONFIG_SIZE`].
pub fn load_config(path: &Path) -> Result<SanctumConfig, DaemonError> {
    if !path.exists() {
        tracing::info!(
            path = %path.display(),
            "config file not found, using defaults"
        );
        return Ok(SanctumConfig::default());
    }

    let meta = fs::metadata(path)
        .map_err(|e| DaemonError::Config(format!("failed to stat {}: {e}", path.display())))?;
    if meta.len() > MAX_CONFIG_SIZE {
        return Err(DaemonError::Config(format!(
            "config file too large ({} bytes, max {MAX_CONFIG_SIZE})",
            meta.len(),
        )));
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
/// - `ai_firewall.default_mcp_policy` cannot be set to `Allow` when global is stricter
/// - `sentinel.watch_pth` forced to `true`
/// - `sentinel.watch_credentials` forced to `true`
/// - `sentinel.pth_response` cannot be downgraded from `Quarantine`
/// - `sentinel.credential_allowlist` must be a subset of the global allowlist
#[allow(clippy::too_many_lines)]
pub fn enforce_security_floor(
    config: &mut SanctumConfig,
    is_project_local: bool,
    global: &SanctumConfig,
) {
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
    // Prevent project-local config from setting default_mcp_policy to Allow or Warn
    // when the global config uses Deny. Warn maps to exit-code 0 so MCP tools
    // still proceed -- it must be treated the same as Allow for security purposes.
    if global.ai_firewall.default_mcp_policy == McpDefaultPolicy::Deny
        && config.ai_firewall.default_mcp_policy != McpDefaultPolicy::Deny
    {
        tracing::warn!(
            "project config tried to weaken default_mcp_policy below deny \u{2014} using global value"
        );
        config.ai_firewall.default_mcp_policy = global.ai_firewall.default_mcp_policy;
    }
    if !config.sentinel.watch_credentials {
        tracing::warn!(
            "project config tried to disable watch_credentials \u{2014} overriding to true"
        );
        config.sentinel.watch_credentials = true;
    }
    // Credential allowlist: project-local list must be a subset of the global list.
    // A project cannot introduce entries not present in the global allowlist.
    let has_non_global_entry = config
        .sentinel
        .credential_allowlist
        .iter()
        .any(|entry| !global.sentinel.credential_allowlist.contains(entry));
    if has_non_global_entry {
        tracing::warn!(
            "project config credential_allowlist contains entries not in global allowlist \u{2014} using global allowlist"
        );
        config
            .sentinel
            .credential_allowlist
            .clone_from(&global.sentinel.credential_allowlist);
    }

    // pth_allowlist: project-local list must be a subset of the global list.
    // A project cannot introduce entries not present in the global allowlist.
    let has_non_global_pth = config
        .sentinel
        .pth_allowlist
        .iter()
        .any(|entry| !global.sentinel.pth_allowlist.contains(entry));
    if has_non_global_pth {
        tracing::warn!(
            "project config pth_allowlist contains entries not in global allowlist \u{2014} using global allowlist"
        );
        config
            .sentinel
            .pth_allowlist
            .clone_from(&global.sentinel.pth_allowlist);
    }

    // MCP rules: global rules always apply. Local rules are additive —
    // they cannot remove or clear global rules, only add more.
    for global_rule in &global.ai_firewall.mcp_rules {
        if !config.ai_firewall.mcp_rules.contains(global_rule) {
            config.ai_firewall.mcp_rules.push(global_rule.clone());
        }
    }

    // Entropy threshold: clamp to 3.5..=6.5 (Shannon entropy bounds).
    if config.ai_firewall.entropy_threshold < 3.5 {
        tracing::warn!(
            "project config entropy_threshold {} below security floor 3.5 \u{2014} clamping",
            config.ai_firewall.entropy_threshold
        );
        config.ai_firewall.entropy_threshold = 3.5;
    }
    if config.ai_firewall.entropy_threshold > 6.5 {
        tracing::warn!(
            "project config entropy_threshold {} above security ceiling 6.5 \u{2014} clamping",
            config.ai_firewall.entropy_threshold
        );
        config.ai_firewall.entropy_threshold = 6.5;
    }

    // Entropy min_length: clamp to 16..=128.
    if config.ai_firewall.entropy_min_length < 16 {
        tracing::warn!(
            "project config entropy_min_length {} below security floor 16 \u{2014} clamping",
            config.ai_firewall.entropy_min_length
        );
        config.ai_firewall.entropy_min_length = 16;
    }
    if config.ai_firewall.entropy_min_length > 128 {
        tracing::warn!(
            "project config entropy_min_length {} above security ceiling 128 \u{2014} clamping",
            config.ai_firewall.entropy_min_length
        );
        config.ai_firewall.entropy_min_length = 128;
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
/// into a single convenience function. When a project-local config is found,
/// the global config is also loaded so security-floor comparisons (e.g.
/// `credential_allowlist`) have a baseline.
///
/// # Errors
///
/// Returns an error if the config file exists but cannot be read or parsed.
pub fn load_and_resolve() -> Result<SanctumConfig, DaemonError> {
    match find_config_path() {
        Some((path, is_project_local)) => {
            let mut config = load_config(&path)?;

            // Load the global config for security-floor comparisons.
            let global = if is_project_local {
                let paths = sanctum_types::paths::WellKnownPaths::default();
                let global_path = paths.config_dir.join("config.toml");
                load_config(&global_path)?
            } else {
                SanctumConfig::default()
            };

            enforce_security_floor(&mut config, is_project_local, &global);
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
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.ai_firewall.claude_hooks = false;
        enforce_security_floor(&mut config, true, &global);
        assert!(config.ai_firewall.claude_hooks);
    }

    #[test]
    fn enforce_security_floor_forces_redact_credentials() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.ai_firewall.redact_credentials = false;
        enforce_security_floor(&mut config, true, &global);
        assert!(config.ai_firewall.redact_credentials);
    }

    #[test]
    fn enforce_security_floor_forces_watch_pth() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.sentinel.watch_pth = false;
        enforce_security_floor(&mut config, true, &global);
        assert!(config.sentinel.watch_pth);
    }

    #[test]
    fn enforce_security_floor_forces_mcp_audit() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.ai_firewall.mcp_audit = false;
        enforce_security_floor(&mut config, true, &global);
        assert!(config.ai_firewall.mcp_audit);
    }

    #[test]
    fn enforce_security_floor_prevents_pth_response_downgrade() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.sentinel.pth_response = PthResponse::Log;
        enforce_security_floor(&mut config, true, &global);
        assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);

        config.sentinel.pth_response = PthResponse::Alert;
        enforce_security_floor(&mut config, true, &global);
        assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);
    }

    #[test]
    fn enforce_security_floor_noop_for_global_config() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.ai_firewall.claude_hooks = false;
        config.ai_firewall.redact_credentials = false;
        config.ai_firewall.mcp_audit = false;
        config.sentinel.watch_pth = false;
        config.sentinel.pth_response = PthResponse::Log;
        enforce_security_floor(&mut config, false, &global);
        // Global config is not subject to the floor.
        assert!(!config.ai_firewall.claude_hooks);
        assert!(!config.ai_firewall.redact_credentials);
        assert!(!config.ai_firewall.mcp_audit);
        assert!(!config.sentinel.watch_pth);
        assert_eq!(config.sentinel.pth_response, PthResponse::Log);
    }

    #[test]
    fn enforce_security_floor_preserves_valid_settings() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        // All defaults are already secure; floor should be a no-op.
        let original = config.clone();
        enforce_security_floor(&mut config, true, &global);
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

    #[test]
    fn enforce_security_floor_forces_watch_credentials() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        config.sentinel.watch_credentials = false;
        enforce_security_floor(&mut config, true, &global);
        assert!(config.sentinel.watch_credentials);
    }

    #[test]
    fn enforce_security_floor_blocks_credential_allowlist_extension() {
        let global = SanctumConfig::default();
        let mut config = SanctumConfig::default();
        // Project-local config tries to add allowlist entries.
        config.sentinel.credential_allowlist = vec!["/usr/bin/sneaky".to_string()];
        enforce_security_floor(&mut config, true, &global);
        // Should be reset to global (empty by default).
        assert!(config.sentinel.credential_allowlist.is_empty());
    }

    #[test]
    fn enforce_security_floor_allows_credential_allowlist_when_subset() {
        let mut global = SanctumConfig::default();
        global.sentinel.credential_allowlist =
            vec!["/usr/bin/git".to_string(), "/usr/bin/ssh".to_string()];
        let mut config = SanctumConfig::default();
        // Project-local config has fewer entries than global — allowed.
        config.sentinel.credential_allowlist = vec!["/usr/bin/git".to_string()];
        enforce_security_floor(&mut config, true, &global);
        assert_eq!(config.sentinel.credential_allowlist.len(), 1);
        assert_eq!(config.sentinel.credential_allowlist[0], "/usr/bin/git");
    }

    #[test]
    fn enforce_security_floor_blocks_mcp_policy_allow_when_global_is_stricter() {
        let mut global = SanctumConfig::default();
        global.ai_firewall.default_mcp_policy = McpDefaultPolicy::Deny;
        let mut config = SanctumConfig::default();
        config.ai_firewall.default_mcp_policy = McpDefaultPolicy::Allow;
        enforce_security_floor(&mut config, true, &global);
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Deny
        );
    }

    #[test]
    fn enforce_security_floor_allows_mcp_policy_deny_when_global_is_allow() {
        let mut global = SanctumConfig::default();
        global.ai_firewall.default_mcp_policy = McpDefaultPolicy::Allow;
        let mut config = SanctumConfig::default();
        config.ai_firewall.default_mcp_policy = McpDefaultPolicy::Deny;
        enforce_security_floor(&mut config, true, &global);
        // Stricter than global is fine.
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Deny
        );
    }

    #[test]
    fn enforce_security_floor_allows_mcp_policy_warn_when_global_is_allow() {
        let mut global = SanctumConfig::default();
        global.ai_firewall.default_mcp_policy = McpDefaultPolicy::Allow;
        let mut config = SanctumConfig::default();
        config.ai_firewall.default_mcp_policy = McpDefaultPolicy::Warn;
        enforce_security_floor(&mut config, true, &global);
        // Warn is stricter than Allow, so it should be kept.
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Warn
        );
    }

    #[test]
    fn test_daemon_floor_blocks_warn_downgrade() {
        let mut global = SanctumConfig::default();
        global.ai_firewall.default_mcp_policy = McpDefaultPolicy::Deny;
        let mut config = SanctumConfig::default();
        config.ai_firewall.default_mcp_policy = McpDefaultPolicy::Warn;
        enforce_security_floor(&mut config, true, &global);
        // Warn maps to exit-code 0, so it must be upgraded to Deny.
        assert_eq!(
            config.ai_firewall.default_mcp_policy,
            McpDefaultPolicy::Deny,
            "Warn should be upgraded to Deny when global is Deny"
        );
    }

    #[test]
    fn test_local_cannot_clear_global_mcp_rules() {
        use sanctum_types::config::McpPolicyRuleConfig;
        let mut global = SanctumConfig::default();
        global.ai_firewall.mcp_rules = vec![McpPolicyRuleConfig {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/secret/**".to_owned()],
        }];
        // Local config has no rules — tries to clear global.
        let mut config = SanctumConfig::default();
        config.ai_firewall.mcp_rules = Vec::new();
        enforce_security_floor(&mut config, true, &global);
        // Global rules must still be present.
        assert_eq!(config.ai_firewall.mcp_rules.len(), 1);
        assert_eq!(config.ai_firewall.mcp_rules[0].tool, "read_file");
    }

    #[test]
    fn test_local_adds_rules_to_global() {
        use sanctum_types::config::McpPolicyRuleConfig;
        let mut global = SanctumConfig::default();
        global.ai_firewall.mcp_rules = vec![McpPolicyRuleConfig {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/secret/**".to_owned()],
        }];
        let mut config = SanctumConfig::default();
        config.ai_firewall.mcp_rules = vec![McpPolicyRuleConfig {
            tool: "write_file".to_owned(),
            restricted_paths: vec!["/tmp/**".to_owned()],
        }];
        enforce_security_floor(&mut config, true, &global);
        // Local rule + global rule should both be present.
        assert_eq!(config.ai_firewall.mcp_rules.len(), 2);
        let tools: Vec<&str> = config.ai_firewall.mcp_rules.iter().map(|r| r.tool.as_str()).collect();
        assert!(tools.contains(&"read_file"));
        assert!(tools.contains(&"write_file"));
    }

    #[test]
    fn test_pth_allowlist_subset_enforcement() {
        use sanctum_types::config::PthAllowlistEntry;
        let mut global = SanctumConfig::default();
        global.sentinel.pth_allowlist = vec![PthAllowlistEntry {
            package: "setuptools".to_owned(),
            hash: "abc123".to_owned(),
        }];
        let mut config = SanctumConfig::default();
        // Local config tries to add a new entry not in global.
        config.sentinel.pth_allowlist = vec![PthAllowlistEntry {
            package: "evil".to_owned(),
            hash: "deadbeef".to_owned(),
        }];
        enforce_security_floor(&mut config, true, &global);
        // Should be replaced with global allowlist.
        assert_eq!(config.sentinel.pth_allowlist.len(), 1);
        assert_eq!(config.sentinel.pth_allowlist[0].package, "setuptools");
    }

    #[test]
    fn test_daemon_floor_clamps_entropy() {
        let global = SanctumConfig::default();

        // Test lower bound clamping
        let mut config = SanctumConfig::default();
        config.ai_firewall.entropy_threshold = 1.0;
        config.ai_firewall.entropy_min_length = 4;
        enforce_security_floor(&mut config, true, &global);
        assert!(
            config.ai_firewall.entropy_threshold >= 3.5,
            "entropy_threshold below 3.5 should be clamped"
        );
        assert!(
            config.ai_firewall.entropy_min_length >= 16,
            "entropy_min_length below 16 should be clamped"
        );

        // Test upper bound clamping
        let mut config = SanctumConfig::default();
        config.ai_firewall.entropy_threshold = 99.0;
        config.ai_firewall.entropy_min_length = 10000;
        enforce_security_floor(&mut config, true, &global);
        assert!(
            config.ai_firewall.entropy_threshold <= 6.5,
            "entropy_threshold above 6.5 should be clamped"
        );
        assert!(
            config.ai_firewall.entropy_min_length <= 128,
            "entropy_min_length above 128 should be clamped"
        );
    }

    #[test]
    fn enforce_security_floor_blocks_allowlist_same_length_different_entries() {
        let mut global = SanctumConfig::default();
        global.sentinel.credential_allowlist = vec!["/usr/bin/git".to_string()];
        let mut config = SanctumConfig::default();
        // Same length but different entry — not a subset of global.
        config.sentinel.credential_allowlist = vec!["/usr/bin/sneaky".to_string()];
        enforce_security_floor(&mut config, true, &global);
        // Should be replaced with global allowlist.
        assert_eq!(
            config.sentinel.credential_allowlist,
            vec!["/usr/bin/git".to_string()]
        );
    }

    #[test]
    fn enforce_security_floor_blocks_allowlist_with_extra_entries() {
        let mut global = SanctumConfig::default();
        global.sentinel.credential_allowlist =
            vec!["/usr/bin/git".to_string(), "/usr/bin/ssh".to_string()];
        let mut config = SanctumConfig::default();
        // Contains a valid entry plus an extra not in global.
        config.sentinel.credential_allowlist =
            vec!["/usr/bin/git".to_string(), "/usr/bin/evil".to_string()];
        enforce_security_floor(&mut config, true, &global);
        // Should be replaced with global allowlist.
        assert_eq!(
            config.sentinel.credential_allowlist,
            vec!["/usr/bin/git".to_string(), "/usr/bin/ssh".to_string()]
        );
    }

    #[test]
    fn load_config_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("huge.toml");
        // Write a file larger than MAX_CONFIG_SIZE (1 MB).
        #[allow(clippy::cast_possible_truncation)]
        let size = (MAX_CONFIG_SIZE as usize) + 1;
        let data = vec![b'#'; size];
        fs::write(&path, &data).expect("write");

        let result = load_config(&path);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("too large"),
            "error should mention size: {msg}"
        );
    }
}
