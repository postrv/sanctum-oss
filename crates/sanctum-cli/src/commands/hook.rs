//! `sanctum hook` — Claude Code hook handler.
//!
//! Invoked by Claude Code's `PreToolUse` and `PostToolUse` hooks. Reads tool
//! invocation JSON from stdin, evaluates it against the firewall policy, and
//! communicates the decision back via exit code and stderr message.
//!
//! Exit codes:
//! - `0` — Allow (or warn).
//! - `2` — Block.

use sanctum_firewall::hooks::claude;
use sanctum_firewall::hooks::protocol::{HookDecision, HookInput, HookOutput};
use sanctum_types::config::AiFirewallConfig;
use sanctum_types::errors::CliError;

/// Return an `AiFirewallConfig` with all protections enabled.
///
/// Used as a fail-closed fallback when a config file exists but cannot be
/// read or parsed.
const fn restrictive_ai_firewall_defaults() -> AiFirewallConfig {
    AiFirewallConfig {
        redact_credentials: true,
        claude_hooks: true,
        mcp_audit: true,
        mcp_rules: Vec::new(),
    }
}

/// Enforce a security floor on project-local AI firewall configs.
///
/// Project-local configs must not disable `claude_hooks` or
/// `redact_credentials`. If they attempt to, the values are forced back
/// to `true` and a warning is emitted.
fn enforce_ai_firewall_security_floor(cfg: &mut AiFirewallConfig) {
    if !cfg.claude_hooks {
        tracing::warn!(
            "Project-local config cannot disable claude_hooks \u{2014} using global default"
        );
        cfg.claude_hooks = true;
    }
    if !cfg.redact_credentials {
        tracing::warn!(
            "Project-local config cannot disable redact_credentials \u{2014} using global default"
        );
        cfg.redact_credentials = true;
    }
}

/// Load AI firewall config from a single config file path.
///
/// If the file cannot be read or parsed, returns restrictive defaults
/// (fail-closed). If `is_local` is `true`, enforces the security floor.
fn load_ai_config_from_path(p: &std::path::Path, is_local: bool) -> AiFirewallConfig {
    let mut cfg = match std::fs::read_to_string(p) {
        Ok(s) => match toml::from_str::<sanctum_types::config::SanctumConfig>(&s) {
            Ok(c) => c.ai_firewall,
            Err(e) => {
                tracing::warn!(
                    path = %p.display(),
                    error = %e,
                    "config parse failed \u{2014} using restrictive defaults"
                );
                restrictive_ai_firewall_defaults()
            }
        },
        Err(e) => {
            tracing::warn!(
                path = %p.display(),
                error = %e,
                "config read failed \u{2014} using restrictive defaults"
            );
            restrictive_ai_firewall_defaults()
        }
    };
    if is_local {
        enforce_ai_firewall_security_floor(&mut cfg);
    }
    cfg
}

/// Locate and load the AI firewall config.
///
/// Tries project-local `.sanctum/config.toml`, then the global config.
/// Returns `None` only when no config file exists at all.
fn load_ai_firewall_config() -> Option<AiFirewallConfig> {
    let local = std::path::PathBuf::from(".sanctum/config.toml");
    if local.exists() {
        tracing::warn!(
            path = %local.display(),
            "Loading project-local config from {} \u{2014} verify this file is trusted",
            local.display()
        );
        return Some(load_ai_config_from_path(&local, true));
    }

    let paths = sanctum_types::paths::WellKnownPaths::default();
    let global = paths.config_dir.join("config.toml");
    if global.exists() {
        return Some(load_ai_config_from_path(&global, false));
    }

    None
}

/// Run a hook action.
///
/// `action` is one of `pre-bash`, `pre-write`, `pre-read`, `pre-mcp`, or `post-bash`.
/// Tool invocation JSON is read from stdin.
pub fn run(action: &str, verbose: bool) -> Result<(), CliError> {
    use std::io::Read;

    if verbose {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
            .with_writer(std::io::stderr)
            .with_target(false)
            .try_init();
    }

    let mut input_str = String::new();
    std::io::stdin()
        .take(1_048_576) // 1MB limit
        .read_to_string(&mut input_str)
        .map_err(|e| CliError::InvalidArgs(format!("failed to read stdin: {e}")))?;

    let mut input: HookInput = serde_json::from_str(&input_str)
        .map_err(|e| CliError::InvalidArgs(format!("invalid hook input JSON: {e}")))?;

    // Load config to respect ai_firewall settings.
    // Fail-closed: if a config file exists but cannot be read or parsed,
    // use restrictive defaults instead of silently disabling protections.
    let ai_config = load_ai_firewall_config();

    input.config.clone_from(&ai_config);
    tracing::debug!(config_loaded = ai_config.is_some(), "firewall config");

    tracing::debug!(%action, tool_name = %input.tool_name, "dispatching hook");

    let output: HookOutput = match action {
        "pre-bash" => claude::pre_bash(&input),
        "pre-write" => claude::pre_write(&input),
        "pre-read" => claude::pre_read(&input),
        "pre-mcp" => claude::pre_mcp_tool_use(&input, None),
        "post-bash" => claude::post_bash(&input),
        _ => {
            return Err(CliError::InvalidArgs(format!(
                "unknown hook action '{action}'. Supported: pre-bash, pre-write, pre-read, pre-mcp, post-bash"
            )));
        }
    };

    tracing::debug!(?output.decision, message = ?output.message, "hook decision");

    match output.decision {
        HookDecision::Allow => {
            // Exit 0 — nothing to print.
        }
        HookDecision::Warn => {
            if let Some(msg) = &output.message {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("sanctum: {msg}");
                }
            }
            // Exit 0 — warn but allow.
        }
        HookDecision::Block => {
            if let Some(msg) = &output.message {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("sanctum: {msg}");
                }
            }
            // Claude Code expects exit code 2 for block decisions.
            std::process::exit(2);
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use sanctum_firewall::hooks::claude;
    use sanctum_firewall::hooks::protocol::{HookDecision, HookInput};
    use serde_json::json;

    fn make_input(tool_name: &str, tool_input: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: tool_name.to_owned(),
            tool_input,
            config: None,
        }
    }

    #[test]
    fn pre_bash_allows_safe_command() {
        let input = make_input("bash", json!({ "command": "ls -la" }));
        let output = claude::pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_blocks_cat_ssh_key() {
        let input = make_input("bash", json!({ "command": "cat ~/.ssh/id_rsa" }));
        let output = claude::pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Block);
        assert!(output.message.is_some());
    }

    #[test]
    fn pre_write_blocks_credential_content() {
        let input = make_input(
            "write",
            json!({
                "file_path": "/tmp/config.yaml",
                "content": "api_key: sk-abcdefghijklmnopqrstuvwxyz"
            }),
        );
        let output = claude::pre_write(&input);
        assert_eq!(output.decision, HookDecision::Block);
        assert!(output.message.is_some());
    }

    #[test]
    fn pre_read_blocks_env_file() {
        let input = make_input("read", json!({ "file_path": "/app/.env" }));
        let output = claude::pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
        assert!(output.message.is_some());
    }

    #[test]
    fn post_bash_always_allows() {
        let input = make_input("bash", json!({ "command": "rm -rf /" }));
        let output = claude::post_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_write_allows_normal_content() {
        let input = make_input(
            "write",
            json!({
                "file_path": "/tmp/hello.txt",
                "content": "Hello, world!"
            }),
        );
        let output = claude::pre_write(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_read_allows_normal_file() {
        let input = make_input(
            "read",
            json!({ "file_path": "/home/user/project/src/main.rs" }),
        );
        let output = claude::pre_read(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn restrictive_defaults_have_all_protections_enabled() {
        let defaults = restrictive_ai_firewall_defaults();
        assert!(defaults.claude_hooks);
        assert!(defaults.redact_credentials);
        assert!(defaults.mcp_audit);
    }

    #[test]
    fn security_floor_forces_claude_hooks_on() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: false,
            redact_credentials: true,
            mcp_audit: true,
            mcp_rules: Vec::new(),
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        assert!(cfg.claude_hooks);
    }

    #[test]
    fn security_floor_forces_redact_credentials_on() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: true,
            redact_credentials: false,
            mcp_audit: true,
            mcp_rules: Vec::new(),
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        assert!(cfg.redact_credentials);
    }

    #[test]
    fn security_floor_preserves_already_enabled() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: true,
            redact_credentials: true,
            mcp_audit: false,
            mcp_rules: Vec::new(),
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        // mcp_audit is not enforced by the floor, so it stays false.
        assert!(!cfg.mcp_audit);
        assert!(cfg.claude_hooks);
        assert!(cfg.redact_credentials);
    }
}
