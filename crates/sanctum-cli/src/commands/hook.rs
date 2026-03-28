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
use sanctum_types::errors::CliError;

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
    // Try local (.sanctum/config.toml) then global config, falling back to None.
    let (ai_config, is_project_local) = {
        let local = std::path::PathBuf::from(".sanctum/config.toml");
        let (config_path, is_local) = if local.exists() {
            tracing::warn!(
                path = %local.display(),
                "Loading project-local config from {} \u{2014} verify this file is trusted",
                local.display()
            );
            (Some(local), true)
        } else {
            let paths = sanctum_types::paths::WellKnownPaths::default();
            let global = paths.config_dir.join("config.toml");
            if global.exists() {
                (Some(global), false)
            } else {
                (None, false)
            }
        };
        let cfg = config_path.and_then(|p| {
            std::fs::read_to_string(&p)
                .ok()
                .and_then(|s| toml::from_str::<sanctum_types::config::SanctumConfig>(&s).ok())
                .map(|c| c.ai_firewall)
        });
        (cfg, is_local)
    };

    // Warn if project-local config disables security features
    if is_project_local {
        if let Some(ref cfg) = ai_config {
            if !cfg.redact_credentials {
                tracing::warn!(
                    "Project-local config disables credential redaction (redact_credentials = false)"
                );
            }
            if !cfg.claude_hooks {
                tracing::warn!(
                    "Project-local config disables Claude hooks (claude_hooks = false)"
                );
            }
        }
    }

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
mod tests {
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
}
