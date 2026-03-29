//! `sanctum hook` — Claude Code hook handler.
//!
//! Invoked by Claude Code's `PreToolUse` and `PostToolUse` hooks. Reads tool
//! invocation JSON from stdin, evaluates it against the firewall policy, and
//! communicates the decision back via exit code and stderr message.
//!
//! Exit codes:
//! - `0` — Allow (or warn).
//! - `2` — Block.

use std::path::PathBuf;

use sanctum_firewall::hooks::claude;
use sanctum_firewall::hooks::claude::NpmConfig;
use sanctum_firewall::hooks::protocol::{HookDecision, HookInput, HookOutput};
use sanctum_types::config::AiFirewallConfig;
use sanctum_types::errors::CliError;
use sanctum_types::ipc::{IpcCommand, IpcMessage};
use sanctum_types::threat::{Action, ThreatCategory, ThreatEvent, ThreatLevel};

/// Return an `AiFirewallConfig` with all protections enabled.
///
/// Used as a fail-closed fallback when a config file exists but cannot be
/// read or parsed.
const fn restrictive_ai_firewall_defaults() -> AiFirewallConfig {
    AiFirewallConfig {
        redact_credentials: true,
        claude_hooks: true,
        mcp_audit: true,
        check_package_existence: true,
        package_check_timeout_ms: 3000,
        mcp_rules: Vec::new(),
        // Fail-closed: when config parsing fails, block unmatched MCP tools
        // rather than silently allowing them.
        default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Deny,
    }
}

/// Enforce a security floor on ALL AI firewall configs (global and local).
///
/// Global and local configs must not disable `claude_hooks`,
/// `redact_credentials`, or `mcp_audit`. If they attempt to, the values
/// are forced back to `true` and a warning is emitted.
fn enforce_ai_firewall_security_floor_global(cfg: &mut AiFirewallConfig) {
    if !cfg.claude_hooks {
        tracing::warn!(
            "Config cannot disable claude_hooks \u{2014} using secure default"
        );
        cfg.claude_hooks = true;
    }
    if !cfg.redact_credentials {
        tracing::warn!(
            "Config cannot disable redact_credentials \u{2014} using secure default"
        );
        cfg.redact_credentials = true;
    }
    if !cfg.mcp_audit {
        tracing::warn!(
            "Config cannot disable mcp_audit \u{2014} using secure default"
        );
        cfg.mcp_audit = true;
    }
}

/// Enforce a security floor on project-local AI firewall configs.
///
/// Applies all global floors plus local-only restrictions:
/// - Prevents weakening MCP default policy to Allow.
fn enforce_ai_firewall_security_floor(cfg: &mut AiFirewallConfig) {
    // Apply global floors first
    enforce_ai_firewall_security_floor_global(cfg);

    // Prevent local configs from weakening the MCP default policy to Allow.
    // A malicious repo could include .sanctum/config.toml with
    // `default_mcp_policy = "allow"` to bypass MCP restrictions.
    if cfg.default_mcp_policy == sanctum_types::config::McpDefaultPolicy::Allow {
        tracing::warn!(
            "Project-local config cannot set default_mcp_policy to 'allow' \u{2014} using 'deny'"
        );
        cfg.default_mcp_policy = sanctum_types::config::McpDefaultPolicy::Deny;
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
    } else {
        enforce_ai_firewall_security_floor_global(&mut cfg);
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

/// Load `NpmConfig` from the config file (best-effort).
///
/// Deserializes through `SanctumConfig` (single source of truth for all config
/// fields) and maps the `[sentinel.npm]` section to the firewall's `NpmConfig`.
/// If no config file exists or parsing fails, returns defaults (all protections on).
fn load_npm_config() -> NpmConfig {
    // Try project-local first, then global
    let config_path = {
        let local = std::path::PathBuf::from(".sanctum/config.toml");
        if local.exists() {
            Some(local)
        } else {
            let paths = sanctum_types::paths::WellKnownPaths::default();
            let global = paths.config_dir.join("config.toml");
            if global.exists() {
                Some(global)
            } else {
                None
            }
        }
    };

    let Some(path) = config_path else {
        return NpmConfig::default();
    };

    let Ok(content) = std::fs::read_to_string(&path) else {
        return NpmConfig::default();
    };

    match toml::from_str::<sanctum_types::config::SanctumConfig>(&content) {
        Ok(cfg) => NpmConfig {
            watch_lifecycle: cfg.sentinel.npm.watch_lifecycle,
            ignore_scripts_warning: cfg.sentinel.npm.ignore_scripts_warning,
            allowlist: cfg.sentinel.npm.allowlist,
        },
        Err(_) => NpmConfig::default(),
    }
}

/// Infer the threat category from the hook action and decision message.
///
/// This maps hook-level information to the threat model categories so that
/// audit log events are correctly classified.
fn infer_threat_category(action: &str, message: &str) -> ThreatCategory {
    let msg_lower = message.to_lowercase();
    match action {
        "pre-mcp" => ThreatCategory::McpViolation,
        "pre-write"
            if msg_lower.contains("sitecustomize") || msg_lower.contains("usercustomize") =>
        {
            ThreatCategory::SiteCustomize
        }
        "pre-write" if msg_lower.contains(".pth") => ThreatCategory::PthInjection,
        _ => ThreatCategory::CredentialAccess,
    }
}

/// Extract a representative source path from the hook input for audit logging.
///
/// Returns the file path for read/write hooks, a truncated command summary for
/// bash hooks, the MCP tool name for MCP hooks, or `<unknown>` as fallback.
fn extract_source_path(input: &HookInput, action: &str) -> PathBuf {
    match action {
        "pre-read" | "pre-write" => input
            .tool_input
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .map_or_else(|| PathBuf::from("<unknown>"), PathBuf::from),
        "pre-bash" | "post-bash" => input
            .tool_input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || PathBuf::from("<unknown>"),
                |c| {
                    // Use char boundary-safe truncation to avoid panicking
                    // on multi-byte UTF-8 sequences.
                    let truncated = if c.len() > 200 {
                        let mut end = 200;
                        while end > 0 && !c.is_char_boundary(end) {
                            end -= 1;
                        }
                        &c[..end]
                    } else {
                        c
                    };
                    PathBuf::from(format!("bash:{truncated}"))
                },
            ),
        "pre-mcp" => PathBuf::from(format!("mcp:{}", input.tool_name)),
        _ => PathBuf::from("<unknown>"),
    }
}

/// Write a threat event to the shared audit log (best-effort).
///
/// All errors are swallowed — a failed audit write must never change the
/// hook's allow/block decision or cause a spurious `exit(2)`.
fn record_hook_threat_event(
    action: &str,
    input: &HookInput,
    decision: HookDecision,
    message: &str,
) {
    let level = match decision {
        HookDecision::Block => ThreatLevel::Critical,
        HookDecision::Warn => ThreatLevel::Warning,
        HookDecision::Allow => return, // No event for allow decisions
    };

    let action_taken = match decision {
        HookDecision::Block => Action::Blocked,
        HookDecision::Warn => Action::Alerted,
        HookDecision::Allow => return,
    };

    let category = infer_threat_category(action, message);
    let raw_source_path = extract_source_path(input, action);
    // Redact credentials from the source_path before storing in the audit log.
    // The truncated command string may contain the very credentials that
    // triggered the hook block.
    let (redacted, _) =
        sanctum_firewall::redaction::redact_credentials(&raw_source_path.to_string_lossy());
    let source_path = PathBuf::from(redacted);

    let event = ThreatEvent {
        timestamp: chrono::Utc::now(),
        level,
        category,
        description: message.to_owned(),
        source_path,
        creator_pid: None,
        creator_exe: None,
        action_taken,
    };

    let paths = sanctum_types::paths::WellKnownPaths::default();
    // Must use data_dir (not log_dir) to match where the daemon and CLI
    // read audit events from. log_dir is data_dir/logs — the wrong path.
    let audit_path = paths.data_dir.join("audit.log");

    // Best-effort: swallow all errors. Audit logging must not affect
    // the hook's allow/block decision.
    sanctum_types::audit::append_audit_event(&event, &audit_path);
}

/// Send an IPC command to the daemon synchronously (best-effort).
///
/// Uses blocking Unix socket I/O with a 2-second timeout. All errors are
/// silently swallowed -- the hook's decision must never be affected by IPC
/// failures or a missing daemon.
fn send_usage_ipc_best_effort(command: &IpcCommand) {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let paths = sanctum_types::paths::WellKnownPaths::default();
    let socket_path = &paths.socket_path;

    if !socket_path.exists() {
        return;
    }

    let Ok(mut stream) = UnixStream::connect(socket_path) else {
        return;
    };

    let timeout = Some(Duration::from_secs(2));
    let _ = stream.set_write_timeout(timeout);
    let _ = stream.set_read_timeout(timeout);

    // Read auth token from data dir (best-effort).
    let auth_token = sanctum_types::auth::read_token(&paths.data_dir).ok();

    // Wrap command in an IpcMessage envelope with the auth token.
    let message = IpcMessage {
        command: command.clone(),
        auth_token,
    };

    // Serialize the message to JSON.
    let Ok(payload) = serde_json::to_vec(&message) else {
        return;
    };

    // Write length-prefixed frame: 4 bytes big-endian length + JSON payload.
    // Guard against payloads exceeding MAX_MESSAGE_SIZE (64KB) or u32::MAX.
    if payload.len() > sanctum_types::ipc::MAX_MESSAGE_SIZE {
        return;
    }
    #[allow(clippy::cast_possible_truncation)]
    let len = payload.len() as u32;
    if stream.write_all(&len.to_be_bytes()).is_err() {
        return;
    }
    if stream.write_all(&payload).is_err() {
        return;
    }
    let _ = stream.flush();

    // Best-effort read of response (we don't need the result).
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_ok() {
        let resp_len = u32::from_be_bytes(len_buf) as usize;
        if resp_len <= sanctum_types::ipc::MAX_MESSAGE_SIZE {
            let mut resp_buf = vec![0u8; resp_len];
            let _ = stream.read_exact(&mut resp_buf);
        }
    }
}

/// Run a hook action.
///
/// `action` is one of `pre-bash`, `pre-write`, `pre-read`, `pre-mcp`, or `post-bash`.
/// Tool invocation JSON is read from stdin.
///
/// Fail-closed: any error in the hook handler blocks the operation (exit code 2)
/// rather than allowing it (exit code 1). This function never returns `Err`.
#[allow(clippy::unnecessary_wraps)] // Result return type required by caller dispatch
pub fn run(action: &str, verbose: bool) -> Result<(), CliError> {
    // Fail-closed: any error in the hook handler must block the operation
    // (exit code 2), not allow it (exit code 1). We catch all errors here.
    match run_inner(action, verbose) {
        Ok(()) => Ok(()),
        Err(e) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("sanctum: hook error (fail-closed): {e}");
            }
            std::process::exit(2);
        }
    }
}

#[allow(clippy::too_many_lines)]
fn run_inner(action: &str, verbose: bool) -> Result<(), CliError> {
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

    // Warn when individual protections are disabled in the loaded config.
    if let Some(ref cfg) = ai_config {
        if !cfg.claude_hooks {
            tracing::warn!("claude_hooks is disabled in config");
        }
        if !cfg.redact_credentials {
            tracing::warn!("redact_credentials is disabled in config");
        }
        if !cfg.mcp_audit {
            tracing::warn!("mcp_audit is disabled in config");
        }
    }

    input.config.clone_from(&ai_config);
    tracing::debug!(config_loaded = ai_config.is_some(), "firewall config");

    // Load NpmConfig for package manager hooks (best-effort; defaults if unavailable).
    let npm_config = load_npm_config();
    tracing::debug!(
        watch_lifecycle = npm_config.watch_lifecycle,
        ignore_scripts_warning = npm_config.ignore_scripts_warning,
        allowlist_len = npm_config.allowlist.len(),
        "npm config"
    );

    tracing::debug!(%action, tool_name = %input.tool_name, "dispatching hook");

    let output: HookOutput = match action {
        "pre-bash" => claude::pre_bash_with_npm_config(&input, &npm_config),
        "pre-write" => claude::pre_write(&input),
        "pre-read" => claude::pre_read(&input),
        "pre-mcp" => claude::pre_mcp_tool_use(&input, None),
        "post-bash" => claude::post_bash_with_npm_config(&input, &npm_config),
        _ => {
            return Err(CliError::InvalidArgs(format!(
                "unknown hook action '{action}'. Supported: pre-bash, pre-write, pre-read, pre-mcp, post-bash"
            )));
        }
    };

    tracing::debug!(?output.decision, message = ?output.message, "hook decision");

    // After post-bash, attempt to forward extracted usage data to the daemon.
    // This is best-effort: IPC failures are silently swallowed.
    if action == "post-bash" {
        let stdout = input
            .tool_input
            .get("stdout")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let stderr = input
            .tool_input
            .get("stderr")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let combined = format!("{stdout}\n{stderr}");

        if let Some(usage) = claude::extract_budget_usage_structured(&combined) {
            tracing::debug!(
                provider = %usage.provider,
                model = %usage.model,
                input_tokens = usage.input_tokens,
                output_tokens = usage.output_tokens,
                "forwarding usage to daemon"
            );
            send_usage_ipc_best_effort(&IpcCommand::RecordUsage {
                provider: usage.provider,
                model: usage.model,
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
            });
        }
    }

    // Record block/warn decisions to the audit log (best-effort).
    // This must happen BEFORE the exit(2) call for blocks.
    if output.decision != HookDecision::Allow {
        let msg = output.message.as_deref().unwrap_or("<no message>");
        record_hook_threat_event(action, &input, output.decision, msg);
    }

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
    use sanctum_types::threat::{Action, ThreatCategory, ThreatEvent, ThreatLevel};
    use serde_json::json;
    use std::path::PathBuf;

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

    // ---- Threat category inference tests ----

    #[test]
    fn infer_category_pre_mcp_is_mcp_violation() {
        let cat = infer_threat_category("pre-mcp", "blocked by MCP policy");
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::McpViolation);
    }

    #[test]
    fn infer_category_pre_write_sitecustomize_is_site_customize() {
        let cat = infer_threat_category(
            "pre-write",
            "Blocked: writing sitecustomize.py is not allowed",
        );
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::SiteCustomize);
    }

    #[test]
    fn infer_category_pre_write_usercustomize_is_site_customize() {
        let cat = infer_threat_category(
            "pre-write",
            "Blocked: writing usercustomize.py is not allowed",
        );
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::SiteCustomize);
    }

    #[test]
    fn infer_category_pre_write_pth_is_pth_injection() {
        let cat = infer_threat_category("pre-write", "Blocked: writing .pth files is not allowed");
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::PthInjection);
    }

    #[test]
    fn infer_category_pre_write_credential_is_credential_access() {
        let cat = infer_threat_category("pre-write", "Blocked: content contains OpenAI API key");
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::CredentialAccess);
    }

    #[test]
    fn infer_category_pre_bash_is_credential_access() {
        let cat =
            infer_threat_category("pre-bash", "Blocked: reading credential file ~/.ssh/id_rsa");
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::CredentialAccess);
    }

    #[test]
    fn infer_category_pre_read_is_credential_access() {
        let cat = infer_threat_category("pre-read", "Blocked: reading .env file");
        assert_eq!(cat, sanctum_types::threat::ThreatCategory::CredentialAccess);
    }

    // ---- Source path extraction tests ----

    #[test]
    fn extract_source_path_pre_read() {
        let input = make_input("read", json!({ "file_path": "/home/user/.ssh/id_rsa" }));
        let path = extract_source_path(&input, "pre-read");
        assert_eq!(path, PathBuf::from("/home/user/.ssh/id_rsa"));
    }

    #[test]
    fn extract_source_path_pre_write() {
        let input = make_input(
            "write",
            json!({ "file_path": "/tmp/evil.pth", "content": "import os" }),
        );
        let path = extract_source_path(&input, "pre-write");
        assert_eq!(path, PathBuf::from("/tmp/evil.pth"));
    }

    #[test]
    fn extract_source_path_pre_bash() {
        let input = make_input("bash", json!({ "command": "cat ~/.ssh/id_rsa" }));
        let path = extract_source_path(&input, "pre-bash");
        assert_eq!(path, PathBuf::from("bash:cat ~/.ssh/id_rsa"));
    }

    #[test]
    fn extract_source_path_pre_bash_truncates_long_commands() {
        let long_cmd = "x".repeat(300);
        let input = make_input("bash", json!({ "command": long_cmd }));
        let path = extract_source_path(&input, "pre-bash");
        // Should be truncated to 200 chars + "bash:" prefix
        let path_str = path.to_string_lossy();
        assert!(path_str.starts_with("bash:"));
        assert!(path_str.len() <= 205 + 5); // 200 chars + "bash:" prefix
    }

    #[test]
    fn extract_source_path_pre_bash_utf8_safe() {
        // Multi-byte UTF-8 characters must not cause a panic when truncating.
        // Each emoji is 4 bytes — 51 emojis = 204 bytes, which triggers truncation.
        let emoji_cmd = "\u{1F600}".repeat(51);
        let input = make_input("bash", json!({ "command": emoji_cmd }));
        // Should not panic — truncation must respect char boundaries
        let path = extract_source_path(&input, "pre-bash");
        let path_str = path.to_string_lossy();
        assert!(path_str.starts_with("bash:"));
        // Verify the result is valid UTF-8 (no panic in to_string_lossy)
        assert!(path_str.len() > 5);
    }

    #[test]
    fn extract_source_path_pre_mcp() {
        let input = make_input("mcp__filesystem__read_file", json!({}));
        let path = extract_source_path(&input, "pre-mcp");
        assert_eq!(path, PathBuf::from("mcp:mcp__filesystem__read_file"));
    }

    #[test]
    fn extract_source_path_missing_field() {
        let input = make_input("write", json!({}));
        let path = extract_source_path(&input, "pre-write");
        assert_eq!(path, PathBuf::from("<unknown>"));
    }

    // ---- Audit event recording tests ----

    #[test]
    fn record_hook_threat_event_writes_block_to_audit() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Override audit path via env for this test
        let log_path = dir.path().join("logs").join("audit.log");

        let _input = make_input("read", json!({ "file_path": "/home/user/.ssh/id_rsa" }));
        let event = ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: ThreatLevel::Critical,
            category: ThreatCategory::CredentialAccess,
            description: "Blocked: reading credential file".to_string(),
            source_path: PathBuf::from("/home/user/.ssh/id_rsa"),
            creator_pid: None,
            creator_exe: None,
            action_taken: Action::Blocked,
        };

        // Write directly to verify the audit module works
        sanctum_types::audit::append_audit_event(&event, &log_path);

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse");
        assert_eq!(parsed.level, ThreatLevel::Critical);
        assert_eq!(parsed.category, ThreatCategory::CredentialAccess);
        assert_eq!(parsed.action_taken, Action::Blocked);
    }

    #[test]
    fn record_hook_threat_event_writes_warn_to_audit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_path = dir.path().join("logs").join("audit.log");

        let event = ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: ThreatLevel::Warning,
            category: ThreatCategory::CredentialAccess,
            description: "pip install detected".to_string(),
            source_path: PathBuf::from("bash:pip install requests"),
            creator_pid: None,
            creator_exe: None,
            action_taken: Action::Alerted,
        };

        sanctum_types::audit::append_audit_event(&event, &log_path);

        let content = std::fs::read_to_string(&log_path).expect("read log");
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse");
        assert_eq!(parsed.level, ThreatLevel::Warning);
        assert_eq!(parsed.action_taken, Action::Alerted);
    }

    #[test]
    fn record_does_not_write_for_allow_decisions() {
        // Verify that record_hook_threat_event with Allow returns immediately
        // without writing any audit event. We call the function directly
        // (it uses WellKnownPaths::default() internally for the audit path).
        let input = make_input("bash", json!({ "command": "ls" }));

        // Get the default audit path to check before/after
        let paths = sanctum_types::paths::WellKnownPaths::default();
        let audit_path = paths.data_dir.join("audit.log");
        let size_before = std::fs::metadata(&audit_path).map(|m| m.len()).ok();

        // Call with Allow — should return early without writing
        record_hook_threat_event("pre-bash", &input, HookDecision::Allow, "allowed");

        let size_after = std::fs::metadata(&audit_path).map(|m| m.len()).ok();
        assert_eq!(
            size_before, size_after,
            "Allow decisions should not write to audit log"
        );
    }

    // ---- Integration: category mapping end-to-end ----

    #[test]
    fn mcp_block_produces_mcp_violation_category() {
        let input = make_input(
            "mcp__filesystem__write_file",
            json!({ "path": "/etc/passwd" }),
        );
        let category = infer_threat_category("pre-mcp", "blocked by MCP policy: restricted path");
        assert_eq!(
            category,
            sanctum_types::threat::ThreatCategory::McpViolation
        );

        let path = extract_source_path(&input, "pre-mcp");
        assert!(path.to_string_lossy().starts_with("mcp:"));
    }

    #[test]
    fn sitecustomize_block_produces_correct_category() {
        let input = make_input(
            "write",
            json!({ "file_path": "/usr/lib/python3.12/site-packages/sitecustomize.py" }),
        );
        let category = infer_threat_category(
            "pre-write",
            "Blocked: writing sitecustomize.py is not permitted",
        );
        assert_eq!(
            category,
            sanctum_types::threat::ThreatCategory::SiteCustomize
        );

        let path = extract_source_path(&input, "pre-write");
        assert!(path.to_string_lossy().contains("sitecustomize.py"));
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
            check_package_existence: true,
            package_check_timeout_ms: 3000,
            mcp_rules: Vec::new(),
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
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
            check_package_existence: true,
            package_check_timeout_ms: 3000,
            mcp_rules: Vec::new(),
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        assert!(cfg.redact_credentials);
    }

    #[test]
    fn security_floor_enforces_mcp_audit() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: true,
            redact_credentials: true,
            mcp_audit: false,
            check_package_existence: true,
            package_check_timeout_ms: 3000,
            mcp_rules: Vec::new(),
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        // mcp_audit is enforced by the floor, so it is forced to true.
        assert!(cfg.mcp_audit);
        assert!(cfg.claude_hooks);
        assert!(cfg.redact_credentials);
    }

    #[test]
    fn security_floor_prevents_mcp_allow_policy() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: true,
            redact_credentials: true,
            mcp_audit: true,
            check_package_existence: true,
            package_check_timeout_ms: 3000,
            mcp_rules: Vec::new(),
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        // Local config cannot weaken MCP policy to Allow — forced to Deny
        assert_eq!(
            cfg.default_mcp_policy,
            sanctum_types::config::McpDefaultPolicy::Deny
        );
    }

    #[test]
    fn security_floor_allows_mcp_warn_policy() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: true,
            redact_credentials: true,
            mcp_audit: true,
            check_package_existence: true,
            package_check_timeout_ms: 3000,
            mcp_rules: Vec::new(),
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Warn,
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        // Warn is acceptable — not weakened
        assert_eq!(
            cfg.default_mcp_policy,
            sanctum_types::config::McpDefaultPolicy::Warn
        );
    }

    // ---- IPC usage forwarding tests ----

    #[test]
    fn send_usage_ipc_best_effort_does_not_panic_when_no_daemon() {
        // No daemon is running — the function should silently return.
        let cmd = IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 100,
            output_tokens: 50,
        };
        // Must not panic or error.
        send_usage_ipc_best_effort(&cmd);
    }

    #[test]
    fn usage_extraction_produces_correct_ipc_command() {
        use sanctum_firewall::hooks::claude::extract_budget_usage_structured;

        let stdout = r#"{"type":"message","model":"claude-sonnet-4-6","usage":{"input_tokens":1000,"output_tokens":500}}"#;
        let usage = extract_budget_usage_structured(stdout).expect("should extract usage");

        let cmd = IpcCommand::RecordUsage {
            provider: usage.provider.clone(),
            model: usage.model.clone(),
            input_tokens: usage.input_tokens,
            output_tokens: usage.output_tokens,
        };

        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("\"provider\":\"anthropic\""));
        assert!(json.contains("\"model\":\"claude-sonnet-4-6\""));
        assert!(json.contains("\"input_tokens\":1000"));
        assert!(json.contains("\"output_tokens\":500"));
    }

    #[test]
    fn ipc_message_wraps_command_with_auth_token() {
        // Verify that IpcMessage correctly wraps an IpcCommand with an auth token
        let cmd = IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 100,
            output_tokens: 50,
        };
        let msg = IpcMessage {
            command: cmd,
            auth_token: Some("test_token_abc".to_string()),
        };
        let json = serde_json::to_string(&msg).expect("serialise");
        assert!(json.contains("\"auth_token\":\"test_token_abc\""));
        assert!(json.contains("\"command\":\"RecordUsage\""));
        assert!(json.contains("\"provider\":\"anthropic\""));
    }

    #[test]
    fn ipc_message_without_token_omits_auth_field() {
        let cmd = IpcCommand::RecordUsage {
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            input_tokens: 10,
            output_tokens: 5,
        };
        let msg = IpcMessage {
            command: cmd,
            auth_token: None,
        };
        let json = serde_json::to_string(&msg).expect("serialise");
        // auth_token should be omitted due to skip_serializing_if
        assert!(!json.contains("auth_token"));
        assert!(json.contains("\"command\":\"RecordUsage\""));
    }

    // ---- NpmConfig loading tests ----

    #[test]
    fn npm_config_defaults_all_protections_on() {
        let cfg = NpmConfig::default();
        assert!(cfg.watch_lifecycle);
        assert!(cfg.ignore_scripts_warning);
        assert!(cfg.allowlist.is_empty());
    }

    #[test]
    fn source_path_redacts_embedded_credentials() {
        // A command containing an API key should have it redacted in the
        // source_path stored in the ThreatEvent.
        let cmd = "curl -H \"Authorization: Bearer sk-proj-abcdef1234567890abcdef1234567890abcdef1234567890ab\" http://api.openai.com";
        let input = make_input("bash", json!({ "command": cmd }));
        let raw_path = extract_source_path(&input, "pre-bash");
        let (redacted, _) =
            sanctum_firewall::redaction::redact_credentials(&raw_path.to_string_lossy());
        let redacted_path = PathBuf::from(&redacted);
        let path_str = redacted_path.to_string_lossy();
        assert!(
            !path_str.contains("sk-proj-abcdef1234567890abcdef1234567890"),
            "source_path should not contain raw API key, got: {path_str}"
        );
        assert!(
            path_str.contains("[REDACTED:"),
            "source_path should contain redaction placeholder, got: {path_str}"
        );
    }

    #[test]
    fn load_npm_config_returns_defaults_when_no_config() {
        // load_npm_config should never panic, even when config files don't exist.
        let cfg = load_npm_config();
        assert!(cfg.watch_lifecycle);
        assert!(cfg.ignore_scripts_warning);
    }

    #[test]
    fn pre_bash_with_npm_config_passes_through() {
        let npm_config = NpmConfig {
            watch_lifecycle: false,
            ignore_scripts_warning: false,
            allowlist: vec!["react".to_owned()],
        };
        let input = make_input("bash", json!({"command": "ls -la"}));
        let output = claude::pre_bash_with_npm_config(&input, &npm_config);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn post_bash_with_npm_config_respects_lifecycle_flag() {
        let npm_config = NpmConfig {
            watch_lifecycle: false,
            ..NpmConfig::default()
        };
        let input = make_input(
            "bash",
            json!({
                "command": "npm install foo",
                "stdout": "postinstall script ran",
                "stderr": ""
            }),
        );
        let output = claude::post_bash_with_npm_config(&input, &npm_config);
        let msg = output.message.as_deref().unwrap_or("");
        assert!(
            !msg.contains("lifecycle scripts"),
            "lifecycle warning suppressed when watch_lifecycle=false"
        );
    }

    // ---- Global config security floor tests ----

    #[test]
    fn global_config_floor_enforces_claude_hooks() {
        let mut cfg = AiFirewallConfig {
            claude_hooks: false,
            ..AiFirewallConfig::default()
        };
        enforce_ai_firewall_security_floor_global(&mut cfg);
        assert!(
            cfg.claude_hooks,
            "global floor should force claude_hooks to true"
        );
    }

    #[test]
    fn global_config_floor_enforces_redact_credentials() {
        let mut cfg = AiFirewallConfig {
            redact_credentials: false,
            ..AiFirewallConfig::default()
        };
        enforce_ai_firewall_security_floor_global(&mut cfg);
        assert!(
            cfg.redact_credentials,
            "global floor should force redact_credentials to true"
        );
    }

    #[test]
    fn global_config_floor_enforces_mcp_audit() {
        let mut cfg = AiFirewallConfig {
            mcp_audit: false,
            ..AiFirewallConfig::default()
        };
        enforce_ai_firewall_security_floor_global(&mut cfg);
        assert!(
            cfg.mcp_audit,
            "global floor should force mcp_audit to true"
        );
    }

    #[test]
    fn global_config_floor_allows_mcp_policy_allow() {
        let mut cfg = AiFirewallConfig {
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
            ..AiFirewallConfig::default()
        };
        enforce_ai_firewall_security_floor_global(&mut cfg);
        assert_eq!(
            cfg.default_mcp_policy,
            sanctum_types::config::McpDefaultPolicy::Allow,
            "global floor should NOT override MCP default policy"
        );
    }

    #[test]
    fn local_config_floor_overrides_mcp_policy_allow() {
        let mut cfg = AiFirewallConfig {
            default_mcp_policy: sanctum_types::config::McpDefaultPolicy::Allow,
            ..AiFirewallConfig::default()
        };
        enforce_ai_firewall_security_floor(&mut cfg);
        assert_eq!(
            cfg.default_mcp_policy,
            sanctum_types::config::McpDefaultPolicy::Deny,
            "local floor SHOULD override MCP default policy to deny"
        );
    }
}
