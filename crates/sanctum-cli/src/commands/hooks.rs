//! `sanctum hooks` — Install or remove hooks for AI coding tools.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use sanctum_types::errors::CliError;

use crate::HooksAction;

/// Run the hooks command.
pub fn run(action: &HooksAction) -> Result<(), CliError> {
    match action {
        HooksAction::Install { tool } => install_hooks(tool),
        HooksAction::Remove { tool } => remove_hooks(tool),
    }
}

fn install_hooks(tool: &str) -> Result<(), CliError> {
    match tool {
        "claude" => install_claude_hooks(),
        other => Err(CliError::InvalidArgs(format!(
            "unknown tool '{other}'. Supported: claude"
        ))),
    }
}

fn remove_hooks(tool: &str) -> Result<(), CliError> {
    match tool {
        "claude" => remove_claude_hooks(),
        other => Err(CliError::InvalidArgs(format!(
            "unknown tool '{other}'. Supported: claude"
        ))),
    }
}

fn claude_hooks_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    Some(home.join(".claude"))
}

/// Build the hooks JSON value for Claude Code settings.
///
/// Uses the current Claude Code hooks API format: three-level nesting with
/// event → matcher group → hooks array. Each hook handler specifies
/// `type: "command"` and the command string.
fn build_hooks_json() -> serde_json::Value {
    serde_json::json!({
        "PreToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sanctum hook pre-bash"
                    }
                ]
            },
            {
                "matcher": "Write|Edit|MultiEdit|NotebookEdit",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sanctum hook pre-write"
                    }
                ]
            },
            {
                "matcher": "Read",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sanctum hook pre-read"
                    }
                ]
            },
            {
                "matcher": "mcp__.*",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sanctum hook pre-mcp"
                    }
                ]
            }
        ],
        "PostToolUse": [
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "sanctum hook post-bash"
                    }
                ]
            }
        ]
    })
}

fn install_claude_hooks() -> Result<(), CliError> {
    let hooks_dir = claude_hooks_dir()
        .ok_or_else(|| CliError::InvalidArgs("could not determine HOME directory".to_string()))?;

    fs::create_dir_all(&hooks_dir)?;

    let settings_path = hooks_dir.join("settings.json");

    // Read existing settings or create new
    let mut settings: serde_json::Value = if settings_path.exists() {
        let content = fs::read_to_string(&settings_path)?;
        serde_json::from_str(&content).map_err(|e| {
            CliError::InvalidArgs(format!(
                "Failed to parse Claude Code settings.json: {e}. \
                 Please fix the file manually or back it up before retrying."
            ))
        })?
    } else {
        serde_json::json!({})
    };

    // Add Sanctum hook configuration
    settings["hooks"] = build_hooks_json();

    let json_str = serde_json::to_string_pretty(&settings)
        .map_err(|e| CliError::InvalidArgs(format!("Failed to serialize settings: {e}")))?;
    // Atomic write: write to temp file, sync, then rename into place
    let tmp_path = settings_path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(json_str.as_bytes())?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp_path, &settings_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    #[allow(clippy::print_stdout)]
    {
        println!("Claude Code hooks installed.");
        println!("  Location: {}", settings_path.display());
        println!("  Hooks will check tool calls against Sanctum policy.");
    }
    Ok(())
}

fn remove_claude_hooks() -> Result<(), CliError> {
    let hooks_dir = claude_hooks_dir()
        .ok_or_else(|| CliError::InvalidArgs("could not determine HOME directory".to_string()))?;

    let settings_path = hooks_dir.join("settings.json");

    if !settings_path.exists() {
        #[allow(clippy::print_stdout)]
        {
            println!("No Claude Code hooks found.");
        }
        return Ok(());
    }

    let content = fs::read_to_string(&settings_path)?;
    let mut settings: serde_json::Value = serde_json::from_str(&content).map_err(|e| {
        CliError::InvalidArgs(format!(
            "Failed to parse Claude Code settings.json: {e}. \
                 Please fix the file manually or back it up before retrying."
        ))
    })?;

    // Remove hooks key
    if let Some(obj) = settings.as_object_mut() {
        obj.remove("hooks");
    }

    let json_str = serde_json::to_string_pretty(&settings)
        .map_err(|e| CliError::InvalidArgs(format!("Failed to serialize settings: {e}")))?;
    // Atomic write: write to temp file, sync, then rename into place
    let tmp_path = settings_path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp_path)?;
        file.write_all(json_str.as_bytes())?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp_path, &settings_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    #[allow(clippy::print_stdout)]
    {
        println!("Claude Code hooks removed.");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hooks_json_has_correct_structure() {
        let hooks = build_hooks_json();

        // Check PreToolUse
        let pre = hooks.get("PreToolUse").expect("should have PreToolUse");
        let pre_arr = pre.as_array().expect("PreToolUse should be array");
        assert_eq!(pre_arr.len(), 4);

        // Bash hook — nested format with type: "command"
        assert_eq!(pre_arr[0]["matcher"], "Bash");
        let bash_hooks = pre_arr[0]["hooks"].as_array().expect("hooks array");
        assert_eq!(bash_hooks.len(), 1);
        assert_eq!(bash_hooks[0]["type"], "command");
        assert_eq!(bash_hooks[0]["command"], "sanctum hook pre-bash");

        // Write|Edit|MultiEdit hook
        assert_eq!(pre_arr[1]["matcher"], "Write|Edit|MultiEdit|NotebookEdit");
        let write_hooks = pre_arr[1]["hooks"].as_array().expect("hooks array");
        assert_eq!(write_hooks.len(), 1);
        assert_eq!(write_hooks[0]["type"], "command");
        assert_eq!(write_hooks[0]["command"], "sanctum hook pre-write");

        // Read hook
        assert_eq!(pre_arr[2]["matcher"], "Read");
        let read_hooks = pre_arr[2]["hooks"].as_array().expect("hooks array");
        assert_eq!(read_hooks.len(), 1);
        assert_eq!(read_hooks[0]["type"], "command");
        assert_eq!(read_hooks[0]["command"], "sanctum hook pre-read");

        // MCP hook — regex pattern for mcp__* tools
        assert_eq!(pre_arr[3]["matcher"], "mcp__.*");
        let mcp_hooks = pre_arr[3]["hooks"].as_array().expect("hooks array");
        assert_eq!(mcp_hooks.len(), 1);
        assert_eq!(mcp_hooks[0]["type"], "command");
        assert_eq!(mcp_hooks[0]["command"], "sanctum hook pre-mcp");

        // Check PostToolUse
        let post = hooks.get("PostToolUse").expect("should have PostToolUse");
        let post_arr = post.as_array().expect("PostToolUse should be array");
        assert_eq!(post_arr.len(), 1);

        assert_eq!(post_arr[0]["matcher"], "Bash");
        let post_bash_hooks = post_arr[0]["hooks"].as_array().expect("hooks array");
        assert_eq!(post_bash_hooks.len(), 1);
        assert_eq!(post_bash_hooks[0]["type"], "command");
        assert_eq!(post_bash_hooks[0]["command"], "sanctum hook post-bash");
    }

    #[test]
    fn hooks_json_no_old_firewall_command() {
        let hooks = build_hooks_json();
        let serialized = serde_json::to_string(&hooks).expect("should serialize");
        assert!(!serialized.contains("firewall"));
        assert!(!serialized.contains("--tool"));
    }

    #[test]
    fn hooks_json_uses_nested_format_with_type_field() {
        let hooks = build_hooks_json();
        let serialized = serde_json::to_string(&hooks).expect("should serialize");
        // Every hook handler must have a "type" field
        assert!(serialized.contains(r#""type":"command"#));
        // Must NOT have top-level "command" keys (flat format)
        // In the correct nested format, "command" only appears inside
        // a handler object that also has "type"
        let pre = hooks.get("PreToolUse").expect("PreToolUse");
        for matcher_group in pre.as_array().expect("array") {
            // Each matcher group must have a "hooks" array, not a direct "command"
            assert!(
                matcher_group.get("hooks").is_some(),
                "matcher group missing 'hooks' array: {matcher_group}"
            );
            assert!(
                matcher_group.get("command").is_none(),
                "matcher group has flat 'command' key (deprecated format): {matcher_group}"
            );
        }
    }

    #[test]
    fn install_writes_correct_json_structure() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let settings_path = dir.path().join("settings.json");

        // Simulate install by building and writing
        let mut settings = serde_json::json!({});
        settings["hooks"] = build_hooks_json();

        let json_str = serde_json::to_string_pretty(&settings).expect("should serialize");
        fs::write(&settings_path, &json_str).expect("should write");

        // Read back and verify nested format
        let content = fs::read_to_string(&settings_path).expect("should read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("should parse JSON");

        let hooks = parsed.get("hooks").expect("should have hooks key");
        let pre = hooks
            .get("PreToolUse")
            .expect("should have PreToolUse")
            .as_array()
            .expect("PreToolUse should be array");

        assert_eq!(pre.len(), 4);
        // Verify nested format: command is inside hooks[0], not at top level
        assert_eq!(pre[0]["hooks"][0]["command"], "sanctum hook pre-bash");
        assert_eq!(pre[0]["hooks"][0]["type"], "command");
        assert_eq!(pre[1]["hooks"][0]["command"], "sanctum hook pre-write");
        assert_eq!(pre[1]["matcher"], "Write|Edit|MultiEdit|NotebookEdit");
        assert_eq!(pre[2]["hooks"][0]["command"], "sanctum hook pre-read");
        assert_eq!(pre[3]["hooks"][0]["command"], "sanctum hook pre-mcp");
        assert_eq!(pre[3]["matcher"], "mcp__.*");

        let post = hooks
            .get("PostToolUse")
            .expect("should have PostToolUse")
            .as_array()
            .expect("PostToolUse should be array");

        assert_eq!(post.len(), 1);
        assert_eq!(post[0]["hooks"][0]["command"], "sanctum hook post-bash");
        assert_eq!(post[0]["hooks"][0]["type"], "command");
    }

    #[test]
    fn install_preserves_existing_settings() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let settings_path = dir.path().join("settings.json");

        // Write some existing settings
        let existing = serde_json::json!({
            "apiKey": "test-key",
            "model": "claude-4"
        });
        let json_str = serde_json::to_string_pretty(&existing).expect("should serialize");
        fs::write(&settings_path, &json_str).expect("should write");

        // Simulate install on existing file
        let content = fs::read_to_string(&settings_path).expect("should read");
        let mut settings: serde_json::Value = serde_json::from_str(&content).expect("should parse");
        settings["hooks"] = build_hooks_json();

        let json_str = serde_json::to_string_pretty(&settings).expect("should serialize");
        fs::write(&settings_path, &json_str).expect("should write");

        // Read back and verify existing settings are preserved
        let content = fs::read_to_string(&settings_path).expect("should read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("should parse");

        assert_eq!(parsed["apiKey"], "test-key");
        assert_eq!(parsed["model"], "claude-4");
        assert!(parsed.get("hooks").is_some());
    }
}
