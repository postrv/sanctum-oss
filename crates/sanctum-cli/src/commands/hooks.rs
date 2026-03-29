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

/// Returns true if a matcher group contains a Sanctum hook command.
fn is_sanctum_entry(entry: &serde_json::Value) -> bool {
    // Check nested format: entry.hooks[*].command contains "sanctum hook"
    if let Some(hooks_arr) = entry.get("hooks").and_then(|h| h.as_array()) {
        for hook in hooks_arr {
            if let Some(cmd) = hook.get("command").and_then(|c| c.as_str()) {
                if cmd.contains("sanctum hook") {
                    return true;
                }
            }
        }
    }
    // Check flat format: entry.command contains "sanctum hook"
    if let Some(cmd) = entry.get("command").and_then(|c| c.as_str()) {
        if cmd.contains("sanctum hook") {
            return true;
        }
    }
    false
}

/// Merge new Sanctum hooks into existing hooks, preserving non-Sanctum entries.
///
/// For each hook type (e.g. `PreToolUse`, `PostToolUse`):
/// 1. Remove any existing Sanctum entries from the current array.
/// 2. Append the new Sanctum entries.
/// 3. Preserve any non-Sanctum entries and any hook types not in the new hooks.
fn merge_hooks(existing: &serde_json::Value, new_hooks: &serde_json::Value) -> serde_json::Value {
    let mut result = existing.clone();

    let Some(new_obj) = new_hooks.as_object() else {
        return result;
    };

    // Ensure result is an object
    if !result.is_object() {
        return new_hooks.clone();
    }

    for (hook_type, new_entries) in new_obj {
        let Some(new_arr) = new_entries.as_array() else {
            continue;
        };

        // Get existing entries for this hook type, filtering out old Sanctum ones
        let mut merged: Vec<serde_json::Value> = result
            .get(hook_type)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|entry| !is_sanctum_entry(entry))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Append new Sanctum entries
        merged.extend(new_arr.iter().cloned());

        result[hook_type] = serde_json::Value::Array(merged);
    }

    result
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

    // Merge Sanctum hook configuration with any existing hooks
    let new_hooks = build_hooks_json();
    if let Some(existing_hooks) = settings.get("hooks").cloned() {
        settings["hooks"] = merge_hooks(&existing_hooks, &new_hooks);
    } else {
        settings["hooks"] = new_hooks;
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

    // Remove Sanctum entries from hooks, preserving non-Sanctum entries
    if let Some(hooks) = settings.get_mut("hooks").and_then(|h| h.as_object_mut()) {
        let keys: Vec<String> = hooks.keys().cloned().collect();
        for key in keys {
            if let Some(arr) = hooks.get_mut(&key).and_then(|v| v.as_array_mut()) {
                arr.retain(|entry| !is_sanctum_entry(entry));
            }
        }
        // Remove empty hook type arrays
        let empty_keys: Vec<String> = hooks
            .iter()
            .filter(|(_, v)| v.as_array().is_some_and(Vec::is_empty))
            .map(|(k, _)| k.clone())
            .collect();
        for key in empty_keys {
            hooks.remove(&key);
        }
        // If hooks object is now empty, remove it entirely
        if hooks.is_empty() {
            if let Some(obj) = settings.as_object_mut() {
                obj.remove("hooks");
            }
        }
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

        // Simulate install by building and writing (no existing hooks)
        let mut settings = serde_json::json!({});
        let new_hooks = build_hooks_json();
        settings["hooks"] = new_hooks;

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
        let new_hooks = build_hooks_json();
        if let Some(existing_hooks) = settings.get("hooks").cloned() {
            settings["hooks"] = merge_hooks(&existing_hooks, &new_hooks);
        } else {
            settings["hooks"] = new_hooks;
        }

        let json_str = serde_json::to_string_pretty(&settings).expect("should serialize");
        fs::write(&settings_path, &json_str).expect("should write");

        // Read back and verify existing settings are preserved
        let content = fs::read_to_string(&settings_path).expect("should read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("should parse");

        assert_eq!(parsed["apiKey"], "test-key");
        assert_eq!(parsed["model"], "claude-4");
        assert!(parsed.get("hooks").is_some());
    }

    #[test]
    fn install_merges_with_existing_hooks() {
        let existing_hooks = serde_json::json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-custom-linter check"
                        }
                    ]
                }
            ],
            "PostToolUse": [
                {
                    "matcher": "Write",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-formatter format"
                        }
                    ]
                }
            ]
        });

        let new_hooks = build_hooks_json();
        let merged = merge_hooks(&existing_hooks, &new_hooks);

        // Custom hooks should be preserved
        let pre = merged["PreToolUse"].as_array().expect("PreToolUse array");
        // Custom linter + 4 sanctum hooks = 5
        assert_eq!(pre.len(), 5);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-custom-linter check");

        let post = merged["PostToolUse"].as_array().expect("PostToolUse array");
        // Custom formatter + 1 sanctum hook = 2
        assert_eq!(post.len(), 2);
        assert_eq!(post[0]["hooks"][0]["command"], "my-formatter format");
    }

    #[test]
    fn install_replaces_old_sanctum_hooks() {
        // Simulate existing settings that already have old Sanctum hooks
        let existing_hooks = serde_json::json!({
            "PreToolUse": [
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "my-custom-linter check"
                        }
                    ]
                },
                {
                    "matcher": "Bash",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "sanctum hook pre-bash"
                        }
                    ]
                }
            ]
        });

        let new_hooks = build_hooks_json();
        let merged = merge_hooks(&existing_hooks, &new_hooks);

        let pre = merged["PreToolUse"].as_array().expect("PreToolUse array");
        // Custom linter (1) + new sanctum hooks (4) = 5
        // The old sanctum hook should have been removed before adding new ones
        assert_eq!(pre.len(), 5);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-custom-linter check");

        // Count sanctum entries -- should be exactly the new set (4)
        let sanctum_count = pre.iter().filter(|e| is_sanctum_entry(e)).count();
        assert_eq!(sanctum_count, 4);
    }

    #[test]
    fn remove_preserves_non_sanctum_hooks() {
        let settings = serde_json::json!({
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "my-custom-linter check"
                            }
                        ]
                    },
                    {
                        "matcher": "Bash",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "sanctum hook pre-bash"
                            }
                        ]
                    }
                ]
            }
        });

        let dir = tempfile::tempdir().expect("should create tempdir");
        let settings_path = dir.path().join("settings.json");
        let json_str = serde_json::to_string_pretty(&settings).expect("should serialize");
        fs::write(&settings_path, &json_str).expect("should write");

        // Simulate remove logic
        let content = fs::read_to_string(&settings_path).expect("should read");
        let mut parsed: serde_json::Value = serde_json::from_str(&content).expect("should parse");

        if let Some(hooks) = parsed.get_mut("hooks").and_then(|h| h.as_object_mut()) {
            let keys: Vec<String> = hooks.keys().cloned().collect();
            for key in keys {
                if let Some(arr) = hooks.get_mut(&key).and_then(|v| v.as_array_mut()) {
                    arr.retain(|entry| !is_sanctum_entry(entry));
                }
            }
        }

        // Custom hook should still be there
        let pre = parsed["hooks"]["PreToolUse"]
            .as_array()
            .expect("PreToolUse array");
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["hooks"][0]["command"], "my-custom-linter check");
    }
}
