//! `sanctum init` — Initialise Sanctum in a directory.

use std::fs;
use std::io::Write;
use std::path::Path;

use sanctum_types::errors::CliError;

use crate::shell::{self, Shell};

/// Run the init command.
///
/// When `--shell <name>` is provided, outputs only the shell hook to stdout
/// (for `eval "$(sanctum init --shell zsh)"` usage).
///
/// Without `--shell`, performs full initialisation: creates config,
/// detects tools, runs a quick scan summary, and shows next steps.
pub fn run(dir: &str, shell_name: Option<&str>) -> Result<(), CliError> {
    if let Some(name) = shell_name {
        return output_shell_hook(name);
    }

    full_init(dir)
}

/// Output only the shell hook for the given shell name.
fn output_shell_hook(name: &str) -> Result<(), CliError> {
    let shell = parse_shell(name)?;
    let hook = shell::generate_shell_hook(shell);

    #[allow(clippy::print_stdout)]
    {
        print!("{hook}");
    }

    Ok(())
}

/// Parse a shell name string into a `Shell` enum value.
fn parse_shell(name: &str) -> Result<Shell, CliError> {
    match name.to_lowercase().as_str() {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        other => Err(CliError::InvalidArgs(format!(
            "unsupported shell '{other}'. Supported: bash, zsh, fish"
        ))),
    }
}

/// Full initialisation: config creation, environment detection, scan summary, next steps.
fn full_init(dir: &str) -> Result<(), CliError> {
    let dir = Path::new(dir);
    let config_dir = dir.join(".sanctum");
    let config_path = config_dir.join("config.toml");

    // Create config if it doesn't exist
    let config_created = create_config(dir, &config_dir, &config_path)?;

    #[allow(clippy::print_stdout)]
    {
        if config_created {
            println!("Sanctum initialised at {}", config_dir.display());
        } else {
            println!(
                "Sanctum configuration already exists at {}",
                config_path.display()
            );
        }
        println!();
    }

    // Detect environment
    detect_python();
    detect_npm(dir);
    detect_nono();
    detect_claude_code();

    // Quick credential scan summary
    run_scan_summary(dir);

    // Recommended next steps
    print_next_steps();

    // Offer to install shell hook
    offer_shell_hook();

    Ok(())
}

/// Detect whether the given directory is an npm/Node.js project.
///
/// Returns `true` if any common Node.js project indicator file exists.
fn detect_npm_project(project_dir: &Path) -> bool {
    let indicators = [
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lockb",
    ];
    indicators.iter().any(|f| project_dir.join(f).exists())
}

/// Create the `.sanctum/config.toml` file if it doesn't exist.
/// Returns `true` if the config was created, `false` if it already existed.
fn create_config(
    project_dir: &Path,
    config_dir: &Path,
    config_path: &Path,
) -> Result<bool, CliError> {
    if config_path.exists() {
        return Ok(false);
    }

    // Create config directory with restricted permissions (0o700 on Unix).
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(config_dir)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(config_dir)?;
    }

    let mut default_config = String::from(
        r#"# Sanctum configuration
# https://sanctum.dev/docs/config

config_version = 1

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = false  # opt-in: monitors outbound connections, may need tuning
watch_npm = false
pth_response = "quarantine"

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[budgets]
# default_session = "$50"
# default_daily = "$200"
alert_at_percent = 75
"#,
    );

    if detect_npm_project(project_dir) {
        // Replace watch_npm = false with true since we detected an npm project
        default_config = default_config.replace("watch_npm = false", "watch_npm = true");
        default_config.push_str(
            r"
[sentinel.npm]
watch_lifecycle = true
ignore_scripts_warning = true
",
        );
    }

    // Atomic write: write to temp file, sync, then rename into place
    let tmp_path = config_path.with_extension("tmp");
    {
        // Remove stale tmp file if it exists (e.g. from prior crash)
        let _ = fs::remove_file(&tmp_path);
        let mut file = sanctum_types::fs_safety::safe_create_exclusive(&tmp_path)?;
        file.write_all(default_config.as_bytes())?;
        file.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp_path, config_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e.into());
    }

    Ok(true)
}

/// Detect Python installations and display site-packages paths.
fn detect_python() {
    let result = std::process::Command::new("python3")
        .args([
            "-c",
            "import site; print('\\n'.join(site.getsitepackages()))",
        ])
        .output();

    #[allow(clippy::print_stdout)]
    {
        match result {
            Ok(output) if output.status.success() => {
                let paths = String::from_utf8_lossy(&output.stdout);
                let paths = paths.trim();
                if paths.is_empty() {
                    println!("Python: detected but no site-packages found");
                } else {
                    println!("Python installations detected:");
                    for path in paths.lines() {
                        println!("  {path}");
                    }
                }
            }
            _ => {
                println!("Python: not found (python3 not in PATH)");
            }
        }
        println!();
    }
}

/// Detect npm/Node.js project and display status.
fn detect_npm(dir: &Path) {
    #[allow(clippy::print_stdout)]
    {
        if detect_npm_project(dir) {
            println!("Node.js/npm: project detected (npm ecosystem monitoring enabled)");
        } else {
            println!("Node.js/npm: no project indicators found");
        }
        println!();
    }
}

/// Detect nono (sandbox tool) and display version if found.
fn detect_nono() {
    let result = std::process::Command::new("which").arg("nono").output();

    #[allow(clippy::print_stdout)]
    {
        match result {
            Ok(output) if output.status.success() => {
                let path = String::from_utf8_lossy(&output.stdout);
                let path = path.trim();

                // Try to get version
                let version = std::process::Command::new("nono")
                    .arg("--version")
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

                match version {
                    Some(v) => println!("nono: {v} ({path})"),
                    None => println!("nono: found at {path}"),
                }
            }
            _ => {
                println!("nono: not found (sandbox not available)");
            }
        }
        println!();
    }
}

/// Detect Claude Code by checking for `~/.claude/` directory.
fn detect_claude_code() {
    let has_claude = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .is_some_and(|home| home.join(".claude").is_dir());

    #[allow(clippy::print_stdout)]
    {
        if has_claude {
            println!("Claude Code: detected (~/.claude/ exists)");
        } else {
            println!("Claude Code: not detected");
        }
        println!();
    }
}

/// Run a quick credential scan and display a count summary.
fn run_scan_summary(dir: &Path) {
    let count = count_credential_issues(dir);

    #[allow(clippy::print_stdout)]
    {
        if count == 0 {
            println!("Credential scan: no issues found");
        } else {
            println!("Credential scan: {count} potential issue(s) found");
            println!("  Run `sanctum scan` for full details");
        }
        println!();
    }
}

/// Count credential exposure issues (lightweight version of scan logic).
fn count_credential_issues(dir: &Path) -> usize {
    let mut count = 0;

    // Check for credential files tracked by git
    let credential_files = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.development",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".aws/credentials",
        "credentials.json",
        "service-account.json",
    ];

    for pattern in &credential_files {
        let path = dir.join(pattern);
        if path.exists() && path.is_file() {
            let is_tracked = std::process::Command::new("git")
                .args(["ls-files", "--error-unmatch", pattern])
                .current_dir(dir)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if is_tracked {
                count += 1;
            }
        }
    }

    // Check for .env files with secrets
    let env_patterns = [".env", ".env.local", ".env.production"];
    let secret_vars = [
        "AWS_SECRET_ACCESS_KEY",
        "DATABASE_URL",
        "DB_PASSWORD",
        "SECRET_KEY",
        "JWT_SECRET",
        "API_KEY",
        "API_SECRET",
        "PRIVATE_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GITHUB_TOKEN",
    ];

    for pattern in &env_patterns {
        let path = dir.join(pattern);
        if let Ok(content) = fs::read_to_string(&path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                for var_name in &secret_vars {
                    if trimmed.starts_with(var_name) && trimmed.contains('=') {
                        count += 1;
                        break;
                    }
                }
            }
        }
    }

    count
}

/// Print recommended next steps.
fn print_next_steps() {
    #[allow(clippy::print_stdout)]
    {
        println!("Recommended next steps:");
        println!("  1. Start the daemon:     sanctum daemon start");
        println!("  2. Install shell hook:    eval \"$(sanctum init --shell zsh)\"");
        println!("  3. Install Claude hooks:  sanctum hooks install claude");
        println!("  4. Run a full scan:       sanctum scan");
        println!();
    }
}

/// Offer to install the shell hook by showing the appropriate command.
fn offer_shell_hook() {
    // Detect current shell from $SHELL
    let shell_name = std::env::var("SHELL").unwrap_or_default();
    let (shell_label, rc_file, eval_line) = if shell_name.contains("zsh") {
        ("zsh", "~/.zshrc", "eval \"$(sanctum init --shell zsh)\"")
    } else if shell_name.contains("fish") {
        (
            "fish",
            "~/.config/fish/config.fish",
            "sanctum init --shell fish | source",
        )
    } else if shell_name.contains("bash") {
        ("bash", "~/.bashrc", "eval \"$(sanctum init --shell bash)\"")
    } else {
        return;
    };

    #[allow(clippy::print_stdout)]
    {
        println!("Shell hook ({shell_label}):");
        println!("  Add to {rc_file}:");
        println!("    {eval_line}");
        println!();
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_shell_bash() {
        let shell = parse_shell("bash");
        assert!(shell.is_ok());
    }

    #[test]
    fn parse_shell_zsh() {
        let shell = parse_shell("zsh");
        assert!(shell.is_ok());
    }

    #[test]
    fn parse_shell_fish() {
        let shell = parse_shell("fish");
        assert!(shell.is_ok());
    }

    #[test]
    fn parse_shell_case_insensitive() {
        let shell = parse_shell("ZSH");
        assert!(shell.is_ok());
    }

    #[test]
    fn parse_shell_invalid() {
        let shell = parse_shell("powershell");
        assert!(shell.is_err());
    }

    #[test]
    fn init_shell_zsh_outputs_hook() {
        // Test that output_shell_hook succeeds for zsh
        // We can't easily capture stdout in a unit test, but we can verify
        // the shell hook is generated correctly
        let shell = parse_shell("zsh").expect("should parse zsh");
        let hook = shell::generate_shell_hook(shell);
        assert!(hook.contains("sanctum daemon start"));
        assert!(hook.contains("SANCTUM_ACTIVE"));
        assert!(hook.contains("zshrc"));
    }

    #[test]
    fn init_shell_bash_outputs_hook() {
        let shell = parse_shell("bash").expect("should parse bash");
        let hook = shell::generate_shell_hook(shell);
        assert!(hook.contains("sanctum daemon start"));
        assert!(hook.contains("SANCTUM_ACTIVE"));
        assert!(hook.contains("bashrc"));
    }

    #[test]
    fn init_shell_fish_outputs_hook() {
        let shell = parse_shell("fish").expect("should parse fish");
        let hook = shell::generate_shell_hook(shell);
        assert!(hook.contains("sanctum daemon start"));
        assert!(hook.contains("SANCTUM_ACTIVE"));
        assert!(hook.contains("config.fish"));
    }

    #[test]
    fn create_config_creates_file() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let config_dir = dir.path().join(".sanctum");
        let config_path = config_dir.join("config.toml");

        let created =
            create_config(dir.path(), &config_dir, &config_path).expect("should create config");
        assert!(created);
        assert!(config_path.exists());

        let content = fs::read_to_string(&config_path).expect("should read config");
        assert!(content.contains("[sentinel]"));
        assert!(content.contains("[ai_firewall]"));
        assert!(content.contains("[budgets]"));
    }

    #[test]
    fn create_config_does_not_overwrite() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let config_dir = dir.path().join(".sanctum");
        let config_path = config_dir.join("config.toml");

        // Create first
        let _ = create_config(dir.path(), &config_dir, &config_path);

        // Write custom content
        fs::write(&config_path, "custom content").expect("should write custom");

        // Should not overwrite
        let created = create_config(dir.path(), &config_dir, &config_path).expect("should succeed");
        assert!(!created);

        let content = fs::read_to_string(&config_path).expect("should read");
        assert_eq!(content, "custom content");
    }

    #[test]
    fn count_credential_issues_empty_dir() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let count = count_credential_issues(dir.path());
        assert_eq!(count, 0);
    }

    #[test]
    fn count_credential_issues_with_env_secrets() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        let env_content = "DATABASE_URL=postgres://user:pass@host/db\nAPI_KEY=sk-1234567890\n";
        fs::write(dir.path().join(".env"), env_content).expect("should write .env");

        let count = count_credential_issues(dir.path());
        assert_eq!(count, 2);
    }

    #[test]
    fn detect_npm_project_with_package_json() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        fs::write(dir.path().join("package.json"), "{}").expect("should write");
        assert!(detect_npm_project(dir.path()));
    }

    #[test]
    fn detect_npm_project_with_yarn_lock() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        fs::write(dir.path().join("yarn.lock"), "").expect("should write");
        assert!(detect_npm_project(dir.path()));
    }

    #[test]
    fn detect_npm_project_without_indicators() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        assert!(!detect_npm_project(dir.path()));
    }

    #[test]
    fn init_generates_npm_config_when_detected() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        // Create a package.json to trigger npm detection
        fs::write(dir.path().join("package.json"), "{}").expect("should write package.json");

        let config_dir = dir.path().join(".sanctum");
        let config_path = config_dir.join("config.toml");

        let created =
            create_config(dir.path(), &config_dir, &config_path).expect("should create config");
        assert!(created);

        let content = fs::read_to_string(&config_path).expect("should read config");
        assert!(content.contains("[sentinel.npm]"));
        assert!(content.contains("watch_lifecycle = true"));
        assert!(content.contains("ignore_scripts_warning = true"));
    }

    #[test]
    fn init_omits_npm_config_when_not_detected() {
        let dir = tempfile::tempdir().expect("should create tempdir");
        // No npm indicators

        let config_dir = dir.path().join(".sanctum");
        let config_path = config_dir.join("config.toml");

        let created =
            create_config(dir.path(), &config_dir, &config_path).expect("should create config");
        assert!(created);

        let content = fs::read_to_string(&config_path).expect("should read config");
        assert!(!content.contains("[sentinel.npm]"));
    }
}
