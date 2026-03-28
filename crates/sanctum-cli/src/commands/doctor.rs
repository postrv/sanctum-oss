//! `sanctum doctor` — Validate Sanctum installation health.

use sanctum_types::config::SanctumConfig;
use sanctum_types::errors::CliError;
use sanctum_types::ipc::IpcCommand;
use sanctum_types::paths::WellKnownPaths;

use crate::ipc_client;

#[derive(Debug)]
enum CheckResult {
    Pass(String),
    Warn(String),
    Fail(String),
}

struct Check {
    name: &'static str,
    result: CheckResult,
}

impl Check {
    const fn label(&self) -> &'static str {
        match &self.result {
            CheckResult::Pass(_) => "[PASS]",
            CheckResult::Warn(_) => "[WARN]",
            CheckResult::Fail(_) => "[FAIL]",
        }
    }

    fn detail(&self) -> &str {
        match &self.result {
            CheckResult::Pass(s) | CheckResult::Warn(s) | CheckResult::Fail(s) => s,
        }
    }
}

/// Run the doctor command — check installation health.
///
/// # Errors
///
/// Returns `CliError::Io` if output cannot be written.
#[allow(clippy::unnecessary_wraps)]
pub fn run() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    let checks = vec![
        Check {
            name: "sanctum binary",
            result: check_sanctum_binary(),
        },
        Check {
            name: "sanctum-daemon binary",
            result: check_daemon_binary(),
        },
        Check {
            name: "Daemon",
            result: check_daemon_reachable(),
        },
        Check {
            name: "Config",
            result: check_config(&paths),
        },
        Check {
            name: "Data directories",
            result: check_data_dirs(&paths),
        },
        Check {
            name: "Python",
            result: check_python(),
        },
        Check {
            name: "nono",
            result: check_nono(),
        },
        Check {
            name: "Claude hooks",
            result: check_claude_hooks(),
        },
    ];

    let mut pass_count: u32 = 0;
    let mut warn_count: u32 = 0;
    let mut fail_count: u32 = 0;

    for check in &checks {
        match &check.result {
            CheckResult::Pass(_) => pass_count += 1,
            CheckResult::Warn(_) => warn_count += 1,
            CheckResult::Fail(_) => fail_count += 1,
        }
    }

    #[allow(clippy::print_stdout)]
    {
        println!("Sanctum Doctor");
        println!("==============");
        println!();
        for check in &checks {
            println!("  {} {}: {}", check.label(), check.name, check.detail());
        }
        println!();
        println!("Summary: {pass_count} pass, {warn_count} warn, {fail_count} fail");
    }

    Ok(())
}

/// Check whether the `sanctum` binary is on `PATH`.
fn check_sanctum_binary() -> CheckResult {
    match std::process::Command::new("which").arg("sanctum").output() {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            CheckResult::Pass(path)
        }
        _ => CheckResult::Fail("not found on PATH".to_string()),
    }
}

/// Check whether the `sanctum-daemon` binary is on `PATH`.
fn check_daemon_binary() -> CheckResult {
    match std::process::Command::new("which")
        .arg("sanctum-daemon")
        .output()
    {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            CheckResult::Pass(path)
        }
        _ => CheckResult::Fail("not found on PATH".to_string()),
    }
}

/// Check whether the daemon is reachable via IPC.
fn check_daemon_reachable() -> CheckResult {
    match ipc_client::send_command(&IpcCommand::Status) {
        Ok(_) => CheckResult::Pass("running".to_string()),
        Err(CliError::DaemonNotRunning) => CheckResult::Fail("not running".to_string()),
        Err(e) => CheckResult::Fail(format!("{e}")),
    }
}

/// Check for a valid configuration file.
fn check_config(paths: &WellKnownPaths) -> CheckResult {
    // Check ~/.sanctum/config.toml first, then the platform config dir.
    let home_config = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".sanctum/config.toml"));

    let platform_config = paths.config_dir.join("config.toml");

    let config_path = if home_config.as_ref().is_some_and(|p| p.exists()) {
        home_config
    } else if platform_config.exists() {
        Some(platform_config)
    } else {
        None
    };

    let Some(path) = config_path else {
        return CheckResult::Warn("no config file found (using defaults)".to_string());
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => match toml::from_str::<SanctumConfig>(&contents) {
            Ok(_) => CheckResult::Pass(path.display().to_string()),
            Err(e) => CheckResult::Fail(format!("parse error in {}: {e}", path.display())),
        },
        Err(e) => CheckResult::Fail(format!("cannot read {}: {e}", path.display())),
    }
}

/// Check whether the data and quarantine directories exist.
fn check_data_dirs(paths: &WellKnownPaths) -> CheckResult {
    let data_exists = paths.data_dir.exists();
    let quarantine_exists = paths.quarantine_dir.exists();

    if data_exists && quarantine_exists {
        CheckResult::Pass(paths.data_dir.display().to_string())
    } else {
        CheckResult::Warn("not yet created (will be created on first event)".to_string())
    }
}

/// Check whether Python 3 is available.
fn check_python() -> CheckResult {
    match std::process::Command::new("python3")
        .arg("--version")
        .output()
    {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // `python3 --version` outputs "Python 3.x.y" — strip the prefix.
            let version = version
                .strip_prefix("Python ")
                .unwrap_or(&version)
                .to_string();
            CheckResult::Pass(version)
        }
        _ => CheckResult::Warn("not installed (optional for .pth analysis)".to_string()),
    }
}

/// Check whether `nono` sandbox is available.
fn check_nono() -> CheckResult {
    match std::process::Command::new("which").arg("nono").output() {
        Ok(output) if output.status.success() => {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            CheckResult::Pass(path)
        }
        _ => CheckResult::Warn("not installed (optional sandbox)".to_string()),
    }
}

/// Check whether Claude Code hooks reference Sanctum.
fn check_claude_hooks() -> CheckResult {
    let settings_path = match std::env::var_os("HOME") {
        Some(home) => std::path::PathBuf::from(home).join(".claude/settings.json"),
        None => return CheckResult::Warn("cannot determine HOME directory".to_string()),
    };

    if !settings_path.exists() {
        return CheckResult::Warn("not installed (~/.claude/settings.json not found)".to_string());
    }

    std::fs::read_to_string(&settings_path).map_or_else(
        |_| CheckResult::Warn("cannot read ~/.claude/settings.json".to_string()),
        |contents| {
            if contents.contains("sanctum") {
                CheckResult::Pass("installed".to_string())
            } else {
                CheckResult::Warn(
                    "not installed (settings.json exists but does not reference sanctum)"
                        .to_string(),
                )
            }
        },
    )
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn check_result_display() {
        let pass = Check {
            name: "test check",
            result: CheckResult::Pass("all good".to_string()),
        };
        assert_eq!(pass.label(), "[PASS]");
        assert_eq!(pass.detail(), "all good");

        let warn = Check {
            name: "warn check",
            result: CheckResult::Warn("something off".to_string()),
        };
        assert_eq!(warn.label(), "[WARN]");
        assert_eq!(warn.detail(), "something off");

        let fail = Check {
            name: "fail check",
            result: CheckResult::Fail("broken".to_string()),
        };
        assert_eq!(fail.label(), "[FAIL]");
        assert_eq!(fail.detail(), "broken");
    }

    #[test]
    fn check_config_with_valid_tempdir_config() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let config_file = dir.path().join("config.toml");
        std::fs::write(&config_file, "[sentinel]\nwatch_pth = true\n").expect("write config");

        let paths = WellKnownPaths {
            ssh_dir: dir.path().join(".ssh"),
            data_dir: dir.path().to_path_buf(),
            config_dir: dir.path().to_path_buf(),
            quarantine_dir: dir.path().join("quarantine"),
            log_dir: dir.path().join("logs"),
            pid_file: dir.path().join("sanctum.pid"),
            socket_path: dir.path().join("sanctum.sock"),
        };

        let result = check_config(&paths);
        assert!(
            matches!(&result, CheckResult::Pass(p) if p.contains("config.toml")),
            "expected Pass containing config.toml, got {result:?}"
        );
    }

    #[test]
    fn check_data_dirs_missing() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let paths = WellKnownPaths {
            ssh_dir: dir.path().join(".ssh"),
            data_dir: dir.path().join("nonexistent_data"),
            config_dir: dir.path().to_path_buf(),
            quarantine_dir: dir.path().join("nonexistent_quarantine"),
            log_dir: dir.path().join("logs"),
            pid_file: dir.path().join("sanctum.pid"),
            socket_path: dir.path().join("sanctum.sock"),
        };

        let result = check_data_dirs(&paths);
        assert!(
            matches!(result, CheckResult::Warn(_)),
            "expected Warn for missing dirs, got {result:?}"
        );
    }
}
