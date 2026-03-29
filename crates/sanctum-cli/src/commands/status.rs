//! `sanctum status` -- Show daemon status.

use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;

use crate::commands::budget::format_budget_summary;
use crate::ipc_client::{self, IpcCommand, IpcResponse};

/// Run the status command.
///
/// Connects to the daemon via IPC and displays current status.
/// If the daemon is not running, displays offline status instead.
pub fn run() -> Result<(), CliError> {
    let response = match ipc_client::send_command(&IpcCommand::Status) {
        Ok(resp) => resp,
        Err(CliError::DaemonNotRunning) => return offline_status(),
        Err(e) => return Err(e),
    };

    match response {
        IpcResponse::Status {
            version,
            uptime_secs,
            watchers_active,
            quarantine_count,
        } => {
            let hours = uptime_secs / 3600;
            let minutes = (uptime_secs % 3600) / 60;
            let secs = uptime_secs % 60;

            #[allow(clippy::print_stdout)]
            {
                println!("Sanctum daemon v{version}");
                println!("  Uptime:     {hours}h {minutes}m {secs}s");
                println!("  Watchers:   {watchers_active} active");
                println!("  Quarantine: {quarantine_count} items");
            }

            // Best-effort budget summary: if the daemon responds, show it;
            // if not, silently skip (budget tracking may not be active).
            if let Ok(IpcResponse::BudgetStatus { providers }) =
                ipc_client::send_command(&IpcCommand::BudgetStatus)
            {
                let has_spend = providers.iter().any(|p| p.session_spent_cents > 0);
                if has_spend {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("  {}", format_budget_summary(&providers));
                    }
                }
            }

            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::DaemonError(message)),
        _ => Err(CliError::DaemonError(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// Display offline status when the daemon is not running.
///
/// All filesystem operations are best-effort — failures are silently handled
/// with fallback display strings.
///
/// Returns `Ok(())` because the status command should succeed whether the
/// daemon is online or offline -- it reports the state either way.
#[allow(clippy::unnecessary_wraps)]
fn offline_status() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    // Check for config file: first ~/.sanctum/config.toml, then paths.config_dir/config.toml
    let home_config = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .map(|h| h.join(".sanctum/config.toml"));

    let platform_config = paths.config_dir.join("config.toml");

    let config_display = if home_config.as_ref().is_some_and(|p| p.exists()) {
        home_config
            .as_ref()
            .map_or_else(|| "not found".to_string(), |p| p.display().to_string())
    } else if platform_config.exists() {
        platform_config.display().to_string()
    } else {
        "not found".to_string()
    };

    // Count quarantine items best-effort
    let quarantine_display = std::fs::read_dir(&paths.quarantine_dir).ok().map_or_else(
        || "directory not created".to_string(),
        |entries| {
            let count = entries.filter_map(std::result::Result::ok).count();
            format!("{count} items")
        },
    );

    #[allow(clippy::print_stdout)]
    {
        println!("Sanctum daemon: offline");
        println!();
        println!("  Config:     {config_display}");
        println!("  Quarantine: {quarantine_display}");
        println!();
        println!("  Start with: sanctum daemon start");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_status_returns_ok() {
        let result = offline_status();
        assert!(result.is_ok(), "offline_status should return Ok(())");
    }
}
