//! `sanctum status` -- Show daemon status.

use sanctum_types::errors::CliError;

use crate::commands::budget::format_budget_summary;
use crate::ipc_client::{self, IpcCommand, IpcResponse};

/// Run the status command.
///
/// Connects to the daemon via IPC and displays current status.
pub fn run() -> Result<(), CliError> {
    let response = ipc_client::send_command(&IpcCommand::Status)?;

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
        IpcResponse::Error { message } => {
            Err(CliError::ConnectionFailed(message))
        }
        _ => Err(CliError::ConnectionFailed(
            "unexpected response from daemon".to_string(),
        )),
    }
}
