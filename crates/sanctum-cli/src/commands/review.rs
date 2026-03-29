//! `sanctum review` — Review quarantined items.

use sanctum_types::errors::CliError;

use crate::ipc_client::{self, IpcCommand, IpcResponse};

/// Run the review command.
///
/// - `--approve <id>`: send `RestoreQuarantine` to the daemon
/// - `--delete <id>`: send `DeleteQuarantine` to the daemon
/// - Neither: list all quarantined items
pub fn run(json: bool, approve: Option<&str>, delete: Option<&str>) -> Result<(), CliError> {
    if let Some(id) = approve {
        return approve_item(id);
    }

    if let Some(id) = delete {
        return delete_item(id);
    }

    list_quarantine(json)
}

/// Approve and restore a quarantined file by ID.
fn approve_item(id: &str) -> Result<(), CliError> {
    let command = IpcCommand::RestoreQuarantine { id: id.to_string() };
    let response = ipc_client::send_command(&command)?;

    match response {
        IpcResponse::Ok { message } => {
            #[allow(clippy::print_stdout)]
            {
                println!("Approved: {message}");
            }
            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::DaemonError(message)),
        _ => Err(CliError::DaemonError(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// Permanently delete a quarantined file by ID.
fn delete_item(id: &str) -> Result<(), CliError> {
    let command = IpcCommand::DeleteQuarantine { id: id.to_string() };
    let response = ipc_client::send_command(&command)?;

    match response {
        IpcResponse::Ok { message } => {
            #[allow(clippy::print_stdout)]
            {
                println!("Deleted: {message}");
            }
            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::DaemonError(message)),
        _ => Err(CliError::DaemonError(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// List all quarantined items.
fn list_quarantine(json: bool) -> Result<(), CliError> {
    let response = ipc_client::send_command(&IpcCommand::ListQuarantine)?;

    match response {
        IpcResponse::QuarantineList { items } => {
            if items.is_empty() {
                #[allow(clippy::print_stdout)]
                {
                    println!("No items in quarantine.");
                }
                return Ok(());
            }

            if json {
                let json_output =
                    serde_json::to_string_pretty(&items).unwrap_or_else(|_| "[]".to_string());
                #[allow(clippy::print_stdout)]
                {
                    println!("{json_output}");
                }
            } else {
                #[allow(clippy::print_stdout)]
                {
                    println!("Quarantined items ({} total):", items.len());
                    println!("{:-<72}", "");
                    for item in &items {
                        println!("  ID:           {}", item.id);
                        println!("  Original:     {}", item.original_path);
                        println!("  Reason:       {}", item.reason);
                        println!("  Quarantined:  {}", item.quarantined_at);
                        println!("{:-<72}", "");
                    }
                    println!();
                    println!("Actions:");
                    println!(
                        "  sanctum review --approve <ID>  — restore file to original location"
                    );
                    println!(
                        "  sanctum review --delete <ID>   — permanently remove quarantined file"
                    );
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn approve_builds_correct_ipc_command() {
        // Verify the IPC command is constructed correctly
        let command = IpcCommand::RestoreQuarantine {
            id: "abc-123".to_string(),
        };

        let serialized = serde_json::to_string(&command).expect("should serialize");
        assert!(serialized.contains("RestoreQuarantine"));
        assert!(serialized.contains("abc-123"));
    }

    #[test]
    fn delete_builds_correct_ipc_command() {
        // Verify the IPC command is constructed correctly
        let command = IpcCommand::DeleteQuarantine {
            id: "def-456".to_string(),
        };

        let serialized = serde_json::to_string(&command).expect("should serialize");
        assert!(serialized.contains("DeleteQuarantine"));
        assert!(serialized.contains("def-456"));
    }

    #[test]
    fn approve_command_serializes_with_tag() {
        let command = IpcCommand::RestoreQuarantine {
            id: "test-id".to_string(),
        };
        let json: serde_json::Value =
            serde_json::to_value(&command).expect("should serialize to value");

        assert_eq!(json["command"], "RestoreQuarantine");
        assert_eq!(json["id"], "test-id");
    }

    #[test]
    fn delete_command_serializes_with_tag() {
        let command = IpcCommand::DeleteQuarantine {
            id: "test-id".to_string(),
        };
        let json: serde_json::Value =
            serde_json::to_value(&command).expect("should serialize to value");

        assert_eq!(json["command"], "DeleteQuarantine");
        assert_eq!(json["id"], "test-id");
    }
}
