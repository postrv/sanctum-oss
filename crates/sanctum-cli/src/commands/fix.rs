//! `sanctum fix` -- Guided threat remediation.

use sanctum_types::errors::CliError;

use crate::ipc_client::{self, IpcCommand, IpcResponse, ThreatListItem};
use crate::FixAction;

/// Run the fix command.
pub fn run(action: Option<&FixAction>, json: bool, yes: bool) -> Result<(), CliError> {
    match action {
        None | Some(FixAction::List { .. }) => {
            // Extract filters from action if it's List
            let (category, level) = match action {
                Some(FixAction::List { category, level }) => (category.clone(), level.clone()),
                _ => (None, None),
            };
            run_list(category, level, json)
        }
        Some(FixAction::Resolve {
            id,
            action: resolve_action,
        }) => run_resolve(id, resolve_action.as_deref(), yes),
        Some(FixAction::All { category }) => run_all(category.as_deref(), yes),
    }
}

/// List unresolved threats from the daemon.
fn run_list(category: Option<String>, level: Option<String>, json: bool) -> Result<(), CliError> {
    let command = IpcCommand::ListThreats { category, level };
    let response = ipc_client::send_command(&command)?;

    match response {
        IpcResponse::ThreatList { threats, truncated } => {
            if threats.is_empty() {
                #[allow(clippy::print_stdout)]
                {
                    println!("No unresolved threats.");
                }
                return Ok(());
            }

            if json {
                for threat in &threats {
                    let json_str =
                        serde_json::to_string(threat).unwrap_or_else(|_| "{}".to_string());
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{json_str}");
                    }
                }
            } else {
                print_threat_table(&threats);
            }

            if truncated {
                #[allow(clippy::print_stdout)]
                {
                    println!("(results truncated — more threats exist than shown)");
                }
            }

            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
        _ => Err(CliError::ConnectionFailed(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// Print a formatted table of threats with colour-coded levels.
fn print_threat_table(threats: &[ThreatListItem]) {
    #[allow(clippy::print_stdout)]
    {
        println!("Unresolved threats ({} total):", threats.len());
        println!("{:-<80}", "");
        for threat in threats {
            let level_str = match threat.level.as_str() {
                "Critical" => "\x1b[31m[CRITICAL]\x1b[0m",
                "Warning" => "\x1b[33m[WARNING]\x1b[0m",
                "Info" => "\x1b[34m[INFO]\x1b[0m",
                other => other,
            };

            println!(
                "  {id}  {ts}  {level}  {desc}",
                id = threat.id,
                ts = threat.timestamp,
                level = level_str,
                desc = threat.description,
            );
            println!(
                "    Category: {cat}  Action: {act}  Path: {path}",
                cat = threat.category,
                act = threat.action_taken,
                path = threat.source_path,
            );
            println!("{:-<80}", "");
        }
        println!();
        println!("Actions:");
        println!("  sanctum fix resolve <ID>                — interactively resolve a threat");
        println!("  sanctum fix resolve <ID> --action dismiss  — dismiss a threat");
        println!("  sanctum fix all --yes                    — batch-dismiss all threats");
    }
}

/// Resolve a specific threat by ID.
fn run_resolve(id: &str, action: Option<&str>, yes: bool) -> Result<(), CliError> {
    // If no action specified and not --yes, show details first
    if action.is_none() && !yes {
        let details_cmd = IpcCommand::GetThreatDetails { id: id.to_string() };
        let response = ipc_client::send_command(&details_cmd)?;

        match response {
            IpcResponse::ThreatDetails {
                id: detail_id,
                timestamp,
                level,
                category,
                description,
                source_path,
                creator_pid,
                creator_exe,
                action_taken,
                quarantine_id,
            } => {
                print_threat_details(
                    &detail_id,
                    &timestamp,
                    &level,
                    &category,
                    &description,
                    &source_path,
                    creator_pid,
                    creator_exe.as_deref(),
                    &action_taken,
                    quarantine_id.as_deref(),
                );
                return Ok(());
            }
            IpcResponse::Error { message } => return Err(CliError::ConnectionFailed(message)),
            _ => {
                return Err(CliError::ConnectionFailed(
                    "unexpected response from daemon".to_string(),
                ));
            }
        }
    }

    // Apply the resolution
    let resolve_action = action.unwrap_or("dismiss");
    let command = IpcCommand::ResolveThreat {
        id: id.to_string(),
        action: resolve_action.to_string(),
        note: String::new(),
    };
    let response = ipc_client::send_command(&command)?;

    match response {
        IpcResponse::Ok { message } => {
            #[allow(clippy::print_stdout)]
            {
                println!("Resolved: {message}");
            }
            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
        _ => Err(CliError::ConnectionFailed(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// Print detailed information about a single threat.
#[allow(clippy::too_many_arguments)]
fn print_threat_details(
    id: &str,
    timestamp: &str,
    level: &str,
    category: &str,
    description: &str,
    source_path: &str,
    creator_pid: Option<u32>,
    creator_exe: Option<&str>,
    action_taken: &str,
    quarantine_id: Option<&str>,
) {
    let level_str = match level {
        "Critical" => "\x1b[31m[CRITICAL]\x1b[0m",
        "Warning" => "\x1b[33m[WARNING]\x1b[0m",
        "Info" => "\x1b[34m[INFO]\x1b[0m",
        other => other,
    };

    #[allow(clippy::print_stdout)]
    {
        println!("Threat Details");
        println!("{:-<50}", "");
        println!("  ID:          {id}");
        println!("  Timestamp:   {timestamp}");
        println!("  Level:       {level_str}");
        println!("  Category:    {category}");
        println!("  Description: {description}");
        println!("  Path:        {source_path}");
        println!("  Action:      {action_taken}");
        if let Some(pid) = creator_pid {
            match creator_exe {
                Some(exe) => println!("  Creator:     PID {pid} ({exe})"),
                None => println!("  Creator:     PID {pid}"),
            }
        }
        if let Some(qid) = quarantine_id {
            println!("  Quarantine:  {qid}");
        }
        println!("{:-<50}", "");
        println!();
        println!("Available actions:");
        println!("  sanctum fix resolve {id} --action restore    — restore from quarantine");
        println!("  sanctum fix resolve {id} --action delete     — permanently delete");
        println!("  sanctum fix resolve {id} --action dismiss    — dismiss without action");
        println!("  sanctum fix resolve {id} --action allowlist  — add to allowlist");
    }
}

/// Batch-resolve all unresolved threats.
fn run_all(category: Option<&str>, yes: bool) -> Result<(), CliError> {
    if !yes {
        return Err(CliError::InvalidArgs(
            "batch mode requires --yes flag: sanctum fix all --yes".to_string(),
        ));
    }

    let command = IpcCommand::ListThreats {
        category: category.map(String::from),
        level: None,
    };
    let response = ipc_client::send_command(&command)?;

    match response {
        IpcResponse::ThreatList { threats, .. } => {
            if threats.is_empty() {
                #[allow(clippy::print_stdout)]
                {
                    println!("No unresolved threats to resolve.");
                }
                return Ok(());
            }

            #[allow(clippy::print_stdout)]
            {
                println!("Resolving {} threats...", threats.len());
            }

            let mut resolved = 0u32;
            let mut failed = 0u32;

            for threat in &threats {
                let resolve_cmd = IpcCommand::ResolveThreat {
                    id: threat.id.clone(),
                    action: "dismiss".to_string(),
                    note: "batch-dismissed via sanctum fix all".to_string(),
                };
                match ipc_client::send_command(&resolve_cmd) {
                    Ok(IpcResponse::Ok { .. }) => {
                        resolved += 1;
                        #[allow(clippy::print_stdout)]
                        {
                            println!("  Dismissed: {} ({})", threat.id, threat.description);
                        }
                    }
                    Ok(IpcResponse::Error { message }) => {
                        failed += 1;
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("  Failed:    {} — {message}", threat.id);
                        }
                    }
                    Ok(_) => {
                        failed += 1;
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("  Failed:    {} — unexpected response", threat.id);
                        }
                    }
                    Err(e) => {
                        failed += 1;
                        #[allow(clippy::print_stderr)]
                        {
                            eprintln!("  Failed:    {} — {e}", threat.id);
                        }
                    }
                }
            }

            #[allow(clippy::print_stdout)]
            {
                println!();
                println!("Done: {resolved} resolved, {failed} failed.");
            }

            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
        _ => Err(CliError::ConnectionFailed(
            "unexpected response from daemon".to_string(),
        )),
    }
}
