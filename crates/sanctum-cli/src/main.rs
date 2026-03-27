//! Sanctum CLI — the primary user interface.
//!
//! Commands:
//! - `sanctum init`     — Initialise Sanctum in current directory
//! - `sanctum status`   — Show daemon status
//! - `sanctum review`   — Review quarantined items
//! - `sanctum scan`     — Scan for credential exposure
//! - `sanctum run`      — Run a command with Sanctum protections
//! - `sanctum config`   — View/edit configuration
//! - `sanctum budget`   — View/manage LLM spend budgets
//! - `sanctum audit`    — View the threat event audit log
//! - `sanctum fix`      — Guided threat remediation
//! - `sanctum hook`     — Claude Code hook handler (pre-bash, pre-write, etc.)
//! - `sanctum hooks`    — Install/remove Claude Code hooks
//! - `sanctum daemon`   — Daemon management (start/stop/restart)

use clap::{Parser, Subcommand};
use std::process::ExitCode;

mod commands;
mod ipc_client;
mod shell;

/// The developer security daemon for the AI coding era.
#[derive(Parser)]
#[command(name = "sanctum", version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialise Sanctum in the current directory.
    Init {
        /// Directory to initialise in (defaults to current).
        #[arg(long, default_value = ".")]
        dir: String,
        /// Output shell hook for the specified shell (bash, zsh, or fish).
        #[arg(long)]
        shell: Option<String>,
    },
    /// Show daemon status.
    Status,
    /// Review quarantined items.
    Review {
        /// Output as JSON.
        #[arg(long)]
        json: bool,
        /// Approve and restore a quarantined file by ID.
        #[arg(long)]
        approve: Option<String>,
        /// Permanently delete a quarantined file by ID.
        #[arg(long)]
        delete: Option<String>,
    },
    /// Scan for credential exposure in the current project.
    Scan,
    /// Run a command with Sanctum protections.
    Run {
        /// Enable sandbox via nono (if installed).
        #[arg(long)]
        sandbox: bool,
        /// The command to run.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// View or edit configuration.
    Config {
        /// Open config in $EDITOR.
        #[arg(long)]
        edit: bool,
    },
    /// View or manage LLM spend budgets.
    Budget {
        #[command(subcommand)]
        action: Option<BudgetAction>,
    },
    /// View the threat event audit log.
    Audit {
        /// Show only events from the last duration (e.g. 24h, 7d, 1h, 30m).
        #[arg(long)]
        last: Option<String>,
        /// Filter by threat level (info, warning, critical).
        #[arg(long)]
        level: Option<String>,
        /// Output as JSON (one event per line).
        #[arg(long)]
        json: bool,
    },
    /// Guided threat remediation.
    Fix {
        #[command(subcommand)]
        action: Option<FixAction>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
        /// Non-interactive mode: apply actions without prompting.
        #[arg(long)]
        yes: bool,
    },
    /// Claude Code hook handler (called by PreToolUse/PostToolUse hooks).
    Hook {
        /// Hook action: pre-bash, pre-write, pre-read, post-bash.
        action: String,
    },
    /// Install or remove Claude Code hooks.
    Hooks {
        #[command(subcommand)]
        action: HooksAction,
    },
    /// Daemon management.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
}

#[derive(Subcommand)]
enum BudgetAction {
    /// Set budget limits.
    Set {
        #[arg(long)]
        session: Option<String>,
        #[arg(long)]
        daily: Option<String>,
    },
    /// Extend current session budget.
    Extend {
        #[arg(long)]
        session: Option<String>,
    },
    /// Reset budget counters.
    Reset,
}

#[derive(Subcommand)]
pub enum FixAction {
    /// List all unresolved threats.
    List {
        /// Filter by category (pth, credential, mcp, budget).
        #[arg(long)]
        category: Option<String>,
        /// Filter by threat level (info, warning, critical).
        #[arg(long)]
        level: Option<String>,
    },
    /// Remediate a specific threat by ID.
    Resolve {
        /// Threat ID from the audit log.
        id: String,
        /// Action: restore, delete, dismiss, allowlist.
        #[arg(long)]
        action: Option<String>,
    },
    /// Batch-remediate all unresolved threats.
    All {
        /// Only process threats of a specific category.
        #[arg(long)]
        category: Option<String>,
    },
}

#[derive(Subcommand)]
enum HooksAction {
    /// Install hooks for a tool.
    Install {
        /// Tool to install hooks for (e.g., "claude").
        tool: String,
    },
    /// Remove hooks for a tool.
    Remove {
        /// Tool to remove hooks from.
        tool: String,
    },
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon.
    Start,
    /// Stop the daemon.
    Stop,
    /// Restart the daemon.
    Restart,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { dir, shell } => commands::init::run(&dir, shell.as_deref()),
        Commands::Status => commands::status::run(),
        Commands::Review { json, approve, delete } => {
            commands::review::run(json, approve.as_deref(), delete.as_deref())
        }
        Commands::Scan => commands::scan::run(),
        Commands::Run { sandbox, command } => {
            commands::run::run(sandbox, &command)
        }
        Commands::Config { edit } => commands::config::run(edit),
        Commands::Budget { action } => commands::budget::run(action.as_ref()),
        Commands::Audit { last, level, json } => {
            commands::audit::run(last.as_deref(), level.as_deref(), json)
        }
        Commands::Fix { action, json, yes } => {
            commands::fix::run(action.as_ref(), json, yes)
        }
        Commands::Hook { action } => commands::hook::run(&action),
        Commands::Hooks { action } => commands::hooks::run(&action),
        Commands::Daemon { action } => commands::daemon::run(&action),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("Error: {e}");
            }
            ExitCode::FAILURE
        }
    }
}
