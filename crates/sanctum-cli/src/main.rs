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
//! - `sanctum proxy`    -- HTTP budget proxy management (preview)
//! - `sanctum doctor`   — Diagnose and verify Sanctum installation

use clap::{Parser, Subcommand};
use std::process::ExitCode;
use std::path::PathBuf;

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
        #[arg(long, value_parser = ["bash", "zsh", "fish"])]
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
        #[arg(long, conflicts_with = "delete")]
        approve: Option<String>,
        /// Permanently delete a quarantined file by ID.
        #[arg(long)]
        delete: Option<String>,
    },
    /// Scan for credential exposure in the current project.
    Scan {
        /// Output findings as NDJSON (one JSON object per line).
        #[arg(long)]
        json: bool,
        /// Also scan npm dependencies for lifecycle scripts.
        #[arg(long)]
        npm: bool,
        /// Path to the npm project to scan (default: current directory).
        #[arg(long, requires = "npm")]
        npm_path: Option<PathBuf>,
        /// Maximum depth of dependency tree to scan.
        #[arg(long, requires = "npm")]
        npm_depth: Option<u32>,
    },
    /// Run a command under Sanctum monitoring (auto-starts daemon, enables file and credential watchers).
    Run {
        /// Enable sandbox via nono (if installed).
        #[arg(long)]
        sandbox: bool,
        /// Command and arguments (use -- to separate flags, e.g. sanctum run -- npm test).
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// View or edit configuration.
    Config {
        /// Open config in $EDITOR.
        #[arg(long)]
        edit: bool,
        /// Output a recommended production configuration.
        #[arg(long, conflicts_with = "edit")]
        recommended: bool,
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
        #[arg(long, value_parser = ["info", "warning", "critical"])]
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
    #[command(hide = true)]
    Hook {
        /// Hook action: pre-bash, pre-write, pre-read, post-bash.
        action: String,
        /// Enable verbose debug output to stderr.
        #[arg(long)]
        verbose: bool,
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
    /// Manage the HTTP gateway proxy.
    Proxy {
        #[command(subcommand)]
        action: ProxyCliAction,
    },
    /// Manage the allowlist for high-entropy strings flagged as possible secrets.
    Entropy {
        #[command(subcommand)]
        action: EntropyAction,
    },
    /// Check installation health.
    Doctor,
}

#[derive(Subcommand)]
enum BudgetAction {
    /// Set budget limits.
    Set {
        /// Session budget limit (e.g. $50).
        #[arg(long, value_name = "AMOUNT")]
        session: Option<String>,
        /// Daily budget limit (e.g. $50).
        #[arg(long, value_name = "AMOUNT")]
        daily: Option<String>,
    },
    /// Extend current session budget.
    Extend {
        /// Amount to add (e.g. $20).
        #[arg(long, value_name = "AMOUNT")]
        session: Option<String>,
    },
    /// Reset budget counters.
    Reset,
    /// Record token usage for a provider/model.
    Record {
        /// API provider name (e.g. anthropic, openai, google).
        #[arg(long)]
        provider: String,
        /// Model identifier (e.g. claude-sonnet-4-6, gpt-4o).
        #[arg(long)]
        model: String,
        /// Number of input (prompt) tokens.
        #[arg(long)]
        input_tokens: u64,
        /// Number of output (completion) tokens.
        #[arg(long)]
        output_tokens: u64,
    },
}

#[derive(Subcommand)]
pub enum EntropyAction {
    /// Add a value to the entropy allowlist.
    ///
    /// Pass value as argument or pipe via stdin:
    ///   echo <value> | sanctum entropy allow
    Allow {
        /// The high-entropy string to allowlist (omit to read from stdin).
        value: Option<String>,
    },
    /// List all allowlisted entropy values.
    List,
}

#[derive(Subcommand)]
pub enum FixAction {
    /// List all unresolved threats.
    List {
        /// Filter by category (pth, credential, mcp, budget).
        #[arg(long, value_parser = ["pth", "credential", "mcp", "budget"])]
        category: Option<String>,
        /// Filter by threat level (info, warning, critical).
        #[arg(long, value_parser = ["info", "warning", "critical"])]
        level: Option<String>,
    },
    /// Remediate a specific threat by ID.
    Resolve {
        /// Threat ID from the audit log.
        id: String,
        /// Action: restore, delete, dismiss, allowlist.
        #[arg(long, value_parser = ["restore", "delete", "dismiss", "allowlist"])]
        action: Option<String>,
    },
    /// Batch-remediate all unresolved threats.
    All {
        /// Only process threats of a specific category.
        #[arg(long, value_parser = ["pth", "credential", "mcp", "budget"])]
        category: Option<String>,
    },
}

#[derive(Subcommand)]
enum HooksAction {
    /// Install hooks for a tool.
    Install {
        /// Tool to install hooks for (e.g., "claude").
        #[arg(value_parser = ["claude"])]
        tool: String,
    },
    /// Remove hooks for a tool.
    Remove {
        /// Tool to remove hooks from.
        #[arg(value_parser = ["claude"])]
        tool: String,
    },
}

#[derive(Subcommand)]
enum ProxyCliAction {
    /// Start the HTTP gateway proxy.
    Start {
        /// Port to listen on (default: 9847).
        #[arg(long, default_value = "9847")]
        port: u16,
    },
    /// Stop the running proxy.
    Stop,
    /// Show proxy status.
    Status,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Start the daemon.
    Start,
    /// Stop the daemon.
    Stop,
    /// Restart the daemon.
    Restart,
    /// Show daemon status.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init { dir, shell } => commands::init::run(&dir, shell.as_deref()),
        Commands::Status => commands::status::run(),
        Commands::Review {
            json,
            approve,
            delete,
        } => commands::review::run(json, approve.as_deref(), delete.as_deref()),
        Commands::Scan {
            json,
            npm: _,
            npm_path: _,
            npm_depth: _,
        } => commands::scan::run(json),
        Commands::Run { sandbox, command } => commands::run::run(sandbox, &command),
        Commands::Config { edit, recommended } => commands::config::run(edit, recommended),
        Commands::Budget { action } => commands::budget::run(action.as_ref()),
        Commands::Audit { last, level, json } => {
            commands::audit::run(last.as_deref(), level.as_deref(), json)
        }
        Commands::Fix { action, json, yes } => commands::fix::run(action.as_ref(), json, yes),
        Commands::Hook { action, verbose } => commands::hook::run(&action, verbose),
        Commands::Hooks { action } => commands::hooks::run(&action),
        Commands::Proxy { action } => commands::proxy::run(&action),
        Commands::Daemon { action } => commands::daemon::run(&action),
        Commands::Entropy { action } => commands::entropy::run(&action),
        Commands::Doctor => commands::doctor::run(),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn npm_path_without_npm_flag_is_rejected() {
        let result = Cli::try_parse_from(["sanctum", "scan", "--npm-path", "/some/path"]);
        assert!(
            result.is_err(),
            "--npm-path without --npm should be rejected by clap"
        );
    }

    #[test]
    fn npm_depth_without_npm_flag_is_rejected() {
        let result = Cli::try_parse_from(["sanctum", "scan", "--npm-depth", "3"]);
        assert!(
            result.is_err(),
            "--npm-depth without --npm should be rejected by clap"
        );
    }

    #[test]
    fn npm_path_with_npm_flag_is_accepted() {
        let result = Cli::try_parse_from(["sanctum", "scan", "--npm", "--npm-path", "/some/path"]);
        assert!(
            result.is_ok(),
            "--npm-path with --npm should be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn npm_depth_with_npm_flag_is_accepted() {
        let result = Cli::try_parse_from(["sanctum", "scan", "--npm", "--npm-depth", "5"]);
        assert!(
            result.is_ok(),
            "--npm-depth with --npm should be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn entropy_allow_accepts_optional_value() {
        let cli =
            Cli::try_parse_from(["sanctum", "entropy", "allow", "my-secret"]).expect("should parse");
        match cli.command {
            Commands::Entropy {
                action: EntropyAction::Allow { value },
            } => {
                assert_eq!(value.as_deref(), Some("my-secret"));
            }
            _ => panic!("expected Entropy Allow variant"),
        }
    }

    #[test]
    fn entropy_allow_without_value_parses() {
        let cli = Cli::try_parse_from(["sanctum", "entropy", "allow"]).expect("should parse");
        match cli.command {
            Commands::Entropy {
                action: EntropyAction::Allow { value },
            } => {
                assert!(value.is_none(), "value should be None when omitted");
            }
            _ => panic!("expected Entropy Allow variant"),
        }
    }
}
