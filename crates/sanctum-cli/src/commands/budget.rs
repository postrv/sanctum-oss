//! `sanctum budget` -- View or manage LLM spend budgets.

use sanctum_types::errors::CliError;

use crate::ipc_client::{self, IpcCommand, IpcResponse, ProviderBudgetInfo};
use crate::BudgetAction;

/// Send an IPC command and handle the common Ok/Error response pattern.
///
/// On `IpcResponse::Ok`, prints the message to stdout and returns `Ok(())`.
fn send_and_print(command: &IpcCommand) -> Result<(), CliError> {
    let response = ipc_client::send_command(command)?;
    match response {
        IpcResponse::Ok { message } => {
            #[allow(clippy::print_stdout)]
            {
                println!("{message}");
            }
            Ok(())
        }
        IpcResponse::Error { message } => Err(CliError::DaemonError(message)),
        _ => Err(CliError::DaemonError(
            "unexpected response from daemon".to_string(),
        )),
    }
}

/// Run the budget command.
pub fn run(action: Option<&BudgetAction>) -> Result<(), CliError> {
    match action {
        None => {
            // Display current budget status from the daemon
            let response = ipc_client::send_command(&IpcCommand::BudgetStatus)?;
            match response {
                IpcResponse::BudgetStatus { providers } => {
                    display_budget_table(&providers);
                    Ok(())
                }
                IpcResponse::Error { message } => Err(CliError::DaemonError(message)),
                _ => Err(CliError::DaemonError(
                    "unexpected response from daemon".to_string(),
                )),
            }
        }
        Some(BudgetAction::Set { session, daily }) => {
            let session_cents = session.as_deref().map(parse_dollar_amount).transpose()?;
            let daily_cents = daily.as_deref().map(parse_dollar_amount).transpose()?;
            send_and_print(&IpcCommand::BudgetSet {
                session_cents,
                daily_cents,
            })
        }
        Some(BudgetAction::Extend { session }) => {
            let amount = match session.as_deref() {
                Some(s) => parse_dollar_amount(s)?,
                None => {
                    return Err(CliError::InvalidArgs(
                        "usage: sanctum budget extend --session <amount>".to_string(),
                    ));
                }
            };
            send_and_print(&IpcCommand::BudgetExtend {
                additional_cents: amount,
            })
        }
        Some(BudgetAction::Reset) => send_and_print(&IpcCommand::BudgetReset),
        Some(BudgetAction::Record {
            provider,
            model,
            input_tokens,
            output_tokens,
        }) => send_and_print(&IpcCommand::RecordUsage {
            provider: provider.clone(),
            model: model.clone(),
            input_tokens: *input_tokens,
            output_tokens: *output_tokens,
        }),
    }
}

/// Parse a dollar string like "$50", "$50.00", or "50.00" into cents.
fn parse_dollar_amount(s: &str) -> Result<u64, CliError> {
    let trimmed = s.trim().trim_start_matches('$');
    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs("empty budget amount".to_string()));
    }

    let amount: f64 = trimmed
        .parse()
        .map_err(|_| CliError::InvalidArgs(format!("invalid budget amount: {s}")))?;

    if amount < 0.0 {
        return Err(CliError::InvalidArgs(
            "budget amount cannot be negative".to_string(),
        ));
    }

    if !amount.is_finite() {
        return Err(CliError::InvalidArgs(
            "budget amount must be a finite number".to_string(),
        ));
    }

    let cents_f = (amount * 100.0).round();
    #[allow(clippy::cast_precision_loss)]
    if cents_f >= u64::MAX as f64 {
        return Err(CliError::InvalidArgs("budget amount too large".to_string()));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let cents = cents_f as u64;
    Ok(cents)
}

/// Format cents as a dollar string.
fn format_dollars(cents: u64) -> String {
    let dollars = cents / 100;
    let remainder = cents % 100;
    format!("${dollars}.{remainder:02}")
}

/// Display a formatted budget table.
fn display_budget_table(providers: &[ProviderBudgetInfo]) {
    #[allow(clippy::print_stdout)]
    {
        println!(
            "{:<13} {:<17} {:<17} {:<15} {:<15}",
            "Provider", "Session Spend", "Session Limit", "Daily Spend", "Daily Limit"
        );
        for provider in providers {
            let session_limit = provider
                .session_limit_cents
                .map_or_else(|| "none".to_string(), format_dollars);
            let daily_limit = provider
                .daily_limit_cents
                .map_or_else(|| "none".to_string(), format_dollars);

            let mut flags = String::new();
            if provider.session_exceeded {
                flags.push_str(" [EXCEEDED]");
            }
            if provider.daily_exceeded {
                flags.push_str(" [DAILY EXCEEDED]");
            }
            if !provider.session_exceeded && !provider.daily_exceeded && provider.alert_triggered {
                flags.push_str(" [ALERT]");
            }

            println!(
                "{:<13} {:<17} {:<17} {:<15} {:<15}{}",
                provider.name,
                format_dollars(provider.session_spent_cents),
                session_limit,
                format_dollars(provider.daily_spent_cents),
                daily_limit,
                flags,
            );
        }
    }
}

/// Format a one-line budget summary for use in status output.
pub fn format_budget_summary(providers: &[ProviderBudgetInfo]) -> String {
    let total_session_spent: u64 = providers.iter().map(|p| p.session_spent_cents).sum();
    let any_exceeded = providers.iter().any(|p| p.session_exceeded);
    let any_alert = providers.iter().any(|p| p.alert_triggered);

    let status = if any_exceeded {
        "EXCEEDED"
    } else if any_alert {
        "WARNING"
    } else {
        "OK"
    };

    format!(
        "Budget: {} total session spend, status: {}",
        format_dollars(total_session_spent),
        status,
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_dollar_amount_basic() {
        assert_eq!(parse_dollar_amount("$50").ok(), Some(5000));
        assert_eq!(parse_dollar_amount("$50.00").ok(), Some(5000));
        assert_eq!(parse_dollar_amount("50").ok(), Some(5000));
        assert_eq!(parse_dollar_amount("$99.99").ok(), Some(9999));
        assert_eq!(parse_dollar_amount("$0.01").ok(), Some(1));
    }

    #[test]
    fn parse_dollar_amount_rejects_negative() {
        assert!(parse_dollar_amount("$-50").is_err());
    }

    #[test]
    fn parse_dollar_amount_rejects_empty() {
        assert!(parse_dollar_amount("$").is_err());
        assert!(parse_dollar_amount("").is_err());
    }

    #[test]
    fn parse_dollar_amount_rejects_text() {
        assert!(parse_dollar_amount("fifty").is_err());
    }

    #[test]
    fn parse_dollar_amount_rejects_infinity_nan() {
        assert!(parse_dollar_amount("$inf").is_err());
        assert!(parse_dollar_amount("$infinity").is_err());
        assert!(parse_dollar_amount("$NaN").is_err());
        assert!(parse_dollar_amount("inf").is_err());
        assert!(parse_dollar_amount("NaN").is_err());
    }

    #[test]
    fn parse_dollar_amount_rejects_overflow() {
        assert!(parse_dollar_amount("$184467440737095517.00").is_err());
    }

    #[test]
    fn format_dollars_basic() {
        assert_eq!(format_dollars(0), "$0.00");
        assert_eq!(format_dollars(1), "$0.01");
        assert_eq!(format_dollars(100), "$1.00");
        assert_eq!(format_dollars(1234), "$12.34");
        assert_eq!(format_dollars(5000), "$50.00");
    }

    #[test]
    fn display_budget_table_no_panic() {
        let providers = vec![
            ProviderBudgetInfo {
                name: "OpenAI".to_string(),
                session_spent_cents: 1234,
                session_limit_cents: Some(5000),
                daily_spent_cents: 4567,
                daily_limit_cents: Some(20000),
                alert_triggered: false,
                session_exceeded: false,
                daily_exceeded: false,
            },
            ProviderBudgetInfo {
                name: "Anthropic".to_string(),
                session_spent_cents: 321,
                session_limit_cents: Some(20000),
                daily_spent_cents: 321,
                daily_limit_cents: Some(100_000),
                alert_triggered: false,
                session_exceeded: false,
                daily_exceeded: false,
            },
        ];
        // Just verify it doesn't panic
        display_budget_table(&providers);
    }

    #[test]
    fn format_budget_summary_ok() {
        let providers = vec![ProviderBudgetInfo {
            name: "OpenAI".to_string(),
            session_spent_cents: 100,
            session_limit_cents: Some(5000),
            daily_spent_cents: 100,
            daily_limit_cents: Some(20000),
            alert_triggered: false,
            session_exceeded: false,
            daily_exceeded: false,
        }];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("$1.00"));
        assert!(summary.contains("OK"));
    }

    #[test]
    fn format_budget_summary_exceeded() {
        let providers = vec![ProviderBudgetInfo {
            name: "OpenAI".to_string(),
            session_spent_cents: 6000,
            session_limit_cents: Some(5000),
            daily_spent_cents: 6000,
            daily_limit_cents: Some(20000),
            alert_triggered: true,
            session_exceeded: true,
            daily_exceeded: false,
        }];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("EXCEEDED"));
    }

    #[test]
    fn format_budget_summary_warning() {
        let providers = vec![ProviderBudgetInfo {
            name: "OpenAI".to_string(),
            session_spent_cents: 4000,
            session_limit_cents: Some(5000),
            daily_spent_cents: 4000,
            daily_limit_cents: Some(20000),
            alert_triggered: true,
            session_exceeded: false,
            daily_exceeded: false,
        }];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("WARNING"));
    }

    // ---- Record command IPC construction tests ----

    #[test]
    fn record_usage_constructs_correct_ipc_command() {
        let cmd = IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 1000,
            output_tokens: 500,
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("\"command\":\"RecordUsage\""));
        assert!(json.contains("\"provider\":\"anthropic\""));
        assert!(json.contains("\"model\":\"claude-sonnet-4-6\""));
        assert!(json.contains("\"input_tokens\":1000"));
        assert!(json.contains("\"output_tokens\":500"));
    }

    #[test]
    fn record_usage_roundtrips_via_json() {
        let cmd = IpcCommand::RecordUsage {
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            input_tokens: 42,
            output_tokens: 17,
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        let roundtripped: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcCommand::RecordUsage {
                provider,
                model,
                input_tokens,
                output_tokens,
            } => {
                assert_eq!(provider, "openai");
                assert_eq!(model, "gpt-4o");
                assert_eq!(input_tokens, 42);
                assert_eq!(output_tokens, 17);
            }
            other => panic!("expected RecordUsage, got {other:?}"),
        }
    }

    #[test]
    fn record_daemon_not_running_produces_error() {
        // When the daemon isn't running, send_command should return DaemonNotRunning.
        // We can't easily call run() here because it needs a socket, but we can
        // verify the ipc_client handles a missing socket correctly.
        let result = ipc_client::send_command(&IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 100,
            output_tokens: 50,
        });
        // Should fail gracefully, not crash.
        assert!(result.is_err());
    }
}
