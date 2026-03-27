//! `sanctum budget` -- View or manage LLM spend budgets.

use sanctum_types::errors::CliError;

use crate::ipc_client::{self, IpcCommand, IpcResponse, ProviderBudgetInfo};
use crate::BudgetAction;

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
                IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
                _ => Err(CliError::ConnectionFailed(
                    "unexpected response from daemon".to_string(),
                )),
            }
        }
        Some(BudgetAction::Set { session, daily }) => {
            let session_cents = session
                .as_deref()
                .map(parse_dollar_amount)
                .transpose()?;
            let daily_cents = daily
                .as_deref()
                .map(parse_dollar_amount)
                .transpose()?;

            let response = ipc_client::send_command(&IpcCommand::BudgetSet {
                session_cents,
                daily_cents,
            })?;
            match response {
                IpcResponse::Ok { message } => {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{message}");
                    }
                    Ok(())
                }
                IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
                _ => Err(CliError::ConnectionFailed(
                    "unexpected response from daemon".to_string(),
                )),
            }
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

            let response =
                ipc_client::send_command(&IpcCommand::BudgetExtend { additional_cents: amount })?;
            match response {
                IpcResponse::Ok { message } => {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{message}");
                    }
                    Ok(())
                }
                IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
                _ => Err(CliError::ConnectionFailed(
                    "unexpected response from daemon".to_string(),
                )),
            }
        }
        Some(BudgetAction::Reset) => {
            let response = ipc_client::send_command(&IpcCommand::BudgetReset)?;
            match response {
                IpcResponse::Ok { message } => {
                    #[allow(clippy::print_stdout)]
                    {
                        println!("{message}");
                    }
                    Ok(())
                }
                IpcResponse::Error { message } => Err(CliError::ConnectionFailed(message)),
                _ => Err(CliError::ConnectionFailed(
                    "unexpected response from daemon".to_string(),
                )),
            }
        }
    }
}

/// Parse a dollar string like "$50", "$50.00", or "50.00" into cents.
fn parse_dollar_amount(s: &str) -> Result<u64, CliError> {
    let trimmed = s.trim().trim_start_matches('$');
    if trimmed.is_empty() {
        return Err(CliError::InvalidArgs("empty budget amount".to_string()));
    }

    let amount: f64 = trimmed.parse().map_err(|_| {
        CliError::InvalidArgs(format!("invalid budget amount: {s}"))
    })?;

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
        return Err(CliError::InvalidArgs(
            "budget amount too large".to_string(),
        ));
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
            } else if provider.alert_triggered {
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
            },
            ProviderBudgetInfo {
                name: "Anthropic".to_string(),
                session_spent_cents: 321,
                session_limit_cents: Some(20000),
                daily_spent_cents: 321,
                daily_limit_cents: Some(100_000),
                alert_triggered: false,
                session_exceeded: false,
            },
        ];
        // Just verify it doesn't panic
        display_budget_table(&providers);
    }

    #[test]
    fn format_budget_summary_ok() {
        let providers = vec![
            ProviderBudgetInfo {
                name: "OpenAI".to_string(),
                session_spent_cents: 100,
                session_limit_cents: Some(5000),
                daily_spent_cents: 100,
                daily_limit_cents: Some(20000),
                alert_triggered: false,
                session_exceeded: false,
            },
        ];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("$1.00"));
        assert!(summary.contains("OK"));
    }

    #[test]
    fn format_budget_summary_exceeded() {
        let providers = vec![
            ProviderBudgetInfo {
                name: "OpenAI".to_string(),
                session_spent_cents: 6000,
                session_limit_cents: Some(5000),
                daily_spent_cents: 6000,
                daily_limit_cents: Some(20000),
                alert_triggered: true,
                session_exceeded: true,
            },
        ];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("EXCEEDED"));
    }

    #[test]
    fn format_budget_summary_warning() {
        let providers = vec![
            ProviderBudgetInfo {
                name: "OpenAI".to_string(),
                session_spent_cents: 4000,
                session_limit_cents: Some(5000),
                daily_spent_cents: 4000,
                daily_limit_cents: Some(20000),
                alert_triggered: true,
                session_exceeded: false,
            },
        ];
        let summary = format_budget_summary(&providers);
        assert!(summary.contains("WARNING"));
    }
}
