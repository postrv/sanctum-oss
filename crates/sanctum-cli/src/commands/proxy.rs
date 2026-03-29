//! `sanctum proxy` -- HTTP budget proxy management (preview feature).
//!
//! The proxy crate has a working server implementation but it is not yet wired
//! into any binary.  For v0.1.0, all proxy subcommands return informative error
//! messages rather than pretending to work.

use sanctum_types::errors::CliError;

use crate::ProxyCliAction;

/// Run the proxy command.
///
/// All actions currently return errors because the proxy is a preview feature
/// that requires shared budget state with the daemon, which is not yet wired.
pub fn run(action: &ProxyCliAction) -> Result<(), CliError> {
    match action {
        ProxyCliAction::Start { .. } => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("sanctum proxy: preview feature (not yet wired into the daemon)");
                eprintln!();
                eprintln!("When complete, `sanctum proxy start` will:");
                eprintln!(
                    "  - Start a transparent HTTPS proxy on 127.0.0.1:{port}",
                    port = sanctum_types::config::DEFAULT_PROXY_PORT
                );
                eprintln!("  - Intercept LLM API requests (OpenAI, Anthropic, Google)");
                eprintln!("  - Enforce per-session and daily spend budgets");
                eprintln!("  - Extract token usage from responses for budget tracking");
                eprintln!();
                eprintln!("Track progress: https://github.com/postrv/sanctum/issues");
            }
            Err(CliError::PreviewFeature(
                "proxy management not yet available".to_string(),
            ))
        }
        ProxyCliAction::Stop => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("sanctum proxy: preview feature (not yet wired into the daemon)");
                eprintln!();
                eprintln!("When complete, `sanctum proxy stop` will:");
                eprintln!("  - Gracefully shut down the running HTTPS proxy");
                eprintln!("  - Drain in-flight requests before stopping");
                eprintln!();
                eprintln!("Track progress: https://github.com/postrv/sanctum/issues");
            }
            Err(CliError::PreviewFeature(
                "proxy management not yet available".to_string(),
            ))
        }
        ProxyCliAction::Status => {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("sanctum proxy: preview feature (not yet wired into the daemon)");
                eprintln!();
                eprintln!("When complete, `sanctum proxy status` will:");
                eprintln!("  - Show whether the proxy is running and its listen address");
                eprintln!("  - Display current budget usage and remaining allowance");
                eprintln!();
                eprintln!("Track progress: https://github.com/postrv/sanctum/issues");
            }
            Err(CliError::PreviewFeature(
                "proxy management not yet available".to_string(),
            ))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_start_returns_nonzero() {
        let result = run(&ProxyCliAction::Start { port: 9847 });
        assert!(result.is_err(), "proxy start should return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("preview feature"),
            "error should mention preview: {err_msg}"
        );
    }

    #[test]
    fn test_proxy_stop_returns_nonzero() {
        let result = run(&ProxyCliAction::Stop);
        assert!(result.is_err(), "proxy stop should return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("preview feature"),
            "error should mention preview: {err_msg}"
        );
    }

    #[test]
    fn test_proxy_status_returns_nonzero() {
        let result = run(&ProxyCliAction::Status);
        assert!(result.is_err(), "proxy status should return an error");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("preview feature"),
            "error should mention preview: {err_msg}"
        );
    }
}
