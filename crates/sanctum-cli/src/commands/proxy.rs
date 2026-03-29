//! Proxy management commands.
//!
//! Provides `start`, `stop`, and `status` subcommands for the HTTP
//! gateway proxy. For now, these print configuration guidance.
//! Actual daemon integration will be wired in a subsequent phase.

use sanctum_types::errors::CliError;

/// Proxy subcommand actions.
pub enum ProxyAction {
    /// Print environment setup and start the proxy.
    Start {
        /// Port to listen on.
        port: u16,
    },
    /// Stop the running proxy.
    Stop,
    /// Show proxy status.
    Status,
}

/// Run a proxy subcommand.
///
/// # Errors
///
/// Returns `CliError` on failure.
pub fn run(action: &ProxyAction) -> Result<(), CliError> {
    match action {
        ProxyAction::Start { port } => run_start(*port),
        ProxyAction::Stop => run_stop(),
        ProxyAction::Status => run_status(),
    }
}

/// Start the proxy (placeholder -- prints environment setup instructions).
///
/// Returns `Result` for consistency with the command interface; daemon
/// integration will make the error path reachable in a future release.
#[allow(clippy::unnecessary_wraps)]
fn run_start(port: u16) -> Result<(), CliError> {
    tracing::info!(port, "proxy start requested");
    #[allow(clippy::print_stdout)]
    {
        println!("Sanctum HTTP Gateway Proxy");
        println!();
        println!("To use the proxy, set these environment variables for your AI tools:");
        println!();
        println!("  export OPENAI_BASE_URL=http://127.0.0.1:{port}/v1");
        println!("  export ANTHROPIC_BASE_URL=http://127.0.0.1:{port}");
        println!();
        println!("The proxy will forward requests to the upstream API providers");
        println!("while tracking token usage for budget enforcement.");
        println!();
        println!("Note: Daemon integration is pending. The proxy will be started");
        println!("automatically by `sanctum daemon start` in a future release.");
    }
    Ok(())
}

/// Stop the proxy (placeholder).
#[allow(clippy::unnecessary_wraps)]
fn run_stop() -> Result<(), CliError> {
    tracing::info!("proxy stop requested");
    #[allow(clippy::print_stdout)]
    {
        println!("Proxy stop is not yet implemented.");
        println!("The proxy will be managed by the daemon in a future release.");
    }
    Ok(())
}

/// Show proxy status (placeholder).
#[allow(clippy::unnecessary_wraps)]
fn run_status() -> Result<(), CliError> {
    tracing::info!("proxy status requested");
    #[allow(clippy::print_stdout)]
    {
        println!("Proxy status is not yet implemented.");
        println!("The proxy will be managed by the daemon in a future release.");
    }
    Ok(())
}
