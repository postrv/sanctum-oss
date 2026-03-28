//! Lightweight IPC client for communicating with the daemon.
//!
//! Uses the same length-prefixed JSON framing as the daemon's IPC server.

use std::path::Path;

use tokio::net::UnixStream;

use sanctum_types::errors::CliError;
pub use sanctum_types::ipc::{IpcCommand, IpcResponse, ProviderBudgetInfo, ThreatListItem};

/// Send a command to the daemon and receive the response.
///
/// # Errors
///
/// Returns `CliError::DaemonNotRunning` if the socket doesn't exist.
/// Returns `CliError::ConnectionFailed` on communication errors.
pub fn send_command(command: &IpcCommand) -> Result<IpcResponse, CliError> {
    let paths = sanctum_types::paths::WellKnownPaths::default();
    let socket_path = &paths.socket_path;

    if !socket_path.exists() {
        return Err(CliError::DaemonNotRunning);
    }

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::ConnectionFailed(format!("failed to create runtime: {e}")))?;

    runtime.block_on(async { send_command_async(socket_path, command).await })
}

async fn send_command_async(
    socket_path: &Path,
    command: &IpcCommand,
) -> Result<IpcResponse, CliError> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| CliError::ConnectionFailed(format!("failed to connect to daemon: {e}")))?;

    // Serialize and send command
    let payload = serde_json::to_vec(command)
        .map_err(|e| CliError::ConnectionFailed(format!("failed to serialize command: {e}")))?;

    sanctum_types::ipc::write_frame(&mut stream, &payload).await?;

    // Read response
    let response_payload = sanctum_types::ipc::read_frame(&mut stream).await?;

    serde_json::from_slice(&response_payload)
        .map_err(|e| CliError::ConnectionFailed(format!("invalid response from daemon: {e}")))
}
