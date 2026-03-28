//! Lightweight IPC client for communicating with the daemon.
//!
//! Uses the same length-prefixed JSON framing as the daemon's IPC server.
//! For commands that require authentication, the client reads the auth token
//! from `{data_dir}/auth_token` and includes it in the IPC message envelope.

use std::path::Path;

use tokio::net::UnixStream;

use sanctum_types::errors::CliError;
use sanctum_types::ipc::IpcMessage;
pub use sanctum_types::ipc::{IpcCommand, IpcResponse, ProviderBudgetInfo, ThreatListItem};

/// Send a command to the daemon and receive the response.
///
/// For commands that require authentication (e.g. `Shutdown`, `BudgetSet`),
/// automatically reads the auth token from the well-known token file and
/// includes it in the message.
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

    // Read auth token if the command requires authentication
    let auth_token = if command.requires_auth() {
        match sanctum_types::auth::read_token(&paths.data_dir) {
            Ok(token) => Some(token),
            Err(e) => {
                tracing::warn!(%e, "failed to read auth token — command may be rejected");
                None
            }
        }
    } else {
        None
    };

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| CliError::ConnectionFailed(format!("failed to create runtime: {e}")))?;

    runtime.block_on(async { send_command_async(socket_path, command, auth_token).await })
}

async fn send_command_async(
    socket_path: &Path,
    command: &IpcCommand,
    auth_token: Option<String>,
) -> Result<IpcResponse, CliError> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| CliError::ConnectionFailed(format!("failed to connect to daemon: {e}")))?;

    // Build the authenticated message envelope
    let message = IpcMessage {
        command: command.clone(),
        auth_token,
    };

    // Serialize and send message
    let payload = serde_json::to_vec(&message)
        .map_err(|e| CliError::ConnectionFailed(format!("failed to serialize command: {e}")))?;

    sanctum_types::ipc::write_frame(&mut stream, &payload).await?;

    // Read response
    let response_payload = sanctum_types::ipc::read_frame(&mut stream).await?;

    serde_json::from_slice(&response_payload)
        .map_err(|e| CliError::ConnectionFailed(format!("invalid response from daemon: {e}")))
}
