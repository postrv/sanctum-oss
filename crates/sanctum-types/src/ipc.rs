//! Shared IPC types and framing protocol for daemon-CLI communication.
//!
//! This module defines the command/response types and the length-prefixed
//! framing protocol used over Unix domain sockets. Both the daemon and CLI
//! depend on these shared definitions to avoid duplication.
//!
//! # Protocol
//!
//! ```text
//! [4 bytes big-endian length][JSON payload]
//! ```

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum IPC message size (64KB).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

/// Commands sent from the CLI to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum IpcCommand {
    /// Request daemon status.
    Status,
    /// Request list of quarantined items.
    ListQuarantine,
    /// Restore a quarantined item by ID.
    RestoreQuarantine { id: String },
    /// Delete a quarantined item by ID.
    DeleteQuarantine { id: String },
    /// Reload configuration.
    ReloadConfig,
    /// Graceful shutdown.
    Shutdown,
    /// Request budget status for all providers.
    BudgetStatus,
    /// Set budget limits (in cents).
    BudgetSet {
        session_cents: Option<u64>,
        daily_cents: Option<u64>,
    },
    /// Extend the current session budget for all providers.
    BudgetExtend { additional_cents: u64 },
    /// Reset all session budget counters.
    BudgetReset,
}

/// Responses sent from the daemon to the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "response")]
pub enum IpcResponse {
    /// Daemon status information.
    Status {
        version: String,
        uptime_secs: u64,
        watchers_active: u32,
        quarantine_count: u32,
    },
    /// List of quarantined items.
    QuarantineList {
        items: Vec<QuarantineListItem>,
    },
    /// Budget status for all tracked providers.
    BudgetStatus {
        providers: Vec<ProviderBudgetInfo>,
    },
    /// Operation succeeded.
    Ok { message: String },
    /// Operation failed.
    Error { message: String },
}

/// Summary of a quarantined item for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineListItem {
    pub id: String,
    pub original_path: String,
    pub reason: String,
    pub quarantined_at: String,
}

/// Budget status for a single provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderBudgetInfo {
    pub name: String,
    pub session_spent_cents: u64,
    pub session_limit_cents: Option<u64>,
    pub daily_spent_cents: u64,
    pub daily_limit_cents: Option<u64>,
    pub alert_triggered: bool,
    pub session_exceeded: bool,
}

/// Read a length-prefixed frame from a stream.
///
/// # Errors
///
/// Returns an `io::Error` if reading fails or the message exceeds `MAX_MESSAGE_SIZE`.
pub async fn read_frame<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Vec<u8>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;

    let len = u32::from_be_bytes(len_buf) as usize;

    if len > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes (max {MAX_MESSAGE_SIZE})"),
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;

    Ok(payload)
}

/// Write a length-prefixed frame to a stream.
///
/// # Errors
///
/// Returns an `io::Error` if writing fails or the payload exceeds `MAX_MESSAGE_SIZE`.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    payload: &[u8],
) -> Result<(), std::io::Error> {
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "message too large: {} bytes (max {MAX_MESSAGE_SIZE})",
                payload.len()
            ),
        ));
    }

    #[allow(clippy::cast_possible_truncation)]
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;

    Ok(())
}
