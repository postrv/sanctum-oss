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
    /// Record token usage for budget tracking.
    RecordUsage {
        provider: String,
        model: String,
        input_tokens: u64,
        output_tokens: u64,
    },
    /// Request unresolved threats from the audit log.
    ListThreats {
        category: Option<String>,
        level: Option<String>,
    },
    /// Get details for a specific threat by ID.
    GetThreatDetails { id: String },
    /// Mark a threat as resolved.
    ResolveThreat {
        id: String,
        action: String,
        note: String,
    },
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
    /// List of unresolved threats.
    ThreatList {
        threats: Vec<ThreatListItem>,
    },
    /// Detailed information about a single threat.
    ThreatDetails {
        id: String,
        timestamp: String,
        level: String,
        category: String,
        description: String,
        source_path: String,
        creator_pid: Option<u32>,
        creator_exe: Option<String>,
        action_taken: String,
        quarantine_id: Option<String>,
    },
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

/// Summary of a threat for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatListItem {
    pub id: String,
    pub timestamp: String,
    pub level: String,
    pub category: String,
    pub description: String,
    pub source_path: String,
    pub action_taken: String,
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_record_usage_command_serialises_correctly() {
        let cmd = IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 1_000_000,
            output_tokens: 500_000,
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
                assert_eq!(provider, "anthropic");
                assert_eq!(model, "claude-sonnet-4-6");
                assert_eq!(input_tokens, 1_000_000);
                assert_eq!(output_tokens, 500_000);
            }
            other => panic!("expected RecordUsage, got {other:?}"),
        }
    }

    #[test]
    fn test_list_threats_command_serialises_correctly() {
        let cmd = IpcCommand::ListThreats {
            category: Some("PthInjection".to_string()),
            level: Some("Critical".to_string()),
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        let roundtripped: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcCommand::ListThreats { category, level } => {
                assert_eq!(category.unwrap(), "PthInjection");
                assert_eq!(level.unwrap(), "Critical");
            }
            other => panic!("expected ListThreats, got {other:?}"),
        }
    }

    #[test]
    fn test_list_threats_command_with_no_filters() {
        let cmd = IpcCommand::ListThreats {
            category: None,
            level: None,
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        let roundtripped: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcCommand::ListThreats { category, level } => {
                assert!(category.is_none());
                assert!(level.is_none());
            }
            other => panic!("expected ListThreats, got {other:?}"),
        }
    }

    #[test]
    fn test_get_threat_details_command_serialises_correctly() {
        let cmd = IpcCommand::GetThreatDetails {
            id: "abcdef012345".to_string(),
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        let roundtripped: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcCommand::GetThreatDetails { id } => {
                assert_eq!(id, "abcdef012345");
            }
            other => panic!("expected GetThreatDetails, got {other:?}"),
        }
    }

    #[test]
    fn test_resolve_threat_command_serialises_correctly() {
        let cmd = IpcCommand::ResolveThreat {
            id: "abcdef012345".to_string(),
            action: "Restored".to_string(),
            note: "Verified safe".to_string(),
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        let roundtripped: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcCommand::ResolveThreat { id, action, note } => {
                assert_eq!(id, "abcdef012345");
                assert_eq!(action, "Restored");
                assert_eq!(note, "Verified safe");
            }
            other => panic!("expected ResolveThreat, got {other:?}"),
        }
    }

    #[test]
    fn test_threat_list_response_serialises_correctly() {
        let resp = IpcResponse::ThreatList {
            threats: vec![ThreatListItem {
                id: "abcdef012345".to_string(),
                timestamp: "2025-06-15T12:00:00Z".to_string(),
                level: "Critical".to_string(),
                category: "PthInjection".to_string(),
                description: "Suspicious .pth file".to_string(),
                source_path: "/tmp/evil.pth".to_string(),
                action_taken: "Quarantined".to_string(),
            }],
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        let roundtripped: IpcResponse = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcResponse::ThreatList { threats } => {
                assert_eq!(threats.len(), 1);
                assert_eq!(threats[0].id, "abcdef012345");
                assert_eq!(threats[0].category, "PthInjection");
            }
            other => panic!("expected ThreatList, got {other:?}"),
        }
    }

    #[test]
    fn test_threat_details_response_serialises_correctly() {
        let resp = IpcResponse::ThreatDetails {
            id: "abcdef012345".to_string(),
            timestamp: "2025-06-15T12:00:00Z".to_string(),
            level: "Critical".to_string(),
            category: "PthInjection".to_string(),
            description: "Suspicious .pth file".to_string(),
            source_path: "/tmp/evil.pth".to_string(),
            creator_pid: Some(12345),
            creator_exe: Some("/usr/bin/python3".to_string()),
            action_taken: "Quarantined".to_string(),
            quarantine_id: Some("q-001".to_string()),
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        let roundtripped: IpcResponse = serde_json::from_str(&json).expect("deserialise");
        match roundtripped {
            IpcResponse::ThreatDetails {
                id,
                creator_pid,
                creator_exe,
                quarantine_id,
                ..
            } => {
                assert_eq!(id, "abcdef012345");
                assert_eq!(creator_pid, Some(12345));
                assert_eq!(creator_exe, Some("/usr/bin/python3".to_string()));
                assert_eq!(quarantine_id, Some("q-001".to_string()));
            }
            other => panic!("expected ThreatDetails, got {other:?}"),
        }
    }
}
