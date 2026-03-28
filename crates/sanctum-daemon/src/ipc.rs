//! IPC server and protocol over Unix domain sockets.
//!
//! The daemon listens on a Unix socket for commands from the CLI.
//! Messages are length-prefixed JSON, capped at 64KB for `DoS` resistance.
//!
//! # Protocol
//!
//! ```text
//! [4 bytes big-endian length][JSON payload]
//! ```

use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use sanctum_types::errors::DaemonError;
pub use sanctum_types::ipc::{
    IpcCommand, IpcResponse, ProviderBudgetInfo, QuarantineListItem, ThreatListItem,
};

// ============================================================
// Rate limiter (per-connection token bucket)
// ============================================================

/// Default messages per second allowed per IPC connection.
const DEFAULT_RATE_LIMIT: u32 = 100;

/// Token-bucket rate limiter for IPC connections.
///
/// Each connection starts with `max_tokens` tokens. One token is consumed per
/// message. Tokens refill at `refill_rate` per second. If the bucket is empty,
/// the message is rejected with an error response.
pub struct RateLimiter {
    available: u32,
    max_tokens: u32,
    refill_rate: u32,
    last_refill: std::time::Instant,
}

impl RateLimiter {
    /// Create a new rate limiter with the given capacity and refill rate.
    #[must_use]
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            available: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: std::time::Instant::now(),
        }
    }

    /// Create a rate limiter with default settings (100 msgs/sec).
    #[must_use]
    pub fn default_limit() -> Self {
        Self::new(DEFAULT_RATE_LIMIT, DEFAULT_RATE_LIMIT)
    }

    /// Try to acquire a token. Returns `true` if allowed, `false` if rate-limited.
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.available > 0 {
            self.available -= 1;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time since last refill.
    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let elapsed_secs = elapsed.as_secs_f64();

        // Only refill if at least some time has passed
        if elapsed_secs > 0.0 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let new_tokens = (elapsed_secs * f64::from(self.refill_rate)) as u32;
            if new_tokens > 0 {
                self.available = self.available.saturating_add(new_tokens).min(self.max_tokens);
                self.last_refill = now;
            }
        }
    }
}

// ============================================================
// IPC Server (daemon side)
// ============================================================

/// IPC server that listens for commands from the CLI.
pub struct IpcServer {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl IpcServer {
    /// Create a new IPC server bound to the given socket path.
    ///
    /// Sets socket permissions to owner-only (0o700 on the parent dir).
    ///
    /// # Errors
    ///
    /// Returns an error if the socket cannot be bound.
    pub fn bind(socket_path: &Path) -> Result<Self, DaemonError> {
        // Remove stale socket file if it exists (atomic try-remove avoids TOCTOU)
        match std::fs::remove_file(socket_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(DaemonError::Ipc(format!(
                    "failed to remove stale socket {}: {e}",
                    socket_path.display()
                )));
            }
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                DaemonError::Ipc(format!(
                    "failed to create socket directory {}: {e}",
                    parent.display()
                ))
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        let listener = UnixListener::bind(socket_path).map_err(|e| {
            DaemonError::Ipc(format!(
                "failed to bind socket {}: {e}",
                socket_path.display()
            ))
        })?;

        // Set owner-only permissions on the socket file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = std::fs::set_permissions(
                socket_path,
                std::fs::Permissions::from_mode(0o600),
            ) {
                tracing::warn!(
                    path = %socket_path.display(),
                    %e,
                    "failed to set socket permissions"
                );
            }
        }

        tracing::info!(path = %socket_path.display(), "IPC server listening");

        Ok(Self {
            listener,
            socket_path: socket_path.to_path_buf(),
        })
    }

    /// Accept the next incoming connection.
    ///
    /// # Errors
    ///
    /// Returns an error if accept fails.
    pub async fn accept(&self) -> Result<IpcConnection, DaemonError> {
        let (stream, _) = self.listener.accept().await.map_err(|e| {
            DaemonError::Ipc(format!("failed to accept connection: {e}"))
        })?;
        Ok(IpcConnection {
            stream,
            rate_limiter: RateLimiter::default_limit(),
        })
    }

}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

/// A single IPC connection (one CLI client).
pub struct IpcConnection {
    stream: UnixStream,
    rate_limiter: RateLimiter,
}

impl IpcConnection {
    /// Read a command from the client.
    ///
    /// Enforces a per-connection rate limit. If the client exceeds the allowed
    /// message rate, returns an error.
    ///
    /// # Errors
    ///
    /// Returns an error if the message is too large, malformed, or rate-limited.
    pub async fn read_command(&mut self) -> Result<IpcCommand, DaemonError> {
        if !self.rate_limiter.try_acquire() {
            return Err(DaemonError::Ipc(
                "rate limit exceeded: too many messages per second".to_string(),
            ));
        }
        let payload = sanctum_types::ipc::read_frame(&mut self.stream).await?;
        serde_json::from_slice(&payload).map_err(|e| {
            DaemonError::Ipc(format!("invalid command JSON: {e}"))
        })
    }

    /// Send a response to the client.
    ///
    /// # Errors
    ///
    /// Returns an error if the response cannot be written.
    pub async fn send_response(&mut self, response: &IpcResponse) -> Result<(), DaemonError> {
        let payload = serde_json::to_vec(response).map_err(|e| {
            DaemonError::Ipc(format!("failed to serialise response: {e}"))
        })?;
        sanctum_types::ipc::write_frame(&mut self.stream, &payload).await?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use sanctum_types::ipc::MAX_MESSAGE_SIZE;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn ipc_roundtrip_status_command() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("test.sock");

        let server = IpcServer::bind(&socket_path).expect("bind should succeed");

        // Spawn server handler
        let socket_path_clone = socket_path.clone();
        let server_handle = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("accept");
            let cmd = conn.read_command().await.expect("read command");
            assert!(matches!(cmd, IpcCommand::Status));

            let response = IpcResponse::Status {
                version: "0.1.0".to_string(),
                uptime_secs: 42,
                watchers_active: 2,
                quarantine_count: 1,
            };
            conn.send_response(&response).await.expect("send response");
        });

        // Client side — use raw stream with shared frame helpers
        let mut stream = UnixStream::connect(&socket_path_clone).await.expect("connect");
        let cmd_payload = serde_json::to_vec(&IpcCommand::Status).expect("serialise");
        sanctum_types::ipc::write_frame(&mut stream, &cmd_payload).await.expect("write");
        let resp_payload = sanctum_types::ipc::read_frame(&mut stream).await.expect("read");
        let response: IpcResponse = serde_json::from_slice(&resp_payload).expect("deserialise");

        match response {
            IpcResponse::Status { version, uptime_secs, watchers_active, quarantine_count } => {
                assert_eq!(version, "0.1.0");
                assert_eq!(uptime_secs, 42);
                assert_eq!(watchers_active, 2);
                assert_eq!(quarantine_count, 1);
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.await.expect("server task");
    }

    #[tokio::test]
    async fn ipc_roundtrip_quarantine_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("test.sock");

        let server = IpcServer::bind(&socket_path).expect("bind");

        let server_handle = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("accept");
            let cmd = conn.read_command().await.expect("read");
            assert!(matches!(cmd, IpcCommand::ListQuarantine));

            let response = IpcResponse::QuarantineList {
                items: vec![QuarantineListItem {
                    id: "test-id".to_string(),
                    original_path: "/tmp/evil.pth".to_string(),
                    reason: "base64 exec detected".to_string(),
                    quarantined_at: "2026-01-01T00:00:00Z".to_string(),
                }],
            };
            conn.send_response(&response).await.expect("send");
        });

        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        let cmd_payload = serde_json::to_vec(&IpcCommand::ListQuarantine).expect("serialise");
        sanctum_types::ipc::write_frame(&mut stream, &cmd_payload).await.expect("write");
        let resp_payload = sanctum_types::ipc::read_frame(&mut stream).await.expect("read");
        let response: IpcResponse = serde_json::from_slice(&resp_payload).expect("deserialise");

        match response {
            IpcResponse::QuarantineList { items } => {
                assert_eq!(items.len(), 1);
                assert_eq!(items[0].id, "test-id");
            }
            other => panic!("unexpected response: {other:?}"),
        }

        server_handle.await.expect("server task");
    }

    #[tokio::test]
    async fn ipc_rejects_oversized_message() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("test.sock");

        let server = IpcServer::bind(&socket_path).expect("bind");

        let server_handle = tokio::spawn(async move {
            let mut conn = server.accept().await.expect("accept");
            // Try to read — should fail because client sends oversized frame
            let result = conn.read_command().await;
            assert!(result.is_err());
        });

        // Client sends an oversized frame directly
        let mut stream = UnixStream::connect(&socket_path).await.expect("connect");
        #[allow(clippy::cast_possible_truncation)]
        let oversized_len = (MAX_MESSAGE_SIZE + 1) as u32;
        stream.write_all(&oversized_len.to_be_bytes()).await.expect("write len");
        // Don't need to write the actual payload — the length check should reject it

        server_handle.await.expect("server task");
    }

    #[tokio::test]
    async fn ipc_server_cleans_up_socket_on_drop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("test.sock");

        {
            let _server = IpcServer::bind(&socket_path).expect("bind");
            assert!(socket_path.exists());
        }
        // After drop, socket should be cleaned up
        assert!(!socket_path.exists());
    }

    #[test]
    fn ipc_command_serialises_correctly() {
        let cmd = IpcCommand::RestoreQuarantine { id: "abc-123".to_string() };
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("RestoreQuarantine"));
        assert!(json.contains("abc-123"));
    }

    #[test]
    fn ipc_response_serialises_correctly() {
        let resp = IpcResponse::Ok { message: "done".to_string() };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("done"));
    }

    #[test]
    fn budget_status_command_serialises_correctly() {
        let cmd = IpcCommand::BudgetStatus;
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("BudgetStatus"));

        let roundtrip: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        assert!(matches!(roundtrip, IpcCommand::BudgetStatus));
    }

    #[test]
    fn budget_set_command_serialises_correctly() {
        let cmd = IpcCommand::BudgetSet {
            session_cents: Some(5000),
            daily_cents: Some(20000),
        };
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("BudgetSet"));
        assert!(json.contains("5000"));
        assert!(json.contains("20000"));

        let roundtrip: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtrip {
            IpcCommand::BudgetSet { session_cents, daily_cents } => {
                assert_eq!(session_cents, Some(5000));
                assert_eq!(daily_cents, Some(20000));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn budget_extend_command_serialises_correctly() {
        let cmd = IpcCommand::BudgetExtend { additional_cents: 1000 };
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("BudgetExtend"));
        assert!(json.contains("1000"));

        let roundtrip: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        match roundtrip {
            IpcCommand::BudgetExtend { additional_cents } => {
                assert_eq!(additional_cents, 1000);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn budget_reset_command_serialises_correctly() {
        let cmd = IpcCommand::BudgetReset;
        let json = serde_json::to_string(&cmd).expect("serialise");
        assert!(json.contains("BudgetReset"));

        let roundtrip: IpcCommand = serde_json::from_str(&json).expect("deserialise");
        assert!(matches!(roundtrip, IpcCommand::BudgetReset));
    }

    #[test]
    fn budget_status_response_serialises_correctly() {
        let resp = IpcResponse::BudgetStatus {
            providers: vec![
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
                    session_limit_cents: None,
                    daily_spent_cents: 321,
                    daily_limit_cents: None,
                    alert_triggered: false,
                    session_exceeded: false,
                },
            ],
        };
        let json = serde_json::to_string(&resp).expect("serialise");
        assert!(json.contains("BudgetStatus"));
        assert!(json.contains("OpenAI"));
        assert!(json.contains("Anthropic"));
        assert!(json.contains("1234"));

        let roundtrip: IpcResponse = serde_json::from_str(&json).expect("deserialise");
        match roundtrip {
            IpcResponse::BudgetStatus { providers } => {
                assert_eq!(providers.len(), 2);
                assert_eq!(providers[0].name, "OpenAI");
                assert_eq!(providers[0].session_spent_cents, 1234);
                assert_eq!(providers[1].name, "Anthropic");
                assert_eq!(providers[1].session_limit_cents, None);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn provider_budget_info_serialises_correctly() {
        let info = ProviderBudgetInfo {
            name: "Google".to_string(),
            session_spent_cents: 500,
            session_limit_cents: Some(10000),
            daily_spent_cents: 1500,
            daily_limit_cents: Some(50000),
            alert_triggered: true,
            session_exceeded: false,
        };
        let json = serde_json::to_string(&info).expect("serialise");
        let roundtrip: ProviderBudgetInfo = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(roundtrip.name, "Google");
        assert_eq!(roundtrip.session_spent_cents, 500);
        assert_eq!(roundtrip.session_limit_cents, Some(10000));
        assert_eq!(roundtrip.daily_spent_cents, 1500);
        assert_eq!(roundtrip.daily_limit_cents, Some(50000));
        assert!(roundtrip.alert_triggered);
        assert!(!roundtrip.session_exceeded);
    }

    // ---- Rate limiter tests ----

    #[test]
    fn rate_limiter_allows_within_capacity() {
        let mut rl = RateLimiter::new(10, 10);
        for _ in 0..10 {
            assert!(rl.try_acquire());
        }
    }

    #[test]
    fn rate_limiter_rejects_when_exhausted() {
        let mut rl = RateLimiter::new(5, 5);
        for _ in 0..5 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire());
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut rl = RateLimiter::new(5, 5);
        // Exhaust all tokens
        for _ in 0..5 {
            assert!(rl.try_acquire());
        }
        assert!(!rl.try_acquire());

        // Simulate time passing (1 second = 5 tokens refilled at rate 5/sec)
        rl.last_refill -= std::time::Duration::from_secs(1);
        assert!(rl.try_acquire());
    }

    #[test]
    fn rate_limiter_does_not_exceed_max_tokens() {
        let mut rl = RateLimiter::new(10, 10);
        // Simulate lots of time passing — tokens should cap at max
        rl.last_refill -= std::time::Duration::from_secs(100);
        // First call refills, but should cap at max_tokens
        assert!(rl.try_acquire());
        assert_eq!(rl.available, 9); // 10 refilled (capped at max), minus 1
    }

    #[test]
    fn rate_limiter_zero_capacity_always_rejects() {
        let mut rl = RateLimiter::new(0, 0);
        assert!(!rl.try_acquire());
    }
}
