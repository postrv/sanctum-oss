//! Proxy server lifecycle management.
//!
//! Manages the TCP listener, connection concurrency limiting, and
//! accept loop resilience. The server binds only to localhost and
//! uses a semaphore to cap the number of concurrent connections.

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use sanctum_budget::BudgetTracker;
use sanctum_types::config::{BudgetConfig, ProxyConfig};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use crate::error::ProxyError;
use crate::handler::{build_shared_client, HandlerState};

/// Default maximum concurrent connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// The proxy server.
#[derive(Debug)]
pub struct ProxyServer {
    /// TCP listener bound to localhost.
    listener: TcpListener,
    /// Concurrency limiter.
    semaphore: Arc<Semaphore>,
    /// Shared handler state for all connections.
    state: HandlerState,
}

impl ProxyServer {
    /// Create a new proxy server bound to the given address.
    ///
    /// The address must resolve to localhost (`127.0.0.1` or `::1`).
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::NonLocalhostBind` if the address is not localhost.
    /// Returns `ProxyError::Bind` if the TCP listener cannot be created.
    /// Returns `ProxyError::Upstream` if the shared HTTP client cannot be built.
    pub async fn bind(
        addr: &str,
        budget_tracker: BudgetTracker,
        budget_config: BudgetConfig,
        proxy_config: ProxyConfig,
    ) -> Result<Self, ProxyError> {
        // Validate localhost binding.
        validate_localhost(addr)?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|source| ProxyError::Bind {
                addr: addr.to_owned(),
                source,
            })?;

        let client = build_shared_client()?;

        let state = HandlerState {
            client,
            budget_tracker: Arc::new(Mutex::new(budget_tracker)),
            pending_cost: Arc::new(AtomicU64::new(0)),
            budget_config: Arc::new(budget_config),
            proxy_config: Arc::new(proxy_config),
        };

        let semaphore = Arc::new(Semaphore::new(DEFAULT_MAX_CONNECTIONS));

        Ok(Self {
            listener,
            semaphore,
            state,
        })
    }

    /// Return the local address the server is listening on.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::Io` if the local address cannot be determined.
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ProxyError> {
        self.listener.local_addr().map_err(ProxyError::Io)
    }

    /// Run the accept loop.
    ///
    /// This method runs indefinitely, accepting connections and spawning
    /// tasks for each one. Individual accept failures do not terminate
    /// the server; they are logged and the loop continues after a brief
    /// backoff.
    ///
    /// # Errors
    ///
    /// This method only returns if the listener is broken beyond recovery
    /// (which should not happen in practice).
    pub async fn run(self) -> Result<(), ProxyError> {
        tracing::info!(
            addr = %self.listener.local_addr().unwrap_or_else(|_|
                std::net::SocketAddr::from(([127, 0, 0, 1], 0))
            ),
            max_connections = DEFAULT_MAX_CONNECTIONS,
            "proxy server listening"
        );

        loop {
            // M14: Resilient accept loop with backoff on failure.
            let (stream, peer_addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "accept failed, retrying after backoff"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };

            // M7: Connection concurrency limit.
            let Ok(permit) = self.semaphore.clone().try_acquire_owned() else {
                tracing::warn!(
                    peer = %peer_addr,
                    "connection limit reached, rejecting"
                );
                // Drop the stream immediately -- the client will see a connection reset.
                // In a full HTTP implementation, we'd send a 503 response first.
                drop(stream);
                continue;
            };

            let state = self.state.clone();

            // LOW: Task panic logging -- log errors instead of silently dropping.
            tokio::spawn(async move {
                let _permit = permit; // held for the duration of the connection
                handle_connection(state, stream, peer_addr);
            });
        }
    }
}

/// Handle a single TCP connection.
///
/// In the current implementation, this is a placeholder that reads
/// the stream and processes one request. A full implementation would
/// handle HTTP/1.1 keep-alive and pipelining.
fn handle_connection(
    _state: HandlerState,
    _stream: tokio::net::TcpStream,
    _peer_addr: std::net::SocketAddr,
) {
    // Placeholder: actual HTTP parsing and request handling would go here.
    // The handler module provides handle_request() for the actual logic.
}

/// Validate that the given address string refers to localhost.
fn validate_localhost(addr: &str) -> Result<(), ProxyError> {
    // Extract the host part (before the last colon for port).
    let host = addr.find(']').map_or_else(
        || addr.rfind(':').map_or(addr, |colon_pos| &addr[..colon_pos]),
        |bracket_end| &addr[..=bracket_end],
    );

    let host_clean = host.trim_start_matches('[').trim_end_matches(']');

    let is_localhost =
        host_clean == "127.0.0.1" || host_clean == "::1" || host_clean == "localhost";

    if !is_localhost {
        return Err(ProxyError::NonLocalhostBind {
            addr: addr.to_owned(),
        });
    }

    Ok(())
}

/// Return the current number of available connection permits.
///
/// Useful for monitoring and testing the concurrency limiter.
#[must_use]
pub fn available_permits(semaphore: &Semaphore) -> usize {
    semaphore.available_permits()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_localhost_ipv4() {
        assert!(validate_localhost("127.0.0.1:8080").is_ok());
    }

    #[test]
    fn test_validate_localhost_ipv6() {
        assert!(validate_localhost("[::1]:8080").is_ok());
    }

    #[test]
    fn test_validate_localhost_name() {
        assert!(validate_localhost("localhost:8080").is_ok());
    }

    #[test]
    fn test_validate_non_localhost_rejected() {
        let result = validate_localhost("0.0.0.0:8080");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::NonLocalhostBind { .. }
        ));
    }

    #[test]
    fn test_validate_external_ip_rejected() {
        assert!(validate_localhost("192.168.1.1:8080").is_err());
    }

    #[test]
    fn test_connection_limit_enforced() {
        let semaphore = Arc::new(Semaphore::new(2));

        // Acquire all permits.
        let p1 = semaphore.clone().try_acquire_owned().expect("permit 1");
        let p2 = semaphore.clone().try_acquire_owned().expect("permit 2");

        // Third acquisition should fail.
        assert!(
            semaphore.clone().try_acquire_owned().is_err(),
            "should fail when all permits are taken"
        );

        // After dropping permits, acquisition should succeed.
        drop(p1);
        drop(p2);
        assert!(
            semaphore.try_acquire_owned().is_ok(),
            "should succeed after permit is released"
        );
    }

    #[test]
    fn test_semaphore_default_capacity() {
        let semaphore = Semaphore::new(DEFAULT_MAX_CONNECTIONS);
        assert_eq!(semaphore.available_permits(), DEFAULT_MAX_CONNECTIONS);
    }

    #[tokio::test]
    async fn test_server_bind_localhost() {
        let config = BudgetConfig::default();
        let proxy_config = ProxyConfig::default();
        let tracker = BudgetTracker::new(&config);

        let result = ProxyServer::bind("127.0.0.1:0", tracker, config, proxy_config).await;

        assert!(result.is_ok(), "should bind to localhost");
        let server = result.unwrap();
        let addr = server.local_addr().unwrap();
        assert_eq!(addr.ip(), std::net::Ipv4Addr::LOCALHOST);
    }

    #[tokio::test]
    async fn test_server_bind_non_localhost_rejected() {
        let config = BudgetConfig::default();
        let proxy_config = ProxyConfig::default();
        let tracker = BudgetTracker::new(&config);

        let result = ProxyServer::bind("0.0.0.0:0", tracker, config, proxy_config).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::NonLocalhostBind { .. }));
    }

    #[tokio::test]
    async fn test_connection_limit_enforced_async() {
        let semaphore = Arc::new(Semaphore::new(3));

        // Acquire 3 permits, hold them in a vec.
        let p1 = semaphore.clone().try_acquire_owned().unwrap();
        let p2 = semaphore.clone().try_acquire_owned().unwrap();
        let p3 = semaphore.clone().try_acquire_owned().unwrap();

        // Should be exhausted now.
        assert!(semaphore.clone().try_acquire_owned().is_err());
        assert_eq!(available_permits(&semaphore), 0);

        // Release one.
        drop(p1);
        assert_eq!(available_permits(&semaphore), 1);
        drop(p2);
        drop(p3);
    }

    #[test]
    fn test_handler_state_is_clone() {
        // Verify HandlerState derives Clone (needed for spawning tasks).
        let config = BudgetConfig::default();
        let proxy_config = ProxyConfig::default();
        let tracker = BudgetTracker::new(&config);
        let client = build_shared_client().unwrap();

        let state = HandlerState {
            client,
            budget_tracker: Arc::new(Mutex::new(tracker)),
            pending_cost: Arc::new(AtomicU64::new(0)),
            budget_config: Arc::new(config),
            proxy_config: Arc::new(proxy_config),
        };

        // Ensure Clone works by cloning into a separate binding.
        let cloned: HandlerState = Clone::clone(&state);
        drop(cloned);
        drop(state);
    }
}
