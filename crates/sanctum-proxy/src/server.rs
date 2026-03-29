//! Proxy server lifecycle: binding, accepting connections, and serving requests.
//!
//! The server binds to a localhost-only address and spawns a task per connection.
//! Each request is handled by [`crate::handler::handle_request`].

use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::sync::RwLock;

use crate::error::ProxyError;
use crate::handler::handle_request;

/// The HTTP gateway proxy server.
///
/// Accepts plain HTTP connections from local AI tools and proxies requests
/// to upstream LLM API providers over HTTPS.
#[derive(Debug)]
pub struct ProxyServer {
    /// The address the server will bind to. Must be localhost.
    bind_addr: SocketAddr,
    /// Shared budget tracker for enforcing spending limits.
    budget_tracker: Arc<RwLock<sanctum_budget::BudgetTracker>>,
}

impl ProxyServer {
    /// Create a new proxy server.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::NonLocalhostBind`] if the bind address is not
    /// `127.0.0.1` or `[::1]`.
    pub fn new(
        bind_addr: SocketAddr,
        budget_tracker: Arc<RwLock<sanctum_budget::BudgetTracker>>,
    ) -> Result<Self, ProxyError> {
        let ip = bind_addr.ip();
        if !ip.is_loopback() {
            return Err(ProxyError::NonLocalhostBind {
                addr: bind_addr.to_string(),
            });
        }

        Ok(Self {
            bind_addr,
            budget_tracker,
        })
    }

    /// Run the proxy server, accepting connections until the future is cancelled.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::Bind`] if the TCP listener cannot be bound, or
    /// [`ProxyError::Io`] on accept errors.
    pub async fn run(&self) -> Result<(), ProxyError> {
        let listener = tokio::net::TcpListener::bind(self.bind_addr)
            .await
            .map_err(|e| ProxyError::Bind {
                addr: self.bind_addr.to_string(),
                source: e,
            })?;

        tracing::info!(addr = %self.bind_addr, "proxy server listening");

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let budget_tracker = Arc::clone(&self.budget_tracker);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| {
                    let tracker = Arc::clone(&budget_tracker);
                    async move { handle_request(req, tracker).await }
                });

                if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await
                {
                    tracing::warn!(peer = %peer_addr, "connection error: {e}");
                }
            });
        }
    }

    /// Return the address the server is configured to bind to.
    #[must_use]
    pub const fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_budget::BudgetTracker;
    use sanctum_types::config::BudgetConfig;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_tracker() -> Arc<RwLock<BudgetTracker>> {
        Arc::new(RwLock::new(BudgetTracker::new(&BudgetConfig::default())))
    }

    #[test]
    fn non_localhost_bind_returns_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080);
        let result = ProxyServer::new(addr, test_tracker());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ProxyError::NonLocalhostBind { .. }),
            "expected NonLocalhostBind, got: {err:?}"
        );
    }

    #[test]
    fn non_localhost_external_ip_returns_error() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8080);
        let result = ProxyServer::new(addr, test_tracker());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::NonLocalhostBind { .. }
        ));
    }

    #[test]
    fn server_constructed_with_ipv4_localhost() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7842);
        let result = ProxyServer::new(addr, test_tracker());
        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.bind_addr(), addr);
    }

    #[test]
    fn server_constructed_with_ipv6_localhost() {
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 7842);
        let result = ProxyServer::new(addr, test_tracker());
        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.bind_addr(), addr);
    }
}
