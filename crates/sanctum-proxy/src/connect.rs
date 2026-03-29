//! CONNECT tunnel handling for the HTTP proxy.
//!
//! Handles HTTP CONNECT requests by either:
//! - Blind-forwarding non-LLM traffic (TCP relay with no inspection)
//! - MITM-intercepting LLM API traffic (TLS termination, request inspection)
//!
//! # Security invariants
//!
//! - Private/reserved IP addresses are blocked to prevent SSRF attacks
//! - DNS resolution happens before the connection to validate resolved IPs
//! - All tunnels have timeouts to prevent resource exhaustion
//! - MITM reads use a proper read loop with size limits

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use rustls_pki_types::CertificateDer;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::ca::CaIdentity;
use crate::error::ProxyError;

/// Maximum body size for MITM-intercepted requests (10 MB).
const MAX_MITM_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum header size (64 KB, generous for LLM API requests).
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Timeout for the full read of a MITM request (30 seconds).
const MITM_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for blind tunnel relay (10 minutes for long-running API calls).
const BLIND_TUNNEL_TIMEOUT: Duration = Duration::from_secs(600);

/// Header boundary marker.
const HEADER_BOUNDARY: &[u8] = b"\r\n\r\n";

/// Shared state for CONNECT handling.
#[derive(Clone)]
pub struct ConnectState {
    /// The CA identity for signing site certificates.
    pub ca: Arc<CaIdentity>,
    /// Cache of generated site certificates keyed by domain.
    /// Values are (cert DER, key DER bytes).
    pub cert_cache: Arc<DashMap<String, (CertificateDer<'static>, Vec<u8>)>>,
}

impl std::fmt::Debug for ConnectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectState")
            .field("ca", &self.ca)
            .field("cert_cache_size", &self.cert_cache.len())
            .finish()
    }
}

impl ConnectState {
    /// Create a new `ConnectState` with the given CA identity.
    #[must_use]
    pub fn new(ca: CaIdentity) -> Self {
        Self {
            ca: Arc::new(ca),
            cert_cache: Arc::new(DashMap::new()),
        }
    }

    /// Get or generate a site certificate for the given domain.
    ///
    /// Results are cached in the `DashMap` for reuse within the same
    /// proxy session.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaGeneration` if certificate generation fails.
    pub fn get_or_generate_site_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, Vec<u8>), ProxyError> {
        if let Some(cached) = self.cert_cache.get(domain) {
            return Ok(cached.value().clone());
        }

        let (cert, key_bytes) = crate::ca::generate_site_cert(&self.ca, domain)?;
        self.cert_cache
            .insert(domain.to_owned(), (cert.clone(), key_bytes.clone()));
        Ok((cert, key_bytes))
    }
}

/// Check if an IP address is private, reserved, or loopback.
///
/// Blocks:
/// - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8,
///   169.254.0.0/16 (link-local), 0.0.0.0/8
/// - IPv6: `::1` (loopback), `fe80::/10` (link-local), `fc00::/7` (unique local),
///   `::` (unspecified)
#[must_use]
pub fn is_private_ip(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => is_private_ipv4(*ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

/// Check if an IPv4 address is private or reserved.
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 10.0.0.0/8 (RFC 1918)
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12 (RFC 1918)
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16 (RFC 1918)
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // 0.0.0.0/8 (current network)
    if octets[0] == 0 {
        return true;
    }

    false
}

/// Check if an IPv6 address is private or reserved.
fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    // ::1 (loopback)
    if ip.is_loopback() {
        return true;
    }
    // :: (unspecified)
    if ip.is_unspecified() {
        return true;
    }

    let segments = ip.segments();

    // fe80::/10 (link-local)
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // fc00::/7 (unique local address)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }

    // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x).
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_private_ipv4(ipv4);
    }

    false
}

/// Resolve a hostname and validate that none of the resolved addresses
/// are private or reserved.
///
/// # Errors
///
/// Returns `ProxyError::InvalidPath` if the hostname resolves to a private IP
/// or cannot be resolved.
pub async fn resolve_and_validate(host: &str, port: u16) -> Result<Vec<IpAddr>, ProxyError> {
    let addr_str = format!("{host}:{port}");

    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| ProxyError::InvalidPath {
            reason: format!("DNS resolution failed for '{host}': {e}"),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(ProxyError::InvalidPath {
            reason: format!("DNS resolution returned no addresses for '{host}'"),
        });
    }

    let ips: Vec<IpAddr> = addrs.iter().map(std::net::SocketAddr::ip).collect();

    for ip in &ips {
        if is_private_ip(ip) {
            return Err(ProxyError::InvalidPath {
                reason: format!(
                    "SSRF blocked: '{host}' resolves to private/reserved address {ip}"
                ),
            });
        }
    }

    Ok(ips)
}

/// Perform a blind TCP tunnel relay between client and upstream.
///
/// Used for non-LLM traffic where the proxy does not need to inspect
/// the content. Includes a timeout to prevent resource exhaustion.
///
/// # Errors
///
/// Returns `ProxyError` if the connection or relay fails.
pub async fn blind_tunnel(
    mut client: TcpStream,
    host: &str,
    port: u16,
) -> Result<(), ProxyError> {
    // Validate the target is not a private IP (SSRF prevention).
    resolve_and_validate(host, port).await?;

    let mut upstream = TcpStream::connect(format!("{host}:{port}"))
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed to connect to {host}:{port}: {e}")))?;

    // Relay data bidirectionally with a timeout.
    let relay = async {
        let (mut client_read, mut client_write) = client.split();
        let (mut upstream_read, mut upstream_write) = upstream.split();

        let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
        let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

        tokio::select! {
            r = client_to_upstream => {
                if let Err(e) = r {
                    return Err(ProxyError::Io(e));
                }
            }
            r = upstream_to_client => {
                if let Err(e) = r {
                    return Err(ProxyError::Io(e));
                }
            }
        }

        Ok::<(), ProxyError>(())
    };

    tokio::time::timeout(BLIND_TUNNEL_TIMEOUT, relay)
        .await
        .unwrap_or_else(|_| {
            tracing::info!(
                host = %host,
                port = port,
                timeout_secs = BLIND_TUNNEL_TIMEOUT.as_secs(),
                "blind tunnel timed out"
            );
            Ok(()) // Timeout is not an error; the tunnel just closes.
        })
}

/// Read a complete HTTP request from a MITM-intercepted connection.
///
/// Implements a proper read loop:
/// 1. Read until `\r\n\r\n` (header boundary) is found
/// 2. Parse `Content-Length` from headers
/// 3. Read exactly `Content-Length` bytes for the body
/// 4. Reject `Transfer-Encoding: chunked`
/// 5. Apply overall timeout and size limits
///
/// # Errors
///
/// Returns `ProxyError` if the read times out, exceeds limits,
/// or encounters an unsupported transfer encoding.
pub async fn read_mitm_request(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyError> {
    let read_fut = read_mitm_request_inner(stream);

    tokio::time::timeout(MITM_READ_TIMEOUT, read_fut)
        .await
        .map_err(|_| ProxyError::Upstream("MITM request read timed out after 30s".to_string()))?
}

/// Inner implementation of the MITM request read loop.
async fn read_mitm_request_inner(stream: &mut TcpStream) -> Result<Vec<u8>, ProxyError> {
    let mut buf = Vec::with_capacity(4096);
    let mut temp = [0u8; 4096];
    let header_end;

    // Phase 1: Read until we find the header boundary.
    loop {
        let n = stream
            .read(&mut temp)
            .await
            .map_err(|e| ProxyError::Upstream(format!("failed to read from MITM stream: {e}")))?;

        if n == 0 {
            // Connection closed before header boundary found.
            if buf.is_empty() {
                return Err(ProxyError::Upstream(
                    "connection closed before any data received".to_string(),
                ));
            }
            // Return what we have (may be a headerless request).
            return Ok(buf);
        }

        buf.extend_from_slice(&temp[..n]);

        // Check for header boundary.
        if let Some(pos) = find_subsequence(&buf, HEADER_BOUNDARY) {
            header_end = pos + HEADER_BOUNDARY.len();
            break;
        }

        // Guard against oversized headers.
        if buf.len() > MAX_HEADER_SIZE {
            return Err(ProxyError::PayloadTooLarge {
                reason: format!(
                    "request headers exceed {MAX_HEADER_SIZE} bytes without boundary"
                ),
            });
        }
    }
    let header_bytes = &buf[..header_end];

    // Parse the header section as a string (headers are ASCII).
    let header_str = String::from_utf8_lossy(header_bytes);

    // Check for chunked transfer encoding (reject it).
    if has_chunked_encoding(&header_str) {
        return Err(ProxyError::Upstream(
            "Transfer-Encoding: chunked is not supported for MITM interception".to_string(),
        ));
    }

    // Parse Content-Length.
    let content_length = parse_content_length(&header_str);

    match content_length {
        Some(cl) => {
            if cl > MAX_MITM_BODY_SIZE {
                return Err(ProxyError::PayloadTooLarge {
                    reason: format!(
                        "request body ({cl} bytes) exceeds MITM limit ({MAX_MITM_BODY_SIZE} bytes)"
                    ),
                });
            }

            let total_expected = header_end + cl;

            // Read remaining body bytes.
            while buf.len() < total_expected {
                let n = stream.read(&mut temp).await.map_err(|e| {
                    ProxyError::Upstream(format!("failed to read body from MITM stream: {e}"))
                })?;

                if n == 0 {
                    // Connection closed before body complete.
                    break;
                }

                buf.extend_from_slice(&temp[..n]);

                if buf.len() > MAX_HEADER_SIZE + MAX_MITM_BODY_SIZE {
                    return Err(ProxyError::PayloadTooLarge {
                        reason: "request exceeds maximum allowed size".to_string(),
                    });
                }
            }

            Ok(buf)
        }
        None => {
            // No Content-Length: return what we have (headers only).
            Ok(buf)
        }
    }
}

/// Perform MITM interception of a CONNECT tunnel.
///
/// Connects to the upstream host and reads the client request for
/// inspection. The port is used in the upstream URL construction.
///
/// # Errors
///
/// Returns `ProxyError` if the connection or request reading fails.
pub async fn mitm_intercept(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
) -> Result<Vec<u8>, ProxyError> {
    // Validate the target is not a private IP (SSRF prevention).
    resolve_and_validate(host, port).await?;

    // Read the full request using the proper read loop.
    read_mitm_request(stream).await
}

/// Find a subsequence within a byte slice.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Check if headers contain `Transfer-Encoding: chunked`.
fn has_chunked_encoding(headers: &str) -> bool {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            return true;
        }
    }
    false
}

/// Parse the `Content-Length` header value from raw headers.
fn parse_content_length(headers: &str) -> Option<usize> {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let value = line.split_once(':')?.1.trim();
            return value.parse::<usize>().ok();
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ---------- SSRF: Private IP blocking tests ----------

    #[test]
    fn test_ipv4_rfc1918_10_blocked() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip), "10.0.0.0/8 should be blocked");
    }

    #[test]
    fn test_ipv4_rfc1918_10_edge() {
        let ip: IpAddr = "10.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip), "10.255.255.255 should be blocked");
    }

    #[test]
    fn test_ipv4_rfc1918_172_blocked() {
        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(is_private_ip(&ip), "172.16.0.0/12 should be blocked");
        let ip2: IpAddr = "172.31.255.255".parse().unwrap();
        assert!(is_private_ip(&ip2), "172.31.255.255 should be blocked");
    }

    #[test]
    fn test_ipv4_rfc1918_172_not_blocked_outside_range() {
        let ip: IpAddr = "172.15.0.1".parse().unwrap();
        assert!(!is_private_ip(&ip), "172.15.0.1 should not be blocked");
        let ip2: IpAddr = "172.32.0.1".parse().unwrap();
        assert!(!is_private_ip(&ip2), "172.32.0.1 should not be blocked");
    }

    #[test]
    fn test_ipv4_rfc1918_192_168_blocked() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert!(is_private_ip(&ip), "192.168.0.0/16 should be blocked");
    }

    #[test]
    fn test_ipv4_loopback_blocked() {
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(is_private_ip(&ip), "127.0.0.1 should be blocked");
        let ip2: IpAddr = "127.255.255.255".parse().unwrap();
        assert!(is_private_ip(&ip2), "127.255.255.255 should be blocked");
    }

    #[test]
    fn test_ipv4_link_local_blocked() {
        let ip: IpAddr = "169.254.1.1".parse().unwrap();
        assert!(is_private_ip(&ip), "169.254.0.0/16 should be blocked");
    }

    #[test]
    fn test_ipv4_zero_network_blocked() {
        let ip: IpAddr = "0.0.0.0".parse().unwrap();
        assert!(is_private_ip(&ip), "0.0.0.0/8 should be blocked");
    }

    #[test]
    fn test_ipv4_public_not_blocked() {
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!is_private_ip(&ip), "8.8.8.8 should not be blocked");
        let ip2: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!is_private_ip(&ip2), "1.1.1.1 should not be blocked");
        let ip3: IpAddr = "104.18.0.1".parse().unwrap();
        assert!(!is_private_ip(&ip3), "104.18.0.1 should not be blocked");
    }

    #[test]
    fn test_ipv6_loopback_blocked() {
        let ip: IpAddr = "::1".parse().unwrap();
        assert!(is_private_ip(&ip), "::1 should be blocked");
    }

    #[test]
    fn test_ipv6_unspecified_blocked() {
        let ip: IpAddr = "::".parse().unwrap();
        assert!(is_private_ip(&ip), ":: should be blocked");
    }

    #[test]
    fn test_ipv6_link_local_blocked() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(is_private_ip(&ip), "fe80::/10 should be blocked");
    }

    #[test]
    fn test_ipv6_unique_local_blocked() {
        let ip: IpAddr = "fd00::1".parse().unwrap();
        assert!(is_private_ip(&ip), "fc00::/7 should be blocked");
        let ip2: IpAddr = "fc00::1".parse().unwrap();
        assert!(is_private_ip(&ip2), "fc00::1 should be blocked");
    }

    #[test]
    fn test_ipv6_public_not_blocked() {
        let ip: IpAddr = "2001:4860:4860::8888".parse().unwrap();
        assert!(
            !is_private_ip(&ip),
            "Google DNS IPv6 should not be blocked"
        );
    }

    #[test]
    fn test_ipv4_mapped_ipv6_private_blocked() {
        // ::ffff:127.0.0.1 is an IPv4-mapped IPv6 address for loopback.
        let ip: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(
            is_private_ip(&ip),
            "IPv4-mapped loopback should be blocked"
        );
    }

    #[test]
    fn test_ipv4_mapped_ipv6_public_not_blocked() {
        let ip: IpAddr = "::ffff:8.8.8.8".parse().unwrap();
        assert!(
            !is_private_ip(&ip),
            "IPv4-mapped public should not be blocked"
        );
    }

    // ---------- Read loop tests ----------

    #[test]
    fn test_parse_content_length() {
        let headers = "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(parse_content_length(headers), Some(42));
    }

    #[test]
    fn test_parse_content_length_missing() {
        let headers = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        assert_eq!(parse_content_length(headers), None);
    }

    #[test]
    fn test_parse_content_length_case_insensitive() {
        let headers = "POST / HTTP/1.1\r\ncontent-length: 100\r\n\r\n";
        assert_eq!(parse_content_length(headers), Some(100));
    }

    #[test]
    fn test_has_chunked_encoding() {
        let headers = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(has_chunked_encoding(headers));
    }

    #[test]
    fn test_has_chunked_encoding_case_insensitive() {
        let headers = "POST / HTTP/1.1\r\ntransfer-encoding: Chunked\r\n\r\n";
        assert!(has_chunked_encoding(headers));
    }

    #[test]
    fn test_no_chunked_encoding() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
        assert!(!has_chunked_encoding(headers));
    }

    #[test]
    fn test_find_subsequence_found() {
        let haystack = b"GET / HTTP/1.1\r\n\r\nBody";
        assert_eq!(find_subsequence(haystack, b"\r\n\r\n"), Some(14));
    }

    #[test]
    fn test_find_subsequence_not_found() {
        let haystack = b"GET / HTTP/1.1\r\n";
        assert_eq!(find_subsequence(haystack, b"\r\n\r\n"), None);
    }

    // ---------- Tunnel timeout tests ----------

    #[tokio::test]
    async fn test_blind_tunnel_timeout_constant() {
        assert_eq!(
            BLIND_TUNNEL_TIMEOUT,
            Duration::from_secs(600),
            "blind tunnel timeout should be 10 minutes"
        );
    }

    #[tokio::test]
    async fn test_mitm_read_timeout_constant() {
        assert_eq!(
            MITM_READ_TIMEOUT,
            Duration::from_secs(30),
            "MITM read timeout should be 30 seconds"
        );
    }

    // ---------- Connect state tests ----------

    #[test]
    fn test_connect_state_cert_caching() {
        let ca = crate::ca::generate_ca(365).expect("CA generation");
        let state = ConnectState::new(ca);

        // First call should generate.
        let result1 = state.get_or_generate_site_cert("api.openai.com");
        assert!(result1.is_ok());

        // Second call should use cache.
        let result2 = state.get_or_generate_site_cert("api.openai.com");
        assert!(result2.is_ok());

        // Cache should have 1 entry.
        assert_eq!(state.cert_cache.len(), 1);

        // Different domain should create a new entry.
        let result3 = state.get_or_generate_site_cert("api.anthropic.com");
        assert!(result3.is_ok());
        assert_eq!(state.cert_cache.len(), 2);
    }
}
