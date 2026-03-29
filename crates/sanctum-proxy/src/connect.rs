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
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use http_body_util::Full;
use rustls::pki_types::CertificateDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use std::fmt::Write as _;

use crate::ca::CaIdentity;
use crate::error::ProxyError;
use crate::handler::HandlerState;
use crate::provider::{identify_provider, should_intercept};

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

/// Parsed HTTP request components: (method, path, query, headers, body).
type ParsedRequest = (String, String, Option<String>, Vec<(String, String)>, Vec<u8>);

/// Shared state for the CONNECT handler, including the CA for MITM.
#[derive(Clone)]
pub struct ConnectState {
    /// The handler state with budget tracker, client, etc.
    pub handler: HandlerState,
    /// The CA identity for signing site certificates.
    pub ca: Arc<CaIdentity>,
    /// Cache of generated site certificates keyed by domain.
    /// Values are (cert DER, key DER bytes).
    pub cert_cache: Arc<DashMap<String, (CertificateDer<'static>, Vec<u8>)>>,
}

impl std::fmt::Debug for ConnectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectState")
            .field("handler", &self.handler)
            .field("ca", &self.ca)
            .field("cert_cache_size", &self.cert_cache.len())
            .finish()
    }
}

impl ConnectState {
    /// Create a new `ConnectState` with the given handler state and CA identity.
    #[must_use]
    pub fn new(handler: HandlerState, ca: CaIdentity) -> Self {
        Self {
            handler,
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

/// Parse a CONNECT request's authority (host:port) into host and port.
///
/// The authority format is `host:port` (e.g., `api.openai.com:443`).
///
/// # Errors
///
/// Returns `ProxyError::InvalidPath` if the authority cannot be parsed.
pub fn parse_connect_authority(authority: &str) -> Result<(String, u16), ProxyError> {
    // Try to find the last colon that separates host from port.
    let colon_pos = authority.rfind(':').ok_or_else(|| ProxyError::InvalidPath {
        reason: format!("CONNECT authority missing port: {authority}"),
    })?;

    let host = &authority[..colon_pos];
    let port_str = &authority[colon_pos + 1..];
    let port = port_str.parse::<u16>().map_err(|_| ProxyError::InvalidPath {
        reason: format!("CONNECT authority has invalid port: {authority}"),
    })?;

    if host.is_empty() {
        return Err(ProxyError::InvalidPath {
            reason: format!("CONNECT authority has empty host: {authority}"),
        });
    }

    Ok((host.to_owned(), port))
}

/// Determine whether a request is a CONNECT request.
#[must_use]
pub fn is_connect_request<T>(req: &Request<T>) -> bool {
    req.method() == Method::CONNECT
}

/// Handle a CONNECT request by either establishing a blind tunnel
/// (for non-LLM hosts) or performing MITM interception (for LLM hosts).
///
/// Returns a `ConnectAction` describing what to do after the 200 response.
///
/// # Errors
///
/// Returns `ProxyError` if the authority cannot be parsed.
pub fn handle_connect(
    req: &Request<Incoming>,
    _state: &ConnectState,
) -> Result<ConnectAction, ProxyError> {
    let authority = req
        .uri()
        .authority()
        .map(std::string::ToString::to_string)
        .or_else(|| {
            req.uri().host().map(|h| {
                let port = req.uri().port_u16().unwrap_or(443);
                format!("{h}:{port}")
            })
        })
        .unwrap_or_default();

    if authority.is_empty() {
        // Try the host header as fallback.
        let host_hdr = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        if host_hdr.is_empty() {
            return Err(ProxyError::InvalidPath {
                reason: "CONNECT request missing authority".to_owned(),
            });
        }
        let (host, port) = parse_connect_authority(host_hdr)?;
        return Ok(determine_action(&host, port));
    }

    let (host, port) = parse_connect_authority(&authority)?;
    Ok(determine_action(&host, port))
}

/// The action to take after sending the 200 response to the client.
#[derive(Debug)]
pub enum ConnectAction {
    /// Blind TCP tunnel -- no inspection, no CA involvement.
    BlindTunnel {
        /// The upstream host to connect to.
        host: String,
        /// The upstream port.
        port: u16,
    },
    /// MITM interception for LLM API hosts.
    MitmIntercept {
        /// The upstream host to intercept.
        host: String,
        /// The upstream port.
        port: u16,
    },
}

impl ConnectAction {
    /// Get the host from the action.
    #[must_use]
    pub fn host(&self) -> &str {
        match self {
            Self::BlindTunnel { host, .. } | Self::MitmIntercept { host, .. } => host,
        }
    }

    /// Get the port from the action.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self {
            Self::BlindTunnel { port, .. } | Self::MitmIntercept { port, .. } => *port,
        }
    }

    /// Whether this is a MITM interception action.
    #[must_use]
    pub const fn is_intercept(&self) -> bool {
        matches!(self, Self::MitmIntercept { .. })
    }
}

/// Determine what action to take based on the host.
fn determine_action(host: &str, port: u16) -> ConnectAction {
    if should_intercept(host) {
        tracing::info!(
            host = %host,
            port = port,
            provider = ?identify_provider(host),
            "CONNECT: MITM interception for LLM API host"
        );
        ConnectAction::MitmIntercept {
            host: host.to_owned(),
            port,
        }
    } else {
        tracing::debug!(
            host = %host,
            port = port,
            "CONNECT: blind tunnel for non-LLM host"
        );
        ConnectAction::BlindTunnel {
            host: host.to_owned(),
            port,
        }
    }
}

/// Perform a blind TCP tunnel relay between client and upstream.
///
/// Used for non-LLM traffic where the proxy does not need to inspect
/// the content. Includes SSRF validation and a timeout to prevent
/// resource exhaustion.
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

/// Build a "200 Connection Established" response for CONNECT requests.
#[must_use]
pub fn connection_established_response() -> Response<Full<bytes::Bytes>> {
    let mut resp = Response::new(Full::new(bytes::Bytes::new()));
    *resp.status_mut() = hyper::StatusCode::OK;
    resp
}

/// Build an error response for CONNECT request failures.
#[must_use]
pub fn connect_error_response(error: &ProxyError) -> Response<Full<bytes::Bytes>> {
    let status = match error.status_code() {
        429 => hyper::StatusCode::TOO_MANY_REQUESTS,
        403 => hyper::StatusCode::FORBIDDEN,
        400 => hyper::StatusCode::BAD_REQUEST,
        502 => hyper::StatusCode::BAD_GATEWAY,
        _ => hyper::StatusCode::INTERNAL_SERVER_ERROR,
    };

    let body = serde_json::json!({
        "error": {
            "message": error.to_string(),
        }
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

    let mut resp = Response::new(Full::new(bytes::Bytes::from(body_bytes)));
    *resp.status_mut() = status;
    resp
}

/// Perform MITM TLS interception for an LLM API host.
///
/// 1. Get or generate a per-host certificate signed by the CA (cached).
/// 2. Perform TLS handshake with the client using the generated cert.
/// 3. Read the HTTP request using a proper read loop with size limits.
/// 4. Forward it to the upstream API (with budget checks and credential redaction).
/// 5. Return the response to the client.
///
/// # Errors
///
/// Returns `ProxyError` if TLS or HTTP operations fail.
pub async fn mitm_intercept(
    client_stream: tokio::net::TcpStream,
    host: &str,
    port: u16,
    state: &ConnectState,
) -> Result<(), ProxyError> {
    // SSRF prevention: validate the target is not a private IP.
    resolve_and_validate(host, port).await?;

    // Get or generate a per-host certificate (with caching).
    let (site_cert, site_key_bytes) = state.get_or_generate_site_cert(host)?;
    let site_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(site_key_bytes),
    );

    // Build TLS server config with the generated cert.
    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![site_cert], site_key)
        .map_err(|e| ProxyError::CaGeneration {
            reason: format!("failed to build TLS config for {host}: {e}"),
        })?;

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    // Perform TLS handshake with the client.
    let mut tls_stream = tls_acceptor.accept(client_stream).await.map_err(|e| {
        ProxyError::Upstream(format!("TLS handshake failed for {host}: {e}"))
    })?;

    // Read the HTTP request from the TLS stream using a proper read loop
    // with Content-Length parsing, size limits, and timeout.
    let request_data = read_mitm_request_from_tls(&mut tls_stream).await?;

    if request_data.is_empty() {
        return Ok(());
    }

    // Parse the HTTP request line and headers.
    let (method, path, query, headers, body) = parse_http_request(&request_data)?;

    // Identify the provider.
    let provider = identify_provider(host).ok_or_else(|| ProxyError::InvalidPath {
        reason: format!("no provider found for intercepted host: {host}"),
    })?;

    // Build a ProxyRequest and process through the existing handler.
    let proxy_req = crate::handler::ProxyRequest {
        method,
        path,
        query,
        headers: headers.clone(),
        body,
        provider,
        content_length: headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok()),
    };

    let response = crate::handler::handle_request(&state.handler, proxy_req).await;

    // Build HTTP response bytes.
    let response_bytes = match response {
        Ok(resp) => format_http_response(resp.status, &resp.headers, &resp.body),
        Err(ref e) => {
            let err_resp = crate::handler::error_response(e);
            format_http_response(err_resp.status, &err_resp.headers, &err_resp.body)
        }
    };

    // Write the response back to the client.
    tls_stream
        .write_all(&response_bytes)
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed to write TLS response: {e}")))?;

    tls_stream
        .shutdown()
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed to shutdown TLS: {e}")))?;

    Ok(())
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
    let read_fut = read_mitm_request_generic(stream);

    tokio::time::timeout(MITM_READ_TIMEOUT, read_fut)
        .await
        .map_err(|_| ProxyError::Upstream("MITM request read timed out after 30s".to_string()))?
}

/// Read a complete HTTP request from a TLS stream using the proper read loop.
async fn read_mitm_request_from_tls<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let read_fut = read_mitm_request_generic(stream);

    tokio::time::timeout(MITM_READ_TIMEOUT, read_fut)
        .await
        .map_err(|_| ProxyError::Upstream("MITM request read timed out after 30s".to_string()))?
}

/// Generic inner implementation of the MITM request read loop.
///
/// Works with any `AsyncRead` stream (TCP or TLS).
async fn read_mitm_request_generic<S>(stream: &mut S) -> Result<Vec<u8>, ProxyError>
where
    S: tokio::io::AsyncRead + Unpin,
{
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

/// Parse a raw HTTP request into components.
///
/// This is a simple parser for HTTP/1.1 requests sufficient for
/// proxying to the handler module.
fn parse_http_request(
    data: &[u8],
) -> Result<ParsedRequest, ProxyError> {
    let request_str =
        std::str::from_utf8(data).map_err(|_| ProxyError::InvalidPath {
            reason: "request is not valid UTF-8".to_owned(),
        })?;

    // Split headers from body.
    let (header_section, body_section) = request_str
        .split_once("\r\n\r\n")
        .unwrap_or((request_str, ""));

    let mut lines = header_section.lines();

    // Parse request line.
    let request_line = lines.next().ok_or_else(|| ProxyError::InvalidPath {
        reason: "empty request".to_owned(),
    })?;

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyError::InvalidPath {
            reason: format!("malformed request line: {request_line}"),
        });
    }

    let method = parts[0].to_owned();
    let raw_path = parts[1];

    // Split path and query.
    let (path, query) = if let Some((p, q)) = raw_path.split_once('?') {
        (p.to_owned(), Some(q.to_owned()))
    } else {
        (raw_path.to_owned(), None)
    };

    // Parse headers.
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }

    let body = body_section.as_bytes().to_vec();

    Ok((method, path, query, headers, body))
}

/// Format an HTTP response as raw bytes.
fn format_http_response(
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        502 => "Bad Gateway",
        _ => "Internal Server Error",
    };

    let mut response = format!("HTTP/1.1 {status} {status_text}\r\n");
    for (name, value) in headers {
        let _ = write!(response, "{name}: {value}\r\n");
    }
    let _ = write!(response, "content-length: {}\r\n", body.len());
    response.push_str("\r\n");

    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(body);
    bytes
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

    // ---------- Authority parsing tests ----------

    #[test]
    fn test_parse_connect_authority_valid() {
        let (host, port) = parse_connect_authority("api.openai.com:443").unwrap();
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_authority_custom_port() {
        let (host, port) = parse_connect_authority("example.com:8443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_parse_connect_authority_missing_port() {
        let result = parse_connect_authority("api.openai.com");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
    }

    #[test]
    fn test_parse_connect_authority_invalid_port() {
        let result = parse_connect_authority("api.openai.com:abc");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_connect_authority_empty_host() {
        let result = parse_connect_authority(":443");
        assert!(result.is_err());
    }

    // ---------- Action determination tests ----------

    #[test]
    fn test_llm_hosts_trigger_intercept() {
        let hosts = [
            "api.openai.com",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
        ];
        for host in hosts {
            assert!(
                should_intercept(host),
                "{host} should trigger interception"
            );
        }
    }

    #[test]
    fn test_non_llm_hosts_use_blind_tunnel() {
        let hosts = ["github.com", "google.com", "example.com", "registry.npmjs.org"];
        for host in hosts {
            assert!(
                !should_intercept(host),
                "{host} should NOT trigger interception"
            );
        }
    }

    // ---------- Connect action tests ----------

    #[test]
    fn test_connect_action_host_and_port() {
        let action = ConnectAction::BlindTunnel {
            host: "example.com".to_owned(),
            port: 443,
        };
        assert_eq!(action.host(), "example.com");
        assert_eq!(action.port(), 443);
        assert!(!action.is_intercept());
    }

    #[test]
    fn test_connect_action_mitm() {
        let action = ConnectAction::MitmIntercept {
            host: "api.openai.com".to_owned(),
            port: 443,
        };
        assert_eq!(action.host(), "api.openai.com");
        assert_eq!(action.port(), 443);
        assert!(action.is_intercept());
    }

    // ---------- HTTP parsing tests ----------

    #[test]
    fn test_parse_http_request_post() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n{\"model\":\"gpt-4o\"}";
        let (method, path, query, headers, body) = parse_http_request(raw).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/chat/completions");
        assert!(query.is_none());
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, "Host");
        assert_eq!(headers[0].1, "api.openai.com");
        assert_eq!(std::str::from_utf8(&body).unwrap(), "{\"model\":\"gpt-4o\"}");
    }

    #[test]
    fn test_parse_http_request_with_query() {
        let raw = b"GET /v1/models?param=test HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (method, path, query, _, _) = parse_http_request(raw).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/v1/models");
        assert_eq!(query, Some("param=test".to_owned()));
    }

    #[test]
    fn test_parse_http_request_empty() {
        let result = parse_http_request(b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_http_request_malformed() {
        let result = parse_http_request(b"INVALID");
        // single-word request line should fail (< 2 parts)
        assert!(result.is_err(), "single-word request line should fail");
    }

    // ---------- Response formatting tests ----------

    #[test]
    fn test_format_http_response_200() {
        let headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        let body = b"{}";
        let response = format_http_response(200, &headers, body);
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response_str.contains("content-type: application/json\r\n"));
        assert!(response_str.contains("content-length: 2\r\n"));
        assert!(response_str.ends_with("{}"));
    }

    #[test]
    fn test_format_http_response_429() {
        let headers = vec![];
        let body = b"budget exceeded";
        let response = format_http_response(429, &headers, body);
        let response_str = String::from_utf8(response).unwrap();
        assert!(response_str.starts_with("HTTP/1.1 429 Too Many Requests\r\n"));
    }

    // ---------- Connection established response ----------

    #[test]
    fn test_connection_established_response() {
        let resp = connection_established_response();
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    // ---------- Budget enforcement via CONNECT ----------

    #[test]
    fn test_connect_error_response_budget_blocked() {
        let err = ProxyError::BudgetBlocked {
            reason: "exceeded".to_owned(),
        };
        let resp = connect_error_response(&err);
        assert_eq!(resp.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn test_connect_error_response_invalid_path() {
        let err = ProxyError::InvalidPath {
            reason: "bad".to_owned(),
        };
        let resp = connect_error_response(&err);
        assert_eq!(resp.status(), hyper::StatusCode::BAD_REQUEST);
    }

    // ---------- Determine action tests ----------

    #[test]
    fn test_determine_action_openai_intercepts() {
        let action = determine_action("api.openai.com", 443);
        assert!(action.is_intercept());
        assert_eq!(action.host(), "api.openai.com");
        assert_eq!(action.port(), 443);
    }

    #[test]
    fn test_determine_action_anthropic_intercepts() {
        let action = determine_action("api.anthropic.com", 443);
        assert!(action.is_intercept());
    }

    #[test]
    fn test_determine_action_google_intercepts() {
        let action = determine_action("generativelanguage.googleapis.com", 443);
        assert!(action.is_intercept());
    }

    #[test]
    fn test_determine_action_unknown_tunnels() {
        let action = determine_action("github.com", 443);
        assert!(!action.is_intercept());
        assert_eq!(action.host(), "github.com");
    }

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
        let client = crate::handler::build_shared_client().expect("build client");
        let config = sanctum_types::config::BudgetConfig::default();
        let proxy_config = sanctum_types::config::ProxyConfig::default();
        let tracker = sanctum_budget::BudgetTracker::new(&config);
        let handler = HandlerState {
            client,
            budget_tracker: Arc::new(std::sync::Mutex::new(tracker)),
            pending_cost: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            budget_config: Arc::new(config),
            proxy_config: Arc::new(proxy_config),
        };
        let state = ConnectState::new(handler, ca);

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
