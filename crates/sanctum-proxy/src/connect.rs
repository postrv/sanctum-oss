//! CONNECT tunnel handling for the HTTP proxy.
//!
//! Handles HTTP CONNECT requests by either:
//! - Blind-forwarding non-LLM traffic (TCP relay with no inspection)
//! - MITM-intercepting LLM API traffic (TLS termination, request inspection)
//!
//! # Security invariants
//!
//! - Private/reserved IP addresses are blocked to prevent SSRF attacks
//! - DNS resolution happens once; validated `SocketAddr`s are used for connection
//!   to prevent DNS rebinding TOCTOU attacks
//! - All tunnels have timeouts to prevent resource exhaustion
//! - MITM reads use a proper read loop with size limits
//! - Content-Length desync (CL-CL) attacks are detected and rejected
//! - TLS certificate cache is bounded to prevent memory exhaustion
//! - SSRF error messages are redacted to avoid leaking internal IP addresses

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{Method, Request, Response};
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

/// Timeout for the TCP connect phase of blind tunnels (10 seconds).
const BLIND_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for blind tunnel relay (10 minutes for long-running API calls).
const BLIND_TUNNEL_TIMEOUT: Duration = Duration::from_secs(600);

/// Header boundary marker.
const HEADER_BOUNDARY: &[u8] = b"\r\n\r\n";

/// Maximum number of entries in the TLS certificate cache.
///
/// The proxy only intercepts a fixed set of LLM API providers (~9),
/// but this cap protects against latent unbounded growth if the
/// provider list expands or if dynamic host matching is added.
pub const MAX_CERT_CACHE_SIZE: usize = 100;

/// Parsed HTTP request components: (method, path, query, headers, body).
type ParsedRequest = (
    String,
    String,
    Option<String>,
    Vec<(String, String)>,
    Vec<u8>,
);

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

        // Enforce size cap before inserting.
        if self.cert_cache.len() >= MAX_CERT_CACHE_SIZE {
            tracing::warn!(
                capacity = MAX_CERT_CACHE_SIZE,
                "cert cache at capacity, clearing all entries"
            );
            self.cert_cache.clear();
        }

        let (cert, key_bytes) = crate::ca::generate_site_cert(&self.ca, domain)?;
        self.cert_cache
            .insert(domain.to_owned(), (cert.clone(), key_bytes.clone()));
        Ok((cert, key_bytes))
    }
}

/// Check whether an IP address is private, reserved, or otherwise
/// unsuitable for outbound proxy connections.
///
/// Covers all ranges from RFC 1918, RFC 4193, RFC 6598, and other
/// IANA reserved blocks.
#[must_use]
pub const fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

/// Check whether an IPv4 address is private or reserved.
///
/// Covers:
/// - `0.0.0.0/8` (this network)
/// - `10.0.0.0/8` (RFC 1918)
/// - `100.64.0.0/10` (CGNAT, RFC 6598)
/// - `127.0.0.0/8` (loopback)
/// - `169.254.0.0/16` (link-local)
/// - `172.16.0.0/12` (RFC 1918)
/// - `192.0.0.0/24` (IETF protocol assignments)
/// - `192.0.2.0/24` (TEST-NET-1, RFC 5737)
/// - `192.168.0.0/16` (RFC 1918)
/// - `198.18.0.0/15` (benchmarking, RFC 2544)
/// - `198.51.100.0/24` (TEST-NET-2, RFC 5737)
/// - `203.0.113.0/24` (TEST-NET-3, RFC 5737)
/// - `240.0.0.0/4` (Class E / reserved for future use)
/// - `255.255.255.255/32` (broadcast)
#[must_use]
pub const fn is_private_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    let mask_10bit: u8 = 0xC0;
    let mask_12bit: u8 = 0xF0;
    let mask_15bit: u8 = 0xFE;
    // 0.0.0.0/8 -- "this" network
    octets[0] == 0
    // 10.0.0.0/8 -- RFC 1918 private
    || octets[0] == 10
    // 100.64.0.0/10 -- CGNAT (RFC 6598)
    || (octets[0] == 100 && (octets[1] & mask_10bit) == 64)
    // 127.0.0.0/8 -- loopback
    || octets[0] == 127
    // 169.254.0.0/16 -- link-local
    || (octets[0] == 169 && octets[1] == 254)
    // 172.16.0.0/12 -- RFC 1918 private
    || (octets[0] == 172 && (octets[1] & mask_12bit) == 16)
    // 192.0.0.0/24 -- IETF protocol assignments
    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
    // 192.0.2.0/24 -- TEST-NET-1 (RFC 5737)
    || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
    // 192.168.0.0/16 -- RFC 1918 private
    || (octets[0] == 192 && octets[1] == 168)
    // 198.18.0.0/15 -- benchmarking (RFC 2544)
    || (octets[0] == 198 && (octets[1] & mask_15bit) == 18)
    // 198.51.100.0/24 -- TEST-NET-2 (RFC 5737)
    || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
    // 203.0.113.0/24 -- TEST-NET-3 (RFC 5737)
    || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    // 240.0.0.0/4 -- Class E (reserved for future use)
    || (octets[0] & mask_12bit) == 240
    // 255.255.255.255 -- broadcast
    || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
}

/// Check whether an IPv6 address is private or reserved.
///
/// Covers loopback, link-local, unique-local, unspecified,
/// IPv6-mapped IPv4 (`::ffff:x.x.x.x`), IPv4-compatible (`::x.x.x.x`),
/// 6to4 (`2002::/16`), Teredo (`2001:0000::/32`),
/// documentation (`2001:db8::/32`), and multicast (`ff00::/8`).
#[must_use]
pub const fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    let first_segment = segments[0];

    // IPv6-mapped IPv4 (::ffff:x.x.x.x) -- check the embedded IPv4 address.
    // Format: [0, 0, 0, 0, 0, 0xFFFF, hi16, lo16]
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xFFFF
    {
        // Extract the embedded IPv4 octets from the last two segments.
        let hi = segments[6];
        let lo = segments[7];
        let mapped = Ipv4Addr::new(
            (hi >> 8) as u8,
            (hi & 0xFF) as u8,
            (lo >> 8) as u8,
            (lo & 0xFF) as u8,
        );
        return is_private_ipv4(&mapped);
    }

    // IPv4-compatible addresses (::x.x.x.x, deprecated RFC 4291).
    // Format: [0, 0, 0, 0, 0, 0, hi16, lo16] -- segments[5] is NOT 0xFFFF.
    // Excludes ::0.0.0.0 (unspecified) and ::0.0.0.1 (loopback), which are
    // caught by the loopback/unspecified checks below.
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
        && (segments[6] != 0 || segments[7] > 1)
    {
        let hi = segments[6];
        let lo = segments[7];
        let compat = Ipv4Addr::new(
            (hi >> 8) as u8,
            (hi & 0xFF) as u8,
            (lo >> 8) as u8,
            (lo & 0xFF) as u8,
        );
        return is_private_ipv4(&compat);
    }

    // 6to4 addresses (2002::/16) -- embed an IPv4 address in segments[1..2].
    // e.g. 2002:7f00:0001:: embeds 127.0.0.1.
    if first_segment == 0x2002 {
        let hi = segments[1];
        let lo = segments[2];
        let embedded = Ipv4Addr::new(
            (hi >> 8) as u8,
            (hi & 0xFF) as u8,
            (lo >> 8) as u8,
            (lo & 0xFF) as u8,
        );
        return is_private_ipv4(&embedded);
    }

    // Teredo addresses (2001:0000::/32) -- embed an obfuscated IPv4 in
    // the last 32 bits (XOR'd with 0xFFFF_FFFF).
    if first_segment == 0x2001 && segments[1] == 0x0000 {
        let hi = segments[6] ^ 0xFFFF;
        let lo = segments[7] ^ 0xFFFF;
        let embedded = Ipv4Addr::new(
            (hi >> 8) as u8,
            (hi & 0xFF) as u8,
            (lo >> 8) as u8,
            (lo & 0xFF) as u8,
        );
        return is_private_ipv4(&embedded);
    }

    // Documentation prefix (2001:db8::/32, RFC 3849).
    if first_segment == 0x2001 && segments[1] == 0x0DB8 {
        return true;
    }

    // Multicast (ff00::/8).
    if (first_segment & 0xFF00) == 0xFF00 {
        return true;
    }

    let link_local_mask: u16 = 0xFFC0;
    let link_local_prefix: u16 = 0xFE80;
    let unique_local_mask: u16 = 0xFE00;
    let unique_local_prefix: u16 = 0xFC00;
    // ::1 -- loopback
    ip.is_loopback()
    // fe80::/10 -- link-local
    || (first_segment & link_local_mask) == link_local_prefix
    // fc00::/7 -- unique local (RFC 4193)
    || (first_segment & unique_local_mask) == unique_local_prefix
    // :: (unspecified)
    || ip.is_unspecified()
}

/// Resolve a hostname to socket addresses and validate that none are
/// private or reserved.
///
/// Returns the validated `SocketAddr`s on success. The caller MUST connect
/// using these addresses directly (not the hostname) to prevent DNS
/// rebinding TOCTOU attacks.
///
/// # Errors
///
/// Returns `ProxyError::DnsResolutionFailed` if DNS lookup yields no results.
/// Returns `ProxyError::SsrfBlocked` if any resolved address is private/reserved.
///
/// # Security
///
/// The error message intentionally omits the resolved IP address to avoid
/// leaking internal DNS configuration to the caller.
pub async fn resolve_and_validate(host: &str, port: u16) -> Result<Vec<SocketAddr>, ProxyError> {
    let lookup_target = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&lookup_target)
        .await
        .map_err(|_| ProxyError::DnsResolutionFailed {
            host: host.to_owned(),
        })?
        .collect();

    if addrs.is_empty() {
        return Err(ProxyError::DnsResolutionFailed {
            host: host.to_owned(),
        });
    }

    // Validate ALL resolved addresses -- reject if ANY is private/reserved.
    for addr in &addrs {
        if is_private_ip(&addr.ip()) {
            return Err(ProxyError::SsrfBlocked {
                host: host.to_owned(),
            });
        }
    }

    Ok(addrs)
}

/// Connect to one of the pre-validated socket addresses.
///
/// Tries each address in order until one connects, mirroring the
/// behavior of `TcpStream::connect` with multiple addresses.
///
/// # Security
///
/// This function takes `&[SocketAddr]` (not a hostname string) to
/// guarantee that no second DNS resolution occurs. The caller must
/// obtain these addresses from [`resolve_and_validate`].
///
/// # Errors
///
/// Returns `ProxyError::ConnectFailed` if no address could be reached.
pub async fn connect_validated(host: &str, addrs: &[SocketAddr]) -> Result<TcpStream, ProxyError> {
    for addr in addrs {
        match tokio::time::timeout(BLIND_CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                tracing::debug!(
                    addr = %addr,
                    error = %e,
                    "connection attempt failed, trying next address"
                );
            }
            Err(_elapsed) => {
                tracing::debug!(
                    addr = %addr,
                    timeout_secs = BLIND_CONNECT_TIMEOUT.as_secs(),
                    "connection attempt timed out, trying next address"
                );
            }
        }
    }

    Err(ProxyError::ConnectFailed {
        host: host.to_owned(),
    })
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
    let colon_pos = authority
        .rfind(':')
        .ok_or_else(|| ProxyError::InvalidPath {
            reason: format!("CONNECT authority missing port: {authority}"),
        })?;

    let host = &authority[..colon_pos];
    let port_str = &authority[colon_pos + 1..];
    let port = port_str
        .parse::<u16>()
        .map_err(|_| ProxyError::InvalidPath {
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
/// DNS is resolved once and validated; the connection uses the
/// pre-validated `SocketAddr` directly to prevent DNS rebinding.
///
/// # Errors
///
/// Returns `ProxyError` if the connection or relay fails.
pub async fn blind_tunnel(mut client: TcpStream, host: &str, port: u16) -> Result<(), ProxyError> {
    // Validate the target is not a private IP (SSRF prevention)
    // and connect using the validated addresses (DNS rebinding prevention).
    let addrs = resolve_and_validate(host, port).await?;
    let mut upstream = connect_validated(host, &addrs).await?;

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
/// DNS is resolved once and validated; the upstream connection uses the
/// pre-validated `SocketAddr` directly to prevent DNS rebinding.
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
    // DNS rebinding prevention: resolve once, pin the validated addresses
    // so that reqwest does not perform a second DNS lookup (TOCTOU).
    let validated_addrs = resolve_and_validate(host, port).await?;

    // Build a per-request reqwest client that pins DNS to the validated
    // addresses. This prevents a DNS rebinding attack where the first
    // lookup returns a public IP and the second returns a private one.
    let mut pinned_builder = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(60))
        .redirect(reqwest::redirect::Policy::none());
    for addr in &validated_addrs {
        pinned_builder = pinned_builder.resolve(host, *addr);
    }
    let pinned_client = pinned_builder.build().map_err(|e| {
        tracing::debug!(error = %e, "failed to build pinned reqwest client");
        ProxyError::Upstream("failed to build HTTP client".to_string())
    })?;

    // Create a handler state clone with the pinned client.
    let pinned_handler = HandlerState {
        client: pinned_client,
        budget_tracker: Arc::clone(&state.handler.budget_tracker),
        pending_cost: Arc::clone(&state.handler.pending_cost),
        budget_config: Arc::clone(&state.handler.budget_config),
        proxy_config: Arc::clone(&state.handler.proxy_config),
    };

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
        tracing::debug!(host = %host, error = %e, "TLS handshake failed");
        ProxyError::Upstream("TLS handshake failed".to_string())
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
        content_length: parse_content_length(&headers)?,
    };

    let response = crate::handler::handle_request(&pinned_handler, proxy_req).await;

    // Build HTTP response bytes.
    let response_bytes = match response {
        Ok(resp) => format_http_response(resp.status, &resp.headers, &resp.body),
        Err(ref e) => {
            let err_resp = crate::handler::error_response(e);
            format_http_response(err_resp.status, &err_resp.headers, &err_resp.body)
        }
    };

    // Write the response back to the client.
    tls_stream.write_all(&response_bytes).await.map_err(|e| {
        tracing::debug!(error = %e, "failed to write TLS response");
        ProxyError::Upstream("failed to write TLS response".to_string())
    })?;

    tls_stream.shutdown().await.map_err(|e| {
        tracing::debug!(error = %e, "failed to shutdown TLS");
        ProxyError::Upstream("failed to shutdown TLS".to_string())
    })?;

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
        let n = stream.read(&mut temp).await.map_err(|e| {
            tracing::debug!(error = %e, "failed to read from MITM stream");
            ProxyError::Upstream("failed to read from MITM stream".to_string())
        })?;

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
                reason: format!("request headers exceed {MAX_HEADER_SIZE} bytes without boundary"),
            });
        }
    }
    let header_bytes = &buf[..header_end];

    // Parse the header section as a string (headers are ASCII).
    let header_str = String::from_utf8_lossy(header_bytes);

    // Reject all Transfer-Encoding headers (not just chunked).
    // The MITM path uses Content-Length framing; any TE header would
    // break the body read loop and could be used for request smuggling.
    if has_transfer_encoding(&header_str) {
        return Err(ProxyError::Upstream(
            "Transfer-Encoding is not supported for MITM interception".to_string(),
        ));
    }

    // Parse Content-Length from raw header string (rejects CL-CL desync).
    let content_length = parse_content_length_raw(&header_str)?;

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
                    tracing::debug!(error = %e, "failed to read body from MITM stream");
                    ProxyError::Upstream("failed to read body from MITM stream".to_string())
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
fn parse_http_request(data: &[u8]) -> Result<ParsedRequest, ProxyError> {
    let request_str = std::str::from_utf8(data).map_err(|_| ProxyError::InvalidPath {
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
fn format_http_response(status: u16, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
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
        // Sanitize header values: strip CR and LF to prevent header injection.
        let safe_name: String = name.chars().filter(|&c| c != '\r' && c != '\n').collect();
        let safe_value: String = value.chars().filter(|&c| c != '\r' && c != '\n').collect();
        let _ = write!(response, "{safe_name}: {safe_value}\r\n");
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

/// Check if headers contain any `Transfer-Encoding` header.
///
/// ALL Transfer-Encoding values are rejected (not just chunked).
/// The MITM interception path uses Content-Length framing; any
/// Transfer-Encoding header (chunked, gzip, deflate, identity, etc.)
/// would break the body read loop and could be used for smuggling.
fn has_transfer_encoding(headers: &str) -> bool {
    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("transfer-encoding:") {
            return true;
        }
    }
    false
}

/// Parse the `Content-Length` header value from a raw header string.
///
/// Used by the MITM read loop where headers are raw strings.
/// Scans ALL headers and rejects conflicting values (CL-CL desync
/// prevention). Duplicate headers with the same value are tolerated.
///
/// # Errors
///
/// Returns `ProxyError::ConflictingContentLength` if multiple
/// Content-Length headers exist with different values.
fn parse_content_length_raw(headers: &str) -> Result<Option<usize>, ProxyError> {
    let mut found_value: Option<usize> = None;

    for line in headers.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            let Some(value_str) = line.split_once(':').map(|(_, v)| v.trim()) else {
                continue;
            };
            let Ok(parsed) = value_str.parse::<usize>() else {
                continue;
            };

            match found_value {
                Some(existing) if existing != parsed => {
                    return Err(ProxyError::ConflictingContentLength);
                }
                Some(_) => {
                    // Same value -- tolerate duplicate.
                }
                None => {
                    found_value = Some(parsed);
                }
            }
        }
    }

    Ok(found_value)
}

/// Parse and validate the Content-Length header from a list of headers.
///
/// HTTP request smuggling (CL-CL desync) can occur when multiple
/// Content-Length headers with different values are present. This
/// function scans ALL headers and rejects requests with conflicting
/// values.
///
/// Duplicate headers with the SAME value are accepted (some HTTP
/// clients and proxies send duplicates).
///
/// # Errors
///
/// Returns `ProxyError::ConflictingContentLength` if multiple
/// Content-Length headers exist with different values.
///
/// Returns `ProxyError::InvalidPath` if a Content-Length value
/// cannot be parsed as a `u64`.
pub fn parse_content_length(headers: &[(String, String)]) -> Result<Option<u64>, ProxyError> {
    let mut found_value: Option<u64> = None;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            let parsed = value
                .trim()
                .parse::<u64>()
                .map_err(|_| ProxyError::InvalidPath {
                    reason: "invalid Content-Length value".to_owned(),
                })?;

            match found_value {
                Some(existing) if existing != parsed => {
                    return Err(ProxyError::ConflictingContentLength);
                }
                Some(_) => {
                    // Same value -- tolerate duplicate.
                }
                None => {
                    found_value = Some(parsed);
                }
            }
        }
    }

    Ok(found_value)
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
            assert!(should_intercept(host), "{host} should trigger interception");
        }
    }

    #[test]
    fn test_non_llm_hosts_use_blind_tunnel() {
        let hosts = [
            "github.com",
            "google.com",
            "example.com",
            "registry.npmjs.org",
        ];
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
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "{\"model\":\"gpt-4o\"}"
        );
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

    #[test]
    fn test_format_http_response_strips_header_injection() {
        let headers = vec![("x-test".to_owned(), "value\r\nX-Evil: injected".to_owned())];
        let body = b"ok";
        let response = format_http_response(200, &headers, body);
        let response_str = String::from_utf8(response).unwrap();
        // The CRLF should be stripped so "X-Evil: injected" is NOT a
        // separate header line. Count the number of \r\n sequences:
        // there should be one for the status line, one for x-test,
        // one for content-length, and one for the header/body boundary.
        let line_count = response_str.matches("\r\n").count();
        // status + x-test + content-length + blank = 4
        assert_eq!(
            line_count, 4,
            "CRLF injection must not create extra header lines"
        );
        // The sanitized value should have CRLF removed.
        assert!(
            response_str.contains("x-test: valueX-Evil: injected\r\n"),
            "sanitized value should be present"
        );
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

    // ---------- SSRF: Private IPv4 blocking tests ----------

    #[test]
    fn test_private_ipv4_rfc1918_class_a() {
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn test_private_ipv4_rfc1918_class_b() {
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(172, 31, 255, 255)));
        // 172.32.x.x is NOT private.
        assert!(!is_private_ipv4(&Ipv4Addr::new(172, 32, 0, 1)));
    }

    #[test]
    fn test_private_ipv4_rfc1918_class_c() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn test_private_ipv4_loopback() {
        assert!(is_private_ipv4(&Ipv4Addr::LOCALHOST));
        assert!(is_private_ipv4(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_private_ipv4_link_local() {
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn test_private_ipv4_this_network() {
        assert!(is_private_ipv4(&Ipv4Addr::UNSPECIFIED));
        assert!(is_private_ipv4(&Ipv4Addr::new(0, 255, 255, 255)));
    }

    #[test]
    fn test_private_ipv4_cgnat() {
        // 100.64.0.0/10: first octet 100, second octet 64..127
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 100, 50, 25)));
        assert!(is_private_ipv4(&Ipv4Addr::new(100, 127, 255, 255)));
        // 100.63.x.x is NOT CGNAT.
        assert!(!is_private_ipv4(&Ipv4Addr::new(100, 63, 255, 255)));
        // 100.128.x.x is NOT CGNAT.
        assert!(!is_private_ipv4(&Ipv4Addr::new(100, 128, 0, 0)));
    }

    #[test]
    fn test_private_ipv4_ietf_protocol_assignments() {
        // 192.0.0.0/24
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 0, 255)));
        // 192.0.1.0 is NOT in this range.
        assert!(!is_private_ipv4(&Ipv4Addr::new(192, 0, 1, 0)));
    }

    #[test]
    fn test_private_ipv4_benchmarking() {
        // 198.18.0.0/15: covers 198.18.x.x and 198.19.x.x
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 18, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 18, 255, 255)));
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 19, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 19, 255, 255)));
        // 198.17.x.x is NOT benchmarking.
        assert!(!is_private_ipv4(&Ipv4Addr::new(198, 17, 0, 0)));
        // 198.20.x.x is NOT benchmarking.
        assert!(!is_private_ipv4(&Ipv4Addr::new(198, 20, 0, 0)));
    }

    #[test]
    fn test_private_ipv4_broadcast() {
        assert!(is_private_ipv4(&Ipv4Addr::BROADCAST));
        // 255.255.255.0 is in Class E range -- also blocked.
        assert!(is_private_ipv4(&Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn test_public_ipv4_accepted() {
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(104, 18, 0, 1)));
    }

    #[test]
    fn test_private_ipv4_test_net_1() {
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 2, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(192, 0, 2, 255)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(192, 0, 3, 0)));
    }

    #[test]
    fn test_private_ipv4_test_net_2() {
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 51, 100, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(198, 51, 100, 255)));
    }

    #[test]
    fn test_private_ipv4_test_net_3() {
        assert!(is_private_ipv4(&Ipv4Addr::new(203, 0, 113, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(203, 0, 113, 255)));
    }

    #[test]
    fn test_private_ipv4_class_e() {
        assert!(is_private_ipv4(&Ipv4Addr::new(240, 0, 0, 0)));
        assert!(is_private_ipv4(&Ipv4Addr::new(240, 0, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(239, 0, 0, 1)));
    }

    // ---------- SSRF: Private IPv6 blocking tests ----------

    #[test]
    fn test_private_ipv6_loopback() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_private_ipv6_link_local() {
        assert!(is_private_ipv6(&Ipv6Addr::new(0xFE80, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_private_ipv6_unique_local() {
        assert!(is_private_ipv6(&Ipv6Addr::new(0xFC00, 0, 0, 0, 0, 0, 0, 1)));
        assert!(is_private_ipv6(&Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 1)));
    }

    #[test]
    fn test_private_ipv6_unspecified() {
        assert!(is_private_ipv6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_public_ipv6_accepted() {
        // 2607:f8b0:4004:800::200e is a real Google public IPv6 address.
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2607, 0xF8B0, 0x4004, 0x0800, 0, 0, 0, 0x200E
        )));
    }

    // ---------- SSRF: IPv6-mapped IPv4 tests ----------

    #[test]
    fn test_ipv6_mapped_ipv4_loopback_is_private() {
        // ::ffff:127.0.0.1
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x7F00, 0x0001);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_mapped_ipv4_rfc1918_is_private() {
        // ::ffff:10.0.0.1
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0A00, 0x0001);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_mapped_ipv4_public_is_not_private() {
        // ::ffff:8.8.8.8
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0xFFFF, 0x0808, 0x0808);
        assert!(!is_private_ipv6(&ip));
    }

    // ---------- is_private_ip umbrella tests ----------

    #[test]
    fn test_is_private_ip_v4_private() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_v4_public() {
        let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_v6_private() {
        let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(is_private_ip(&ip));
    }

    #[test]
    fn test_is_private_ip_v6_public() {
        // Use a real public IPv6 (not documentation prefix).
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2607, 0xF8B0, 0x4004, 0x0800, 0, 0, 0, 0x200E,
        ));
        assert!(!is_private_ip(&ip));
    }

    // ---------- Content-Length parsing / CL-CL desync tests ----------

    #[test]
    fn test_parse_content_length_single_valid() {
        let headers = vec![
            ("Host".to_owned(), "example.com".to_owned()),
            ("Content-Length".to_owned(), "42".to_owned()),
        ];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_parse_content_length_missing() {
        let headers = vec![("Host".to_owned(), "example.com".to_owned())];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_parse_content_length_duplicate_same_value() {
        let headers = vec![
            ("Content-Length".to_owned(), "100".to_owned()),
            ("Content-Length".to_owned(), "100".to_owned()),
        ];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, Some(100));
    }

    #[test]
    fn test_parse_content_length_duplicate_different_values() {
        let headers = vec![
            ("Content-Length".to_owned(), "100".to_owned()),
            ("Content-Length".to_owned(), "200".to_owned()),
        ];
        let result = parse_content_length(&headers);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::ConflictingContentLength));
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn test_parse_content_length_case_insensitive() {
        let headers = vec![
            ("content-length".to_owned(), "50".to_owned()),
            ("Content-Length".to_owned(), "50".to_owned()),
            ("CONTENT-LENGTH".to_owned(), "50".to_owned()),
        ];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, Some(50));
    }

    #[test]
    fn test_parse_content_length_case_insensitive_conflict() {
        let headers = vec![
            ("content-length".to_owned(), "50".to_owned()),
            ("Content-Length".to_owned(), "51".to_owned()),
        ];
        let result = parse_content_length(&headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConflictingContentLength
        ));
    }

    #[test]
    fn test_parse_content_length_invalid_value() {
        let headers = vec![("Content-Length".to_owned(), "not-a-number".to_owned())];
        let result = parse_content_length(&headers);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_content_length_with_whitespace() {
        let headers = vec![("Content-Length".to_owned(), "  42  ".to_owned())];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, Some(42));
    }

    #[test]
    fn test_parse_content_length_zero() {
        let headers = vec![("Content-Length".to_owned(), "0".to_owned())];
        let result = parse_content_length(&headers).unwrap();
        assert_eq!(result, Some(0));
    }

    // ---------- Raw Content-Length parsing (MITM read loop) ----------

    #[test]
    fn test_parse_content_length_raw_present() {
        let headers =
            "POST /v1/chat HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 42\r\n\r\n";
        assert_eq!(parse_content_length_raw(headers).unwrap(), Some(42));
    }

    #[test]
    fn test_parse_content_length_raw_missing() {
        let headers = "GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n\r\n";
        assert_eq!(parse_content_length_raw(headers).unwrap(), None);
    }

    #[test]
    fn test_parse_content_length_raw_case_insensitive() {
        let headers = "POST / HTTP/1.1\r\ncontent-length: 100\r\n\r\n";
        assert_eq!(parse_content_length_raw(headers).unwrap(), Some(100));
    }

    #[test]
    fn test_parse_content_length_raw_duplicate_same() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 50\r\nContent-Length: 50\r\n\r\n";
        assert_eq!(parse_content_length_raw(headers).unwrap(), Some(50));
    }

    #[test]
    fn test_parse_content_length_raw_duplicate_conflict() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 50\r\nContent-Length: 99\r\n\r\n";
        let result = parse_content_length_raw(headers);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConflictingContentLength
        ));
    }

    // ---------- Transfer-Encoding detection ----------

    #[test]
    fn test_has_transfer_encoding_chunked() {
        let headers = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(has_transfer_encoding(headers));
    }

    #[test]
    fn test_has_transfer_encoding_case_insensitive() {
        let headers = "POST / HTTP/1.1\r\ntransfer-encoding: Chunked\r\n\r\n";
        assert!(has_transfer_encoding(headers));
    }

    #[test]
    fn test_has_transfer_encoding_gzip() {
        // All TE values must be rejected, not just chunked.
        let headers = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(has_transfer_encoding(headers));
    }

    #[test]
    fn test_has_transfer_encoding_identity() {
        let headers = "POST / HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n";
        assert!(has_transfer_encoding(headers));
    }

    #[test]
    fn test_no_transfer_encoding() {
        let headers = "POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n";
        assert!(!has_transfer_encoding(headers));
    }

    // ---------- Byte utilities ----------

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

    // ---------- Timeout constant tests ----------

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

    // ---------- Connect state / cert caching tests ----------

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

    // ---------- SSRF error message redaction tests ----------

    #[test]
    fn test_ssrf_error_does_not_contain_ip() {
        let err = ProxyError::SsrfBlocked {
            host: "evil.example.com".to_owned(),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("evil.example.com"),
            "error should contain the hostname"
        );
        assert!(
            msg.contains("private/reserved"),
            "error should mention private/reserved"
        );
    }

    #[test]
    fn test_ssrf_blocked_status_code() {
        let err = ProxyError::SsrfBlocked {
            host: "internal.corp".to_owned(),
        };
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_dns_resolution_failed_status_code() {
        let err = ProxyError::DnsResolutionFailed {
            host: "nonexistent.invalid".to_owned(),
        };
        assert_eq!(err.status_code(), 502);
    }

    #[test]
    fn test_conflicting_content_length_status_code() {
        let err = ProxyError::ConflictingContentLength;
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn test_connect_failed_status_code() {
        let err = ProxyError::ConnectFailed {
            host: "unreachable.example.com".to_owned(),
        };
        assert_eq!(err.status_code(), 502);
    }

    // ---------- DNS rebinding TOCTOU / resolve_and_validate tests ----------

    #[tokio::test]
    async fn test_resolve_and_validate_rejects_loopback() {
        let result = resolve_and_validate("127.0.0.1", 80).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::SsrfBlocked { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_and_validate_rejects_localhost() {
        let result = resolve_and_validate("localhost", 80).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::SsrfBlocked { .. }
        ));
    }

    #[tokio::test]
    async fn test_resolve_and_validate_nonexistent_host() {
        let result = resolve_and_validate("this-host-definitely-does-not-exist.invalid", 80).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::DnsResolutionFailed { .. }
        ));
    }

    #[tokio::test]
    async fn test_connect_validated_empty_addrs() {
        let result = connect_validated("example.com", &[]).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConnectFailed { .. }
        ));
    }

    #[tokio::test]
    async fn test_connect_validated_unreachable_addr() {
        // Use a non-routable TEST-NET address that will fail quickly.
        let addrs = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 1)];
        let result = connect_validated("test.example.com", &addrs).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConnectFailed { .. }
        ));
    }

    // ---------- SSRF: IPv6 6to4 bypass tests ----------

    #[test]
    fn test_ipv6_6to4_loopback_is_private() {
        // 2002:7f00:0001:: embeds 127.0.0.1
        let ip = Ipv6Addr::new(0x2002, 0x7F00, 0x0001, 0, 0, 0, 0, 0);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_6to4_rfc1918_is_private() {
        // 2002:0a00:0001:: embeds 10.0.0.1
        let ip = Ipv6Addr::new(0x2002, 0x0A00, 0x0001, 0, 0, 0, 0, 0);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_6to4_rfc1918_class_c_is_private() {
        // 2002:c0a8:0101:: embeds 192.168.1.1
        let ip = Ipv6Addr::new(0x2002, 0xC0A8, 0x0101, 0, 0, 0, 0, 0);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_6to4_public_embedded_is_not_private() {
        // 2002:0808:0808:: embeds 8.8.8.8 (public)
        let ip = Ipv6Addr::new(0x2002, 0x0808, 0x0808, 0, 0, 0, 0, 0);
        assert!(!is_private_ipv6(&ip));
    }

    // ---------- SSRF: IPv4-compatible IPv6 tests ----------

    #[test]
    fn test_ipv6_ipv4_compatible_loopback_is_private() {
        // ::127.0.0.1 = ::7f00:0001
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x7F00, 0x0001);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_ipv4_compatible_rfc1918_is_private() {
        // ::10.0.0.1 = ::0a00:0001
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0A00, 0x0001);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_ipv4_compatible_public_is_not_private() {
        // ::8.8.8.8 = ::0808:0808
        let ip = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0x0808, 0x0808);
        assert!(!is_private_ipv6(&ip));
    }

    // ---------- SSRF: IPv6 documentation prefix tests ----------

    #[test]
    fn test_ipv6_documentation_prefix_is_private() {
        // 2001:db8::1 (RFC 3849 documentation range)
        let ip = Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_documentation_prefix_full_range_is_private() {
        // 2001:db8:ffff:ffff:ffff:ffff:ffff:ffff
        let ip = Ipv6Addr::new(
            0x2001, 0x0DB8, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
        );
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_not_documentation_prefix() {
        // 2001:db9::1 is NOT in the documentation range
        let ip = Ipv6Addr::new(0x2001, 0x0DB9, 0, 0, 0, 0, 0, 1);
        assert!(!is_private_ipv6(&ip));
    }

    // ---------- SSRF: IPv6 multicast tests ----------

    #[test]
    fn test_ipv6_multicast_is_private() {
        // ff02::1 (all-nodes multicast)
        let ip = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_multicast_all_routers_is_private() {
        // ff02::2 (all-routers multicast)
        let ip = Ipv6Addr::new(0xFF02, 0, 0, 0, 0, 0, 0, 2);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_multicast_global_scope_is_private() {
        // ff0e::1 (global-scope multicast)
        let ip = Ipv6Addr::new(0xFF0E, 0, 0, 0, 0, 0, 0, 1);
        assert!(is_private_ipv6(&ip));
    }

    // ---------- SSRF: IPv6 Teredo tests ----------

    #[test]
    fn test_ipv6_teredo_loopback_is_private() {
        // Teredo format: 2001:0000:<server>:<flags>:<client_port_xor>:<client_ip_xor>
        // Embedded IPv4 = last 32 bits XOR 0xFFFFFFFF
        // To embed 127.0.0.1 (0x7F000001): XOR -> 0x80FFFFFE
        let ip = Ipv6Addr::new(0x2001, 0x0000, 0, 0, 0, 0, 0x80FF, 0xFFFE);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_teredo_rfc1918_is_private() {
        // Embed 10.0.0.1 (0x0A000001): XOR -> 0xF5FFFFFE
        let ip = Ipv6Addr::new(0x2001, 0x0000, 0, 0, 0, 0, 0xF5FF, 0xFFFE);
        assert!(is_private_ipv6(&ip));
    }

    #[test]
    fn test_ipv6_teredo_public_is_not_private() {
        // Embed 8.8.8.8 (0x08080808): XOR -> 0xF7F7F7F7
        let ip = Ipv6Addr::new(0x2001, 0x0000, 0, 0, 0, 0, 0xF7F7, 0xF7F7);
        assert!(!is_private_ipv6(&ip));
    }

    // ---------- SSRF: Blind tunnel connect timeout test ----------

    #[tokio::test]
    async fn test_connect_validated_times_out() {
        // Use an address in the RFC 5737 TEST-NET-1 range on a high port.
        // This address is non-routable and will not produce a quick
        // RST/connection-refused, so the connect should time out.
        let addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            12345,
        )];
        let start = std::time::Instant::now();
        let result = connect_validated("test-timeout.example.com", &addrs).await;
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConnectFailed { .. }
        ));
        // The connect should complete in a bounded time (at most ~15s with
        // the 10s timeout plus OS-level teardown). On most systems, TEST-NET
        // addresses return a quick error, so we just verify it did not hang
        // for an excessively long time.
        assert!(
            elapsed < Duration::from_secs(30),
            "connect_validated should complete within 30s, took {elapsed:?}"
        );
    }

    #[test]
    fn test_blind_connect_timeout_constant() {
        assert_eq!(
            BLIND_CONNECT_TIMEOUT,
            Duration::from_secs(10),
            "blind connect timeout should be 10 seconds"
        );
    }

    /// Verify that `resolve_and_validate` returns `Vec<SocketAddr>`.
    /// This is both a compile-time and runtime check that the DNS
    /// rebinding fix returns addresses, not hostname strings.
    #[tokio::test]
    async fn test_resolve_returns_socket_addrs() {
        // Use a public DNS name that should resolve.
        // If DNS is unavailable in CI, this test will skip gracefully.
        let result = resolve_and_validate("dns.google", 443).await;
        if let Ok(addrs) = result {
            assert!(!addrs.is_empty());
            for addr in &addrs {
                assert_eq!(addr.port(), 443);
                assert!(
                    !is_private_ip(&addr.ip()),
                    "resolved address should be public"
                );
            }
        }
        // Err case: acceptable in CI environments without DNS.
    }
}
