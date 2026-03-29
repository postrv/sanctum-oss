//! HTTP CONNECT tunnel handler for HTTPS proxy operation.
//!
//! Handles the `CONNECT` method used by HTTPS proxies. For LLM API hosts,
//! the proxy performs MITM TLS interception using a locally-generated
//! certificate signed by the Sanctum CA. For all other hosts, a blind
//! TCP tunnel is established without inspection.

use std::sync::Arc;

use hyper::body::Incoming;
use hyper::{Method, Request, Response};
use http_body_util::Full;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use std::fmt::Write as _;

use crate::ca::CertificateAuthority;
use crate::error::ProxyError;
use crate::handler::HandlerState;
use crate::provider::{identify_provider, should_intercept};

/// Parsed HTTP request components: (method, path, query, headers, body).
type ParsedRequest = (String, String, Option<String>, Vec<(String, String)>, Vec<u8>);

/// Shared state for the CONNECT handler, including the CA for MITM.
#[derive(Clone)]
pub struct ConnectState {
    /// The handler state with budget tracker, client, etc.
    pub handler: HandlerState,
    /// The CA for generating per-host TLS certificates.
    pub ca: Arc<CertificateAuthority>,
}

impl std::fmt::Debug for ConnectState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectState")
            .field("handler", &self.handler)
            .field("ca", &"<CertificateAuthority>")
            .finish()
    }
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

/// Perform a blind TCP tunnel between client and upstream.
///
/// Simply copies bytes in both directions without inspection.
///
/// # Errors
///
/// Returns `ProxyError::Upstream` if the upstream connection fails.
pub async fn blind_tunnel(
    mut client_stream: tokio::net::TcpStream,
    host: &str,
    port: u16,
) -> Result<(), ProxyError> {
    let upstream_addr = format!("{host}:{port}");
    let mut upstream = TcpStream::connect(&upstream_addr).await.map_err(|e| {
        ProxyError::Upstream(format!("failed to connect to {upstream_addr}: {e}"))
    })?;

    let (mut client_read, mut client_write) = client_stream.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = async {
        let result = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        let _ = upstream_write.shutdown().await;
        result
    };

    let upstream_to_client = async {
        let result = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        let _ = client_write.shutdown().await;
        result
    };

    // Run both copies concurrently. When either side closes, both stop.
    let _ = tokio::join!(client_to_upstream, upstream_to_client);

    Ok(())
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
/// 1. Generate a per-host certificate signed by the CA.
/// 2. Perform TLS handshake with the client using the generated cert.
/// 3. Read the HTTP request from the client.
/// 4. Forward it to the upstream API (with budget checks and credential redaction).
/// 5. Return the response to the client.
///
/// # Errors
///
/// Returns `ProxyError` if TLS or HTTP operations fail.
pub async fn mitm_intercept(
    client_stream: tokio::net::TcpStream,
    host: &str,
    _port: u16,
    state: &ConnectState,
) -> Result<(), ProxyError> {
    // Generate a per-host certificate.
    let (site_cert, site_key) = state.ca.generate_site_cert(host)?;

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

    // Read the HTTP request from the TLS stream.
    // We read up to 64KB of request data (header + body).
    let mut buf = vec![0u8; 65536];
    let n = tls_stream.read(&mut buf).await.map_err(|e| {
        ProxyError::Upstream(format!("failed to read from TLS client: {e}"))
    })?;

    if n == 0 {
        return Ok(());
    }

    let request_data = &buf[..n];

    // Parse the HTTP request line and headers.
    let (method, path, query, headers, body) = parse_http_request(request_data)?;

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
}
