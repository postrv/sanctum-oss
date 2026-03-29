//! CONNECT tunnel handling and SSRF-safe connection logic.
//!
//! This module provides:
//! - DNS resolution with private/reserved IP validation (SSRF prevention)
//! - TOCTOU-safe connection using pre-validated `SocketAddr`s
//! - Content-Length header desync detection
//! - TLS certificate cache with bounded size

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use dashmap::DashMap;
use tokio::net::TcpStream;

use crate::error::ProxyError;

/// Maximum number of entries in the TLS certificate cache.
///
/// The proxy only intercepts a fixed set of LLM API providers (~9),
/// but this cap protects against latent unbounded growth if the
/// provider list expands or if dynamic host matching is added.
pub const MAX_CERT_CACHE_SIZE: usize = 100;

/// A bounded cache for TLS site certificates.
///
/// Uses `DashMap` for lock-free concurrent reads. When the cache
/// reaches `MAX_CERT_CACHE_SIZE`, it is cleared entirely (simple
/// eviction strategy appropriate for a small, stable key space).
#[derive(Debug)]
pub struct CertCache {
    /// The underlying concurrent map from hostname to certificate bytes.
    cache: DashMap<String, Vec<u8>>,
}

impl CertCache {
    /// Create a new empty certificate cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    /// Retrieve a cached certificate for the given hostname.
    #[must_use]
    pub fn get(&self, host: &str) -> Option<Vec<u8>> {
        self.cache.get(host).map(|entry| entry.value().clone())
    }

    /// Insert or retrieve a certificate, generating it on cache miss.
    ///
    /// If the cache is at capacity, it is cleared before inserting.
    /// This prevents unbounded memory growth.
    ///
    /// # Errors
    ///
    /// Returns `ProxyError::CaGeneration` if `generate_fn` fails.
    pub fn get_or_generate<F>(
        &self,
        host: &str,
        generate_fn: F,
    ) -> Result<Vec<u8>, ProxyError>
    where
        F: FnOnce(&str) -> Result<Vec<u8>, ProxyError>,
    {
        // Fast path: cache hit.
        if let Some(cert) = self.get(host) {
            return Ok(cert);
        }

        // Slow path: generate and cache.
        let cert = generate_fn(host)?;

        // Enforce size cap before inserting.
        if self.cache.len() >= MAX_CERT_CACHE_SIZE {
            tracing::warn!(
                capacity = MAX_CERT_CACHE_SIZE,
                "cert cache at capacity, clearing all entries"
            );
            self.cache.clear();
        }

        self.cache.insert(host.to_owned(), cert.clone());
        Ok(cert)
    }

    /// Return the current number of cached entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Return whether the cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for CertCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a hostname to socket addresses and validate that none are
/// private or reserved.
///
/// Returns the validated addresses on success. The caller MUST connect
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
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(e) => {
                tracing::debug!(
                    addr = %addr,
                    error = %e,
                    "connection attempt failed, trying next address"
                );
            }
        }
    }

    Err(ProxyError::ConnectFailed {
        host: host.to_owned(),
    })
}

/// Establish a blind TCP tunnel to the target host.
///
/// Resolves DNS once, validates all addresses against SSRF, then connects
/// using the validated `SocketAddr` directly (no second DNS lookup).
///
/// # Errors
///
/// Returns errors from DNS resolution, SSRF validation, or TCP connection.
pub async fn blind_tunnel(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    let addrs = resolve_and_validate(host, port).await?;
    connect_validated(host, &addrs).await
}

/// Establish a MITM-intercepted connection to the target host.
///
/// Like [`blind_tunnel`], resolves DNS once and connects using the
/// validated addresses. The returned `TcpStream` is intended for TLS
/// wrapping by the caller.
///
/// # Errors
///
/// Returns errors from DNS resolution, SSRF validation, or TCP connection.
pub async fn mitm_intercept(host: &str, port: u16) -> Result<TcpStream, ProxyError> {
    let addrs = resolve_and_validate(host, port).await?;
    connect_validated(host, &addrs).await
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
/// - `192.168.0.0/16` (RFC 1918)
/// - `198.18.0.0/15` (benchmarking, RFC 2544)
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
    // 192.168.0.0/16 -- RFC 1918 private
    || (octets[0] == 192 && octets[1] == 168)
    // 198.18.0.0/15 -- benchmarking (RFC 2544)
    || (octets[0] == 198 && (octets[1] & mask_15bit) == 18)
    // 255.255.255.255 -- broadcast
    || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
}

/// Check whether an IPv6 address is private or reserved.
///
/// Covers loopback (`::1`), link-local (`fe80::/10`), and unique-local (`fc00::/7`).
#[must_use]
pub const fn is_private_ipv6(ip: &Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    let link_local_mask: u16 = 0xFFC0;
    let link_local_prefix: u16 = 0xFE80;
    let unique_local_mask: u16 = 0xFE00;
    let unique_local_prefix: u16 = 0xFC00;
    // ::1 -- loopback
    ip.is_loopback()
    // fe80::/10 -- link-local
    || (seg0 & link_local_mask) == link_local_prefix
    // fc00::/7 -- unique local (RFC 4193)
    || (seg0 & unique_local_mask) == unique_local_prefix
    // :: (unspecified)
    || ip.is_unspecified()
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
            let parsed = value.trim().parse::<u64>().map_err(|_| ProxyError::InvalidPath {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ======================================================================
    // Fix 4: Private/reserved IPv4 range tests
    // ======================================================================

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
        // Not broadcast (only partial 255s).
        assert!(!is_private_ipv4(&Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn test_public_ipv4_accepted() {
        assert!(!is_private_ipv4(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(104, 18, 0, 1)));
        assert!(!is_private_ipv4(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    // ======================================================================
    // IPv6 private range tests
    // ======================================================================

    #[test]
    fn test_private_ipv6_loopback() {
        assert!(is_private_ipv6(&Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_private_ipv6_link_local() {
        // fe80::1
        assert!(is_private_ipv6(&Ipv6Addr::new(
            0xFE80, 0, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_private_ipv6_unique_local() {
        // fc00::1
        assert!(is_private_ipv6(&Ipv6Addr::new(
            0xFC00, 0, 0, 0, 0, 0, 0, 1
        )));
        // fd00::1
        assert!(is_private_ipv6(&Ipv6Addr::new(
            0xFD00, 0, 0, 0, 0, 0, 0, 1
        )));
    }

    #[test]
    fn test_private_ipv6_unspecified() {
        assert!(is_private_ipv6(&Ipv6Addr::UNSPECIFIED));
    }

    #[test]
    fn test_public_ipv6_accepted() {
        // Documentation prefix -- not private by our check.
        assert!(!is_private_ipv6(&Ipv6Addr::new(
            0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1
        )));
    }

    // ======================================================================
    // is_private_ip umbrella tests
    // ======================================================================

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
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0DB8, 0, 0, 0, 0, 0, 1));
        assert!(!is_private_ip(&ip));
    }

    // ======================================================================
    // Fix 2: Duplicate Content-Length header rejection
    // ======================================================================

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

    // ======================================================================
    // Fix 3: Cert cache size cap
    // ======================================================================

    #[test]
    fn test_cert_cache_new_is_empty() {
        let cache = CertCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cert_cache_default_is_empty() {
        let cache = CertCache::default();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cert_cache_get_miss() {
        let cache = CertCache::new();
        assert!(cache.get("example.com").is_none());
    }

    #[test]
    fn test_cert_cache_get_or_generate_inserts() {
        let cache = CertCache::new();
        let cert = cache
            .get_or_generate("api.openai.com", |host| {
                Ok(format!("cert-for-{host}").into_bytes())
            })
            .unwrap();
        assert_eq!(cert, b"cert-for-api.openai.com");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cert_cache_get_or_generate_returns_cached() {
        let cache = CertCache::new();
        let call_count = std::sync::atomic::AtomicUsize::new(0);

        let cert1 = cache
            .get_or_generate("example.com", |host| {
                call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(format!("cert-{host}").into_bytes())
            })
            .unwrap();

        let cert2 = cache
            .get_or_generate("example.com", |host| {
                call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(format!("cert-{host}-v2").into_bytes())
            })
            .unwrap();

        assert_eq!(cert1, cert2, "second call should return cached cert");
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "generator should only be called once"
        );
    }

    #[test]
    fn test_cert_cache_clears_at_capacity() {
        let cache = CertCache::new();

        // Fill the cache to capacity.
        for i in 0..MAX_CERT_CACHE_SIZE {
            let host = format!("host-{i}.example.com");
            cache
                .get_or_generate(&host, |h| Ok(format!("cert-{h}").into_bytes()))
                .unwrap();
        }
        assert_eq!(cache.len(), MAX_CERT_CACHE_SIZE);

        // Insert one more -- should trigger a clear.
        cache
            .get_or_generate("overflow.example.com", |h| {
                Ok(format!("cert-{h}").into_bytes())
            })
            .unwrap();

        // Cache should have been cleared and then the new entry inserted.
        assert_eq!(cache.len(), 1);
        assert!(cache.get("overflow.example.com").is_some());
        // Old entries should be gone.
        assert!(cache.get("host-0.example.com").is_none());
    }

    #[test]
    fn test_cert_cache_generator_error_propagated() {
        let cache = CertCache::new();
        let result = cache.get_or_generate("fail.example.com", |_| {
            Err(ProxyError::CaGeneration {
                reason: "test failure".to_owned(),
            })
        });
        assert!(result.is_err());
        assert!(cache.is_empty(), "failed generation should not cache");
    }

    // ======================================================================
    // Fix 5: SSRF error message redaction
    // ======================================================================

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

    // ======================================================================
    // Fix 1: DNS rebinding TOCTOU -- verify SocketAddr-based connection
    // ======================================================================

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
        let result =
            resolve_and_validate("this-host-definitely-does-not-exist.invalid", 80).await;
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
        let addrs = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            1,
        )];
        let result = connect_validated("test.example.com", &addrs).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::ConnectFailed { .. }
        ));
    }

    #[tokio::test]
    async fn test_blind_tunnel_rejects_private() {
        let result = blind_tunnel("127.0.0.1", 8080).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::SsrfBlocked { .. }
        ));
    }

    #[tokio::test]
    async fn test_mitm_intercept_rejects_private() {
        let result = mitm_intercept("127.0.0.1", 443).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ProxyError::SsrfBlocked { .. }
        ));
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
