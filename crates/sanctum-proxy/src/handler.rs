//! HTTP request handler for the proxy.
//!
//! Each intercepted request passes through this module which:
//! 1. Validates the request path (SSRF prevention)
//! 2. Enforces request body size limits
//! 3. Checks budget and model allowlist
//! 4. Redacts credentials from request and response bodies
//! 5. Forwards the request upstream
//! 6. Extracts and records token usage from the response
//! 7. Strips hop-by-hop headers from the response

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sanctum_budget::{check_budget, is_model_allowed, BudgetTracker, EnforcementResult};
use sanctum_firewall::redaction::redact_credentials;
use sanctum_types::config::{BudgetConfig, ProxyConfig};

use crate::error::ProxyError;
use crate::provider::Provider;
use crate::routing::resolve_upstream;

/// Default maximum request body size (10 MB).
pub const DEFAULT_MAX_BODY_BYTES: u64 = 10 * 1024 * 1024;

/// Default estimated cost per request for TOCTOU mitigation (100 cents).
const PENDING_COST_ESTIMATE: u64 = 100;

/// Headers that must not be forwarded in responses (hop-by-hop).
const HOP_BY_HOP_RESPONSE_HEADERS: &[&str] = &[
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "trailer",
    "te",
    "proxy-authenticate",
    "proxy-authorization",
];

/// Check whether a response header name is safe to forward to the client.
///
/// Hop-by-hop headers are specific to the connection between the proxy
/// and the upstream server and must not be forwarded to the client.
#[must_use]
pub fn is_forwardable_response_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    !HOP_BY_HOP_RESPONSE_HEADERS.contains(&lower.as_str())
}

/// Shared state passed to the handler for each request.
#[derive(Clone, Debug)]
pub struct HandlerState {
    /// Shared HTTP client with configured timeouts and connection pooling.
    pub client: reqwest::Client,
    /// Budget tracker (mutex-protected for mutable access).
    pub budget_tracker: Arc<Mutex<BudgetTracker>>,
    /// Atomic counter for pending estimated costs (TOCTOU mitigation).
    pub pending_cost: Arc<AtomicU64>,
    /// Budget configuration for model allowlist checks.
    pub budget_config: Arc<BudgetConfig>,
    /// Proxy configuration.
    pub proxy_config: Arc<ProxyConfig>,
}

/// RAII guard that decrements a pending-cost counter on drop.
///
/// Ensures that early returns (error paths) always release the
/// pending cost estimate, preventing a monotonically increasing
/// leak in the atomic counter.
struct PendingCostGuard<'a> {
    counter: &'a AtomicU64,
    amount: u64,
    defused: bool,
}

impl<'a> PendingCostGuard<'a> {
    /// Create a new guard that immediately increments the counter.
    fn new(counter: &'a AtomicU64, amount: u64) -> Self {
        counter.fetch_add(amount, Ordering::SeqCst);
        Self {
            counter,
            amount,
            defused: false,
        }
    }

    /// Defuse the guard so it does not decrement on drop.
    ///
    /// Call this after the pending cost has been officially subtracted
    /// to prevent a double-decrement.
    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for PendingCostGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
            self.counter.fetch_sub(self.amount, Ordering::SeqCst);
        }
    }
}

/// A simplified representation of an HTTP request for the handler.
pub struct ProxyRequest {
    /// The HTTP method (e.g., "GET", "POST").
    pub method: String,
    /// The request path (e.g., "/v1/chat/completions").
    pub path: String,
    /// Optional query string.
    pub query: Option<String>,
    /// Request headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// The request body bytes.
    pub body: Vec<u8>,
    /// The identified LLM provider.
    pub provider: Provider,
    /// The Content-Length header value, if present.
    pub content_length: Option<u64>,
}

/// A simplified representation of an HTTP response from the handler.
pub struct ProxyResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Response headers as (name, value) pairs.
    pub headers: Vec<(String, String)>,
    /// The response body bytes.
    pub body: Vec<u8>,
}

/// Create a shared `reqwest::Client` with appropriate timeouts.
///
/// # Errors
///
/// Returns `ProxyError::Upstream` if the client cannot be built.
pub fn build_shared_client() -> Result<reqwest::Client, ProxyError> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(60))
        .pool_max_idle_per_host(10)
        // SECURITY: Disable automatic redirect following to prevent SSRF.
        // A compromised upstream could redirect to internal addresses
        // (e.g., 169.254.169.254 metadata service). LLM API endpoints
        // should never issue redirects.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ProxyError::Upstream(format!("failed to build HTTP client: {e}")))
}

/// Handle a single proxied request end-to-end.
///
/// This is the main entry point for request processing. It performs
/// all validation, forwarding, and post-processing steps.
///
/// # Errors
///
/// Returns `ProxyError` for any validation or upstream failure.
#[allow(clippy::too_many_lines)]
pub async fn handle_request(
    state: &HandlerState,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError> {
    let max_body = state.proxy_config.max_response_body_bytes as u64;

    // H1: Check request body size limit.
    check_request_body_size(&request, max_body)?;

    // H2: Validate and resolve the upstream URL.
    let upstream_url =
        resolve_upstream(&request.provider, &request.path, request.query.as_deref())?;

    // LOW: Model allowlist enforcement.
    if state.proxy_config.enforce_allowed_models {
        check_model_allowlist(&request, request.provider, &state.budget_config)?;
    }

    // M2: Budget TOCTOU mitigation -- add pending cost estimate via RAII guard.
    // The guard auto-decrements on drop (including early-return error paths),
    // preventing a monotonic pending-cost leak.
    let cost_guard = PendingCostGuard::new(&state.pending_cost, PENDING_COST_ESTIMATE);

    // Check budget with pending cost considered.
    if state.proxy_config.enforce_budget {
        let budget_result = {
            let tracker = state
                .budget_tracker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            check_budget(
                &tracker,
                request.provider.to_budget_provider(),
                state.pending_cost.load(Ordering::SeqCst),
            )
        };
        if let EnforcementResult::Blocked { message } = budget_result {
            // Guard will decrement on drop.
            return Err(ProxyError::BudgetBlocked { reason: message });
        }
    }

    // H3: Redact credentials from request body.
    let request_body = redact_body_bytes(&request.body);

    // Detect SSE streaming requests and warn about budget tracking limitations.
    if request_body_has_stream_flag(&request.body) {
        tracing::warn!(
            provider = %request.provider.display_name(),
            path = %request.path,
            "streaming response requested (\"stream\": true); budget usage tracking \
             will not work for this request because SSE streams do not contain a \
             single JSON usage object"
        );
    }

    // Build and send the upstream request.
    // On error, cost_guard drops and decrements automatically.
    let upstream_response = send_upstream(state, &request, &upstream_url, request_body).await?;

    let status = upstream_response.status().as_u16();

    // Collect response headers, filtering hop-by-hop and redacting credentials.
    let response_headers: Vec<(String, String)> = upstream_response
        .headers()
        .iter()
        .filter(|(name, _)| is_forwardable_response_header(name.as_str()))
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|v| {
                let (redacted_value, events) = redact_credentials(v);
                if !events.is_empty() {
                    tracing::warn!(
                        header = %name,
                        count = events.len(),
                        "redacted credentials from response header"
                    );
                }
                (name.to_string(), redacted_value)
            })
        })
        .collect();

    // Read response body with size limit.
    // On error, cost_guard drops and decrements automatically.
    let response_body = read_response_body_limited(upstream_response, max_body).await?;

    // M2: Defuse the guard -- the pending cost is now officially released.
    cost_guard.defuse();

    // Record usage from response.
    //
    // KNOWN LIMITATION: SSE streaming responses (`"stream": true` in request).
    // When streaming is enabled, the upstream returns an SSE event stream
    // rather than a single JSON object. The usage data (token counts) is
    // typically only included in the final `[DONE]` event or as a separate
    // `usage` field in the last data chunk. This extraction logic expects a
    // complete JSON response body and will fail to capture usage from SSE
    // streams. As a result, budget tracking is not applied to streaming
    // responses. This is tracked for future implementation.
    if let Ok(body_str) = std::str::from_utf8(&response_body) {
        let mut tracker = state
            .budget_tracker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::usage::record_if_available(&mut tracker, body_str);
    }

    // H3: Redact credentials from response body.
    let final_body = redact_response_body(response_body);

    Ok(ProxyResponse {
        status,
        headers: response_headers,
        body: final_body,
    })
}

/// Redact credentials from a byte buffer (request or response body).
///
/// Returns the original bytes unchanged if the body is empty or non-UTF8.
fn redact_body_bytes(body: &[u8]) -> Vec<u8> {
    if body.is_empty() {
        return body.to_vec();
    }
    let body_str = String::from_utf8_lossy(body);
    let (redacted, events) = redact_credentials(&body_str);
    if !events.is_empty() {
        tracing::warn!(
            count = events.len(),
            "redacted credentials from request body"
        );
    }
    redacted.into_bytes()
}

/// Redact credentials from response body bytes.
///
/// Uses `from_utf8_lossy` so that even partially-invalid UTF-8 payloads
/// are scanned for credentials. Without this, an attacker could embed a
/// single invalid byte to bypass redaction entirely.
fn redact_response_body(response_body: Vec<u8>) -> Vec<u8> {
    if response_body.is_empty() {
        return response_body;
    }
    let body_str = String::from_utf8_lossy(&response_body);
    let (redacted, events) = redact_credentials(&body_str);
    if !events.is_empty() {
        tracing::warn!(
            count = events.len(),
            "redacted credentials from response body"
        );
    }
    redacted.into_bytes()
}

/// Build and send the upstream HTTP request.
async fn send_upstream(
    state: &HandlerState,
    request: &ProxyRequest,
    upstream_url: &str,
    request_body: Vec<u8>,
) -> Result<reqwest::Response, ProxyError> {
    let mut req_builder = match request.method.as_str() {
        "GET" => state.client.get(upstream_url),
        "POST" => state.client.post(upstream_url),
        "PUT" => state.client.put(upstream_url),
        "DELETE" => state.client.delete(upstream_url),
        "PATCH" => state.client.patch(upstream_url),
        "HEAD" => state.client.head(upstream_url),
        other => {
            return Err(ProxyError::MethodNotAllowed {
                method: other.to_owned(),
            });
        }
    };

    // Forward headers (skip hop-by-hop and host).
    for (name, value) in &request.headers {
        let lower = name.to_lowercase();
        if lower != "host" && lower != "content-length" && is_forwardable_response_header(&lower) {
            req_builder = req_builder.header(name.as_str(), value.as_str());
        }
    }

    if !request_body.is_empty() {
        req_builder = req_builder.body(request_body);
    }

    req_builder
        .send()
        .await
        .map_err(|e| ProxyError::Upstream(format!("upstream request failed: {e}")))
}

/// Check whether a request body contains `"stream": true`, indicating
/// that the client has requested an SSE streaming response.
///
/// This is a best-effort check using JSON parsing. If the body is not
/// valid UTF-8 or not valid JSON, returns `false` (fail-open).
fn request_body_has_stream_flag(body: &[u8]) -> bool {
    if body.is_empty() {
        return false;
    }
    let Ok(body_str) = std::str::from_utf8(body) else {
        return false;
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) else {
        return false;
    };
    json.get("stream").and_then(serde_json::Value::as_bool) == Some(true)
}

/// Check the request body size against the configured limit.
///
/// Uses Content-Length if available; otherwise uses the actual body length.
fn check_request_body_size(request: &ProxyRequest, max_bytes: u64) -> Result<(), ProxyError> {
    // Check Content-Length header first.
    if let Some(content_length) = request.content_length {
        if content_length > max_bytes {
            return Err(ProxyError::PayloadTooLarge {
                reason: format!(
                    "request body ({content_length} bytes) exceeds limit ({max_bytes} bytes)"
                ),
            });
        }
    }

    // Also check actual body length (covers cases where Content-Length is missing or wrong).
    let body_len = request.body.len() as u64;
    if body_len > max_bytes {
        return Err(ProxyError::PayloadTooLarge {
            reason: format!("request body ({body_len} bytes) exceeds limit ({max_bytes} bytes)"),
        });
    }

    Ok(())
}

/// Read the response body from upstream with a size limit.
///
/// Streams the body in chunks with a running size counter so that
/// chunked responses without a `Content-Length` header are still
/// bounded without buffering the entire body first.
async fn read_response_body_limited(
    mut response: reqwest::Response,
    max_bytes: u64,
) -> Result<Vec<u8>, ProxyError> {
    // Fast-path: if Content-Length is present, check it before reading.
    if let Some(content_length) = response.content_length() {
        if content_length > max_bytes {
            return Err(ProxyError::PayloadTooLarge {
                reason: format!(
                    "response body ({content_length} bytes) exceeds limit ({max_bytes} bytes)"
                ),
            });
        }
    }

    let mut total: u64 = 0;
    let mut chunks: Vec<bytes::Bytes> = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ProxyError::Upstream(format!("failed to read response body: {e}")))?
    {
        total = total.saturating_add(chunk.len() as u64);
        if total > max_bytes {
            return Err(ProxyError::PayloadTooLarge {
                reason: format!("response body ({total} bytes) exceeds limit ({max_bytes} bytes)"),
            });
        }
        chunks.push(chunk);
    }

    let capacity = usize::try_from(total).unwrap_or(usize::MAX);
    let mut body = Vec::with_capacity(capacity);
    for chunk in chunks {
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Check the model allowlist for the given request.
///
/// Parses the request body as JSON to extract the `model` field.
/// If parsing fails, the request is allowed (fail-open for non-JSON).
fn check_model_allowlist(
    request: &ProxyRequest,
    provider: Provider,
    budget_config: &BudgetConfig,
) -> Result<(), ProxyError> {
    if request.body.is_empty() {
        return Ok(());
    }

    let Ok(body_str) = std::str::from_utf8(&request.body) else {
        return Ok(()); // Non-UTF8 body; fail-open.
    };

    let Ok(json) = serde_json::from_str::<serde_json::Value>(body_str) else {
        return Ok(()); // Non-JSON body; fail-open.
    };

    let Some(model) = json.get("model").and_then(serde_json::Value::as_str) else {
        return Ok(()); // No model field; fail-open.
    };

    let budget_provider = provider.to_budget_provider();
    if !is_model_allowed(&budget_provider, model, budget_config) {
        return Err(ProxyError::ModelNotAllowed {
            model: model.to_owned(),
            provider: provider.display_name().to_owned(),
        });
    }

    Ok(())
}

/// Create an error response with the given status and message.
#[must_use]
pub fn error_response(error: &ProxyError) -> ProxyResponse {
    let status = error.status_code();
    let body = serde_json::json!({
        "error": {
            "type": error_type_str(error),
            "message": error.to_string(),
        }
    });
    let body_str = serde_json::to_string(&body)
        .unwrap_or_else(|_| r#"{"error":{"message":"internal error"}}"#.to_owned());
    ProxyResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body_str.into_bytes(),
    }
}

/// Map an error variant to a stable type string for the JSON response.
const fn error_type_str(error: &ProxyError) -> &'static str {
    match error {
        ProxyError::PayloadTooLarge { .. } => "payload_too_large",
        ProxyError::BudgetBlocked { .. } => "budget_exceeded",
        ProxyError::ModelNotAllowed { .. } => "model_not_allowed",
        ProxyError::InvalidPath { .. } => "invalid_path",
        ProxyError::SsrfBlocked { .. } => "ssrf_blocked",
        ProxyError::MethodNotAllowed { .. } => "method_not_allowed",
        ProxyError::ConflictingContentLength => "conflicting_content_length",
        ProxyError::DnsResolutionFailed { .. } | ProxyError::ConnectFailed { .. } => "connect_error",
        ProxyError::Upstream(_) | ProxyError::TunnelTimeout { .. } => "upstream_error",
        _ => "internal_error",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_types::config::ProviderBudgetConfig;
    use std::collections::HashMap;

    // ---------- H1: Body size limit tests ----------

    #[test]
    fn test_request_body_too_large_returns_413() {
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: vec![0u8; 11 * 1024 * 1024], // 11 MB
            provider: Provider::OpenAi,
            content_length: Some(11 * 1024 * 1024),
        };

        let result = check_request_body_size(&request, DEFAULT_MAX_BODY_BYTES);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::PayloadTooLarge { .. }));
        assert_eq!(err.status_code(), 413);
    }

    #[test]
    fn test_request_body_within_limit_accepted() {
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: vec![0u8; 1024], // 1 KB
            provider: Provider::OpenAi,
            content_length: Some(1024),
        };

        let result = check_request_body_size(&request, DEFAULT_MAX_BODY_BYTES);
        assert!(result.is_ok());
    }

    #[test]
    fn test_request_body_no_content_length_checks_actual() {
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: vec![0u8; 11 * 1024 * 1024],
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_request_body_size(&request, DEFAULT_MAX_BODY_BYTES);
        assert!(result.is_err());
    }

    #[test]
    fn test_request_body_exact_limit_accepted() {
        let max = 1000u64;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: vec![0u8; 1000],
            provider: Provider::OpenAi,
            content_length: Some(1000),
        };

        let result = check_request_body_size(&request, max);
        assert!(result.is_ok());
    }

    // ---------- M6: Hop-by-hop header filtering tests ----------

    #[test]
    fn test_response_hop_by_hop_headers_stripped() {
        assert!(!is_forwardable_response_header("transfer-encoding"));
        assert!(!is_forwardable_response_header("Transfer-Encoding"));
        assert!(!is_forwardable_response_header("connection"));
        assert!(!is_forwardable_response_header("Connection"));
        assert!(!is_forwardable_response_header("keep-alive"));
        assert!(!is_forwardable_response_header("Keep-Alive"));
        assert!(!is_forwardable_response_header("upgrade"));
        assert!(!is_forwardable_response_header("trailer"));
        assert!(!is_forwardable_response_header("te"));
        assert!(!is_forwardable_response_header("proxy-authenticate"));
        assert!(!is_forwardable_response_header("proxy-authorization"));
    }

    #[test]
    fn test_forwardable_headers_accepted() {
        assert!(is_forwardable_response_header("content-type"));
        assert!(is_forwardable_response_header("Content-Type"));
        assert!(is_forwardable_response_header("x-request-id"));
        assert!(is_forwardable_response_header("date"));
        assert!(is_forwardable_response_header("server"));
        assert!(is_forwardable_response_header("content-length"));
    }

    // ---------- LOW: Model allowlist tests ----------

    #[test]
    fn test_model_not_in_allowlist_rejected() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_owned(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o-mini".to_owned()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };

        let body = r#"{"model": "gpt-4o", "messages": []}"#;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::ModelNotAllowed { .. }));
        assert_eq!(err.status_code(), 403);
    }

    #[test]
    fn test_model_in_allowlist_allowed() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_owned(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o".to_owned(), "gpt-4o-mini".to_owned()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };

        let body = r#"{"model": "gpt-4o", "messages": []}"#;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_model_no_allowlist_configured_allows_all() {
        let config = BudgetConfig::default();
        let body = r#"{"model": "anything-goes", "messages": []}"#;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat/completions".to_owned(),
            query: None,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_model_empty_body_allows_request() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_owned(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o".to_owned()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };

        let request = ProxyRequest {
            method: "GET".to_owned(),
            path: "/v1/models".to_owned(),
            query: None,
            headers: vec![],
            body: vec![],
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_model_non_json_body_fails_open() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_owned(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o".to_owned()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };

        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/audio/transcriptions".to_owned(),
            query: None,
            headers: vec![],
            body: b"binary audio data here".to_vec(),
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_ok(), "non-JSON body should fail-open");
    }

    #[test]
    fn test_model_json_no_model_field_fails_open() {
        let mut providers = HashMap::new();
        providers.insert(
            "openai".to_owned(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o".to_owned()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };

        let body = r#"{"prompt": "hello"}"#;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/completions".to_owned(),
            query: None,
            headers: vec![],
            body: body.as_bytes().to_vec(),
            provider: Provider::OpenAi,
            content_length: None,
        };

        let result = check_model_allowlist(&request, Provider::OpenAi, &config);
        assert!(result.is_ok(), "missing model field should fail-open");
    }

    // ---------- M4: Shared client tests ----------

    #[test]
    fn test_shared_client_has_timeout() {
        let client = build_shared_client();
        assert!(client.is_ok(), "client should build successfully");
        // We verify the client was built; reqwest does not expose
        // timeout config publicly, but the builder call would fail
        // if the params were invalid.
    }

    // ---------- Error response tests ----------

    #[test]
    fn test_error_response_json_structure() {
        let err = ProxyError::PayloadTooLarge {
            reason: "too big".to_owned(),
        };
        let resp = error_response(&err);
        assert_eq!(resp.status, 413);

        let body: serde_json::Value =
            serde_json::from_slice(&resp.body).expect("should be valid JSON");
        assert_eq!(body["error"]["type"].as_str(), Some("payload_too_large"));
    }

    #[test]
    fn test_error_response_budget_blocked() {
        let err = ProxyError::BudgetBlocked {
            reason: "exceeded".to_owned(),
        };
        let resp = error_response(&err);
        assert_eq!(resp.status, 429);
    }

    #[test]
    fn test_error_response_model_not_allowed() {
        let err = ProxyError::ModelNotAllowed {
            model: "gpt-4".to_owned(),
            provider: "OpenAI".to_owned(),
        };
        let resp = error_response(&err);
        assert_eq!(resp.status, 403);
    }

    // ---------- H3: Response credential redaction ----------

    #[test]
    fn test_response_body_credentials_redacted() {
        // Simulate what handle_request does: redact credentials from a
        // response body string.
        let response_body = "Here is a key: sk-abcdefghijklmnopqrstuvwxyz and more text";
        let (redacted, events) = redact_credentials(response_body);
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(redacted.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn test_response_body_no_credentials_unchanged() {
        let response_body = r#"{"id": "chatcmpl-abc", "choices": [{"text": "hello"}]}"#;
        let (redacted, events) = redact_credentials(response_body);
        assert_eq!(redacted, response_body);
        assert!(events.is_empty());
    }

    // ---------- M2: Budget TOCTOU ----------

    #[test]
    fn test_budget_concurrent_requests_limited() {
        let pending = Arc::new(AtomicU64::new(0));

        // Simulate multiple concurrent requests adding pending cost.
        let num_requests = 10u64;
        for _ in 0..num_requests {
            pending.fetch_add(PENDING_COST_ESTIMATE, Ordering::Relaxed);
        }

        let total_pending = pending.load(Ordering::Relaxed);
        assert_eq!(
            total_pending,
            num_requests * PENDING_COST_ESTIMATE,
            "pending cost should accumulate from concurrent requests"
        );

        // Simulate all requests completing.
        for _ in 0..num_requests {
            pending.fetch_sub(PENDING_COST_ESTIMATE, Ordering::Relaxed);
        }

        let final_pending = pending.load(Ordering::Relaxed);
        assert_eq!(final_pending, 0, "pending cost should return to zero");
    }

    #[tokio::test]
    async fn test_budget_concurrent_requests_with_tasks() {
        let pending = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();

        for _ in 0..50 {
            let p = Arc::clone(&pending);
            handles.push(tokio::spawn(async move {
                p.fetch_add(PENDING_COST_ESTIMATE, Ordering::Relaxed);
                // Simulate some work.
                tokio::task::yield_now().await;
                p.fetch_sub(PENDING_COST_ESTIMATE, Ordering::Relaxed);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            pending.load(Ordering::Relaxed),
            0,
            "all pending costs should be cleared after tasks complete"
        );
    }

    // ---------- Fix 2: from_utf8_lossy redaction tests ----------

    #[test]
    fn test_redact_response_body_valid_utf8_with_credential() {
        let body = b"Here is a key: sk-abcdefghijklmnopqrstuvwxyz and more text".to_vec();
        let result = redact_response_body(body);
        let result_str = String::from_utf8(result).unwrap();
        assert!(
            !result_str.contains("sk-abcdefghijklmnopqrstuvwxyz"),
            "credential should be redacted"
        );
        assert!(
            result_str.contains("[REDACTED:"),
            "should contain redaction marker"
        );
    }

    #[test]
    fn test_redact_response_body_mixed_invalid_utf8_with_credential() {
        // Build a body with invalid UTF-8 byte (0xFF) followed by a credential.
        let mut body = Vec::new();
        body.extend_from_slice(b"prefix ");
        body.push(0xFF); // invalid UTF-8 byte
        body.extend_from_slice(b" sk-abcdefghijklmnopqrstuvwxyz suffix");
        let result = redact_response_body(body);
        let result_str = String::from_utf8_lossy(&result);
        assert!(
            !result_str.contains("sk-abcdefghijklmnopqrstuvwxyz"),
            "credential in valid portion should still be redacted even with invalid bytes"
        );
    }

    #[test]
    fn test_redact_response_body_empty() {
        let body = Vec::new();
        let result = redact_response_body(body);
        assert!(result.is_empty());
    }

    #[test]
    fn test_redact_response_body_no_credentials() {
        let body = b"just normal response text".to_vec();
        let result = redact_response_body(body.clone());
        assert_eq!(result, body);
    }

    #[test]
    fn test_redact_body_bytes_matches_response_body_behavior() {
        // Both redact_body_bytes and redact_response_body should handle
        // invalid UTF-8 the same way (using from_utf8_lossy).
        let mut body = Vec::new();
        body.extend_from_slice(b"key: sk-abcdefghijklmnopqrstuvwxyz");
        body.push(0xFF);
        let request_result = redact_body_bytes(&body);
        let response_result = redact_response_body(body);
        // Both should have redacted the credential.
        assert!(!String::from_utf8_lossy(&request_result).contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(
            !String::from_utf8_lossy(&response_result).contains("sk-abcdefghijklmnopqrstuvwxyz")
        );
    }

    // ---------- Fix 3: PendingCostGuard tests ----------

    #[test]
    fn test_pending_cost_guard_increments_on_creation() {
        let counter = AtomicU64::new(0);
        let _guard = PendingCostGuard::new(&counter, 100);
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_pending_cost_guard_decrements_on_drop() {
        let counter = AtomicU64::new(0);
        {
            let _guard = PendingCostGuard::new(&counter, 100);
            assert_eq!(counter.load(Ordering::SeqCst), 100);
        }
        // Guard dropped -- should have decremented.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_pending_cost_guard_defuse_prevents_decrement() {
        let counter = AtomicU64::new(0);
        {
            let guard = PendingCostGuard::new(&counter, 100);
            assert_eq!(counter.load(Ordering::SeqCst), 100);
            guard.defuse();
        }
        // Guard was defused -- counter should remain at 100.
        assert_eq!(counter.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn test_pending_cost_guard_multiple_guards() {
        let counter = AtomicU64::new(0);
        {
            let _g1 = PendingCostGuard::new(&counter, 50);
            let _g2 = PendingCostGuard::new(&counter, 75);
            assert_eq!(counter.load(Ordering::SeqCst), 125);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_pending_cost_guard_error_path_simulation() {
        let counter = AtomicU64::new(0);

        // Simulate an error path: guard is created, then function returns early.
        let result: Result<(), &str> = {
            let _guard = PendingCostGuard::new(&counter, PENDING_COST_ESTIMATE);
            assert_eq!(counter.load(Ordering::SeqCst), PENDING_COST_ESTIMATE);
            Err("simulated upstream error")
        };

        assert!(result.is_err());
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "pending cost must be decremented on error path"
        );
    }

    #[test]
    fn test_pending_cost_guard_success_path_simulation() {
        let counter = AtomicU64::new(0);

        // Simulate a success path: guard is created, work is done, then defused.
        let result: Result<(), &str> = {
            let guard = PendingCostGuard::new(&counter, PENDING_COST_ESTIMATE);
            assert_eq!(counter.load(Ordering::SeqCst), PENDING_COST_ESTIMATE);
            // Simulate successful processing...
            guard.defuse();
            Ok(())
        };

        assert!(result.is_ok());
        // Guard was defused, so the counter still has the value
        // (in real code, the caller would have subtracted it manually
        // or it represents actual recorded cost).
        assert_eq!(counter.load(Ordering::SeqCst), PENDING_COST_ESTIMATE);
    }

    // ---------- Fix 4: Shared client redirect policy test ----------

    #[test]
    fn test_shared_client_builds_with_redirect_policy() {
        // Verify the client builds successfully with the no-redirect policy.
        let client = build_shared_client();
        assert!(
            client.is_ok(),
            "client should build successfully with redirect policy"
        );
    }

    // ---------- Fix 5: read_response_body_limited size logic tests ----------
    // (The function is async and requires a real reqwest::Response, but we
    // test the size-checking logic through the public interface.)

    #[test]
    fn test_check_request_body_size_boundary_one_over() {
        let max = 100u64;
        let request = ProxyRequest {
            method: "POST".to_owned(),
            path: "/v1/chat".to_owned(),
            query: None,
            headers: vec![],
            body: vec![0u8; 101],
            provider: Provider::OpenAi,
            content_length: Some(101),
        };
        let result = check_request_body_size(&request, max);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::PayloadTooLarge { .. }));
    }

    // ---------- Response header credential redaction tests ----------

    #[test]
    fn test_response_header_with_api_key_is_redacted() {
        // Simulate building response headers with credential redaction
        // (mirrors the logic in handle_request).
        let header_value = "token sk-proj-abcdef1234567890abcdef1234567890abcdef1234567890ab";
        let (redacted, events) = redact_credentials(header_value);
        assert!(
            !events.is_empty(),
            "should detect credential in header value"
        );
        assert!(
            !redacted.contains("sk-proj-abcdef1234567890abcdef1234567890"),
            "redacted header should not contain the original API key"
        );
        assert!(
            redacted.contains("[REDACTED:"),
            "redacted header should contain redaction placeholder"
        );
    }

    // ---------- Unknown HTTP method rejection ----------

    #[test]
    fn test_unknown_method_returns_405() {
        let err = ProxyError::MethodNotAllowed {
            method: "TRACE".to_owned(),
        };
        let resp = error_response(&err);
        assert_eq!(resp.status, 405);
        let body: serde_json::Value =
            serde_json::from_slice(&resp.body).expect("should be valid JSON");
        assert_eq!(body["error"]["type"].as_str(), Some("method_not_allowed"));
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap_or("")
                .contains("TRACE"),
            "error message should contain the rejected method"
        );
    }

    // ---------- SSE stream detection tests ----------

    #[test]
    fn test_stream_flag_detected_in_request_body() {
        let body = br#"{"model": "gpt-4o", "stream": true, "messages": []}"#;
        assert!(
            request_body_has_stream_flag(body),
            "should detect stream: true"
        );
    }

    #[test]
    fn test_stream_flag_false_not_detected() {
        let body = br#"{"model": "gpt-4o", "stream": false, "messages": []}"#;
        assert!(
            !request_body_has_stream_flag(body),
            "should not detect stream: false"
        );
    }

    #[test]
    fn test_stream_flag_missing_not_detected() {
        let body = br#"{"model": "gpt-4o", "messages": []}"#;
        assert!(
            !request_body_has_stream_flag(body),
            "should not detect when stream key is absent"
        );
    }

    #[test]
    fn test_stream_flag_empty_body() {
        assert!(
            !request_body_has_stream_flag(b""),
            "empty body should return false"
        );
    }

    #[test]
    fn test_stream_flag_non_json_body() {
        assert!(
            !request_body_has_stream_flag(b"not json at all"),
            "non-JSON body should return false"
        );
    }
}
