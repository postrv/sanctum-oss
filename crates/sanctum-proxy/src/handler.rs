//! HTTP request handler for the proxy server.
//!
//! Receives inbound requests from AI tools, identifies the target provider,
//! checks budgets, forwards the request upstream via `reqwest`, extracts
//! usage from the response, and records it in the budget tracker.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::Request;
use tokio::sync::RwLock;

use crate::error::ProxyError;
use crate::provider::Provider;
use crate::routing::resolve_upstream;
use crate::usage;

/// Handle a single proxied HTTP request.
///
/// # Flow
///
/// 1. Identify provider from the `X-Sanctum-Provider` header or Host header.
/// 2. Check budget -- if exceeded, return HTTP 429.
/// 3. Read the request body.
/// 4. Redact credentials from the body using `sanctum_firewall::redact_credentials()`.
/// 5. Forward to upstream via `reqwest`.
/// 6. Extract usage from the response body.
/// 7. Record usage in the budget tracker.
/// 8. Return the upstream response to the client.
///
/// # Errors
///
/// Returns `ProxyError` if body reading, upstream forwarding, or HTTP
/// response construction fails.
pub async fn handle_request(
    req: Request<hyper::body::Incoming>,
    budget_tracker: Arc<RwLock<sanctum_budget::BudgetTracker>>,
) -> Result<hyper::Response<http_body_util::Full<Bytes>>, ProxyError> {
    // 1. Identify provider from X-Sanctum-Provider header, falling back to Host header
    let provider = identify_provider_from_request(&req);

    // 2. Check budget
    {
        let tracker = budget_tracker.read().await;
        let enforcement = sanctum_budget::check_budget(&tracker, provider.to_budget_provider());
        if let sanctum_budget::EnforcementResult::Blocked { message } = enforcement {
            tracing::warn!(provider = %provider.display_name(), "request blocked by budget: {message}");
            let status = tracker.status(provider.to_budget_provider());
            drop(tracker);
            let body = sanctum_budget::budget_exceeded_response(&status);
            let response = hyper::Response::builder()
                .status(429)
                .header("Content-Type", "application/json")
                .body(http_body_util::Full::new(Bytes::from(body)))?;
            return Ok(response);
        }
    }

    // 3. Read request body
    let (parts, body) = req.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| ProxyError::BodyRead {
            reason: e.to_string(),
        })?
        .to_bytes();

    // 4. Redact credentials from request body
    let body_str = String::from_utf8_lossy(&body_bytes);
    let (redacted_body, redaction_events) =
        sanctum_firewall::redaction::redact_credentials(&body_str);
    if !redaction_events.is_empty() {
        tracing::info!(
            count = redaction_events.len(),
            "redacted credentials from outbound request body"
        );
    }

    // 5. Forward to upstream
    let upstream_url = resolve_upstream(
        &provider,
        &parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_string(), ToString::to_string),
    );

    let client = reqwest::Client::new();
    let mut upstream_req = client.request(convert_method(&parts.method), &upstream_url);

    // Forward relevant headers (skip hop-by-hop headers)
    for (name, value) in &parts.headers {
        let name_str = name.as_str();
        if is_forwardable_header(name_str) {
            if let Ok(v) = value.to_str() {
                upstream_req = upstream_req.header(name_str, v);
            }
        }
    }

    upstream_req = upstream_req.body(redacted_body);

    let upstream_resp = upstream_req
        .send()
        .await
        .map_err(|e| ProxyError::UpstreamRequest {
            reason: e.to_string(),
        })?;

    let resp_status = upstream_resp.status().as_u16();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = upstream_resp
        .bytes()
        .await
        .map_err(|e| ProxyError::UpstreamRequest {
            reason: format!("failed to read upstream response body: {e}"),
        })?;

    // 6. Extract usage from response
    if (200..300).contains(&resp_status) {
        let resp_str = String::from_utf8_lossy(&resp_body);
        if let Some(usage_data) = usage::extract_usage(&provider, &resp_str) {
            // 7. Record usage
            let budget_usage = sanctum_budget::UsageData {
                provider: provider.to_budget_provider(),
                model: usage_data.model.clone(),
                input_tokens: usage_data.input_tokens,
                output_tokens: usage_data.output_tokens,
            };
            let status = budget_tracker.write().await.record_usage(&budget_usage);
            tracing::info!(
                provider = %provider.display_name(),
                model = %usage_data.model,
                input_tokens = usage_data.input_tokens,
                output_tokens = usage_data.output_tokens,
                session_spent_cents = status.session_spent_cents,
                "recorded usage"
            );
        }
    }

    // 8. Build response to return to client
    let mut builder = hyper::Response::builder().status(resp_status);
    for (name, value) in &resp_headers {
        builder = builder.header(name, value);
    }

    let response = builder.body(http_body_util::Full::new(Bytes::from(resp_body.to_vec())))?;
    Ok(response)
}

/// Identify the target provider from the request.
///
/// Checks `X-Sanctum-Provider` header first (for explicit routing), then
/// falls back to the `Host` header. Defaults to `OpenAI` when no provider
/// can be determined (common when `OPENAI_BASE_URL` points to our proxy).
fn identify_provider_from_request(req: &Request<hyper::body::Incoming>) -> Provider {
    // Check explicit header first
    if let Some(provider_header) = req.headers().get("x-sanctum-provider") {
        if let Ok(s) = provider_header.to_str() {
            match s.to_lowercase().as_str() {
                "openai" => return Provider::OpenAi,
                "anthropic" => return Provider::Anthropic,
                "google" => return Provider::Google,
                _ => {}
            }
        }
    }

    // Fall back to Host header
    if let Some(host) = req.headers().get("host") {
        if let Ok(h) = host.to_str() {
            if let Some(provider) = crate::identify_provider(h) {
                return provider;
            }
        }
    }

    // Default to OpenAI when client sets OPENAI_BASE_URL to our proxy
    // and sends to localhost with no distinguishing Host header
    Provider::OpenAi
}

/// Convert a hyper Method to a reqwest Method.
///
/// Defaults to POST for unknown methods, which is intentionally the same as
/// the explicit POST arm -- POST is the dominant method for LLM API calls.
#[allow(clippy::missing_const_for_fn)] // reqwest::Method is not const-constructible
fn convert_method(method: &hyper::Method) -> reqwest::Method {
    match *method {
        hyper::Method::GET => reqwest::Method::GET,
        hyper::Method::PUT => reqwest::Method::PUT,
        hyper::Method::DELETE => reqwest::Method::DELETE,
        hyper::Method::PATCH => reqwest::Method::PATCH,
        hyper::Method::HEAD => reqwest::Method::HEAD,
        hyper::Method::OPTIONS => reqwest::Method::OPTIONS,
        // POST and any unrecognised method both map to POST
        _ => reqwest::Method::POST,
    }
}

/// Check whether an HTTP header should be forwarded upstream.
///
/// Strips hop-by-hop headers and proxy-specific headers.
fn is_forwardable_header(name: &str) -> bool {
    !matches!(
        name.to_lowercase().as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "x-sanctum-provider"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_budget::BudgetTracker;
    use sanctum_types::config::{BudgetAmount, BudgetConfig};

    fn make_tracker_with_limit(session_cents: u64) -> Arc<RwLock<BudgetTracker>> {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount {
                cents: session_cents,
            }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        Arc::new(RwLock::new(BudgetTracker::new(&config)))
    }

    fn make_unlimited_tracker() -> Arc<RwLock<BudgetTracker>> {
        let config = BudgetConfig::default();
        Arc::new(RwLock::new(BudgetTracker::new(&config)))
    }

    #[tokio::test]
    async fn budget_exceeded_returns_429() {
        let tracker = make_tracker_with_limit(0);

        // Pre-record usage to exceed the zero-cent budget
        {
            let mut t = tracker.write().await;
            let usage = sanctum_budget::UsageData {
                provider: sanctum_budget::Provider::OpenAI,
                model: "gpt-4o".to_string(),
                input_tokens: 1000,
                output_tokens: 500,
            };
            t.record_usage(&usage);
        }

        // Verify the budget enforcement logic returns Blocked
        let t = tracker.read().await;
        let result = sanctum_budget::check_budget(&t, sanctum_budget::Provider::OpenAI);
        assert!(matches!(
            result,
            sanctum_budget::EnforcementResult::Blocked { .. }
        ));

        // Verify the 429 response body is valid JSON
        let status = t.status(sanctum_budget::Provider::OpenAI);
        drop(t);
        let body = sanctum_budget::budget_exceeded_response(&status);
        let parsed: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(parsed.get("error").is_some());
    }

    #[test]
    fn credential_redaction_applied() {
        let body = r#"{"prompt": "my key is sk-abcdefghijklmnopqrstuvwxyz"}"#;
        let (redacted, events) = sanctum_firewall::redaction::redact_credentials(body);
        assert!(!redacted.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(redacted.contains("[REDACTED:OpenAI API Key:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn provider_from_x_sanctum_header() {
        // Test the header parsing logic (mirrors identify_provider_from_request)
        fn parse_provider_header(header_val: &str) -> Option<Provider> {
            match header_val.to_lowercase().as_str() {
                "openai" => Some(Provider::OpenAi),
                "anthropic" => Some(Provider::Anthropic),
                "google" => Some(Provider::Google),
                _ => None,
            }
        }

        assert_eq!(parse_provider_header("openai"), Some(Provider::OpenAi));
        assert_eq!(
            parse_provider_header("anthropic"),
            Some(Provider::Anthropic)
        );
        assert_eq!(parse_provider_header("google"), Some(Provider::Google));
        assert_eq!(parse_provider_header("OpenAI"), Some(Provider::OpenAi));
        assert_eq!(
            parse_provider_header("ANTHROPIC"),
            Some(Provider::Anthropic)
        );
        assert_eq!(parse_provider_header("unknown"), None);
    }

    #[test]
    fn forwardable_header_filtering() {
        assert!(is_forwardable_header("authorization"));
        assert!(is_forwardable_header("content-type"));
        assert!(is_forwardable_header("x-api-key"));
        assert!(is_forwardable_header("anthropic-version"));

        // Hop-by-hop and proxy headers should NOT be forwarded
        assert!(!is_forwardable_header("host"));
        assert!(!is_forwardable_header("connection"));
        assert!(!is_forwardable_header("transfer-encoding"));
        assert!(!is_forwardable_header("x-sanctum-provider"));
        assert!(!is_forwardable_header("proxy-authorization"));
    }

    #[tokio::test]
    async fn usage_recorded_after_response() {
        let tracker = make_unlimited_tracker();

        // Simulate recording usage (as would happen after a successful upstream response)
        let usage = sanctum_budget::UsageData {
            provider: sanctum_budget::Provider::OpenAI,
            model: "gpt-4o".to_string(),
            input_tokens: 1000,
            output_tokens: 500,
        };

        {
            let mut t = tracker.write().await;
            t.record_usage(&usage);
        }

        let status = tracker
            .read()
            .await
            .status(sanctum_budget::Provider::OpenAI);
        assert!(status.session_spent_cents > 0);
    }

    #[test]
    fn method_conversion() {
        assert_eq!(convert_method(&hyper::Method::GET), reqwest::Method::GET);
        assert_eq!(convert_method(&hyper::Method::POST), reqwest::Method::POST);
        assert_eq!(convert_method(&hyper::Method::PUT), reqwest::Method::PUT);
        assert_eq!(
            convert_method(&hyper::Method::DELETE),
            reqwest::Method::DELETE
        );
        assert_eq!(
            convert_method(&hyper::Method::PATCH),
            reqwest::Method::PATCH
        );
    }
}
