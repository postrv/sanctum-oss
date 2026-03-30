//! Usage extraction and budget recording from upstream responses.
//!
//! After forwarding a request to the upstream LLM API, this module parses
//! the response body to extract token usage data and records it in the
//! budget tracker. Supports both standard JSON responses and SSE streaming
//! responses.

use sanctum_budget::{parse_usage, BudgetTracker, UsageData};
use tracing::warn;

use crate::sse;

/// Attempt to extract usage data from an upstream response body.
///
/// Returns `None` if the body cannot be parsed (e.g., non-JSON or
/// missing usage fields). Failures are logged but not propagated,
/// because failing to extract usage should not break the proxy.
#[must_use]
pub fn extract_usage(body: &str) -> Option<UsageData> {
    match parse_usage(body) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!(error = %e, "failed to extract usage from upstream response");
            None
        }
    }
}

/// Extract usage data from an SSE streaming response body.
///
/// Parses the SSE event stream, then tries provider-specific extraction
/// (Anthropic, Google, `OpenAI`) to find token usage data.
///
/// Returns `None` if no usage data can be found (e.g., provider did not
/// include usage in the stream, or the stream is malformed).
#[must_use]
pub fn extract_usage_from_sse(body: &str) -> Option<UsageData> {
    let events = sse::parse_sse_events(body);
    if events.is_empty() {
        return None;
    }
    sse::extract_usage_from_events(&events)
}

/// Record usage data in the budget tracker if extraction succeeds.
///
/// Returns the extracted `UsageData` if successful, `None` otherwise.
pub fn record_if_available(tracker: &mut BudgetTracker, body: &str) -> Option<UsageData> {
    let data = extract_usage(body)?;
    Some(record_usage(tracker, data))
}

/// Record usage from an SSE streaming response in the budget tracker.
///
/// Returns the extracted `UsageData` if successful, `None` otherwise.
pub fn record_sse_if_available(tracker: &mut BudgetTracker, body: &str) -> Option<UsageData> {
    let data = extract_usage_from_sse(body)?;
    Some(record_usage(tracker, data))
}

/// Log and record a `UsageData` in the budget tracker.
fn record_usage(tracker: &mut BudgetTracker, data: UsageData) -> UsageData {
    let status = tracker.record_usage(&data);
    tracing::info!(
        provider = %data.provider,
        model = %data.model,
        input_tokens = data.input_tokens,
        output_tokens = data.output_tokens,
        session_spent = status.session_spent_cents,
        daily_spent = status.daily_spent_cents,
        "recorded usage"
    );
    data
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use sanctum_budget::Provider;
    use sanctum_types::config::{BudgetAmount, BudgetConfig};

    fn test_config() -> BudgetConfig {
        BudgetConfig {
            default_session: Some(BudgetAmount { cents: 50_000 }),
            default_daily: Some(BudgetAmount { cents: 200_000 }),
            alert_at_percent: 75,
            ..BudgetConfig::default()
        }
    }

    #[test]
    fn extract_usage_from_openai_response() {
        let body = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            },
            "choices": []
        }"#;
        let data = extract_usage(body);
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.provider, Provider::OpenAI);
        assert_eq!(data.input_tokens, 100);
        assert_eq!(data.output_tokens, 50);
    }

    #[test]
    fn extract_usage_from_invalid_json_returns_none() {
        let data = extract_usage("not json");
        assert!(data.is_none());
    }

    #[test]
    fn extract_usage_from_non_llm_response_returns_none() {
        let data = extract_usage(r#"{"status": "ok"}"#);
        assert!(data.is_none());
    }

    #[test]
    fn record_if_available_updates_tracker() {
        let mut tracker = BudgetTracker::new(&test_config());
        let body = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 1000000,
                "completion_tokens": 500000,
                "total_tokens": 1500000
            },
            "choices": []
        }"#;

        let before = tracker.status(Provider::OpenAI).session_spent_cents;
        let result = record_if_available(&mut tracker, body);
        assert!(result.is_some());
        let after = tracker.status(Provider::OpenAI).session_spent_cents;
        assert!(
            after > before,
            "spend should increase after recording usage"
        );
    }

    #[test]
    fn record_if_available_with_bad_json_returns_none() {
        let mut tracker = BudgetTracker::new(&test_config());
        let result = record_if_available(&mut tracker, "garbage");
        assert!(result.is_none());
    }

    // ---- SSE usage extraction tests ----

    #[test]
    fn extract_sse_openai_streaming() {
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}],\"usage\":null}\n\n",
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":500,\"completion_tokens\":200,\"total_tokens\":700}}\n\n",
            "data: [DONE]\n\n"
        );
        let data = extract_usage_from_sse(body);
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.provider, Provider::OpenAI);
        assert_eq!(data.input_tokens, 500);
        assert_eq!(data.output_tokens, 200);
    }

    #[test]
    fn extract_sse_anthropic_streaming() {
        let body = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-sonnet-4-6-20260320\",\"usage\":{\"input_tokens\":1000,\"output_tokens\":0}}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":500}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );
        let data = extract_usage_from_sse(body);
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.provider, Provider::Anthropic);
        assert_eq!(data.input_tokens, 1000);
        assert_eq!(data.output_tokens, 500);
    }

    #[test]
    fn extract_sse_google_streaming() {
        let body = "data: {\"modelVersion\":\"gemini-2.5-pro\",\"candidates\":[],\"usageMetadata\":{\"promptTokenCount\":800,\"candidatesTokenCount\":400}}\n\n";
        let data = extract_usage_from_sse(body);
        assert!(data.is_some());
        let data = data.unwrap();
        assert_eq!(data.provider, Provider::Google);
        assert_eq!(data.input_tokens, 800);
        assert_eq!(data.output_tokens, 400);
    }

    #[test]
    fn extract_sse_empty_body_returns_none() {
        assert!(extract_usage_from_sse("").is_none());
    }

    #[test]
    fn extract_sse_non_sse_body_returns_none() {
        // Plain JSON (not SSE) fed to SSE extractor should return None
        assert!(extract_usage_from_sse(r#"{"model":"gpt-4o"}"#).is_none());
    }

    #[test]
    fn record_sse_if_available_updates_tracker() {
        let mut tracker = BudgetTracker::new(&test_config());
        let body = concat!(
            "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":1000000,\"completion_tokens\":500000,\"total_tokens\":1500000}}\n\n",
            "data: [DONE]\n\n"
        );
        let before = tracker.status(Provider::OpenAI).session_spent_cents;
        let result = record_sse_if_available(&mut tracker, body);
        assert!(result.is_some());
        let after = tracker.status(Provider::OpenAI).session_spent_cents;
        assert!(
            after > before,
            "spend should increase after recording SSE usage"
        );
    }

    #[test]
    fn record_sse_if_available_with_no_usage_returns_none() {
        let mut tracker = BudgetTracker::new(&test_config());
        let body = "data: {\"model\":\"gpt-4o\",\"choices\":[],\"usage\":null}\n\ndata: [DONE]\n\n";
        let result = record_sse_if_available(&mut tracker, body);
        assert!(result.is_none());
    }
}
