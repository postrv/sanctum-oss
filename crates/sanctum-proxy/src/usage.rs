//! Usage extraction and budget recording from upstream responses.
//!
//! After forwarding a request to the upstream LLM API, this module parses
//! the response body to extract token usage data and records it in the
//! budget tracker.

use sanctum_budget::{parse_usage, BudgetTracker, UsageData};
use tracing::warn;

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

/// Record usage data in the budget tracker if extraction succeeds.
///
/// Returns the extracted `UsageData` if successful, `None` otherwise.
pub fn record_if_available(tracker: &mut BudgetTracker, body: &str) -> Option<UsageData> {
    let data = extract_usage(body)?;
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
    Some(data)
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
}
