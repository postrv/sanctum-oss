//! Usage extraction from LLM API response bodies.
//!
//! Parses JSON responses to extract token usage, which is then fed into the
//! budget tracker. Each provider uses a slightly different schema for reporting
//! usage in responses.

use crate::provider::Provider;

/// Extracted usage data from an API response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageData {
    /// The provider name string (e.g. "openai", "anthropic", "google").
    pub provider: String,
    /// The model identifier from the response.
    pub model: String,
    /// Number of input (prompt) tokens.
    pub input_tokens: u64,
    /// Number of output (completion) tokens.
    pub output_tokens: u64,
}

/// Extract token usage from an API response body.
///
/// Returns `None` if the body cannot be parsed or does not contain usage
/// information. This is intentionally lenient -- streaming intermediate
/// chunks and non-JSON responses simply return `None`.
#[must_use]
pub fn extract_usage(provider: &Provider, body: &str) -> Option<UsageData> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let obj = value.as_object()?;

    match provider {
        Provider::OpenAi => extract_openai(obj),
        Provider::Anthropic => extract_anthropic(obj),
        Provider::Google => extract_google(obj),
    }
}

/// Extract usage from an OpenAI-format response.
///
/// Expected structure:
/// ```json
/// { "model": "gpt-4o", "usage": { "prompt_tokens": N, "completion_tokens": N } }
/// ```
fn extract_openai(obj: &serde_json::Map<String, serde_json::Value>) -> Option<UsageData> {
    let usage = obj.get("usage")?.as_object()?;
    let model = obj
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    let input_tokens = usage
        .get("prompt_tokens")
        .and_then(serde_json::Value::as_u64)?;
    let output_tokens = usage
        .get("completion_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Some(UsageData {
        provider: "openai".to_string(),
        model: model.to_string(),
        input_tokens,
        output_tokens,
    })
}

/// Extract usage from an Anthropic-format response.
///
/// Expected structure:
/// ```json
/// { "model": "claude-...", "usage": { "input_tokens": N, "output_tokens": N } }
/// ```
fn extract_anthropic(obj: &serde_json::Map<String, serde_json::Value>) -> Option<UsageData> {
    let usage = obj.get("usage")?.as_object()?;
    let model = obj
        .get("model")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)?;
    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Some(UsageData {
        provider: "anthropic".to_string(),
        model: model.to_string(),
        input_tokens,
        output_tokens,
    })
}

/// Extract usage from a Google-format response.
///
/// Expected structure:
/// ```json
/// { "modelVersion": "gemini-...", "usageMetadata": { "promptTokenCount": N, "candidatesTokenCount": N } }
/// ```
fn extract_google(obj: &serde_json::Map<String, serde_json::Value>) -> Option<UsageData> {
    let usage_meta = obj.get("usageMetadata")?.as_object()?;
    let model = obj
        .get("modelVersion")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    let input_tokens = usage_meta
        .get("promptTokenCount")
        .and_then(serde_json::Value::as_u64)?;
    let output_tokens = usage_meta
        .get("candidatesTokenCount")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);

    Some(UsageData {
        provider: "google".to_string(),
        model: model.to_string(),
        input_tokens,
        output_tokens,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_openai_response() {
        let body = r#"{
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o-2024-05-13",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            },
            "choices": []
        }"#;

        let usage = extract_usage(&Provider::OpenAi, body).unwrap();
        assert_eq!(usage.provider, "openai");
        assert_eq!(usage.model, "gpt-4o-2024-05-13");
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 50);
    }

    #[test]
    fn parse_anthropic_response() {
        let body = r#"{
            "id": "msg_abc123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-6-20260320",
            "usage": {
                "input_tokens": 200,
                "output_tokens": 100
            },
            "content": []
        }"#;

        let usage = extract_usage(&Provider::Anthropic, body).unwrap();
        assert_eq!(usage.provider, "anthropic");
        assert_eq!(usage.model, "claude-sonnet-4-6-20260320");
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 100);
    }

    #[test]
    fn parse_google_response() {
        let body = r#"{
            "candidates": [],
            "usageMetadata": {
                "promptTokenCount": 300,
                "candidatesTokenCount": 150,
                "totalTokenCount": 450
            },
            "modelVersion": "gemini-2.5-pro-preview-03-25"
        }"#;

        let usage = extract_usage(&Provider::Google, body).unwrap();
        assert_eq!(usage.provider, "google");
        assert_eq!(usage.model, "gemini-2.5-pro-preview-03-25");
        assert_eq!(usage.input_tokens, 300);
        assert_eq!(usage.output_tokens, 150);
    }

    #[test]
    fn missing_usage_field_returns_none() {
        let body = r#"{
            "id": "chatcmpl-abc123",
            "model": "gpt-4o",
            "choices": []
        }"#;

        let usage = extract_usage(&Provider::OpenAi, body);
        assert!(usage.is_none());
    }

    #[test]
    fn malformed_json_returns_none() {
        let body = "this is not valid json {{{";
        let usage = extract_usage(&Provider::OpenAi, body);
        assert!(usage.is_none());
    }

    #[test]
    fn empty_body_returns_none() {
        let usage = extract_usage(&Provider::OpenAi, "");
        assert!(usage.is_none());
    }

    #[test]
    fn streaming_final_chunk_with_usage() {
        // OpenAI streaming responses include usage in the final chunk
        let body = r#"{
            "id": "chatcmpl-stream",
            "object": "chat.completion.chunk",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 500,
                "completion_tokens": 200,
                "total_tokens": 700
            },
            "choices": []
        }"#;

        let usage = extract_usage(&Provider::OpenAi, body).unwrap();
        assert_eq!(usage.input_tokens, 500);
        assert_eq!(usage.output_tokens, 200);
    }

    #[test]
    fn missing_completion_tokens_defaults_to_zero() {
        // Some responses may omit completion_tokens if none were generated
        let body = r#"{
            "id": "chatcmpl-abc",
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 42
            }
        }"#;

        let usage = extract_usage(&Provider::OpenAi, body).unwrap();
        assert_eq!(usage.input_tokens, 42);
        assert_eq!(usage.output_tokens, 0);
    }

    #[test]
    fn missing_model_field_defaults_to_unknown() {
        let body = r#"{
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5
            }
        }"#;

        let usage = extract_usage(&Provider::OpenAi, body).unwrap();
        assert_eq!(usage.model, "unknown");
    }

    #[test]
    fn json_array_returns_none() {
        let body = "[1, 2, 3]";
        let usage = extract_usage(&Provider::OpenAi, body);
        assert!(usage.is_none());
    }

    #[test]
    fn google_missing_candidates_token_count_defaults_to_zero() {
        let body = r#"{
            "candidates": [],
            "usageMetadata": {
                "promptTokenCount": 100
            },
            "modelVersion": "gemini-2.5-pro"
        }"#;

        let usage = extract_usage(&Provider::Google, body).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 0);
    }
}
