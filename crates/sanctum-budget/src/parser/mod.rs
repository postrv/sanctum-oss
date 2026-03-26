//! API response parsers for extracting token usage data.
//!
//! Supports auto-detection of provider from response JSON structure,
//! as well as explicit per-provider parsing.

mod anthropic;
mod google;
mod openai;

use crate::error::BudgetError;
use crate::provider::Provider;

/// Extracted token usage data from an LLM API response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageData {
    /// The provider that served the request.
    pub provider: Provider,
    /// The model identifier from the response.
    pub model: String,
    /// Number of input (prompt) tokens consumed.
    pub input_tokens: u64,
    /// Number of output (completion) tokens consumed.
    pub output_tokens: u64,
}

/// Parse token usage from an API response body, auto-detecting the provider.
///
/// Detection heuristics:
/// - Anthropic responses contain a top-level `"type"` field alongside `"usage"`.
/// - Google responses contain a top-level `"usageMetadata"` field.
/// - Everything else is assumed to be `OpenAI` format.
///
/// # Errors
///
/// Returns `BudgetError::ParseError` if the JSON is malformed or missing
/// required usage fields.
pub fn parse_usage(body: &str) -> Result<UsageData, BudgetError> {
    let value: serde_json::Value =
        serde_json::from_str(body).map_err(|e| BudgetError::ParseError(e.to_string()))?;

    let obj = value
        .as_object()
        .ok_or_else(|| BudgetError::ParseError("response is not a JSON object".to_string()))?;

    // Anthropic responses have a "type" field at the top level alongside "usage"
    if obj.contains_key("type") && obj.contains_key("usage") {
        return anthropic::parse_anthropic(&value);
    }

    // Google responses have a "usageMetadata" field
    if obj.contains_key("usageMetadata") {
        return google::parse_google(&value);
    }

    // Default to OpenAI format
    openai::parse_openai(&value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detect_openai() {
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

        let usage = parse_usage(body);
        assert!(usage.is_ok());
        let data = match usage {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(data.provider, Provider::OpenAI);
        assert_eq!(data.input_tokens, 100);
        assert_eq!(data.output_tokens, 50);
    }

    #[test]
    fn auto_detect_anthropic() {
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

        let usage = parse_usage(body);
        assert!(usage.is_ok());
        let data = match usage {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(data.provider, Provider::Anthropic);
        assert_eq!(data.input_tokens, 200);
        assert_eq!(data.output_tokens, 100);
    }

    #[test]
    fn auto_detect_google() {
        let body = r#"{
            "candidates": [],
            "usageMetadata": {
                "promptTokenCount": 300,
                "candidatesTokenCount": 150,
                "totalTokenCount": 450
            },
            "modelVersion": "gemini-2.5-pro-preview-03-25"
        }"#;

        let usage = parse_usage(body);
        assert!(usage.is_ok());
        let data = match usage {
            Ok(d) => d,
            Err(_) => return,
        };
        assert_eq!(data.provider, Provider::Google);
        assert_eq!(data.input_tokens, 300);
        assert_eq!(data.output_tokens, 150);
    }

    #[test]
    fn invalid_json_returns_parse_error() {
        let result = parse_usage("not json at all");
        assert!(result.is_err());
        assert!(matches!(result, Err(BudgetError::ParseError(_))));
    }

    #[test]
    fn non_object_json_returns_parse_error() {
        let result = parse_usage("[1, 2, 3]");
        assert!(result.is_err());
        assert!(matches!(result, Err(BudgetError::ParseError(_))));
    }
}
