//! `OpenAI` API response parser.

use crate::error::BudgetError;
use crate::parser::UsageData;
use crate::provider::Provider;

/// Parse token usage from an `OpenAI` chat completion response.
///
/// Expected structure:
/// ```json
/// {
///   "model": "gpt-4o-2024-05-13",
///   "usage": {
///     "prompt_tokens": 100,
///     "completion_tokens": 50
///   }
/// }
/// ```
pub(super) fn parse_openai(value: &serde_json::Value) -> Result<UsageData, BudgetError> {
    let model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| BudgetError::ParseError("missing 'model' field in OpenAI response".into()))?
        .to_string();

    let usage = value.get("usage").ok_or_else(|| {
        BudgetError::ParseError("missing 'usage' field in OpenAI response".into())
    })?;

    let input_tokens = usage
        .get("prompt_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'usage.prompt_tokens' in OpenAI response".into())
        })?;

    let output_tokens = usage
        .get("completion_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'usage.completion_tokens' in OpenAI response".into())
        })?;

    Ok(UsageData {
        provider: Provider::OpenAI,
        model,
        input_tokens,
        output_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_openai_response() {
        let json = serde_json::json!({
            "id": "chatcmpl-abc123",
            "object": "chat.completion",
            "model": "gpt-4o-2024-05-13",
            "usage": {
                "prompt_tokens": 1500,
                "completion_tokens": 800,
                "total_tokens": 2300
            },
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello!"
                },
                "finish_reason": "stop"
            }]
        });

        let result = parse_openai(&json);
        assert!(result.is_ok());
        let Ok(data) = result else { return };
        assert_eq!(data.provider, Provider::OpenAI);
        assert_eq!(data.model, "gpt-4o-2024-05-13");
        assert_eq!(data.input_tokens, 1500);
        assert_eq!(data.output_tokens, 800);
    }

    #[test]
    fn missing_model_field() {
        let json = serde_json::json!({
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50
            }
        });
        assert!(parse_openai(&json).is_err());
    }

    #[test]
    fn missing_usage_field() {
        let json = serde_json::json!({
            "model": "gpt-4o"
        });
        assert!(parse_openai(&json).is_err());
    }

    #[test]
    fn missing_prompt_tokens() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "usage": {
                "completion_tokens": 50
            }
        });
        assert!(parse_openai(&json).is_err());
    }

    #[test]
    fn missing_completion_tokens() {
        let json = serde_json::json!({
            "model": "gpt-4o",
            "usage": {
                "prompt_tokens": 100
            }
        });
        assert!(parse_openai(&json).is_err());
    }
}
