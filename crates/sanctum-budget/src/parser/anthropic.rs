//! Anthropic API response parser.

use crate::error::BudgetError;
use crate::parser::UsageData;
use crate::provider::Provider;

/// Parse token usage from an Anthropic messages API response.
///
/// Expected structure:
/// ```json
/// {
///   "type": "message",
///   "model": "claude-sonnet-4-6-20260320",
///   "usage": {
///     "input_tokens": 200,
///     "output_tokens": 100
///   }
/// }
/// ```
pub(super) fn parse_anthropic(value: &serde_json::Value) -> Result<UsageData, BudgetError> {
    let model = value
        .get("model")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'model' field in Anthropic response".into())
        })?
        .to_string();

    let usage = value.get("usage").ok_or_else(|| {
        BudgetError::ParseError("missing 'usage' field in Anthropic response".into())
    })?;

    let input_tokens = usage
        .get("input_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'usage.input_tokens' in Anthropic response".into())
        })?;

    let output_tokens = usage
        .get("output_tokens")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'usage.output_tokens' in Anthropic response".into())
        })?;

    Ok(UsageData {
        provider: Provider::Anthropic,
        model,
        input_tokens,
        output_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_anthropic_response() {
        let json = serde_json::json!({
            "id": "msg_abc123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-6-20260320",
            "content": [{
                "type": "text",
                "text": "Hello!"
            }],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 2048,
                "output_tokens": 512
            }
        });

        let result = parse_anthropic(&json);
        assert!(result.is_ok());
        let Ok(data) = result else { return };
        assert_eq!(data.provider, Provider::Anthropic);
        assert_eq!(data.model, "claude-sonnet-4-6-20260320");
        assert_eq!(data.input_tokens, 2048);
        assert_eq!(data.output_tokens, 512);
    }

    #[test]
    fn missing_model_field() {
        let json = serde_json::json!({
            "type": "message",
            "usage": {
                "input_tokens": 100,
                "output_tokens": 50
            }
        });
        assert!(parse_anthropic(&json).is_err());
    }

    #[test]
    fn missing_usage_field() {
        let json = serde_json::json!({
            "type": "message",
            "model": "claude-sonnet-4-6-20260320"
        });
        assert!(parse_anthropic(&json).is_err());
    }

    #[test]
    fn missing_input_tokens() {
        let json = serde_json::json!({
            "type": "message",
            "model": "claude-sonnet-4-6-20260320",
            "usage": {
                "output_tokens": 50
            }
        });
        assert!(parse_anthropic(&json).is_err());
    }

    #[test]
    fn missing_output_tokens() {
        let json = serde_json::json!({
            "type": "message",
            "model": "claude-sonnet-4-6-20260320",
            "usage": {
                "input_tokens": 100
            }
        });
        assert!(parse_anthropic(&json).is_err());
    }
}
