//! Google Gemini API response parser.

use crate::error::BudgetError;
use crate::parser::UsageData;
use crate::provider::Provider;

/// Parse token usage from a Google Gemini API response.
///
/// Expected structure:
/// ```json
/// {
///   "modelVersion": "gemini-2.5-pro-preview-03-25",
///   "usageMetadata": {
///     "promptTokenCount": 300,
///     "candidatesTokenCount": 150
///   }
/// }
/// ```
pub(super) fn parse_google(value: &serde_json::Value) -> Result<UsageData, BudgetError> {
    let model = value
        .get("modelVersion")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            BudgetError::ParseError("missing 'modelVersion' field in Google response".into())
        })?
        .to_string();

    let usage_metadata = value.get("usageMetadata").ok_or_else(|| {
        BudgetError::ParseError("missing 'usageMetadata' field in Google response".into())
    })?;

    let input_tokens = usage_metadata
        .get("promptTokenCount")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError(
                "missing 'usageMetadata.promptTokenCount' in Google response".into(),
            )
        })?;

    let output_tokens = usage_metadata
        .get("candidatesTokenCount")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            BudgetError::ParseError(
                "missing 'usageMetadata.candidatesTokenCount' in Google response".into(),
            )
        })?;

    Ok(UsageData {
        provider: Provider::Google,
        model,
        input_tokens,
        output_tokens,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_google_response() {
        let json = serde_json::json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello!"}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 4096,
                "candidatesTokenCount": 1024,
                "totalTokenCount": 5120
            },
            "modelVersion": "gemini-2.5-pro-preview-03-25"
        });

        let result = parse_google(&json);
        assert!(result.is_ok());
        let Ok(data) = result else { return };
        assert_eq!(data.provider, Provider::Google);
        assert_eq!(data.model, "gemini-2.5-pro-preview-03-25");
        assert_eq!(data.input_tokens, 4096);
        assert_eq!(data.output_tokens, 1024);
    }

    #[test]
    fn missing_model_version() {
        let json = serde_json::json!({
            "usageMetadata": {
                "promptTokenCount": 100,
                "candidatesTokenCount": 50
            }
        });
        assert!(parse_google(&json).is_err());
    }

    #[test]
    fn missing_usage_metadata() {
        let json = serde_json::json!({
            "modelVersion": "gemini-2.5-pro"
        });
        assert!(parse_google(&json).is_err());
    }

    #[test]
    fn missing_prompt_token_count() {
        let json = serde_json::json!({
            "modelVersion": "gemini-2.5-pro",
            "usageMetadata": {
                "candidatesTokenCount": 50
            }
        });
        assert!(parse_google(&json).is_err());
    }

    #[test]
    fn missing_candidates_token_count() {
        let json = serde_json::json!({
            "modelVersion": "gemini-2.5-pro",
            "usageMetadata": {
                "promptTokenCount": 100
            }
        });
        assert!(parse_google(&json).is_err());
    }
}
