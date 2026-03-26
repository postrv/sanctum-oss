//! Budget enforcement decisions and response generation.
//!
//! Determines whether an API request should be allowed, warned about,
//! or blocked based on current budget status.

use crate::provider::Provider;
use crate::tracker::{BudgetStatus, BudgetTracker};
use sanctum_types::config::BudgetConfig;

/// Result of a budget enforcement check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforcementResult {
    /// The request is within budget and can proceed.
    Allowed,
    /// The request is approaching the budget limit.
    Warning {
        /// Human-readable warning message.
        message: String,
        /// Current spend as a percentage of the limit.
        percent: u8,
    },
    /// The request has been blocked because the budget is exceeded.
    Blocked {
        /// Human-readable message explaining why the request was blocked.
        message: String,
    },
}

/// Check whether a request to the given provider should be allowed.
///
/// Returns:
/// - `Blocked` if either session or daily limit is exceeded
/// - `Warning` if the alert threshold has been crossed but limits not exceeded
/// - `Allowed` otherwise
#[must_use]
pub fn check_budget(tracker: &BudgetTracker, provider: Provider) -> EnforcementResult {
    let status = tracker.status(provider);

    if status.session_exceeded {
        let limit = status.session_limit_cents.unwrap_or(0);
        return EnforcementResult::Blocked {
            message: format!(
                "Session budget exceeded for {provider}: spent {spent} cents of {limit} cent limit",
                spent = status.session_spent_cents,
            ),
        };
    }

    if status.daily_exceeded {
        let limit = status.daily_limit_cents.unwrap_or(0);
        return EnforcementResult::Blocked {
            message: format!(
                "Daily budget exceeded for {provider}: spent {spent} cents of {limit} cent limit",
                spent = status.daily_spent_cents,
            ),
        };
    }

    if status.alert_triggered {
        let percent = compute_max_percent(&status);
        return EnforcementResult::Warning {
            message: format!(
                "Budget alert for {provider}: approaching limit ({percent}% used)"
            ),
            percent,
        };
    }

    EnforcementResult::Allowed
}

/// Generate a JSON response body for a budget-exceeded (429) response.
///
/// Returns a JSON string suitable for returning as an HTTP 429 response body.
#[must_use]
pub fn budget_exceeded_response(status: &BudgetStatus) -> String {
    let session_limit = status.session_limit_cents.unwrap_or(0);
    let daily_limit = status.daily_limit_cents.unwrap_or(0);

    let error_obj = serde_json::json!({
        "error": {
            "type": "budget_exceeded",
            "message": format!(
                "Budget limit exceeded for {}. Session: {} / {} cents. Daily: {} / {} cents.",
                status.provider,
                status.session_spent_cents,
                session_limit,
                status.daily_spent_cents,
                daily_limit,
            ),
            "provider": status.provider.to_string(),
            "session_spent_cents": status.session_spent_cents,
            "session_limit_cents": session_limit,
            "daily_spent_cents": status.daily_spent_cents,
            "daily_limit_cents": daily_limit,
        }
    });

    // serde_json::to_string on a Value constructed from json! macro is infallible
    // in practice, but we handle the error path gracefully.
    serde_json::to_string(&error_obj).unwrap_or_else(|_| {
        r#"{"error":{"type":"budget_exceeded","message":"Budget limit exceeded"}}"#.to_string()
    })
}

/// Check whether a model is allowed for the given provider.
///
/// Looks up the provider's `allowed_models` list in the budget config.
/// If no `allowed_models` list is configured (i.e. `None`), all models
/// are allowed. If the list is `Some` but empty, all models are blocked.
/// Matching is case-insensitive.
#[must_use]
pub fn is_model_allowed(provider: &Provider, model: &str, config: &BudgetConfig) -> bool {
    let provider_key = provider.to_string().to_lowercase();
    let Some(provider_config) = config.providers.get(&provider_key) else {
        // No per-provider config means no restrictions.
        return true;
    };
    let Some(allowed) = &provider_config.allowed_models else {
        // allowed_models is None, so all models are allowed.
        return true;
    };
    let model_lower = model.to_lowercase();
    allowed.iter().any(|m| m.to_lowercase() == model_lower)
}

/// Compute the maximum usage percentage across session and daily limits.
fn compute_max_percent(status: &BudgetStatus) -> u8 {
    let session_pct = status
        .session_limit_cents
        .filter(|&l| l > 0)
        .map_or(0, |limit| status.session_spent_cents.saturating_mul(100) / limit);

    let daily_pct = status
        .daily_limit_cents
        .filter(|&l| l > 0)
        .map_or(0, |limit| status.daily_spent_cents.saturating_mul(100) / limit);

    let max_pct = session_pct.max(daily_pct);

    // Clamp to u8 range
    #[allow(clippy::cast_possible_truncation)]
    if max_pct > 255 {
        255
    } else {
        max_pct as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::UsageData;
    use sanctum_types::config::{BudgetAmount, BudgetConfig, ProviderBudgetConfig};

    fn make_tracker_with_session_limit(limit_cents: u64) -> BudgetTracker {
        let config = BudgetConfig {
            default_session: Some(BudgetAmount {
                cents: limit_cents,
            }),
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        BudgetTracker::new(&config)
    }

    #[test]
    fn allowed_under_limit() {
        let tracker = make_tracker_with_session_limit(10000);
        let result = check_budget(&tracker, Provider::OpenAI);
        assert_eq!(result, EnforcementResult::Allowed);
    }

    #[test]
    fn warning_at_threshold() {
        let mut tracker = make_tracker_with_session_limit(1000);

        // Spend 750 out of 1000 = 75%
        let usage = UsageData {
            provider: Provider::OpenAI,
            model: "gpt-4o".to_string(),
            input_tokens: 1_000_000,
            output_tokens: 500_000,
        };
        tracker.record_usage(&usage);

        let result = check_budget(&tracker, Provider::OpenAI);
        match result {
            EnforcementResult::Warning { percent, .. } => {
                assert!(percent >= 75);
            }
            other => panic!("expected Warning, got {other:?}"),
        }
    }

    #[test]
    fn blocked_when_exceeded() {
        let mut tracker = make_tracker_with_session_limit(100);

        // gpt-4o: 1M input = 250 cents > 100 cent limit
        let usage = UsageData {
            provider: Provider::OpenAI,
            model: "gpt-4o".to_string(),
            input_tokens: 1_000_000,
            output_tokens: 0,
        };
        tracker.record_usage(&usage);

        let result = check_budget(&tracker, Provider::OpenAI);
        match result {
            EnforcementResult::Blocked { message } => {
                assert!(message.contains("exceeded"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn daily_blocked_when_exceeded() {
        let config = BudgetConfig {
            default_session: None,
            default_daily: Some(BudgetAmount { cents: 100 }),
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        let usage = UsageData {
            provider: Provider::Anthropic,
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 1_000_000,
            output_tokens: 0,
        };
        tracker.record_usage(&usage);

        let result = check_budget(&tracker, Provider::Anthropic);
        match result {
            EnforcementResult::Blocked { message } => {
                assert!(message.contains("Daily"));
            }
            other => panic!("expected Blocked, got {other:?}"),
        }
    }

    #[test]
    fn valid_json_response() {
        let status = BudgetStatus {
            provider: Provider::OpenAI,
            session_spent_cents: 500,
            session_limit_cents: Some(100),
            daily_spent_cents: 500,
            daily_limit_cents: Some(1000),
            alert_triggered: true,
            session_exceeded: true,
            daily_exceeded: false,
        };

        let json_str = budget_exceeded_response(&status);

        // Verify it's valid JSON
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
        assert!(parsed.is_ok());

        let value = match parsed {
            Ok(v) => v,
            Err(_) => return,
        };

        let error = match value.get("error") {
            Some(e) => e,
            None => return,
        };

        assert_eq!(
            error.get("type").and_then(|v| v.as_str()),
            Some("budget_exceeded")
        );
        assert_eq!(
            error.get("provider").and_then(|v| v.as_str()),
            Some("OpenAI")
        );
        assert_eq!(
            error.get("session_spent_cents").and_then(|v| v.as_u64()),
            Some(500)
        );
        assert_eq!(
            error.get("session_limit_cents").and_then(|v| v.as_u64()),
            Some(100)
        );
    }

    #[test]
    fn no_limits_always_allowed() {
        let config = BudgetConfig {
            default_session: None,
            default_daily: None,
            alert_at_percent: 75,
            ..BudgetConfig::default()
        };
        let mut tracker = BudgetTracker::new(&config);

        let usage = UsageData {
            provider: Provider::OpenAI,
            model: "gpt-4o".to_string(),
            input_tokens: 100_000_000,
            output_tokens: 100_000_000,
        };
        tracker.record_usage(&usage);

        let result = check_budget(&tracker, Provider::OpenAI);
        assert_eq!(result, EnforcementResult::Allowed);
    }

    // --- is_model_allowed tests ---

    #[test]
    fn model_allowed_when_list_is_none() {
        let config = BudgetConfig::default();
        assert!(is_model_allowed(&Provider::OpenAI, "gpt-4o", &config));
        assert!(is_model_allowed(&Provider::Anthropic, "claude-sonnet-4-6", &config));
    }

    #[test]
    fn model_allowed_when_in_list() {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o".to_string(), "gpt-4o-mini".to_string()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };
        assert!(is_model_allowed(&Provider::OpenAI, "gpt-4o", &config));
        assert!(is_model_allowed(&Provider::OpenAI, "gpt-4o-mini", &config));
    }

    #[test]
    fn model_blocked_when_not_in_list() {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["gpt-4o-mini".to_string()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };
        assert!(!is_model_allowed(&Provider::OpenAI, "gpt-4o", &config));
    }

    #[test]
    fn empty_allowed_list_blocks_all() {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "anthropic".to_string(),
            ProviderBudgetConfig {
                allowed_models: Some(Vec::new()),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };
        assert!(!is_model_allowed(&Provider::Anthropic, "claude-sonnet-4-6", &config));
        assert!(!is_model_allowed(&Provider::Anthropic, "claude-opus-4-6", &config));
    }

    #[test]
    fn model_matching_is_case_insensitive() {
        let mut providers = std::collections::HashMap::new();
        providers.insert(
            "openai".to_string(),
            ProviderBudgetConfig {
                allowed_models: Some(vec!["GPT-4o".to_string()]),
                ..ProviderBudgetConfig::default()
            },
        );
        let config = BudgetConfig {
            providers,
            ..BudgetConfig::default()
        };
        assert!(is_model_allowed(&Provider::OpenAI, "gpt-4o", &config));
        assert!(is_model_allowed(&Provider::OpenAI, "GPT-4O", &config));
        assert!(is_model_allowed(&Provider::OpenAI, "Gpt-4o", &config));
    }
}
