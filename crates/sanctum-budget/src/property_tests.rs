//! Property-based tests for the budget crate.

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use crate::parser::UsageData;
    use crate::pricing::calculate_cost;
    use crate::provider::Provider;
    use crate::tracker::BudgetTracker;
    use proptest::prelude::*;
    use sanctum_types::config::{BudgetAmount, BudgetConfig};

    fn config_with_limits(session_cents: u64, daily_cents: u64) -> BudgetConfig {
        BudgetConfig {
            default_session: Some(BudgetAmount {
                cents: session_cents,
            }),
            default_daily: Some(BudgetAmount { cents: daily_cents }),
            alert_at_percent: 75,
            ..BudgetConfig::default()
        }
    }

    fn arb_provider() -> impl Strategy<Value = Provider> {
        prop_oneof![
            Just(Provider::OpenAI),
            Just(Provider::Anthropic),
            Just(Provider::Google),
        ]
    }

    proptest! {
        /// Pricing calculation never overflows for tokens < 10^12.
        #[test]
        fn pricing_no_overflow(
            input_tokens in 0u64..1_000_000_000_000u64,
            output_tokens in 0u64..1_000_000_000_000u64,
        ) {
            // Should not panic or overflow for any provider/model
            let cost_openai = calculate_cost(Provider::OpenAI, "gpt-4o", input_tokens, output_tokens);
            let cost_anthropic = calculate_cost(Provider::Anthropic, "claude-sonnet-4-6", input_tokens, output_tokens);
            let cost_google = calculate_cost(Provider::Google, "gemini-2.5-pro", input_tokens, output_tokens);

            // Verify costs are finite (the function returned without panic/overflow).
            // For u64 this is always true, but documents the intent that no overflow occurred.
            let _ = (cost_openai, cost_anthropic, cost_google);

            // If both token counts are zero, cost must be zero
            if input_tokens == 0 && output_tokens == 0 {
                prop_assert_eq!(cost_openai, 0);
                prop_assert_eq!(cost_anthropic, 0);
                prop_assert_eq!(cost_google, 0);
            }
        }

        /// Tracker spend is always monotonically increasing within a session.
        #[test]
        fn tracker_spend_monotonically_increasing(
            usage_count in 1usize..20,
            input_tokens in 1u64..100_000,
            output_tokens in 1u64..100_000,
        ) {
            let config = BudgetConfig {
                default_session: None,
                default_daily: None,
                alert_at_percent: 75,
                ..BudgetConfig::default()
            };
            let mut tracker = BudgetTracker::new(&config);
            let mut prev_session = 0u64;
            let mut prev_daily = 0u64;

            for _ in 0..usage_count {
                let usage = UsageData {
                    provider: Provider::OpenAI,
                    model: "gpt-4o".to_string(),
                    input_tokens,
                    output_tokens,
                };
                let status = tracker.record_usage(&usage);
                prop_assert!(status.session_spent_cents >= prev_session,
                    "session spend decreased: {} < {}", status.session_spent_cents, prev_session);
                prop_assert!(status.daily_spent_cents >= prev_daily,
                    "daily spend decreased: {} < {}", status.daily_spent_cents, prev_daily);
                prev_session = status.session_spent_cents;
                prev_daily = status.daily_spent_cents;
            }
        }

        /// Save/load roundtrip preserves all spend data for any provider.
        #[test]
        fn save_load_roundtrip_preserves_spend(
            provider in arb_provider(),
            input_tokens in 1u64..10_000_000,
            output_tokens in 1u64..10_000_000,
        ) {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("budget_prop.json");

            let config = config_with_limits(100_000, 500_000);
            let mut tracker = BudgetTracker::new(&config);

            let usage = UsageData {
                provider,
                model: "gpt-4o".to_string(),
                input_tokens,
                output_tokens,
            };
            let _ = tracker.record_usage(&usage);

            let original_session = tracker.status(provider).session_spent_cents;
            let original_daily = tracker.status(provider).daily_spent_cents;

            tracker.save_to_file(&path).expect("save");
            let loaded = BudgetTracker::load_from_file(&path, &config).expect("load");

            prop_assert_eq!(loaded.status(provider).session_spent_cents, original_session);
            prop_assert_eq!(loaded.status(provider).daily_spent_cents, original_daily);
        }
    }
}
