//! Model pricing tables and cost calculation.
//!
//! All prices are in cents per million tokens (integer only).
//! Cost calculation uses ceiling division to ensure we never undercount.

use crate::provider::Provider;

/// Price entry for a model: (`input_cents_per_million`, `output_cents_per_million`).
struct ModelPrice {
    model_prefix: &'static str,
    input_price: u64,
    output_price: u64,
}

/// `OpenAI` model pricing (cents per million tokens).
/// NOTE: More-specific prefixes MUST appear before less-specific ones
/// (e.g. "gpt-4o-mini" before "gpt-4o") so prefix matching works correctly.
const OPENAI_PRICING: &[ModelPrice] = &[
    ModelPrice {
        model_prefix: "gpt-4o-mini",
        input_price: 15,
        output_price: 60,
    },
    ModelPrice {
        model_prefix: "gpt-4o",
        input_price: 250,
        output_price: 1000,
    },
    ModelPrice {
        model_prefix: "gpt-4-turbo",
        input_price: 1000,
        output_price: 3000,
    },
    ModelPrice {
        model_prefix: "gpt-4.1-nano",
        input_price: 10,
        output_price: 40,
    },
    ModelPrice {
        model_prefix: "gpt-4.1-mini",
        input_price: 40,
        output_price: 160,
    },
    ModelPrice {
        model_prefix: "gpt-4.1",
        input_price: 200,
        output_price: 800,
    },
    ModelPrice {
        model_prefix: "o3-mini",
        input_price: 110,
        output_price: 440,
    },
    ModelPrice {
        model_prefix: "o4-mini",
        input_price: 110,
        output_price: 440,
    },
    ModelPrice {
        model_prefix: "o1-mini",
        input_price: 110,
        output_price: 440,
    },
    ModelPrice {
        model_prefix: "o1-preview",
        input_price: 1500,
        output_price: 6000,
    },
    ModelPrice {
        model_prefix: "o1",
        input_price: 1500,
        output_price: 6000,
    },
];

/// Anthropic model pricing (cents per million tokens).
const ANTHROPIC_PRICING: &[ModelPrice] = &[
    ModelPrice {
        model_prefix: "claude-opus-4-6",
        input_price: 1500,
        output_price: 7500,
    },
    ModelPrice {
        model_prefix: "claude-sonnet-4-6",
        input_price: 300,
        output_price: 1500,
    },
    ModelPrice {
        model_prefix: "claude-haiku-4-5",
        input_price: 80,
        output_price: 400,
    },
];

/// Google model pricing (cents per million tokens).
const GOOGLE_PRICING: &[ModelPrice] = &[
    ModelPrice {
        model_prefix: "gemini-2.5-pro",
        input_price: 125,
        output_price: 1000,
    },
    ModelPrice {
        model_prefix: "gemini-2.5-flash",
        input_price: 15,
        output_price: 60,
    },
];

/// Default fallback prices per provider (cents per million tokens).
const DEFAULT_OPENAI: (u64, u64) = (250, 1000);
const DEFAULT_ANTHROPIC: (u64, u64) = (300, 1500);
const DEFAULT_GOOGLE: (u64, u64) = (125, 1000);

/// Look up pricing for a model within a provider's pricing table.
fn lookup_price(table: &[ModelPrice], model: &str) -> Option<(u64, u64)> {
    let model_lower = model.to_lowercase();
    // Iterate the table; the first match wins. Tables are ordered so that
    // more-specific prefixes (e.g. "gpt-4o-mini") appear before less-specific
    // ones (e.g. "gpt-4o").
    for entry in table {
        if model_lower.starts_with(entry.model_prefix) {
            return Some((entry.input_price, entry.output_price));
        }
    }
    None
}

/// Calculate cost in cents using ceiling division.
///
/// Formula: `(tokens * price_per_million + 999_999) / 1_000_000`
///
/// This ensures we always round up, never undercharging.
const fn ceiling_cost(tokens: u64, price_per_million: u64) -> u64 {
    if tokens == 0 || price_per_million == 0 {
        return 0;
    }
    (tokens
        .saturating_mul(price_per_million)
        .saturating_add(999_999))
        / 1_000_000
}

/// Calculate the total cost in cents for the given token usage.
///
/// Returns the cost as integer cents. Uses ceiling division so partial-cent
/// amounts are always rounded up (we never undercount spend).
///
/// Unknown models fall back to a conservative default price for the provider.
#[must_use]
pub fn calculate_cost(
    provider: Provider,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
) -> u64 {
    let (input_price, output_price) = match provider {
        Provider::OpenAI => lookup_price(OPENAI_PRICING, model).unwrap_or(DEFAULT_OPENAI),
        Provider::Anthropic => lookup_price(ANTHROPIC_PRICING, model).unwrap_or(DEFAULT_ANTHROPIC),
        Provider::Google => lookup_price(GOOGLE_PRICING, model).unwrap_or(DEFAULT_GOOGLE),
    };

    let input_cost = ceiling_cost(input_tokens, input_price);
    let output_cost = ceiling_cost(output_tokens, output_price);
    input_cost.saturating_add(output_cost)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn known_model_gpt4o() {
        // 1M input at 250 cents/M = 250, 1M output at 1000 cents/M = 1000
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 1_000_000, 1_000_000);
        assert_eq!(cost, 1250);
    }

    #[test]
    fn known_model_gpt4o_mini() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o-mini", 1_000_000, 1_000_000);
        assert_eq!(cost, 75); // 15 + 60
    }

    #[test]
    fn known_model_claude_sonnet() {
        let cost = calculate_cost(
            Provider::Anthropic,
            "claude-sonnet-4-6-20260320",
            1_000_000,
            1_000_000,
        );
        assert_eq!(cost, 1800); // 300 + 1500
    }

    #[test]
    fn known_model_claude_opus() {
        let cost = calculate_cost(
            Provider::Anthropic,
            "claude-opus-4-6-20260320",
            1_000_000,
            1_000_000,
        );
        assert_eq!(cost, 9000); // 1500 + 7500
    }

    #[test]
    fn known_model_claude_haiku() {
        let cost = calculate_cost(
            Provider::Anthropic,
            "claude-haiku-4-5-20260320",
            1_000_000,
            1_000_000,
        );
        assert_eq!(cost, 480); // 80 + 400
    }

    #[test]
    fn known_model_gemini_pro() {
        let cost = calculate_cost(
            Provider::Google,
            "gemini-2.5-pro-preview",
            1_000_000,
            1_000_000,
        );
        assert_eq!(cost, 1125); // 125 + 1000
    }

    #[test]
    fn known_model_gemini_flash() {
        let cost = calculate_cost(Provider::Google, "gemini-2.5-flash", 1_000_000, 1_000_000);
        assert_eq!(cost, 75); // 15 + 60
    }

    #[test]
    fn known_model_o1() {
        let cost = calculate_cost(Provider::OpenAI, "o1", 1_000_000, 1_000_000);
        assert_eq!(cost, 7500); // 1500 + 6000
    }

    #[test]
    fn known_model_o3_mini() {
        let cost = calculate_cost(Provider::OpenAI, "o3-mini", 1_000_000, 1_000_000);
        assert_eq!(cost, 550); // 110 + 440
    }

    #[test]
    fn known_model_o4_mini() {
        let cost = calculate_cost(Provider::OpenAI, "o4-mini", 1_000_000, 1_000_000);
        assert_eq!(cost, 550); // 110 + 440
    }

    #[test]
    fn o1_mini_uses_own_pricing() {
        let cost = calculate_cost(Provider::OpenAI, "o1-mini", 1_000_000, 1_000_000);
        assert_eq!(cost, 550); // 110 + 440, NOT 1500 + 6000
    }

    #[test]
    fn o1_preview_uses_own_pricing() {
        let cost = calculate_cost(Provider::OpenAI, "o1-preview", 1_000_000, 1_000_000);
        assert_eq!(cost, 7500); // 1500 + 6000
    }

    #[test]
    fn known_model_gpt4_turbo() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4-turbo", 1_000_000, 1_000_000);
        assert_eq!(cost, 4000); // 1000 + 3000
    }

    #[test]
    fn known_model_gpt41() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4.1", 1_000_000, 1_000_000);
        assert_eq!(cost, 1000); // 200 + 800
    }

    #[test]
    fn known_model_gpt41_mini() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4.1-mini", 1_000_000, 1_000_000);
        assert_eq!(cost, 200); // 40 + 160
    }

    #[test]
    fn known_model_gpt41_nano() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4.1-nano", 1_000_000, 1_000_000);
        assert_eq!(cost, 50); // 10 + 40
    }

    #[test]
    fn unknown_model_uses_default() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-5-ultra-turbo", 1_000_000, 1_000_000);
        assert_eq!(cost, 1250); // default OpenAI: 250 + 1000
    }

    #[test]
    fn unknown_anthropic_model_uses_default() {
        let cost = calculate_cost(
            Provider::Anthropic,
            "claude-unknown-9000",
            1_000_000,
            1_000_000,
        );
        assert_eq!(cost, 1800); // default Anthropic: 300 + 1500
    }

    #[test]
    fn unknown_google_model_uses_default() {
        let cost = calculate_cost(Provider::Google, "gemini-4.0-ultra", 1_000_000, 1_000_000);
        assert_eq!(cost, 1125); // default Google: 125 + 1000
    }

    #[test]
    fn zero_tokens_zero_cost() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 0, 0);
        assert_eq!(cost, 0);
    }

    #[test]
    fn zero_input_tokens() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 0, 1_000_000);
        assert_eq!(cost, 1000);
    }

    #[test]
    fn zero_output_tokens() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        assert_eq!(cost, 250);
    }

    #[test]
    fn ceiling_division_rounds_up() {
        // 1 token at 250 cents/M -> ceil(250/1_000_000) = 1
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 1, 0);
        assert_eq!(cost, 1);
    }

    #[test]
    fn ceiling_division_exact_million() {
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 1_000_000, 0);
        assert_eq!(cost, 250);
    }

    #[test]
    fn small_token_count_ceiling() {
        // 500_000 tokens at 250 cents/M = 125 cents exactly
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 500_000, 0);
        assert_eq!(cost, 125);
    }

    #[test]
    fn small_token_count_with_remainder() {
        // 500_001 tokens at 250 cents/M = 125.00025 -> ceil to 126
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", 500_001, 0);
        assert_eq!(cost, 126);
    }

    #[test]
    fn model_name_case_insensitive() {
        let cost = calculate_cost(Provider::OpenAI, "GPT-4o", 1_000_000, 1_000_000);
        assert_eq!(cost, 1250);
    }

    #[test]
    fn u64_max_tokens_does_not_panic() {
        // With u64::MAX input tokens and a known model, the saturating
        // arithmetic in ceiling_cost must produce a valid u64 — no panic
        // or overflow.
        let cost = calculate_cost(Provider::OpenAI, "gpt-4o", u64::MAX, u64::MAX);

        // ceiling_cost(u64::MAX, 250) saturates the multiply to u64::MAX,
        // then saturating_add(999_999) stays at u64::MAX, divided by 1M
        // gives 18_446_744_073_709.  Two of those saturating_add → still
        // a valid u64.  The exact value is less important than "no panic".
        assert!(cost > 0);
    }

    #[test]
    fn zero_tokens_zero_price() {
        // Explicitly verify that 0 input + 0 output = 0 cost for every provider.
        assert_eq!(calculate_cost(Provider::OpenAI, "gpt-4o", 0, 0), 0);
        assert_eq!(
            calculate_cost(Provider::Anthropic, "claude-sonnet-4-6", 0, 0),
            0
        );
        assert_eq!(calculate_cost(Provider::Google, "gemini-2.5-pro", 0, 0), 0);
    }
}

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(2)]
    fn ceiling_cost_no_overflow() {
        let tokens: u64 = kani::any();
        let price: u64 = kani::any();

        let result = ceiling_cost(tokens, price);

        // Zero tokens or zero price must yield zero cost.
        if tokens == 0 || price == 0 {
            assert!(result == 0, "zero input must yield zero cost");
        }

        // Non-zero case: result must be at least 1 cent (ceiling division
        // rounds up, so any non-zero usage produces a non-zero cost).
        if tokens > 0 && price > 0 {
            assert!(result >= 1, "non-zero usage must produce at least 1 cent");
        }

        // Ceiling property: result * 1_000_000 >= tokens * price (before saturation).
        // When the multiplication doesn't saturate, this proves we never undercount.
        if tokens <= 1_000_000 && price <= 1_000_000 {
            // Safe range — no saturation occurs.
            assert!(
                result.saturating_mul(1_000_000) >= tokens * price,
                "ceiling division must never undercount"
            );
        }

        // Verify both paths are reachable.
        kani::cover!(tokens == 0, "zero tokens path reachable");
        kani::cover!(tokens > 0 && price > 0, "non-zero path reachable");
    }
}
