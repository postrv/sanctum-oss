//! Sanctum Budget -- LLM spend tracking, budget enforcement, and API response parsing.
//!
//! This crate provides the budget controller for the Sanctum security daemon:
//!
//! - **Provider identification**: Distinguishes between `OpenAI`, Anthropic, and Google APIs.
//! - **Pricing calculation**: Computes costs in integer cents using model-specific pricing tables.
//! - **Response parsing**: Extracts token usage from LLM API responses with auto-detection.
//! - **Budget tracking**: Monitors per-provider session and daily spending against limits.
//! - **Enforcement**: Decides whether requests should be allowed, warned, or blocked.

pub mod enforcement;
pub mod error;
pub mod parser;
pub mod pricing;
pub mod provider;
pub mod tracker;

pub use enforcement::{budget_exceeded_response, check_budget, is_model_allowed, EnforcementResult};
pub use error::BudgetError;
pub use parser::{parse_usage, UsageData};
pub use pricing::calculate_cost;
pub use provider::Provider;
pub use tracker::{BudgetStatus, BudgetTracker};

#[cfg(test)]
mod property_tests;
