//! Budget error types.

use thiserror::Error;

/// Errors that can occur during budget tracking and enforcement.
#[derive(Debug, Error)]
pub enum BudgetError {
    /// The session spending limit has been exceeded for a provider.
    #[error(
        "session limit exceeded for {provider}: spent {spent_cents} cents, limit {limit_cents} cents"
    )]
    SessionLimitExceeded {
        /// The provider that exceeded the limit.
        provider: String,
        /// The amount spent in cents.
        spent_cents: u64,
        /// The limit in cents.
        limit_cents: u64,
    },

    /// The daily spending limit has been exceeded for a provider.
    #[error(
        "daily limit exceeded for {provider}: spent {spent_cents} cents, limit {limit_cents} cents"
    )]
    DailyLimitExceeded {
        /// The provider that exceeded the limit.
        provider: String,
        /// The amount spent in cents.
        spent_cents: u64,
        /// The limit in cents.
        limit_cents: u64,
    },

    /// An unknown provider was encountered.
    #[error("unknown provider: {0}")]
    UnknownProvider(String),

    /// Failed to parse an API response.
    #[error("parse error: {0}")]
    ParseError(String),

    /// An I/O error occurred.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A JSON serialization/deserialization error occurred.
    #[error(transparent)]
    Serde(#[from] serde_json::Error),
}
