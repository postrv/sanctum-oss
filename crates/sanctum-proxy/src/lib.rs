//! HTTP gateway proxy for LLM API budget enforcement.
//!
//! The proxy intercepts outbound HTTP requests to known LLM API providers
//! (`OpenAI`, Anthropic, Google), forwards them upstream via HTTPS, extracts
//! token usage from responses, and enforces budget limits configured in Sanctum.
//!
//! # Architecture
//!
//! AI tools set `OPENAI_BASE_URL=http://127.0.0.1:7842/v1` (or equivalent).
//! The proxy receives plain HTTP, makes upstream HTTPS calls via `reqwest`,
//! parses usage from responses, and records it through the budget tracker.
//!
//! # Security invariants
//!
//! - The proxy MUST bind to `127.0.0.1` only (never `0.0.0.0`)
//! - Request headers (including API keys) are NEVER logged or persisted
//! - Only LLM API hosts are intercepted; all other traffic is rejected

pub mod error;
pub mod handler;
pub mod provider;
pub mod routing;
pub mod server;
pub mod usage;

pub use error::ProxyError;
pub use provider::{identify_provider, Provider};
