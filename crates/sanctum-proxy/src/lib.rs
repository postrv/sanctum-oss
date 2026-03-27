//! Transparent HTTP proxy for LLM API budget enforcement.
//!
//! The proxy intercepts outbound HTTPS requests to known LLM API providers
//! (`OpenAI`, Anthropic, Google), extracts token usage from responses, and
//! enforces budget limits configured in Sanctum.
//!
//! # Architecture
//!
//! The proxy sits between the developer's tools and the LLM API endpoints.
//! It is configured via the `HTTPS_PROXY` environment variable, set per-tool
//! (not system-wide). For LLM API hosts, the proxy performs MITM TLS using
//! a locally-generated CA certificate. For all other hosts, it performs blind
//! TCP forwarding without inspection.
//!
//! # Security invariants
//!
//! - The proxy MUST bind to `127.0.0.1` only (never `0.0.0.0`)
//! - The CA private key is stored with 0o600 permissions
//! - Request headers (including API keys) are NEVER logged or persisted
//! - Only LLM API hosts are intercepted; all other traffic passes through blindly

pub mod error;
pub mod provider;

pub use error::ProxyError;
pub use provider::{Provider, identify_provider};
