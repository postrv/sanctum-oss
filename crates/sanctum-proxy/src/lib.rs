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
//! - Request and response bodies are scanned for credentials and redacted
//! - Request paths are validated to prevent SSRF and path injection attacks
//! - Hop-by-hop headers are stripped from forwarded responses
//! - Body sizes are limited to prevent memory exhaustion

pub mod ca;
pub mod connect;
pub mod error;
pub mod handler;
pub mod provider;
pub mod routing;
pub mod server;
pub mod usage;

pub use ca::CertificateAuthority;
pub use connect::{ConnectAction, ConnectState};
pub use error::ProxyError;
pub use handler::{HandlerState, ProxyRequest, ProxyResponse};
pub use provider::{identify_provider, Provider};
pub use routing::resolve_upstream;
pub use server::ProxyServer;
