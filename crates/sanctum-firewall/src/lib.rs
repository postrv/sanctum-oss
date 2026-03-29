//! Sanctum Firewall — AI agent security boundary enforcement.
//!
//! This crate provides the security firewall for AI coding agents:
//!
//! - **Credential pattern detection**: Compiled regex patterns for common API
//!   keys, tokens, and secrets with ReDoS-safe construction.
//! - **Shannon entropy analysis**: Identifies high-entropy strings that may be
//!   undiscovered secret formats.
//! - **Credential redaction**: Replaces detected secrets with safe placeholders
//!   that include type and hash prefix for traceability.
//! - **Claude Code hooks**: Pre/post tool-call handlers that block dangerous
//!   operations like credential exfiltration and supply chain writes.
//! - **MCP audit and policy**: Logs and enforces policy on MCP tool invocations.

pub mod entropy;
pub mod hooks;
pub mod mcp;
pub mod patterns;
pub mod redaction;
pub mod registry;
