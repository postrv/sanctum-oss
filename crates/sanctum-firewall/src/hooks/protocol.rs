//! Hook protocol types.
//!
//! Defines the input/output data structures for Claude Code tool-call hooks.
//! These types are serialisation-friendly and used across all hook handlers.

use serde::{Deserialize, Serialize};

/// Input to a hook handler, describing the tool invocation being evaluated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookInput {
    /// The name of the tool being invoked (e.g., "bash", "write", "read").
    pub tool_name: String,
    /// The JSON arguments passed to the tool.
    pub tool_input: serde_json::Value,
    /// Optional AI firewall configuration. When `None`, all checks are active.
    /// Injected by the CLI before calling hook functions — not deserialized from JSON.
    #[serde(skip)]
    pub config: Option<sanctum_types::config::AiFirewallConfig>,
    /// SHA-256 hashes of known-safe high-entropy strings that should be
    /// excluded from entropy-based credential detection.
    /// Loaded from `$DATA_DIR/entropy_allowlist.txt` at runtime.
    #[serde(skip)]
    pub entropy_allowlist: Vec<String>,
}

/// Output from a hook handler, containing the policy decision and optional message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookOutput {
    /// The policy decision for this tool invocation.
    pub decision: HookDecision,
    /// Optional human-readable message explaining the decision.
    pub message: Option<String>,
}

/// A hook policy decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookDecision {
    /// Allow the tool invocation to proceed.
    Allow,
    /// Allow but warn the user about potential risks.
    Warn,
    /// Block the tool invocation entirely.
    Block,
}

impl HookOutput {
    /// Create an Allow decision with no message.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            decision: HookDecision::Allow,
            message: None,
        }
    }

    /// Create a Warn decision with an explanatory message.
    #[must_use]
    pub fn warn(message: impl Into<String>) -> Self {
        Self {
            decision: HookDecision::Warn,
            message: Some(message.into()),
        }
    }

    /// Create a Block decision with an explanatory message.
    #[must_use]
    pub fn block(message: impl Into<String>) -> Self {
        Self {
            decision: HookDecision::Block,
            message: Some(message.into()),
        }
    }
}
