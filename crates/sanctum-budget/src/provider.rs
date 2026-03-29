//! LLM provider identification.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported LLM API providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provider {
    /// `OpenAI` (GPT-4o, o1, o3-mini, etc.)
    OpenAI,
    /// Anthropic (Claude Sonnet, Opus, Haiku, etc.)
    Anthropic,
    /// Google (Gemini 2.5 Pro, Flash, etc.)
    Google,
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenAI => write!(f, "OpenAI"),
            Self::Anthropic => write!(f, "Anthropic"),
            Self::Google => write!(f, "Google"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_providers() {
        assert_eq!(Provider::OpenAI.to_string(), "OpenAI");
        assert_eq!(Provider::Anthropic.to_string(), "Anthropic");
        assert_eq!(Provider::Google.to_string(), "Google");
    }

    #[test]
    fn provider_equality() {
        assert_eq!(Provider::OpenAI, Provider::OpenAI);
        assert_ne!(Provider::OpenAI, Provider::Anthropic);
    }
}
