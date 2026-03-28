//! LLM API provider identification from request hostnames.
//!
//! Maps upstream hostnames to known LLM API providers. Only connections
//! to identified providers are subject to MITM interception and budget
//! enforcement. All other traffic is forwarded blindly.

/// Known LLM API providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provider {
    /// `OpenAI` API (`api.openai.com`)
    OpenAi,
    /// Anthropic API (`api.anthropic.com`)
    Anthropic,
    /// Google Generative AI (`generativelanguage.googleapis.com`)
    Google,
}

impl Provider {
    /// The canonical hostname for this provider's API.
    #[must_use]
    pub const fn hostname(&self) -> &'static str {
        match self {
            Self::OpenAi => "api.openai.com",
            Self::Anthropic => "api.anthropic.com",
            Self::Google => "generativelanguage.googleapis.com",
        }
    }

    /// The display name for this provider.
    #[must_use]
    pub const fn display_name(&self) -> &'static str {
        match self {
            Self::OpenAi => "OpenAI",
            Self::Anthropic => "Anthropic",
            Self::Google => "Google",
        }
    }

    /// Convert to the budget system's provider type.
    #[must_use]
    pub const fn to_budget_provider(&self) -> sanctum_budget::Provider {
        match self {
            Self::OpenAi => sanctum_budget::Provider::OpenAI,
            Self::Anthropic => sanctum_budget::Provider::Anthropic,
            Self::Google => sanctum_budget::Provider::Google,
        }
    }
}

/// All known LLM API hostnames that should be intercepted.
pub const INTERCEPT_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
];

/// Identify an LLM API provider from a hostname.
///
/// Returns `None` for hostnames that are not known LLM API providers.
/// These connections should be forwarded blindly without interception.
#[must_use]
pub fn identify_provider(hostname: &str) -> Option<Provider> {
    match hostname {
        "api.openai.com" => Some(Provider::OpenAi),
        "api.anthropic.com" => Some(Provider::Anthropic),
        "generativelanguage.googleapis.com" => Some(Provider::Google),
        _ => None,
    }
}

/// Check if a hostname should be intercepted for budget enforcement.
#[must_use]
pub fn should_intercept(hostname: &str) -> bool {
    identify_provider(hostname).is_some()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn identify_known_providers() {
        assert_eq!(identify_provider("api.openai.com"), Some(Provider::OpenAi));
        assert_eq!(
            identify_provider("api.anthropic.com"),
            Some(Provider::Anthropic)
        );
        assert_eq!(
            identify_provider("generativelanguage.googleapis.com"),
            Some(Provider::Google)
        );
    }

    #[test]
    fn identify_unknown_host_returns_none() {
        assert_eq!(identify_provider("example.com"), None);
    }

    #[test]
    fn should_intercept_known_hosts() {
        assert!(should_intercept("api.openai.com"));
        assert!(should_intercept("api.anthropic.com"));
        assert!(should_intercept("generativelanguage.googleapis.com"));
    }

    #[test]
    fn should_intercept_unknown_hosts() {
        assert!(!should_intercept("example.com"));
        assert!(!should_intercept("google.com"));
        assert!(!should_intercept("github.com"));
    }

    #[test]
    fn provider_hostname_roundtrip() {
        let providers = [Provider::OpenAi, Provider::Anthropic, Provider::Google];
        for p in providers {
            assert_eq!(
                identify_provider(p.hostname()),
                Some(p),
                "roundtrip failed for {p:?}"
            );
        }
    }

    #[test]
    fn provider_display_names() {
        let providers = [Provider::OpenAi, Provider::Anthropic, Provider::Google];
        for p in providers {
            assert!(!p.display_name().is_empty(), "empty display name for {p:?}");
        }
    }

    #[test]
    fn provider_to_budget_provider() {
        assert_eq!(
            Provider::OpenAi.to_budget_provider(),
            sanctum_budget::Provider::OpenAI
        );
        assert_eq!(
            Provider::Anthropic.to_budget_provider(),
            sanctum_budget::Provider::Anthropic
        );
        assert_eq!(
            Provider::Google.to_budget_provider(),
            sanctum_budget::Provider::Google
        );
    }
}
