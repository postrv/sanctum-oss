//! Route proxy requests to upstream LLM API providers.
//!
//! Maps request paths from the local proxy to the correct upstream HTTPS URL
//! based on the identified provider.

use crate::provider::Provider;

/// Map a proxy request path to the full upstream URL for the given provider.
///
/// The path is appended directly to the provider's base URL, preserving
/// any query string or sub-paths.
#[must_use]
pub fn resolve_upstream(provider: &Provider, path: &str) -> String {
    match provider {
        Provider::OpenAi => format!("https://api.openai.com{path}"),
        Provider::Anthropic => format!("https://api.anthropic.com{path}"),
        Provider::Google => format!("https://generativelanguage.googleapis.com{path}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn openai_path_resolution() {
        let url = resolve_upstream(&Provider::OpenAi, "/v1/chat/completions");
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn anthropic_path_resolution() {
        let url = resolve_upstream(&Provider::Anthropic, "/v1/messages");
        assert_eq!(url, "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn google_path_resolution() {
        let url = resolve_upstream(
            &Provider::Google,
            "/v1beta/models/gemini-2.5-pro:generateContent",
        );
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent"
        );
    }

    #[test]
    fn preserves_query_string() {
        let url = resolve_upstream(&Provider::Google, "/v1beta/models?key=abc");
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models?key=abc"
        );
    }

    #[test]
    fn root_path() {
        let url = resolve_upstream(&Provider::OpenAi, "/");
        assert_eq!(url, "https://api.openai.com/");
    }
}
