//! Request routing and upstream URL resolution.
//!
//! Validates request paths to prevent SSRF and path injection attacks,
//! then constructs the upstream URL for the target LLM API provider.

use crate::error::ProxyError;
use crate::provider::Provider;

/// Characters that must never appear in a forwarded path.
///
/// - `@` can be used for credential injection in URLs (`user:pass@host`)
/// - `\r` and `\n` can be used for HTTP response splitting
const FORBIDDEN_PATH_CHARS: &[char] = &['@', '\r', '\n'];

/// Resolve the upstream URL for a given provider and request path.
///
/// # Validation
///
/// 1. The path must start with `/`.
/// 2. The path must not contain `@`, `\r`, or `\n`.
/// 3. After URL construction, the host of the resulting URL must match
///    the provider's canonical hostname (prevents open-redirect / SSRF).
///
/// # Errors
///
/// Returns `ProxyError::InvalidPath` if any validation check fails.
pub fn resolve_upstream(
    provider: &Provider,
    path: &str,
    query: Option<&str>,
) -> Result<String, ProxyError> {
    validate_path(path)?;

    let hostname = provider.hostname();
    let base = query.map_or_else(
        || format!("https://{hostname}{path}"),
        |q| format!("https://{hostname}{path}?{q}"),
    );

    // Parse and verify the constructed URL to prevent SSRF.
    let parsed = url::Url::parse(&base).map_err(|e| ProxyError::InvalidPath {
        reason: format!("malformed URL: {e}"),
    })?;

    let actual_host = parsed.host_str().unwrap_or_default();
    if actual_host != hostname {
        return Err(ProxyError::InvalidPath {
            reason: format!("URL host mismatch: expected '{hostname}', got '{actual_host}'"),
        });
    }

    Ok(parsed.as_str().to_owned())
}

/// Validate a request path for safety.
///
/// # Errors
///
/// Returns `ProxyError::InvalidPath` if the path fails validation.
pub fn validate_path(path: &str) -> Result<(), ProxyError> {
    if !path.starts_with('/') {
        return Err(ProxyError::InvalidPath {
            reason: format!(
                "path must start with '/', got: '{}'",
                truncate_for_log(path)
            ),
        });
    }

    if let Some(pos) = path.find(FORBIDDEN_PATH_CHARS) {
        let ch = path[pos..].chars().next().unwrap_or('?');
        let ch_desc = match ch {
            '\r' => "\\r".to_owned(),
            '\n' => "\\n".to_owned(),
            other => other.to_string(),
        };
        return Err(ProxyError::InvalidPath {
            reason: format!("path contains forbidden character '{ch_desc}' at position {pos}"),
        });
    }

    Ok(())
}

/// Truncate a string for safe inclusion in log messages.
fn truncate_for_log(s: &str) -> String {
    const MAX_LOG_LEN: usize = 80;
    if s.len() <= MAX_LOG_LEN {
        s.to_owned()
    } else {
        let mut truncated = s[..MAX_LOG_LEN].to_owned();
        truncated.push_str("...");
        truncated
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_path_accepted() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat/completions", None);
        assert!(result.is_ok());
        let url = result.unwrap();
        assert_eq!(url, "https://api.openai.com/v1/chat/completions");
    }

    #[test]
    fn test_valid_path_with_query() {
        let result = resolve_upstream(
            &Provider::Google,
            "/v1/models/gemini-2.5-pro:generateContent",
            Some("key=abc"),
        );
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.contains("key=abc"));
        assert!(url.starts_with("https://generativelanguage.googleapis.com/"));
    }

    #[test]
    fn test_path_with_at_sign_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat@evil.com/completions", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
        assert!(err.to_string().contains('@'));
    }

    #[test]
    fn test_path_with_crlf_rejected() {
        let result = resolve_upstream(&Provider::Anthropic, "/v1/messages\r\nHost: evil.com", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
    }

    #[test]
    fn test_path_with_newline_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat\nInjection: yes", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_path_not_starting_with_slash_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "v1/chat/completions", None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
        assert!(err.to_string().contains("must start with '/'"));
    }

    #[test]
    fn test_path_empty_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_providers_resolve() {
        for provider in &[Provider::OpenAi, Provider::Anthropic, Provider::Google] {
            let result = resolve_upstream(provider, "/v1/test", None);
            assert!(result.is_ok(), "failed for {provider:?}");
            let url = result.unwrap();
            assert!(url.contains(provider.hostname()));
        }
    }

    #[test]
    fn test_validate_path_standalone() {
        assert!(validate_path("/v1/chat").is_ok());
        assert!(validate_path("/").is_ok());
        assert!(validate_path("no-slash").is_err());
        assert!(validate_path("/with@at").is_err());
        assert!(validate_path("/with\nnewline").is_err());
        assert!(validate_path("/with\rcarriage").is_err());
    }

    #[test]
    fn test_truncate_for_log_short() {
        let result = truncate_for_log("short");
        assert_eq!(result, "short");
    }

    #[test]
    fn test_truncate_for_log_long() {
        let long = "a".repeat(200);
        let result = truncate_for_log(&long);
        assert!(result.len() < 100);
        assert!(result.ends_with("..."));
    }
}
