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

    // Validate query string for the same forbidden characters as the path.
    if let Some(q) = query {
        if q.contains(FORBIDDEN_PATH_CHARS) {
            return Err(ProxyError::InvalidPath {
                reason: format!(
                    "query string contains forbidden characters: {}",
                    truncate_for_log(q)
                ),
            });
        }
    }

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

    // Reject path traversal: `..` as a path segment (e.g., `/..`, `/../`, `/v1/../admin`).
    // We split on `/` and check for any segment that is exactly `..`.
    // This allows `..` within filenames (e.g., `/v1/path..name`).
    if path.split('/').any(|segment| segment == "..") {
        return Err(ProxyError::InvalidPath {
            reason: format!(
                "path contains directory traversal segment '..': '{}'",
                truncate_for_log(path)
            ),
        });
    }

    Ok(())
}

/// Truncate a string for safe inclusion in log messages.
///
/// Uses char-boundary-aware slicing so that multi-byte UTF-8 characters
/// are never split, which would cause a panic on `&s[..n]`.
fn truncate_for_log(s: &str) -> String {
    const MAX_LOG_LEN: usize = 80;
    if s.len() <= MAX_LOG_LEN {
        s.to_owned()
    } else {
        let mut end = MAX_LOG_LEN;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let mut truncated = s[..end].to_owned();
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

    #[test]
    fn test_truncate_for_log_empty() {
        let result = truncate_for_log("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_truncate_for_log_exact_boundary() {
        // Exactly 80 ASCII chars -- should not be truncated.
        let s = "a".repeat(80);
        let result = truncate_for_log(&s);
        assert_eq!(result, s);
    }

    #[test]
    fn test_truncate_for_log_one_over_boundary() {
        // 81 ASCII chars -- should be truncated.
        let s = "a".repeat(81);
        let result = truncate_for_log(&s);
        assert!(result.ends_with("..."));
        assert_eq!(result.len(), 83); // 80 + "..."
    }

    #[test]
    fn test_truncate_for_log_multibyte_chinese() {
        // Chinese chars are 3 bytes each in UTF-8.
        // 27 Chinese chars = 81 bytes, which exceeds 80.
        let s = "\u{4e16}".repeat(27); // '世' repeated
        assert_eq!(s.len(), 81);
        let result = truncate_for_log(&s);
        // Should not panic and should truncate at a char boundary.
        assert!(result.ends_with("..."));
        // The truncated portion should be valid UTF-8 (it compiled, so it is).
        // Should contain 26 Chinese chars (78 bytes) + "..."
        let without_ellipsis = &result[..result.len() - 3];
        assert_eq!(without_ellipsis.len(), 78);
        assert_eq!(without_ellipsis.chars().count(), 26);
    }

    #[test]
    fn test_truncate_for_log_multibyte_emoji() {
        // Emoji like '😀' are 4 bytes each in UTF-8.
        // 20 emoji = 80 bytes exactly (should not be truncated).
        let s = "\u{1F600}".repeat(20);
        assert_eq!(s.len(), 80);
        let result = truncate_for_log(&s);
        assert_eq!(result, s);

        // 21 emoji = 84 bytes (should truncate at byte 80 = char boundary).
        let s2 = "\u{1F600}".repeat(21);
        assert_eq!(s2.len(), 84);
        let result2 = truncate_for_log(&s2);
        assert!(result2.ends_with("..."));
        let without_ellipsis = &result2[..result2.len() - 3];
        assert_eq!(without_ellipsis.len(), 80);
        assert_eq!(without_ellipsis.chars().count(), 20);
    }

    #[test]
    fn test_truncate_for_log_multibyte_split_boundary() {
        // 79 ASCII bytes + a 2-byte char = 81 bytes total.
        // Byte 80 is mid-char, so truncation should back up to byte 79.
        let mut s = "a".repeat(79);
        s.push('\u{00E9}'); // 'é' is 2 bytes in UTF-8
        assert_eq!(s.len(), 81);
        let result = truncate_for_log(&s);
        assert!(result.ends_with("..."));
        let without_ellipsis = &result[..result.len() - 3];
        // Should be the 79 ASCII chars (backed up from mid-char at byte 80).
        assert_eq!(without_ellipsis.len(), 79);
    }

    // ---------- Fix 6: Query string validation ----------

    #[test]
    fn test_query_with_at_sign_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat", Some("user@evil.com"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
        assert!(err.to_string().contains("query string"));
    }

    #[test]
    fn test_query_with_cr_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat", Some("foo\rbar"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
    }

    #[test]
    fn test_query_with_lf_rejected() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat", Some("foo\nbar"));
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
    }

    #[test]
    fn test_query_normal_accepted() {
        let result = resolve_upstream(
            &Provider::OpenAi,
            "/v1/chat",
            Some("model=gpt-4&stream=true"),
        );
        assert!(result.is_ok());
        let url = result.unwrap();
        assert!(url.contains("model=gpt-4"));
        assert!(url.contains("stream=true"));
    }

    #[test]
    fn test_query_empty_accepted() {
        let result = resolve_upstream(&Provider::OpenAi, "/v1/chat", Some(""));
        assert!(result.is_ok());
    }

    // ---------- Path traversal tests ----------

    #[test]
    fn test_path_traversal_with_admin_rejected() {
        let result = validate_path("/v1/../admin");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
        assert!(err.to_string().contains("traversal"));
    }

    #[test]
    fn test_path_with_double_dot_in_filename_allowed() {
        // `..` within a filename is fine; only exact `..` segments are rejected.
        let result = validate_path("/v1/path..name");
        assert!(result.is_ok());
    }

    #[test]
    fn test_path_trailing_double_dot_rejected() {
        let result = validate_path("/v1/..");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProxyError::InvalidPath { .. }));
        assert!(err.to_string().contains("traversal"));
    }
}
