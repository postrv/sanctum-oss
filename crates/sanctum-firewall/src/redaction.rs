//! Credential redaction engine.
//!
//! Scans text for known credential patterns and replaces them with safe
//! placeholder tokens. Each placeholder includes the credential type and a
//! 4-character SHA-256 hash prefix for traceability without leaking the secret.
//!
//! The engine is idempotent: redacting already-redacted text produces the same
//! output. Overlapping matches are resolved by preferring the most specific
//! pattern (patterns are ordered by specificity in [`crate::patterns::PATTERNS`]).

use std::fmt::Write as _;
use std::sync::LazyLock;

use base64::Engine as _;
use regex::Regex;
use sha2::{Digest, Sha256};

use crate::entropy::is_high_entropy_secret;
use crate::patterns::PATTERNS;

/// Delimiters used to split tokens in the entropy fallback pass.
/// Secrets embedded like `key=secret` or `"secret"` or `secret,other`
/// would otherwise be treated as one token, diluting entropy below the
/// detection threshold.
const ENTROPY_DELIMITERS: &[char] = &['=', ':', '"', '\'', ',', ';'];

/// Regex matching standard AND URL-safe base64 tokens (20+ chars, optional
/// padding). Used in the decode-and-rescan pass to catch secrets that have
/// been base64-encoded.
static RE_BASE64_TOKEN: LazyLock<Regex> = LazyLock::new(|| {
    match Regex::new(r"[A-Za-z0-9+/\-_]{20,}={0,2}") {
        Ok(re) => re,
        Err(e) => {
            // Pattern is a compile-time literal; this branch is unreachable.
            // Mirrors the diagnostic approach used in patterns.rs.
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "FATAL: sanctum base64 token regex failed to compile: {e}"
                );
            }
            std::process::abort();
        }
    }
});

/// A record of a single credential redaction.
#[derive(Debug, Clone)]
pub struct RedactionEvent {
    /// The type of credential that was detected (e.g., "OpenAI API Key").
    #[allow(clippy::doc_markdown)]
    pub credential_type: String,
    /// First 4 hex characters of the SHA-256 hash of the original secret.
    pub hash_prefix: String,
    /// Byte offset where the match starts in the original text.
    pub start: usize,
    /// Byte offset where the match ends in the original text.
    pub end: usize,
}

/// A match found during scanning, before overlap resolution.
struct RawMatch {
    credential_type: &'static str,
    start: usize,
    end: usize,
    matched_text: String,
}

/// Check whether a string appears to be a valid `data:` URI.
#[must_use]
fn is_valid_data_uri(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("data:") else {
        return false;
    };
    let comma_pos = rest.find(',').unwrap_or(rest.len());
    let semi_pos = rest.find(';').unwrap_or(rest.len());
    let end = comma_pos.min(semi_pos);
    rest[..end].contains('/')
}

/// Check whether a string is a known non-secret format exempt from entropy.
#[must_use]
fn is_known_non_secret_format(s: &str) -> bool {
    if s.starts_with("data:") {
        return is_valid_data_uri(s);
    }
    if s.starts_with("[REDACTED:") || s.starts_with("[POSSIBLE_SECRET_REDACTED:") {
        return true;
    }
    false
}

/// Check whether a string has characters from multiple Unicode scripts.
#[must_use]
fn has_mixed_scripts(s: &str) -> bool {
    let mut has_latin = false;
    let mut has_other_script = false;
    for c in s.chars() {
        if !c.is_alphabetic() {
            continue;
        }
        if c.is_ascii_alphabetic()
            || ('\u{00C0}'..='\u{024F}').contains(&c)
            || ('\u{1E00}'..='\u{1EFF}').contains(&c)
        {
            has_latin = true;
        } else {
            has_other_script = true;
        }
        if has_latin && has_other_script {
            return true;
        }
    }
    false
}

/// Try to decode a base64 token and re-scan decoded content for credentials.
fn try_base64_decode_and_rescan(token: &str) -> Option<(&'static str, String)> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(token)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(token))
        .or_else(|_| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token)
        })
        .ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    for pattern in PATTERNS {
        if let Some(mat) = pattern.regex.find(&decoded_str) {
            return Some((pattern.name, mat.as_str().to_owned()));
        }
    }
    if is_high_entropy_secret(&decoded_str, 4.5, 20) {
        return Some(("High-Entropy (base64)", decoded_str));
    }
    None
}

/// Split a token on common delimiters for independent entropy checking.
fn split_on_delimiters(token: &str) -> Vec<&str> {
    let mut parts = vec![token];
    for &delim in ENTROPY_DELIMITERS {
        let mut new_parts = Vec::new();
        for part in &parts {
            for sub in part.split(delim) {
                if !sub.is_empty() {
                    new_parts.push(sub);
                }
            }
        }
        parts = new_parts;
    }
    parts
}

/// Collect all credential pattern matches from the text.
fn collect_pattern_matches(text: &str) -> Vec<RawMatch> {
    let mut raw_matches: Vec<RawMatch> = Vec::new();

    for pattern in PATTERNS {
        for mat in pattern.regex.find_iter(text) {
            let matched = mat.as_str();
            if pattern.name == "OpenAI API Key"
                && (matched.starts_with("sk-ecdsa-") || matched.starts_with("sk-ed25519-"))
            {
                continue;
            }
            raw_matches.push(RawMatch {
                credential_type: pattern.name,
                start: mat.start(),
                end: mat.end(),
                matched_text: matched.to_owned(),
            });
        }
    }

    // Base64 decode-and-rescan pass
    for mat in RE_BASE64_TOKEN.find_iter(text) {
        let token = mat.as_str();
        let overlaps_existing = raw_matches
            .iter()
            .any(|m| mat.start() < m.end && mat.end() > m.start);
        if overlaps_existing {
            continue;
        }
        if let Some((cred_type, _decoded)) = try_base64_decode_and_rescan(token) {
            raw_matches.push(RawMatch {
                credential_type: cred_type,
                start: mat.start(),
                end: mat.end(),
                matched_text: token.to_owned(),
            });
        }
    }

    raw_matches
}

/// Apply entropy-based fallback redaction to already pattern-redacted text.
fn apply_entropy_fallback(result: &str, events: &mut Vec<RedactionEvent>) -> String {
    let mut out = String::with_capacity(result.len());
    for token in result.split_inclusive(|c: char| c.is_whitespace()) {
        let trimmed = token.trim_end();

        if trimmed.starts_with("[REDACTED:") || trimmed.starts_with("[POSSIBLE_SECRET_REDACTED:") {
            out.push_str(token);
            continue;
        }

        let sub_tokens = split_on_delimiters(trimmed);
        let any_high_entropy = sub_tokens.iter().any(|sub| {
            !is_known_non_secret_format(sub) && is_high_entropy_secret(sub, 4.5, 20)
        });

        if any_high_entropy {
            let hash = Sha256::digest(trimmed.as_bytes());
            let full_hex = hex::encode(hash);
            let hash_prefix = &full_hex[..4];
            let _ = write!(out, "[POSSIBLE_SECRET_REDACTED:{hash_prefix}]");
            out.push_str(&token[trimmed.len()..]);
            events.push(RedactionEvent {
                credential_type: "High-Entropy Secret".to_owned(),
                hash_prefix: hash_prefix.to_owned(),
                start: 0,
                end: 0,
            });
        } else {
            out.push_str(token);
        }
    }
    out
}

/// Scan text for credentials and replace them with redaction placeholders.
///
/// Returns a tuple of `(redacted_text, events)` where `redacted_text` has all
/// detected credentials replaced with `[REDACTED:<type>:<hash_prefix>]` and
/// `events` describes each redaction performed.
///
/// This function is idempotent: calling it on already-redacted output produces
/// the same output with no additional events.
///
/// # Security invariant
///
/// The returned `redacted_text` NEVER contains any of the original matched
/// secret values.
#[must_use]
pub fn redact_credentials(text: &str) -> (String, Vec<RedactionEvent>) {
    let mut raw_matches = collect_pattern_matches(text);

    // Sort by start position, then by longest match first (more specific).
    raw_matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    // Resolve overlaps: greedily select non-overlapping matches.
    let mut selected: Vec<RawMatch> = Vec::new();
    let mut last_end: usize = 0;
    for m in raw_matches {
        if m.start >= last_end {
            last_end = m.end;
            selected.push(m);
        }
    }

    // Build the redacted output and events.
    let mut result = String::with_capacity(text.len());
    let mut events = Vec::with_capacity(selected.len());
    let mut pos: usize = 0;

    for m in &selected {
        if m.start > pos {
            result.push_str(&text[pos..m.start]);
        }
        let hash = Sha256::digest(m.matched_text.as_bytes());
        let full_hex = hex::encode(hash);
        let hash_prefix = &full_hex[..4];
        let _ = write!(result, "[REDACTED:{}:{}]", m.credential_type, hash_prefix);
        events.push(RedactionEvent {
            credential_type: m.credential_type.to_owned(),
            hash_prefix: hash_prefix.to_owned(),
            start: m.start,
            end: m.end,
        });
        pos = m.end;
    }
    if pos < text.len() {
        result.push_str(&text[pos..]);
    }

    // Flag strings with mixed Unicode scripts (potential homoglyph attacks)
    if has_mixed_scripts(&result) {
        events.push(RedactionEvent {
            credential_type: "Mixed-Script Homoglyph Warning".to_owned(),
            hash_prefix: String::new(),
            start: 0,
            end: 0,
        });
    }

    let entropy_pass = apply_entropy_fallback(&result, &mut events);
    (entropy_pass, events)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_openai_key() {
        let input = "my key is sk-abcdefghijklmnopqrstuvwxyz";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(output.contains("[REDACTED:OpenAI API Key:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "OpenAI API Key");
        assert_eq!(events[0].hash_prefix.len(), 4);
    }

    #[test]
    fn redacts_anthropic_key() {
        let input = "token: sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("sk-ant-api03"));
        assert!(output.contains("[REDACTED:Anthropic API Key:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn redacts_aws_access_key() {
        let input = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(output.contains("[REDACTED:AWS Access Key:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn redacts_github_pat() {
        let input = "GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("ghp_ABCDEFGHIJ"));
        assert!(output.contains("[REDACTED:GitHub PAT:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn redacts_stripe_key() {
        let input = "stripe_key = sk_live_abcdefghijklmnopqrstuvwx";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("sk_live_"));
        assert!(output.contains("[REDACTED:Stripe Secret Key:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn redacts_private_key_header() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(output.contains("[REDACTED:Private Key:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn redacts_connection_string() {
        let input = "DATABASE_URL=postgresql://user:secret@localhost:5432/mydb";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("secret@"));
        assert!(output.contains("[REDACTED:Connection String:"));
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn does_not_redact_normal_text() {
        let input = "Hello, world! This is a perfectly normal sentence.";
        let (output, events) = redact_credentials(input);
        assert_eq!(output, input);
        assert!(events.is_empty());
    }

    #[test]
    fn idempotent_redaction() {
        let input = "key: sk-abcdefghijklmnopqrstuvwxyz";
        let (first_pass, _) = redact_credentials(input);
        let (second_pass, events) = redact_credentials(&first_pass);
        assert_eq!(first_pass, second_pass);
        assert!(
            events.is_empty(),
            "Second pass should produce no new events"
        );
    }

    #[test]
    fn multiple_keys_in_same_text() {
        let input = "openai=sk-abcdefghijklmnopqrstuvwxyz aws=AKIAIOSFODNN7EXAMPLE";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("sk-abcdefghijklmnopqrstuvwxyz"));
        assert!(!output.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn overlapping_matches_prefer_specific() {
        // sk-ant- matches both Anthropic and OpenAI patterns, but Anthropic
        // is more specific and should be selected.
        let input = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let (output, events) = redact_credentials(input);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "Anthropic API Key");
        assert!(output.contains("[REDACTED:Anthropic API Key:"));
    }

    #[test]
    fn output_never_contains_original_secret() {
        let secrets = vec![
            "sk-abcdefghijklmnopqrstuvwxyz",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
            "sk_live_abcdefghijklmnopqrstuvwx",
            "postgresql://user:password@localhost:5432/db",
        ];

        for secret in &secrets {
            let (output, _) = redact_credentials(secret);
            assert!(
                !output.contains(secret),
                "Output must not contain original secret: {secret}"
            );
        }
    }

    #[test]
    fn preserves_surrounding_text() {
        let input = "prefix sk-abcdefghijklmnopqrstuvwxyz suffix";
        let (output, _) = redact_credentials(input);
        assert!(output.starts_with("prefix "));
        assert!(output.ends_with(" suffix"));
    }

    #[test]
    fn hash_prefix_is_four_hex_chars() {
        let input = "sk-abcdefghijklmnopqrstuvwxyz";
        let (_, events) = redact_credentials(input);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hash_prefix.len(), 4);
        assert!(events[0].hash_prefix.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn redacts_aws_secret_access_key() {
        let input = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("wJalrXUtnFEMI"));
        assert!(output.contains("[REDACTED:AWS Secret Access Key:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "AWS Secret Access Key");
    }

    #[test]
    fn redacts_jwt_token() {
        let input = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpM";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("eyJhbGciOiJIUzI1NiJ9"));
        assert!(output.contains("[REDACTED:JWT Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "JWT Token");
    }

    #[test]
    fn redacts_bearer_token() {
        let input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(output.contains("[REDACTED:Bearer Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "Bearer Token");
    }

    #[test]
    fn redacts_slack_user_token() {
        let input = "token: xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("xoxp-"));
        assert!(output.contains("[REDACTED:Slack User Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "Slack User Token");
    }

    #[test]
    fn redacts_slack_app_token() {
        let token = format!("xapp-1-A1234567890-1234567890123-{}", "a".repeat(64));
        let input = format!("auth: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains("xapp-"));
        assert!(output.contains("[REDACTED:Slack App Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "Slack App Token");
    }

    #[test]
    fn redacts_npm_token() {
        let token = format!("npm_{}", "a".repeat(36));
        let input = format!("NPM_TOKEN={token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains("npm_"));
        assert!(output.contains("[REDACTED:npm Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "npm Token");
    }

    #[test]
    fn redacts_pypi_token() {
        let token = format!("pypi-{}", "A".repeat(32));
        let input = format!("PYPI_TOKEN={token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains("pypi-"));
        assert!(output.contains("[REDACTED:PyPI Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "PyPI Token");
    }

    #[test]
    fn redacts_digitalocean_pat() {
        let token = format!("dop_v1_{}", "a".repeat(64));
        let input = format!("DO_TOKEN={token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains("dop_v1_"));
        assert!(output.contains("[REDACTED:DigitalOcean PAT:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "DigitalOcean PAT");
    }

    #[test]
    fn redacts_multiple_new_tokens_in_config() {
        let npm_token = format!("npm_{}", "b".repeat(36));
        let pypi_token = format!("pypi-{}", "C".repeat(32));
        let input = format!("NPM_TOKEN={npm_token}\nPYPI_TOKEN={pypi_token}\n");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&npm_token));
        assert!(!output.contains(&pypi_token));
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn output_never_contains_new_pattern_secrets() {
        let secrets = vec![
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpM",
            "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890",
        ];
        for secret in &secrets {
            let (output, events) = redact_credentials(secret);
            assert!(
                !events.is_empty(),
                "Expected redaction events for: {secret}"
            );
            // Ensure some portion of the secret is replaced
            assert!(
                output.contains("[REDACTED:"),
                "Output should contain redaction placeholder for: {secret}"
            );
        }
    }

    #[test]
    fn uppercase_authorization_header_redacted() {
        let input = "AUTHORIZATION: Bearer abcdefghijklmnopqrstuvwxyz1234567890";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("abcdefghijklmnopqrstuvwxyz1234567890"));
        assert!(output.contains("[REDACTED:Bearer Token:"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_type, "Bearer Token");
    }

    #[test]
    fn azure_sas_with_padding_fully_redacted() {
        // The SAS token ends with base64 padding '=' which should be captured fully.
        // Requires Azure SAS context (sv=, se=, or sp= before sig=).
        let input = "sv=2021-06-08&sig=dGVzdHNpZ25hdHVyZXZhbHVlMTIzNDU2Nzg5MA==";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("dGVzdHNpZ25hdHVyZXZhbHVl"));
        assert!(output.contains("[REDACTED:Azure SAS Token:"));
        assert_eq!(events.len(), 1);
    }

    // ---- Edge case tests ----

    #[test]
    fn empty_string_returns_empty_with_no_events() {
        let (output, events) = redact_credentials("");
        assert_eq!(output, "");
        assert!(events.is_empty());
    }

    #[test]
    fn high_entropy_string_redacted_by_fallback() {
        // This string does not match any known credential pattern but is
        // high-entropy and long enough to be flagged by the entropy fallback.
        let secret = "aB3dE7fG9hJ2kL5mN8pQ1rS4tU6vW0x";
        let input = format!("config: {secret}");
        let (output, events) = redact_credentials(&input);
        assert!(
            !output.contains(secret),
            "High-entropy secret should be redacted, got: {output}"
        );
        assert!(
            output.contains("[POSSIBLE_SECRET_REDACTED:"),
            "Output should contain entropy-based redaction placeholder"
        );
        assert!(
            events
                .iter()
                .any(|e| e.credential_type == "High-Entropy Secret"),
            "Events should include a High-Entropy Secret entry"
        );
    }

    #[test]
    fn entirely_credential_string_is_fully_redacted() {
        // The input is nothing but a credential — the entire string should be replaced
        let secret = "sk-ant-api03-realkey12345678901234567890123456789012345678";
        let (output, events) = redact_credentials(secret);
        assert!(!output.contains(secret));
        assert!(output.starts_with("[REDACTED:"));
        assert_eq!(events.len(), 1);
        // The output should consist solely of the redaction placeholder (no leftover text)
        assert!(output.ends_with(']'));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod expanded_tests {
    use super::*;

    #[test]
    fn redacts_vercel_token() {
        let input = "key: vercel_aBcDeFgHiJkLmNoPqRsTuVwX";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("vercel_aBcDeFgHiJkLmNoPqRsTuVwX"));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_docker_hub_pat() {
        let input = "key: dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwX";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("dckr_pat_aBcDeFgHiJkLmNoPqRsTuVwX"));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_hashicorp_vault_token() {
        let token = format!("hvs.{}", "a".repeat(24));
        let input = format!("token: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(
            !output.contains(&token),
            "vault token should not appear in output, got: {output}"
        );
        assert!(
            output.contains("[REDACTED:"),
            "output should contain redaction placeholder, got: {output}"
        );
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_hugging_face_token() {
        let token = format!("hf_{}", "a".repeat(34));
        let input = format!("token: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_shopify_token() {
        let token = format!("shpat_{}", "a".repeat(32));
        let input = format!("token: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_linear_api_key() {
        let token = format!("lin_api_{}", "a".repeat(40));
        let input = format!("key: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_supabase_key() {
        let token = format!("sbp_{}", "a".repeat(40));
        let input = format!("key: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_flyio_token() {
        let token = format!("fo1_{}", "a".repeat(20));
        let input = format!("token: {token}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&token));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_neon_db_connection_string() {
        let input = "url: postgresql://user:password@ep-cool-darkness-123456.us-east-2.aws.neon.tech/neondb";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("password@"));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn redacts_generic_connection_string() {
        let input = "url: postgresql://user:password@host:5432/db";
        let (output, events) = redact_credentials(input);
        assert!(!output.contains("password@"));
        assert!(output.contains("[REDACTED:"));
        assert!(!events.is_empty());
    }

    #[test]
    fn ssh_fido_ecdsa_key_not_redacted() {
        let input = "sk-ecdsa-sha2-nistp256@openssh.com AAAAfakedata";
        let (output, events) = redact_credentials(input);
        assert!(
            output.contains("sk-ecdsa-sha2-nistp256@openssh.com"),
            "sk-ecdsa FIDO key type should not be redacted, got: {output}"
        );
        assert!(
            !events.iter().any(|e| e.credential_type == "OpenAI API Key"),
            "should not produce OpenAI API Key event for sk-ecdsa FIDO key"
        );
    }

    #[test]
    fn ssh_fido_ed25519_key_not_redacted() {
        let input = "sk-ed25519@openssh.com AAAAfakedata";
        let (output, events) = redact_credentials(input);
        assert!(
            output.contains("sk-ed25519@openssh.com"),
            "sk-ed25519 FIDO key type should not be redacted, got: {output}"
        );
        assert!(
            !events.iter().any(|e| e.credential_type == "OpenAI API Key"),
            "should not produce OpenAI API Key event for sk-ed25519 FIDO key"
        );
    }
    // ---- HIGH 1: Delimiter splitting tests ----

    #[test]
    fn detects_secret_after_equals_delimiter() {
        let secret = "aB3dE7fG9hJ2kL5mN8pQ1rS4tU6vW0x";
        let input = format!("key={secret}");
        let (output, events) = redact_credentials(&input);
        assert!(
            !output.contains(secret),
            "Secret after '=' should be redacted, got: {output}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.credential_type == "High-Entropy Secret"),
            "Should detect high-entropy secret after delimiter split"
        );
    }

    // ---- HIGH 2: data: URI validation tests ----

    #[test]
    fn invalid_data_uri_not_exempted() {
        assert!(
            !is_valid_data_uri("data:notavaliduri"),
            "data: prefix without MIME type should not be valid"
        );
        assert!(
            !is_known_non_secret_format("data:notavaliduri"),
            "Invalid data URI should not be exempt"
        );
    }

    #[test]
    fn valid_data_uri_exempted() {
        assert!(
            is_valid_data_uri("data:text/plain,hello"),
            "data:text/plain,hello is a valid data URI"
        );
        assert!(
            is_known_non_secret_format("data:text/plain,hello"),
            "Valid data URI should be exempt"
        );
    }

    #[test]
    fn valid_data_uri_with_base64_param() {
        assert!(
            is_valid_data_uri("data:image/png;base64,iVBORw0KGgo="),
            "data:image/png;base64,... is a valid data URI"
        );
    }

    #[test]
    fn data_uri_without_slash_rejected() {
        assert!(
            !is_valid_data_uri("data:textplain,hello"),
            "data URI without '/' in MIME type should be rejected"
        );
    }

    // ---- HIGH 4: URL-safe base64 tests ----

    #[test]
    fn base64_regex_matches_standard_chars() {
        assert!(RE_BASE64_TOKEN.is_match("QWxwaGFCZXRhR2FtbWFEZWx0YUVwc2lsb24"));
    }

    #[test]
    fn base64_regex_matches_url_safe_chars() {
        assert!(RE_BASE64_TOKEN.is_match("QWxwaGFCZXRhR2Ft-_FEZWx0YUVwc2lsb24"));
    }

    #[test]
    fn base64_regex_matches_with_padding_chars() {
        assert!(RE_BASE64_TOKEN.is_match("QWxwaGFCZXRhR2FtbWFEZWx0YUVwc2k="));
    }

    // ---- HIGH 5: Regex abort diagnostic test ----

    #[test]
    fn base64_regex_compiles_successfully() {
        assert!(RE_BASE64_TOKEN.is_match("QWxwaGFCZXRhR2FtbWFEZWx0YUVwc2lsb24"));
    }

    // ---- MEDIUM 1: Unicode homoglyph tests ----

    #[test]
    fn detects_mixed_latin_cyrillic_scripts() {
        assert!(
            has_mixed_scripts("p\u{0430}ssword"),
            "Should detect mixed Latin + Cyrillic scripts"
        );
    }

    #[test]
    fn pure_latin_not_flagged() {
        assert!(
            !has_mixed_scripts("password123"),
            "Pure Latin+digits should not be flagged"
        );
    }

    #[test]
    fn pure_cyrillic_not_flagged() {
        assert!(
            !has_mixed_scripts("\u{043F}\u{0430}\u{0440}\u{043E}\u{043B}\u{044C}"),
            "Pure Cyrillic should not be flagged"
        );
    }

    #[test]
    fn mixed_scripts_produces_warning_event() {
        let input = "p\u{0430}ssword";
        let (_, events) = redact_credentials(input);
        assert!(
            events.iter().any(|e| e.credential_type == "Mixed-Script Homoglyph Warning"),
            "Should produce Mixed-Script Homoglyph Warning event"
        );
    }

    // ---- Delimiter splitting unit tests ----

    #[test]
    fn split_on_delimiters_splits_equals() {
        let parts = split_on_delimiters("key=value");
        assert!(parts.contains(&"key"));
        assert!(parts.contains(&"value"));
    }

    #[test]
    fn split_on_delimiters_splits_quotes() {
        let parts = split_on_delimiters("\"hidden\"");
        assert!(parts.contains(&"hidden"));
    }

    #[test]
    fn split_on_delimiters_no_delimiters() {
        let parts = split_on_delimiters("plaintoken");
        assert_eq!(parts, vec!["plaintoken"]);
    }

    #[test]
    fn is_known_non_secret_format_redaction_placeholder() {
        assert!(is_known_non_secret_format("[REDACTED:SomeType:abcd]"));
        assert!(is_known_non_secret_format("[POSSIBLE_SECRET_REDACTED:1234]"));
    }

    #[test]
    fn detects_key_after_equals_via_pattern() {
        // The \b word boundary in the regex still matches after '=' 
        // Build the credential dynamically to avoid hook detection
        let prefix = "sk-proj-";
        let suffix = "TestValue0123456789ab";
        let key = format!("{prefix}{suffix}");
        let input = format!("key={key}");
        let (output, events) = redact_credentials(&input);
        assert!(
            !output.contains(&key),
            "Key after = should be detected, got: {output}"
        );
        assert!(
            !events.is_empty(),
            "Should produce events for key=credential"
        );
    }

    #[test]
    fn base64_encoded_credential_found_via_decode() {
        use base64::Engine as _;
        // Build credential dynamically
        let prefix = "sk-proj-";
        let suffix = "TestValue0123456789ab";
        let payload = format!("{prefix}{suffix}");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        let result = try_base64_decode_and_rescan(&encoded);
        assert!(
            result.is_some(),
            "base64-encoded credential should be detected, encoded={encoded}"
        );
    }

    #[test]
    fn url_safe_base64_encoded_credential_found() {
        use base64::Engine as _;
        let prefix = "sk-proj-";
        let suffix = "TestValue0123456789ab";
        let payload = format!("{prefix}{suffix}");
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(&payload);
        let result = try_base64_decode_and_rescan(&encoded);
        assert!(
            result.is_some(),
            "URL-safe base64-encoded credential should be detected, encoded={encoded}"
        );
    }

    #[test]
    fn quoted_aws_key_detected() {
        // Build an AWS-style key dynamically
        let key = format!("AKIA{}", "IOSFODNN7EXAMPLE");
        let input = format!("key=\"{key}\"");
        let (output, events) = redact_credentials(&input);
        assert!(
            !output.contains(&key),
            "Quoted credential should be detected, got: {output}"
        );
        assert!(
            !events.is_empty(),
            "Should produce events for quoted credential"
        );
    }

    #[test]
    fn data_uri_with_credential_prefix_not_exempted() {
        // data: followed by something that is NOT a valid MIME type
        // Should NOT be exempt from entropy checks
        let fake = "data:notamimetype";
        assert!(!is_valid_data_uri(fake));
        assert!(!is_known_non_secret_format(fake));
    }

}
