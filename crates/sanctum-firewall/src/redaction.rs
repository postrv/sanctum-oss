//! Credential redaction engine.
//!
//! Scans text for known credential patterns and replaces them with safe
//! placeholder tokens. Each placeholder includes the credential type and a
//! 4-character SHA-256 hash prefix for traceability without leaking the secret.
//!
//! The engine is idempotent: redacting already-redacted text produces the same
//! output. Overlapping matches are resolved by preferring the most specific
//! pattern (patterns are ordered by specificity in [`crate::patterns::PATTERNS`]).

use std::collections::HashSet;
use std::fmt::Write as _;

use regex::Regex;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;

use crate::entropy::is_high_entropy_secret;
use crate::patterns::{CredentialPattern, PATTERNS};

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

/// Default entropy threshold (bits per character).
pub const DEFAULT_ENTROPY_THRESHOLD: f64 = 5.0;

/// Default minimum length for entropy-based secret detection.
pub const DEFAULT_ENTROPY_MIN_LENGTH: usize = 20;

// --- Known non-secret format patterns ---

/// Hex-only string of exactly 40 characters (e.g., Git SHA-1).
static RE_HEX_40: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{40}$").unwrap_or_else(|_| {
        std::process::abort();
    }));

/// Hex-only string of exactly 64 characters (e.g., Git SHA-256, file hash).
static RE_HEX_64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{64}$").unwrap_or_else(|_| {
        std::process::abort();
    }));

/// UUID format (with or without hyphens).
static RE_UUID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$").unwrap_or_else(|_| {
        std::process::abort();
    }));

/// Docker image digest format.
static RE_DOCKER_DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^sha256:[0-9a-fA-F]{64}$").unwrap_or_else(|_| {
        std::process::abort();
    }));

/// Base64-like string pattern for decode-and-rescan.
static RE_BASE64_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap_or_else(|_| {
        std::process::abort();
    }));

/// Check whether a string matches a known non-secret format.
#[must_use]
pub fn is_known_non_secret_format(s: &str) -> bool {
    if s.starts_with("data:") {
        return true;
    }
    if RE_DOCKER_DIGEST.is_match(s) {
        return true;
    }
    if RE_HEX_40.is_match(s) {
        return true;
    }
    if RE_HEX_64.is_match(s) {
        return true;
    }
    if RE_UUID.is_match(s) {
        return true;
    }
    false
}

/// Maximum decoded size for base64 decode-and-rescan (1 MB).
const MAX_BASE64_DECODED_SIZE: usize = 1_048_576;

/// Maximum recursion depth for base64 decode-and-rescan.
const MAX_BASE64_DECODE_DEPTH: usize = 2;

/// Attempt to base64-decode a token and scan the decoded content for
/// credential patterns.
fn try_base64_decode_and_rescan(
    token: &str,
    patterns: &[CredentialPattern],
    depth: usize,
) -> Option<RedactionEvent> {
    if depth >= MAX_BASE64_DECODE_DEPTH {
        return None;
    }
    if !RE_BASE64_TOKEN.is_match(token) {
        return None;
    }
    let estimated_decoded_size = (token.len() * 3) / 4;
    if estimated_decoded_size > MAX_BASE64_DECODED_SIZE {
        return None;
    }

    let decoded_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(token)
            .ok()?
    };
    if decoded_bytes.len() > MAX_BASE64_DECODED_SIZE {
        return None;
    }
    let decoded = String::from_utf8(decoded_bytes).ok()?;

    for pattern in patterns {
        if pattern.regex.is_match(&decoded) {
            let hash = Sha256::digest(token.as_bytes());
            let full_hex = hex::encode(hash);
            let hash_prefix = if full_hex.len() >= 4 {
                full_hex[..4].to_owned()
            } else {
                full_hex
            };
            return Some(RedactionEvent {
                credential_type: format!("Base64-Encoded {}", pattern.name),
                hash_prefix,
                start: 0,
                end: 0,
            });
        }
    }

    try_base64_decode_and_rescan(&decoded, patterns, depth + 1)
}

/// Check whether a value's SHA-256 hash is in the entropy allowlist.
fn is_allowlisted(allowlist: &HashSet<String>, value: &str) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    let hash = Sha256::digest(value.as_bytes());
    let hex_hash = hex::encode(hash);
    allowlist.contains(&hex_hash)
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
    redact_credentials_with_config(
        text,
        DEFAULT_ENTROPY_THRESHOLD,
        DEFAULT_ENTROPY_MIN_LENGTH,
        &HashSet::new(),
    )
}

/// Scan text for credentials with configurable entropy threshold and allowlist.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn redact_credentials_with_config(
    text: &str,
    threshold: f64,
    min_length: usize,
    entropy_allowlist: &HashSet<String>,
) -> (String, Vec<RedactionEvent>) {
    // Collect all matches across all patterns.
    let mut raw_matches: Vec<RawMatch> = Vec::new();

    for pattern in PATTERNS {
        for mat in pattern.regex.find_iter(text) {
            let matched = mat.as_str();
            // Filter out SSH FIDO key types (sk-ecdsa-*, sk-ed25519-*) that
            // false-positive against the OpenAI sk-* pattern.
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

    // Sort by start position, then by longest match first (more specific).
    raw_matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    // Resolve overlaps: greedily select non-overlapping matches, preferring
    // earlier start and longer span.
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
        // Append text before this match.
        if m.start > pos {
            result.push_str(&text[pos..m.start]);
        }

        // Compute hash prefix of the original secret.
        let hash = Sha256::digest(m.matched_text.as_bytes());
        let full_hex = hex::encode(hash);
        let hash_prefix = &full_hex[..4];

        // Append redaction placeholder.
        // write! on String is infallible, so the error can be safely ignored.
        let _ = write!(result, "[REDACTED:{}:{}]", m.credential_type, hash_prefix);

        events.push(RedactionEvent {
            credential_type: m.credential_type.to_owned(),
            hash_prefix: hash_prefix.to_owned(),
            start: m.start,
            end: m.end,
        });

        pos = m.end;
    }

    // Append any remaining text after the last match.
    if pos < text.len() {
        result.push_str(&text[pos..]);
    }

    // Base64 decode-and-rescan pass
    let mut b64_pass = String::with_capacity(result.len());
    for token in result.split_inclusive(|c: char| c.is_whitespace()) {
        let trimmed = token.trim_end();
        if !trimmed.starts_with("[REDACTED:") {
            if let Some(evt) = try_base64_decode_and_rescan(trimmed, PATTERNS, 0) {
                let _ = write!(
                    b64_pass,
                    "[REDACTED:{}:{}]",
                    evt.credential_type, evt.hash_prefix
                );
                let trailing = &token[trimmed.len()..];
                b64_pass.push_str(trailing);
                events.push(evt);
                continue;
            }
        }
        b64_pass.push_str(token);
    }

    // Entropy-based fallback: scan for high-entropy tokens that were not caught
    // by any regex pattern. Split on whitespace and check each token, skipping
    // tokens that are already redaction placeholders.
    let mut entropy_pass = String::with_capacity(b64_pass.len());
    for token in b64_pass.split_inclusive(|c: char| c.is_whitespace()) {
        // split_inclusive keeps the delimiter attached to the token, so strip
        // trailing whitespace for the entropy check but preserve it in output.
        let trimmed = token.trim_end();
        if !trimmed.starts_with("[REDACTED:")
            && !is_known_non_secret_format(trimmed)
            && !is_allowlisted(entropy_allowlist, trimmed)
            && is_high_entropy_secret(trimmed, threshold, min_length)
        {
            let hash = Sha256::digest(trimmed.as_bytes());
            let full_hex = hex::encode(hash);
            let hash_prefix = &full_hex[..4];
            let _ = write!(entropy_pass, "[POSSIBLE_SECRET_REDACTED:{hash_prefix}]");
            // Preserve trailing whitespace
            let trailing = &token[trimmed.len()..];
            entropy_pass.push_str(trailing);
            events.push(RedactionEvent {
                credential_type: "High-Entropy Secret".to_owned(),
                hash_prefix: hash_prefix.to_owned(),
                start: 0,
                end: 0,
            });
        } else {
            entropy_pass.push_str(token);
        }
    }

    (entropy_pass, events)
}

/// Like [`redact_credentials`] but skips the entropy-based fallback pass.
///
/// This is used when the caller knows the context makes entropy detection
/// unreliable (e.g., the value is under a key like `sha256`, `digest`, `nonce`,
/// etc. where high-entropy strings are expected and benign).
#[must_use]
pub fn redact_credentials_no_entropy(text: &str) -> (String, Vec<RedactionEvent>) {
    // Collect all matches across all patterns (same as redact_credentials).
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

    raw_matches.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));

    let mut selected: Vec<RawMatch> = Vec::new();
    let mut last_end: usize = 0;

    for m in raw_matches {
        if m.start >= last_end {
            last_end = m.end;
            selected.push(m);
        }
    }

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

    // NOTE: No entropy fallback pass -- that is the whole point of this variant.

    (result, events)
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
        // high-entropy (> 5.0 bits/char) and long enough to be flagged by the entropy fallback.
        let secret = "Kj7mPq2Xz9LwN5vR4Ts8BfCdGhYa6Ue1Wo";
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


    // ---- Task 2: Known-format exclusion tests ----

    #[test]
    fn git_sha1_not_flagged() {
        let sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
        let input = format!("commit: {sha1}");
        let (output, events) = redact_credentials(&input);
        assert!(output.contains(sha1));
        assert!(events.is_empty());
    }

    #[test]
    fn git_sha256_not_flagged() {
        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let input = format!("hash: {sha256}");
        let (output, events) = redact_credentials(&input);
        assert!(output.contains(sha256));
        assert!(events.is_empty());
    }

    #[test]
    fn uuid_with_hyphens_not_flagged() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let input = format!("id: {uuid}");
        let (output, events) = redact_credentials(&input);
        assert!(output.contains(uuid));
        assert!(events.is_empty());
    }

    #[test]
    fn uuid_without_hyphens_not_flagged() {
        let uuid = "550e8400e29b41d4a716446655440000";
        let input = format!("id: {uuid}");
        let (output, events) = redact_credentials(&input);
        assert!(output.contains(uuid));
        assert!(events.is_empty());
    }

    #[test]
    fn data_uri_not_flagged() {
        let data_uri = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg";
        let input = format!("src: {data_uri}");
        let (output, _events) = redact_credentials(&input);
        assert!(output.contains("data:image/png"));
    }

    #[test]
    fn docker_digest_not_flagged() {
        let d = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let input = format!("image: {d}");
        let (output, events) = redact_credentials(&input);
        assert!(output.contains(d));
        assert!(events.is_empty());
    }

    #[test]
    fn is_known_non_secret_format_unit_tests() {
        assert!(is_known_non_secret_format("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(is_known_non_secret_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(is_known_non_secret_format("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_known_non_secret_format("550e8400e29b41d4a716446655440000"));
        assert!(is_known_non_secret_format("data:image/png;base64,abc"));
        assert!(is_known_non_secret_format("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        assert!(!is_known_non_secret_format("some_random_string_here"));
        assert!(!is_known_non_secret_format("abcdef"));
    }

    // ---- Task 3: Base64 decode-and-rescan tests ----

    #[test]
    fn base64_encoded_aws_key_caught() {
        use base64::Engine;
        let aws_key = format!("{}IOSFODNN7EXAMPLE", "AKIA");
        let encoded = base64::engine::general_purpose::STANDARD.encode(&aws_key);
        let input = format!("token: {encoded}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&encoded));
        assert!(events.iter().any(|e| e.credential_type.contains("AWS")));
    }

    #[test]
    fn double_base64_encoded_credential_caught() {
        use base64::Engine;
        let aws_key = format!("{}IOSFODNN7EXAMPLE", "AKIA");
        let single = base64::engine::general_purpose::STANDARD.encode(&aws_key);
        let double = base64::engine::general_purpose::STANDARD.encode(&single);
        let input = format!("token: {double}");
        let (output, events) = redact_credentials(&input);
        assert!(!output.contains(&double));
        assert!(events.iter().any(|e| e.credential_type.contains("AWS")));
    }

    #[test]
    fn triple_base64_not_caught() {
        use base64::Engine;
        let aws_key = format!("{}IOSFODNN7EXAMPLE", "AKIA");
        let single = base64::engine::general_purpose::STANDARD.encode(&aws_key);
        let double = base64::engine::general_purpose::STANDARD.encode(&single);
        let triple = base64::engine::general_purpose::STANDARD.encode(&double);
        let input = format!("token: {triple}");
        let (_output, events) = redact_credentials(&input);
        assert!(!events.iter().any(|e| e.credential_type.contains("AWS")));
    }

    #[test]
    fn non_base64_string_ignored() {
        let input = "normal text without any base64 content";
        let (output, events) = redact_credentials(input);
        assert_eq!(output, input);
        assert!(events.is_empty());
    }

    #[test]
    fn normal_base64_not_flagged() {
        use base64::Engine;
        let data = "Hello, world! This is just normal text.";
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        let input = format!("data: {encoded}");
        let (_, events) = redact_credentials(&input);
        assert!(!events.iter().any(|e| e.credential_type.contains("Base64")));
    }

    // ---- Task 4: Configurable entropy threshold tests ----

    #[test]
    fn redact_with_config_custom_threshold() {
        let moderate = "abcdefghijklmnopqrstu";
        let input = format!("val: {moderate}");
        let (_output, events) = redact_credentials_with_config(&input, 2.0, 20, &HashSet::new());
        assert!(events.iter().any(|e| e.credential_type == "High-Entropy Secret"));
    }

    #[test]
    fn redact_with_config_custom_min_length() {
        let short = "Kj7mPq2Xz9LwN5vR4T";
        let input = format!("val: {short}");
        let (_, events) = redact_credentials_with_config(&input, 3.0, 25, &HashSet::new());
        assert!(!events.iter().any(|e| e.credential_type == "High-Entropy Secret"));
    }

    // ---- Task 5: Entropy allowlist tests ----

    #[test]
    fn allowlisted_value_not_flagged() {
        let secret = "Kj7mPq2Xz9LwN5vR4Ts8BfCdGhYa6Ue1Wo";
        let hash = Sha256::digest(secret.as_bytes());
        let hex_hash = hex::encode(hash);
        let mut allowlist = HashSet::new();
        allowlist.insert(hex_hash);
        let input = format!("config: {secret}");
        let (output, events) = redact_credentials_with_config(&input, 5.0, 20, &allowlist);
        assert!(output.contains(secret));
        assert!(!events.iter().any(|e| e.credential_type == "High-Entropy Secret"));
    }

    #[test]
    fn non_allowlisted_value_still_flagged() {
        let secret = "Kj7mPq2Xz9LwN5vR4Ts8BfCdGhYa6Ue1Wo";
        let input = format!("config: {secret}");
        let (output, events) = redact_credentials_with_config(&input, 5.0, 20, &HashSet::new());
        assert!(!output.contains(secret));
        assert!(events.iter().any(|e| e.credential_type == "High-Entropy Secret"));
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
}
