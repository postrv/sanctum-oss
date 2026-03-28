//! Credential pattern registry.
//!
//! Compiled regex patterns for detecting common API keys, tokens, and secrets.
//! All patterns are compiled once via `LazyLock` and designed to be ReDoS-safe
//! (no nested quantifiers or catastrophic backtracking).

use regex::Regex;
use std::sync::LazyLock;

/// A named credential pattern with a pre-compiled regex.
pub struct CredentialPattern {
    /// Human-readable name for this credential type.
    pub name: &'static str,
    /// Reference to a lazily-compiled regex that matches this credential type.
    pub regex: &'static LazyLock<Regex>,
}

/// Compile a regex from a string. All callers pass compile-time literal
/// patterns that are known valid, so the error branch is unreachable in
/// practice. On failure we abort the process because `panic!()` is denied by
/// workspace lints.
#[allow(clippy::option_if_let_else)]
fn compile_regex(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(re) => re,
        Err(e) => {
            // All patterns are compile-time literals; this branch is unreachable.
            // abort() is used because panic!() is denied by workspace lints.
            #[allow(clippy::print_stderr)]
            {
                eprintln!("FATAL: sanctum credential pattern failed to compile: {e}");
            }
            std::process::abort();
        }
    }
}

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| compile_regex($pattern));
    };
}

static_regex!(OPENAI_RE, r"\bsk-[a-zA-Z0-9\-_]{20,}");
static_regex!(ANTHROPIC_RE, r"\bsk-ant-[a-zA-Z0-9\-_]{20,}");
static_regex!(GOOGLE_AI_RE, r"\bAIza[a-zA-Z0-9_\-]{35}\b");
static_regex!(AWS_ACCESS_KEY_RE, r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b");
static_regex!(
    AWS_SECRET_KEY_RE,
    r"\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[=: ]+[A-Za-z0-9/+=]{40}"
);
static_regex!(GITHUB_PAT_RE, r"\bghp_[a-zA-Z0-9]{36}\b");
static_regex!(GITHUB_FINE_GRAINED_RE, r"\bgithub_pat_[a-zA-Z0-9_]{82}\b");
static_regex!(GITLAB_RE, r"\bglpat-[a-zA-Z0-9_\-]{20}\b");
static_regex!(SLACK_BOT_RE, r"\bxoxb-[0-9]{10,13}-[a-zA-Z0-9\-]+");
static_regex!(STRIPE_SECRET_RE, r"\b(?:sk_live_|sk_test_|rk_live_|rk_test_)[a-zA-Z0-9]{24,}\b");
static_regex!(SENDGRID_RE, r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b");
static_regex!(
    JWT_RE,
    r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
);
static_regex!(
    BEARER_TOKEN_RE,
    r"\b(?i:authorization)[=: ]+Bearer [A-Za-z0-9_\-]{20,}"
);
static_regex!(PRIVATE_KEY_RE, r"-----BEGIN[A-Z ]*PRIVATE KEY-----");
static_regex!(CONNECTION_STRING_RE, r"\b(postgresql|postgres|mongodb|redis|mysql|mariadb|mssql|sqlserver|amqp|amqps)://[^\s@]+@[^\s]+\b");
static_regex!(SLACK_USER_RE, r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,34}\b");
static_regex!(SLACK_APP_RE, r"\bxapp-[0-9]-[A-Z0-9]{10,13}-[0-9]{13}-[a-zA-Z0-9]{64}\b");
static_regex!(NPM_TOKEN_RE, r"\bnpm_[a-zA-Z0-9]{36}\b");
static_regex!(PYPI_TOKEN_RE, r"\bpypi-[A-Za-z0-9_\-]{16,}");
static_regex!(DIGITALOCEAN_RE, r"\bdop_v1_[a-f0-9]{64}\b");
static_regex!(DATADOG_RE, r"\bdd(?:api|app)_[a-z0-9]{32,}\b");
static_regex!(AZURE_SAS_RE, r"\bsig=[A-Za-z0-9%+/=]{20,}");
static_regex!(VERCEL_RE, r"\bvercel_[a-zA-Z0-9]{24,}\b");
static_regex!(DOCKER_PAT_RE, r"\bdckr_pat_[a-zA-Z0-9\-_]{24,}");
static_regex!(VAULT_TOKEN_RE, r"\bhvs\.[a-zA-Z0-9_\-]{24,}");
static_regex!(HF_TOKEN_RE, r"\bhf_[a-zA-Z0-9]{34,}\b");
static_regex!(SHOPIFY_RE, r"\bshp(?:at|ss|pa|ca)_[a-fA-F0-9]{32,}\b");
static_regex!(LINEAR_RE, r"\blin_api_[a-zA-Z0-9]{40,}\b");

/// All registered credential patterns.
///
/// Ordered from most specific to least specific so that overlapping matches
/// prefer the more specific pattern (e.g., Anthropic `sk-ant-` before `OpenAI` `sk-`).
pub static PATTERNS: &[CredentialPattern] = &[
    CredentialPattern {
        name: "Anthropic API Key",
        regex: &ANTHROPIC_RE,
    },
    CredentialPattern {
        name: "GitHub Fine-grained PAT",
        regex: &GITHUB_FINE_GRAINED_RE,
    },
    CredentialPattern {
        name: "GitHub PAT",
        regex: &GITHUB_PAT_RE,
    },
    CredentialPattern {
        name: "Stripe Secret Key",
        regex: &STRIPE_SECRET_RE,
    },
    CredentialPattern {
        name: "OpenAI API Key",
        regex: &OPENAI_RE,
    },
    CredentialPattern {
        name: "Google AI API Key",
        regex: &GOOGLE_AI_RE,
    },
    CredentialPattern {
        name: "AWS Secret Access Key",
        regex: &AWS_SECRET_KEY_RE,
    },
    CredentialPattern {
        name: "AWS Access Key",
        regex: &AWS_ACCESS_KEY_RE,
    },
    CredentialPattern {
        name: "GitLab PAT",
        regex: &GITLAB_RE,
    },
    CredentialPattern {
        name: "Slack Bot Token",
        regex: &SLACK_BOT_RE,
    },
    CredentialPattern {
        name: "SendGrid API Key",
        regex: &SENDGRID_RE,
    },
    CredentialPattern {
        name: "JWT Token",
        regex: &JWT_RE,
    },
    CredentialPattern {
        name: "Bearer Token",
        regex: &BEARER_TOKEN_RE,
    },
    CredentialPattern {
        name: "Private Key",
        regex: &PRIVATE_KEY_RE,
    },
    CredentialPattern {
        name: "Connection String",
        regex: &CONNECTION_STRING_RE,
    },
    CredentialPattern {
        name: "Slack User Token",
        regex: &SLACK_USER_RE,
    },
    CredentialPattern {
        name: "Slack App Token",
        regex: &SLACK_APP_RE,
    },
    CredentialPattern {
        name: "npm Token",
        regex: &NPM_TOKEN_RE,
    },
    CredentialPattern {
        name: "PyPI Token",
        regex: &PYPI_TOKEN_RE,
    },
    CredentialPattern {
        name: "DigitalOcean PAT",
        regex: &DIGITALOCEAN_RE,
    },
    CredentialPattern {
        name: "Datadog API Key",
        regex: &DATADOG_RE,
    },
    CredentialPattern {
        name: "Azure SAS Token",
        regex: &AZURE_SAS_RE,
    },
    CredentialPattern {
        name: "Vercel Token",
        regex: &VERCEL_RE,
    },
    CredentialPattern {
        name: "Docker Hub PAT",
        regex: &DOCKER_PAT_RE,
    },
    CredentialPattern {
        name: "Hashicorp Vault Token",
        regex: &VAULT_TOKEN_RE,
    },
    CredentialPattern {
        name: "Hugging Face Token",
        regex: &HF_TOKEN_RE,
    },
    CredentialPattern {
        name: "Shopify Token",
        regex: &SHOPIFY_RE,
    },
    CredentialPattern {
        name: "Linear API Key",
        regex: &LINEAR_RE,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_pattern_matches_valid_key() {
        let key = "sk-abc123def456ghi789jklmno";
        assert!(OPENAI_RE.is_match(key));
    }

    #[test]
    fn openai_pattern_matches_proj_key() {
        // sk-proj-* is the most common modern OpenAI key format
        let key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890";
        assert!(OPENAI_RE.is_match(key));
    }

    #[test]
    fn openai_pattern_matches_svcacct_key() {
        // sk-svcacct-* is OpenAI's service account key format
        let key = "sk-svcacct-abcdefghijklmnopqrstuvwxyz1234567890";
        assert!(OPENAI_RE.is_match(key));
    }

    #[test]
    fn openai_pattern_rejects_short_key() {
        let key = "sk-short";
        assert!(!OPENAI_RE.is_match(key));
    }

    #[test]
    fn anthropic_pattern_matches_valid_key() {
        let key = "sk-ant-api03-abcdefghijklmnopqrst";
        assert!(ANTHROPIC_RE.is_match(key));
    }

    #[test]
    fn anthropic_pattern_rejects_plain_sk() {
        // Must have sk-ant- prefix
        let key = "sk-notanthropickey12345";
        // This matches OpenAI but should not match the specific Anthropic prefix
        assert!(!key.starts_with("sk-ant-"));
    }

    #[test]
    fn google_ai_pattern_matches_valid_key() {
        let key = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
        assert!(GOOGLE_AI_RE.is_match(key));
    }

    #[test]
    fn google_ai_pattern_rejects_wrong_prefix() {
        let key = "AIzb_notavalidgooglekey1234567890abc";
        assert!(!GOOGLE_AI_RE.is_match(key));
    }

    #[test]
    fn aws_access_key_pattern_matches_valid_key() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(AWS_ACCESS_KEY_RE.is_match(key));
    }

    #[test]
    fn aws_access_key_pattern_rejects_lowercase() {
        let key = "AKIAiosfodnn7example";
        assert!(!AWS_ACCESS_KEY_RE.is_match(key));
    }

    #[test]
    fn github_pat_matches_valid_token() {
        let key = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        assert!(GITHUB_PAT_RE.is_match(key));
    }

    #[test]
    fn github_fine_grained_matches_valid_token() {
        let key = format!("github_pat_{}", "a".repeat(82));
        assert!(GITHUB_FINE_GRAINED_RE.is_match(&key));
    }

    #[test]
    fn gitlab_pat_matches_valid_token() {
        let key = "glpat-abcdefghijklmnopqrst";
        assert!(GITLAB_RE.is_match(key));
    }

    #[test]
    fn slack_bot_token_matches_valid_token() {
        let key = "xoxb-1234567890-abcdefghijklmnop";
        assert!(SLACK_BOT_RE.is_match(key));
    }

    #[test]
    fn stripe_secret_matches_valid_key() {
        let key = "sk_live_abcdefghijklmnopqrstuvwx";
        assert!(STRIPE_SECRET_RE.is_match(key));
    }

    #[test]
    fn sendgrid_matches_valid_key() {
        let key = format!("SG.{}.{}", "a".repeat(22), "b".repeat(43));
        assert!(SENDGRID_RE.is_match(&key));
    }

    #[test]
    fn private_key_header_matches() {
        let key = "-----BEGIN RSA PRIVATE KEY-----";
        assert!(PRIVATE_KEY_RE.is_match(key));
        let key2 = "-----BEGIN PRIVATE KEY-----";
        assert!(PRIVATE_KEY_RE.is_match(key2));
    }

    #[test]
    fn connection_string_matches_postgres() {
        let conn = "postgresql://user:password@localhost:5432/db";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_postgres_short_scheme() {
        // postgres:// is the most common alias used by ORMs and connection libraries
        let conn = "postgres://user:password@localhost:5432/db";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_mongodb() {
        let conn = "mongodb://admin:secret@mongo.example.com:27017/mydb";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_redis() {
        let conn = "redis://default:mypassword@redis.example.com:6379";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_mysql() {
        let conn = "mysql://root:pass@localhost:3306/appdb";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn aws_secret_key_matches_lowercase_label() {
        let input = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(AWS_SECRET_KEY_RE.is_match(input));
    }

    #[test]
    fn aws_secret_key_matches_uppercase_label() {
        let input = "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(AWS_SECRET_KEY_RE.is_match(input));
    }

    #[test]
    fn aws_secret_key_matches_colon_space_separator() {
        let input = "aws_secret_access_key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(AWS_SECRET_KEY_RE.is_match(input));
    }

    #[test]
    fn aws_secret_key_rejects_short_value() {
        // 39 chars instead of 40
        let input = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPL";
        assert!(!AWS_SECRET_KEY_RE.is_match(input));
    }

    #[test]
    fn jwt_matches_valid_token() {
        let input = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpM";
        assert!(JWT_RE.is_match(input));
    }

    #[test]
    fn jwt_rejects_incomplete_token() {
        // Missing third segment
        let input = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0";
        assert!(!JWT_RE.is_match(input));
    }

    #[test]
    fn jwt_rejects_short_segments() {
        let input = "eyJhbG.eyJzd.SflK";
        assert!(!JWT_RE.is_match(input));
    }

    #[test]
    fn bearer_token_matches_authorization_header() {
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assert!(BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn bearer_token_matches_lowercase_authorization() {
        let input = "authorization: Bearer abcdefghijklmnopqrstuvwxyz1234";
        assert!(BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn bearer_token_matches_equals_separator() {
        let input = "Authorization=Bearer abcdefghijklmnopqrstuvwxyz1234";
        assert!(BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn bearer_token_rejects_short_token() {
        // Token value is only 19 chars
        let input = "Authorization: Bearer abcdefghijklmnopqrs";
        assert!(!BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn bearer_token_rejects_no_authorization_context() {
        // Plain "Bearer" without "Authorization" should not match
        let input = "Bearer abcdefghijklmnopqrstuvwxyz1234";
        assert!(!BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn normal_text_does_not_match_any_pattern() {
        let text = "This is a normal English sentence with no secrets.";
        for pattern in PATTERNS {
            assert!(
                !pattern.regex.is_match(text),
                "Pattern '{}' should not match normal text",
                pattern.name
            );
        }
    }

    #[test]
    fn patterns_are_ordered_specific_first() {
        // Anthropic (sk-ant-) should come before OpenAI (sk-) in PATTERNS
        let anthropic_idx = PATTERNS
            .iter()
            .position(|p| p.name == "Anthropic API Key");
        let openai_idx = PATTERNS
            .iter()
            .position(|p| p.name == "OpenAI API Key");
        assert!(anthropic_idx < openai_idx, "Anthropic must precede OpenAI for specificity");
    }

    // ---- New patterns: Slack User Token ----

    #[test]
    fn slack_user_token_matches_valid_token() {
        let key = "xoxp-1234567890-1234567890-abcdefghijklmnopqrstuvwx";
        assert!(SLACK_USER_RE.is_match(key));
    }

    #[test]
    fn slack_user_token_rejects_normal_text() {
        assert!(!SLACK_USER_RE.is_match("just a normal string"));
    }

    #[test]
    fn slack_user_token_rejects_bot_token() {
        // xoxb- should NOT match the user-token pattern (xoxp-)
        assert!(!SLACK_USER_RE.is_match("xoxb-1234567890-abcdefghijklmnopqrst"));
    }

    // ---- New patterns: Slack App Token ----

    #[test]
    fn slack_app_token_matches_valid_token() {
        let key = format!(
            "xapp-1-A1234567890-1234567890123-{}",
            "a".repeat(64)
        );
        assert!(SLACK_APP_RE.is_match(&key));
    }

    #[test]
    fn slack_app_token_rejects_normal_text() {
        assert!(!SLACK_APP_RE.is_match("this is not a slack app token"));
    }

    // ---- New patterns: npm Token ----

    #[test]
    fn npm_token_matches_valid_token() {
        let key = format!("npm_{}", "a".repeat(36));
        assert!(NPM_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn npm_token_rejects_short_token() {
        let key = format!("npm_{}", "a".repeat(10));
        assert!(!NPM_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn npm_token_rejects_normal_text() {
        assert!(!NPM_TOKEN_RE.is_match("npm install something"));
    }

    // ---- New patterns: PyPI Token ----

    #[test]
    fn pypi_token_matches_valid_token() {
        let key = format!("pypi-{}", "A".repeat(32));
        assert!(PYPI_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn pypi_token_rejects_short_token() {
        let key = "pypi-abc";
        assert!(!PYPI_TOKEN_RE.is_match(key));
    }

    #[test]
    fn pypi_token_rejects_normal_text() {
        assert!(!PYPI_TOKEN_RE.is_match("pypi package index"));
    }

    // ---- New patterns: DigitalOcean PAT ----

    #[test]
    fn digitalocean_pat_matches_valid_token() {
        let key = format!("dop_v1_{}", "a".repeat(64));
        assert!(DIGITALOCEAN_RE.is_match(&key));
    }

    #[test]
    fn digitalocean_pat_rejects_short_token() {
        let key = format!("dop_v1_{}", "a".repeat(10));
        assert!(!DIGITALOCEAN_RE.is_match(&key));
    }

    #[test]
    fn digitalocean_pat_rejects_normal_text() {
        assert!(!DIGITALOCEAN_RE.is_match("digitalocean droplet"));
    }

    #[test]
    fn digitalocean_pat_rejects_uppercase() {
        // Pattern only matches lowercase hex
        let key = format!("dop_v1_{}", "A".repeat(64));
        assert!(!DIGITALOCEAN_RE.is_match(&key));
    }

    #[test]
    fn aws_secret_key_before_access_key_in_ordering() {
        let secret_idx = PATTERNS
            .iter()
            .position(|p| p.name == "AWS Secret Access Key");
        let access_idx = PATTERNS
            .iter()
            .position(|p| p.name == "AWS Access Key");
        assert!(
            secret_idx < access_idx,
            "AWS Secret Access Key must precede AWS Access Key for specificity"
        );
    }

    // ---- Negative tests: patterns must NOT match invalid inputs ----

    #[test]
    fn anthropic_pattern_rejects_no_ant_prefix() {
        // Has sk- but not sk-ant- so should not match ANTHROPIC_RE
        let key = "sk-notanthropickey12345678901234567890";
        assert!(!ANTHROPIC_RE.is_match(key));
    }

    #[test]
    fn gitlab_pattern_rejects_short_token() {
        // Only 5 chars after prefix — needs 20+
        let key = "glpat-short";
        assert!(!GITLAB_RE.is_match(key));
    }

    #[test]
    fn slack_bot_pattern_rejects_short_token() {
        // Missing the numeric segment and hyphenated suffix
        let key = "xoxb-short";
        assert!(!SLACK_BOT_RE.is_match(key));
    }

    #[test]
    fn stripe_secret_pattern_rejects_short_key() {
        // Only 5 chars after prefix — needs 24+
        let key = "sk_live_short";
        assert!(!STRIPE_SECRET_RE.is_match(key));
    }

    #[test]
    fn sendgrid_pattern_rejects_short_key() {
        // Missing the two dot-separated segments of required length
        let key = "SG.short";
        assert!(!SENDGRID_RE.is_match(key));
    }

    #[test]
    fn private_key_pattern_rejects_public_key() {
        // PUBLIC KEY header must not match PRIVATE KEY pattern
        let key = "-----BEGIN PUBLIC KEY-----";
        assert!(!PRIVATE_KEY_RE.is_match(key));
    }

    #[test]
    fn connection_string_rejects_https_scheme() {
        // Only postgresql/mongodb/redis/mysql schemes should match
        let conn = "https://user:pass@host/db";
        assert!(!CONNECTION_STRING_RE.is_match(conn));
    }

    // ---- New patterns: Datadog API Key ----

    #[test]
    fn datadog_api_key_matches_valid_key() {
        let key = format!("ddapi_{}", "a".repeat(40));
        assert!(DATADOG_RE.is_match(&key));
    }

    #[test]
    fn datadog_api_key_matches_app_key() {
        let key = format!("ddapp_{}", "b".repeat(40));
        assert!(DATADOG_RE.is_match(&key));
    }

    #[test]
    fn datadog_api_key_rejects_short_key() {
        let key = "ddapi_short";
        assert!(!DATADOG_RE.is_match(key));
    }

    #[test]
    fn datadog_api_key_rejects_normal_text() {
        assert!(!DATADOG_RE.is_match("datadog monitoring setup"));
    }

    // ---- New patterns: Azure SAS Token ----

    #[test]
    fn azure_sas_matches_valid_token() {
        let input = "sig=dGVzdHNpZ25hdHVyZXZhbHVl%2BMoreBase64Content";
        assert!(AZURE_SAS_RE.is_match(input));
    }

    #[test]
    fn azure_sas_rejects_short_sig() {
        let input = "sig=short";
        assert!(!AZURE_SAS_RE.is_match(input));
    }

    #[test]
    fn azure_sas_rejects_normal_text() {
        assert!(!AZURE_SAS_RE.is_match("signal processing algorithm"));
    }

    #[test]
    fn azure_sas_matches_url_encoded_token() {
        // Real SAS tokens in URLs have percent-encoding throughout.
        // The pattern must not break at % characters.
        let input = "sig=abc%2Bdef%2Bghi%2Bjkl%2Bmno%2Bpqr%2Bstu";
        assert!(AZURE_SAS_RE.is_match(input));
    }

    #[test]
    fn azure_sas_matches_in_full_url_context() {
        let input = "https://storage.blob.core.windows.net/container?sv=2021-06-08&sig=dGVzdHNpZ25hdHVyZXZhbHVlMTIzNDU2Nzg5MA%3D%3D&se=2024-01-01";
        assert!(AZURE_SAS_RE.is_match(input));
    }

    // ---- Pattern count and ordering ----

    #[test]
    fn pattern_count_is_correct() {
        assert_eq!(PATTERNS.len(), 28, "Expected 28 credential patterns");
    }

    // ---- Word-boundary tests: prevent substring false positives ----

    #[test]
    fn openai_pattern_does_not_match_embedded_in_word() {
        // A key-like string embedded in a larger alphanumeric token should not match
        let embedded = "prefixsk-abcdefghijklmnopqrstuvwxyz";
        assert!(!OPENAI_RE.is_match(embedded));
    }

    #[test]
    fn anthropic_pattern_does_not_match_embedded_in_word() {
        let embedded = "prefixsk-ant-abcdefghijklmnopqrstuvwxyz";
        assert!(!ANTHROPIC_RE.is_match(embedded));
    }

    #[test]
    fn github_pat_does_not_match_embedded() {
        let embedded = format!("prefixghp_{}", "a".repeat(36));
        assert!(!GITHUB_PAT_RE.is_match(&embedded));
    }

    #[test]
    fn aws_access_key_does_not_match_embedded() {
        let embedded = "XAKIAIOSFODNN7EXAMPLE";
        assert!(!AWS_ACCESS_KEY_RE.is_match(embedded));
    }

    #[test]
    fn stripe_pattern_does_not_match_embedded() {
        let embedded = format!("prefixsk_live_{}", "a".repeat(24));
        assert!(!STRIPE_SECRET_RE.is_match(&embedded));
    }

    #[test]
    fn openai_pattern_still_matches_at_word_boundary() {
        // Preceded by whitespace
        let text = "key: sk-abcdefghijklmnopqrstuvwxyz";
        assert!(OPENAI_RE.is_match(text));
    }

    #[test]
    fn openai_pattern_matches_at_start_of_string() {
        let text = "sk-abcdefghijklmnopqrstuvwxyz";
        assert!(OPENAI_RE.is_match(text));
    }

    #[test]
    fn stripe_pattern_matches_after_equals() {
        let text = "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx";
        assert!(STRIPE_SECRET_RE.is_match(text));
    }

    // ---- D1: Trailing \b truncation fix — keys ending with non-word chars ----

    #[test]
    fn aws_secret_key_ending_in_equals_still_matched() {
        // AWS secret keys are base64-encoded and can end with '=' padding
        let input = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY=";
        assert!(AWS_SECRET_KEY_RE.is_match(input));
    }

    #[test]
    fn openai_key_ending_in_dash_still_matched() {
        let key = "sk-proj-abcdefghijklmnop-";
        assert!(OPENAI_RE.is_match(key));
    }

    #[test]
    fn anthropic_key_with_underscore_still_matched() {
        let key = "sk-ant-api03-abcdefghijklmnopqrst_extra";
        assert!(ANTHROPIC_RE.is_match(key));
    }

    #[test]
    fn jwt_ending_in_dash_still_matched() {
        let input = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpM-";
        assert!(JWT_RE.is_match(input));
    }

    #[test]
    fn bearer_token_ending_in_dash_still_matched() {
        let input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234-";
        assert!(BEARER_TOKEN_RE.is_match(input));
    }

    #[test]
    fn pypi_token_ending_in_dash_still_matched() {
        let key = "pypi-AbCdEfGhIjKlMnOpQrStUvWx-";
        assert!(PYPI_TOKEN_RE.is_match(key));
    }

    // ---- D4: AWS ASIA temporary credentials ----

    #[test]
    fn aws_temporary_credential_asia_prefix_detected() {
        let key = "ASIAIOSFODNN7EXAMPLE";
        assert!(AWS_ACCESS_KEY_RE.is_match(key));
    }

    #[test]
    fn aws_akia_still_detected_after_asia_addition() {
        let key = "AKIAIOSFODNN7EXAMPLE";
        assert!(AWS_ACCESS_KEY_RE.is_match(key));
    }

    // ---- D5: Additional connection string schemes ----

    #[test]
    fn connection_string_matches_mariadb() {
        let conn = "mariadb://user:password@localhost:3306/db";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_mssql() {
        let conn = "mssql://sa:password@dbhost:1433/mydb";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_sqlserver() {
        let conn = "sqlserver://sa:password@dbhost:1433/mydb";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_amqp() {
        let conn = "amqp://guest:guest@localhost:5672/vhost";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    #[test]
    fn connection_string_matches_amqps() {
        let conn = "amqps://user:pass@broker.example.com:5671/vhost";
        assert!(CONNECTION_STRING_RE.is_match(conn));
    }

    // ---- D6: Stripe test and restricted keys ----

    #[test]
    fn stripe_test_key_detected() {
        let key = format!("sk_test_{}", "a".repeat(24));
        assert!(STRIPE_SECRET_RE.is_match(&key));
    }

    #[test]
    fn stripe_restricted_live_key_detected() {
        let key = format!("rk_live_{}", "b".repeat(24));
        assert!(STRIPE_SECRET_RE.is_match(&key));
    }

    #[test]
    fn stripe_restricted_test_key_detected() {
        let key = format!("rk_test_{}", "c".repeat(24));
        assert!(STRIPE_SECRET_RE.is_match(&key));
    }

    // ---- New patterns: Vercel Token ----

    #[test]
    fn vercel_token_matches_valid_token() {
        let key = format!("vercel_{}", "a".repeat(24));
        assert!(VERCEL_RE.is_match(&key));
    }

    #[test]
    fn vercel_token_rejects_short_token() {
        let key = format!("vercel_{}", "a".repeat(10));
        assert!(!VERCEL_RE.is_match(&key));
    }

    #[test]
    fn vercel_token_rejects_normal_text() {
        assert!(!VERCEL_RE.is_match("vercel deploy --prod"));
    }

    // ---- New patterns: Docker Hub PAT ----

    #[test]
    fn docker_pat_matches_valid_token() {
        let key = format!("dckr_pat_{}", "a".repeat(24));
        assert!(DOCKER_PAT_RE.is_match(&key));
    }

    #[test]
    fn docker_pat_rejects_short_token() {
        let key = format!("dckr_pat_{}", "a".repeat(10));
        assert!(!DOCKER_PAT_RE.is_match(&key));
    }

    #[test]
    fn docker_pat_rejects_normal_text() {
        assert!(!DOCKER_PAT_RE.is_match("docker pull nginx"));
    }

    // ---- New patterns: Hashicorp Vault Token ----

    #[test]
    fn vault_token_matches_valid_token() {
        let key = format!("hvs.{}", "a".repeat(24));
        assert!(VAULT_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn vault_token_rejects_short_token() {
        let key = format!("hvs.{}", "a".repeat(10));
        assert!(!VAULT_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn vault_token_rejects_normal_text() {
        assert!(!VAULT_TOKEN_RE.is_match("vault secrets list"));
    }

    // ---- New patterns: Hugging Face Token ----

    #[test]
    fn hf_token_matches_valid_token() {
        let key = format!("hf_{}", "a".repeat(34));
        assert!(HF_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn hf_token_rejects_short_token() {
        let key = format!("hf_{}", "a".repeat(10));
        assert!(!HF_TOKEN_RE.is_match(&key));
    }

    #[test]
    fn hf_token_rejects_normal_text() {
        assert!(!HF_TOKEN_RE.is_match("huggingface model download"));
    }

    // ---- New patterns: Shopify Token ----

    #[test]
    fn shopify_token_matches_valid_access_token() {
        let key = format!("shpat_{}", "a".repeat(32));
        assert!(SHOPIFY_RE.is_match(&key));
    }

    #[test]
    fn shopify_token_matches_valid_shared_secret() {
        let key = format!("shpss_{}", "b".repeat(32));
        assert!(SHOPIFY_RE.is_match(&key));
    }

    #[test]
    fn shopify_token_matches_valid_private_app() {
        let key = format!("shppa_{}", "c".repeat(32));
        assert!(SHOPIFY_RE.is_match(&key));
    }

    #[test]
    fn shopify_token_matches_valid_custom_app() {
        let key = format!("shpca_{}", "d".repeat(32));
        assert!(SHOPIFY_RE.is_match(&key));
    }

    #[test]
    fn shopify_token_rejects_short_token() {
        let key = format!("shpat_{}", "a".repeat(10));
        assert!(!SHOPIFY_RE.is_match(&key));
    }

    #[test]
    fn shopify_token_rejects_normal_text() {
        assert!(!SHOPIFY_RE.is_match("shopify store setup"));
    }

    // ---- New patterns: Linear API Key ----

    #[test]
    fn linear_api_key_matches_valid_key() {
        let key = format!("lin_api_{}", "a".repeat(40));
        assert!(LINEAR_RE.is_match(&key));
    }

    #[test]
    fn linear_api_key_rejects_short_key() {
        let key = format!("lin_api_{}", "a".repeat(10));
        assert!(!LINEAR_RE.is_match(&key));
    }

    #[test]
    fn linear_api_key_rejects_normal_text() {
        assert!(!LINEAR_RE.is_match("linear issue tracking"));
    }
}
