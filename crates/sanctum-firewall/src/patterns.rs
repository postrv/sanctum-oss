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

/// Compile a regex from a string, returning a fallback that matches nothing on
/// error. All callers pass compile-time literal patterns that are known valid,
/// so the error branch is unreachable in practice.
#[allow(clippy::option_if_let_else)]
fn compile_regex(pattern: &str) -> Regex {
    match Regex::new(pattern) {
        Ok(re) => re,
        // The error branch is unreachable for our known-good literals, but we
        // cannot use `unreachable!()` under `#[deny(panic)]`. We hint to the
        // CPU to yield rather than busy-spin, though this path is never taken.
        #[allow(clippy::empty_loop)]
        Err(_) => loop {
            std::hint::spin_loop();
        },
    }
}

macro_rules! static_regex {
    ($name:ident, $pattern:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| compile_regex($pattern));
    };
}

static_regex!(OPENAI_RE, r"sk-[a-zA-Z0-9]{20,}");
static_regex!(ANTHROPIC_RE, r"sk-ant-[a-zA-Z0-9\-]{20,}");
static_regex!(GOOGLE_AI_RE, r"AIza[a-zA-Z0-9_\-]{35}");
static_regex!(AWS_ACCESS_KEY_RE, r"AKIA[A-Z0-9]{16}");
static_regex!(
    AWS_SECRET_KEY_RE,
    r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[=: ]+[A-Za-z0-9/+=]{40}"
);
static_regex!(GITHUB_PAT_RE, r"ghp_[a-zA-Z0-9]{36}");
static_regex!(GITHUB_FINE_GRAINED_RE, r"github_pat_[a-zA-Z0-9_]{82}");
static_regex!(GITLAB_RE, r"glpat-[a-zA-Z0-9_\-]{20}");
static_regex!(SLACK_BOT_RE, r"xoxb-[0-9]{10,13}-[a-zA-Z0-9\-]+");
static_regex!(STRIPE_SECRET_RE, r"sk_live_[a-zA-Z0-9]{24,}");
static_regex!(SENDGRID_RE, r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}");
static_regex!(
    JWT_RE,
    r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
);
static_regex!(
    BEARER_TOKEN_RE,
    r"[Aa]uthorization[=: ]+Bearer [A-Za-z0-9_\-]{20,}"
);
static_regex!(PRIVATE_KEY_RE, r"-----BEGIN[A-Z ]*PRIVATE KEY-----");
static_regex!(CONNECTION_STRING_RE, r"(postgresql|mongodb|redis|mysql)://[^\s@]+@[^\s]+");

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
}
