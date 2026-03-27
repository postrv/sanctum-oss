//! MCP policy engine.
//!
//! Evaluates MCP tool invocations against a set of configurable rules.
//! Rules use simple glob-style matching to restrict which paths a tool
//! may access.

use serde::{Deserialize, Serialize};

use crate::hooks::protocol::HookDecision;

/// A single policy rule that restricts a tool's access to certain paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// The tool name this rule applies to (exact match).
    pub tool: String,
    /// Glob patterns for paths that are restricted.
    /// If a tool's arguments reference a path matching any of these globs,
    /// the invocation is blocked.
    pub restricted_paths: Vec<String>,
}

/// MCP policy configuration.
#[derive(Debug, Clone, Default)]
pub struct McpPolicy {
    rules: Vec<PolicyRule>,
}

impl McpPolicy {
    /// Create an MCP policy from configuration.
    ///
    /// Validates all glob patterns at load time. Patterns with unsupported
    /// multi-wildcard syntax are stripped with a warning rather than silently
    /// failing to match at evaluation time. An empty set of rules means
    /// everything is allowed.
    #[must_use]
    pub fn from_config(rules: Vec<PolicyRule>) -> Self {
        let validated_rules = rules
            .into_iter()
            .map(|rule| {
                let valid_paths: Vec<String> = rule
                    .restricted_paths
                    .into_iter()
                    .filter(|pattern| {
                        if is_supported_glob(pattern) {
                            true
                        } else {
                            tracing::warn!(
                                tool = rule.tool,
                                pattern = pattern.as_str(),
                                "stripping unsupported glob pattern from MCP policy — \
                                 only `prefix/**`, `**/suffix`, `prefix*suffix`, and \
                                 exact match patterns are supported"
                            );
                            false
                        }
                    })
                    .collect();
                PolicyRule {
                    tool: rule.tool,
                    restricted_paths: valid_paths,
                }
            })
            .collect();
        Self { rules: validated_rules }
    }

    /// Create an MCP policy from configuration rules.
    #[must_use]
    pub fn from_config_rules(rules: &[sanctum_types::config::McpPolicyRuleConfig]) -> Self {
        let policy_rules = rules
            .iter()
            .map(|r| PolicyRule {
                tool: r.tool.clone(),
                restricted_paths: r.restricted_paths.clone(),
            })
            .collect();
        Self::from_config(policy_rules)
    }

    /// Evaluate a tool invocation against the policy.
    ///
    /// Inspects the tool name and its arguments for path references, then
    /// checks whether any restricted-path glob matches.
    #[must_use]
    pub fn evaluate(&self, tool: &str, args: &serde_json::Value) -> HookDecision {
        // Find all rules that apply to this tool.
        let applicable_rules: Vec<&PolicyRule> =
            self.rules.iter().filter(|r| r.tool == tool).collect();

        if applicable_rules.is_empty() {
            return HookDecision::Allow;
        }

        // Extract any path-like string values from the arguments.
        let paths = extract_path_values(args);

        for rule in &applicable_rules {
            for path in &paths {
                for pattern in &rule.restricted_paths {
                    if glob_matches(pattern, path) {
                        return HookDecision::Block;
                    }
                }
            }
        }

        HookDecision::Allow
    }
}

/// Extract string values from a JSON value that look like file paths.
///
/// Recurses into objects and arrays, collecting any string that contains
/// a path separator.
fn extract_path_values(value: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_path_strings(value, &mut paths);
    paths
}

fn collect_path_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(s) => {
            // Heuristic: treat any string containing '/' as a potential path.
            if s.contains('/') || s.contains('\\') {
                out.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values() {
                collect_path_strings(v, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_path_strings(v, out);
            }
        }
        _ => {}
    }
}

/// Check whether a glob pattern uses only supported syntax.
///
/// Supported forms: `prefix/**`, `**/suffix`, `prefix*suffix` (single `*`),
/// and exact match (no wildcards). Patterns with multiple `*` characters that
/// don't fit these forms are unsupported.
fn is_supported_glob(pattern: &str) -> bool {
    if !pattern.contains('*') {
        return true; // Exact match — always valid.
    }
    if pattern.ends_with("/**") {
        return true; // prefix/**
    }
    if let Some(suffix) = pattern.strip_prefix("**/") {
        // **/suffix or **/*.ext — the suffix may contain at most one *
        return suffix.chars().filter(|&c| c == '*').count() <= 1;
    }
    // Single * only
    pattern.chars().filter(|&c| c == '*').count() == 1
}

/// Simple glob matching supporting `*` (any sequence within a segment) and
/// `**` (any number of path segments).
///
/// This is intentionally minimal — not a full glob implementation — to avoid
/// `ReDoS` and keep the attack surface small.
fn glob_matches(pattern: &str, path: &str) -> bool {
    // Handle the common case of prefix glob: "/foo/bar/**"
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix) || path == prefix;
    }

    // Handle the common case of extension glob: "**/*.pth"
    if let Some(suffix) = pattern.strip_prefix("**/") {
        // The suffix may itself contain a wildcard (e.g., "*.pth").
        if suffix.contains('*') {
            // Split on '*' and check that the last path component matches.
            let star_parts: Vec<&str> = suffix.split('*').collect();
            if star_parts.len() == 2 {
                let before_star = star_parts.first().copied().unwrap_or("");
                let after_star = star_parts.get(1).copied().unwrap_or("");
                // Match any path component ending with the extension
                // AND whose filename starts with the prefix before the '*'.
                if !path.ends_with(after_star) {
                    return false;
                }
                // Extract the filename (last path component) and verify the prefix.
                let filename = path.rsplit('/').next().unwrap_or(path);
                return before_star.is_empty() || filename.starts_with(before_star);
            }
        }
        return path.ends_with(&format!("/{suffix}")) || path == suffix;
    }

    // Handle single-star within a pattern: "/foo/*/bar"
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts.first().copied().unwrap_or("");
            let suffix = parts.get(1).copied().unwrap_or("");
            return path.starts_with(prefix) && path.ends_with(suffix);
        }
        // Multiple wildcards beyond the supported single-star form.
        // Return false rather than falling through to exact match, which would
        // silently fail to glob-match anything. This is a security-relevant
        // correctness issue: a pattern like "/foo/*/bar/*.txt" should never
        // match only the literal string "/foo/*/bar/*.txt".
        tracing::warn!(
            pattern = pattern,
            path = path,
            "glob pattern with multiple wildcards is not supported; treating as non-match"
        );
        return false;
    }

    // Exact match fallback — only reached for patterns without any wildcards.
    pattern == path
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_policy_allows_everything() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate("any_tool", &json!({"path": "/etc/passwd"}));
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn blocks_restricted_path() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
        }]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn allows_unrestricted_path() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
        }]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/src/main.rs"}),
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn allows_different_tool() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
        }]);
        // Rule is for read_file, not write_file
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn blocks_extension_glob() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "write_file".to_owned(),
            restricted_paths: vec!["**/*.pth".to_owned()],
        }]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/site-packages/evil.pth"}),
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn blocks_exact_path() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/etc/shadow".to_owned()],
        }]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/etc/shadow"}),
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn multiple_rules_for_same_tool() {
        let policy = McpPolicy::from_config(vec![
            PolicyRule {
                tool: "read_file".to_owned(),
                restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
            },
            PolicyRule {
                tool: "read_file".to_owned(),
                restricted_paths: vec!["/home/user/.aws/**".to_owned()],
            },
        ]);
        let decision1 = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
        );
        let decision2 = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.aws/credentials"}),
        );
        assert_eq!(decision1, HookDecision::Block);
        assert_eq!(decision2, HookDecision::Block);
    }

    #[test]
    fn extracts_paths_from_nested_json() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "complex_tool".to_owned(),
            restricted_paths: vec!["/secret/**".to_owned()],
        }]);
        let decision = policy.evaluate(
            "complex_tool",
            &json!({"nested": {"deep": {"path": "/secret/key.pem"}}}),
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn glob_prefix_match_works() {
        assert!(glob_matches("/home/user/.ssh/**", "/home/user/.ssh/id_rsa"));
        assert!(glob_matches("/home/user/.ssh/**", "/home/user/.ssh/known_hosts"));
        assert!(!glob_matches("/home/user/.ssh/**", "/home/user/project/file.txt"));
    }

    #[test]
    fn glob_suffix_match_works() {
        assert!(glob_matches("**/*.pth", "/usr/lib/python3/evil.pth"));
        assert!(glob_matches("**/*.pth", "/some/deep/path/file.pth"));
        assert!(!glob_matches("**/*.pth", "/some/path/file.py"));
    }

    #[test]
    fn test_from_config_rules() {
        use sanctum_types::config::McpPolicyRuleConfig;

        let config_rules = vec![
            McpPolicyRuleConfig {
                tool: "read_file".to_owned(),
                restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
            },
            McpPolicyRuleConfig {
                tool: "write_file".to_owned(),
                restricted_paths: vec!["**/*.pth".to_owned()],
            },
        ];

        let policy = McpPolicy::from_config_rules(&config_rules);

        // read_file accessing .ssh should be blocked
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
        );
        assert_eq!(decision, HookDecision::Block);

        // write_file writing a .pth should be blocked
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/evil.pth"}),
        );
        assert_eq!(decision, HookDecision::Block);

        // read_file accessing a normal file should be allowed
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/main.rs"}),
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn multi_star_pattern_does_not_silently_match_exact() {
        // Patterns with multiple wildcards (beyond the supported forms) must NOT
        // silently fall through to exact-match. Before the fix, "/foo/*/bar/*.txt"
        // would only match the literal string "/foo/*/bar/*.txt" — never a real path.
        assert!(!glob_matches("/foo/*/bar/*.txt", "/foo/*/bar/*.txt"));
        assert!(!glob_matches("/foo/*/bar/*.txt", "/foo/x/bar/baz.txt"));
        assert!(!glob_matches("/a/*/b/*", "/a/x/b/y"));
    }

    #[test]
    fn single_star_pattern_still_works() {
        // Single-star matches any substring between prefix and suffix.
        // This is intentionally broader than segment-only matching — for a security
        // blocklist, matching too broadly (blocking more paths) is the safe direction.
        assert!(glob_matches("/foo/*/bar", "/foo/anything/bar"));
        assert!(glob_matches("/usr/*/bin", "/usr/local/bin"));
        assert!(glob_matches("/etc/*", "/etc/passwd"));
        assert!(!glob_matches("/foo/*/bar", "/baz/anything/bar"));
    }

    #[test]
    fn glob_double_star_with_prefix_wildcard() {
        // Pattern **/config*.json should match files whose name starts with "config"
        // and ends with ".json", but NOT arbitrary .json files.
        assert!(glob_matches("**/config*.json", "/home/config-dev.json"));
        assert!(glob_matches("**/config*.json", "/home/user/config.json"));
        assert!(glob_matches("**/config*.json", "/home/user/config_prod.json"));
        assert!(!glob_matches("**/config*.json", "/home/random.json"));
        assert!(!glob_matches("**/config*.json", "/home/user/settings.json"));
    }

    #[test]
    fn glob_double_star_env_does_not_match_envrc() {
        assert!(!glob_matches("**/.env", "/home/user/.envrc"));
        assert!(glob_matches("**/.env", "/home/user/.env"));
    }

    #[test]
    fn unsupported_patterns_are_rejected_at_load_time() {
        // Patterns with multiple wildcards that don't match /**  or **/
        // should be stripped from the policy at load time with a warning,
        // not silently ignored at match time.
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec![
                "/home/user/.ssh/**".to_owned(),        // valid — kept
                "/foo/*/bar/*.txt".to_owned(),           // invalid — stripped
                "**/*.pth".to_owned(),                   // valid — kept
            ],
        }]);
        // The invalid pattern should have been removed
        assert_eq!(policy.rules[0].restricted_paths.len(), 2);
        assert_eq!(policy.rules[0].restricted_paths[0], "/home/user/.ssh/**");
        assert_eq!(policy.rules[0].restricted_paths[1], "**/*.pth");
    }
}

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(10)]
    fn glob_matches_exact_match_works() {
        // Prove: for any 4-byte ASCII string, exact match (no wildcards) is
        // equivalent to string equality.
        let bytes: [u8; 4] = kani::any();
        let path_bytes: [u8; 4] = kani::any();

        // Only test printable ASCII (no wildcards in pattern)
        kani::assume(bytes.iter().all(|&b| b >= 0x20 && b <= 0x7E && b != b'*'));
        kani::assume(path_bytes.iter().all(|&b| b >= 0x20 && b <= 0x7E));

        if let (Ok(pattern), Ok(path)) = (
            std::str::from_utf8(&bytes),
            std::str::from_utf8(&path_bytes),
        ) {
            let result = glob_matches(pattern, path);
            // Without wildcards, glob_matches must be equivalent to ==
            assert_eq!(result, pattern == path);
        }
    }
}
