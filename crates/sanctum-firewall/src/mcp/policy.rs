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
    /// An empty set of rules means everything is allowed.
    #[must_use]
    pub const fn from_config(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
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
                let after_star = star_parts.get(1).copied().unwrap_or("");
                // Match any path component ending with the extension.
                return path.ends_with(after_star);
            }
        }
        return path.ends_with(suffix) || path.contains(&format!("/{suffix}"));
    }

    // Handle single-star within a pattern: "/foo/*/bar"
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts.first().copied().unwrap_or("");
            let suffix = parts.get(1).copied().unwrap_or("");
            return path.starts_with(prefix) && path.ends_with(suffix);
        }
    }

    // Exact match fallback.
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
}
