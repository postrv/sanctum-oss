//! MCP policy engine.
//!
//! Evaluates MCP tool invocations against a set of configurable rules.
//! Rules use simple glob-style matching to restrict which paths a tool
//! may access.

use sanctum_types::config::{McpCelRule, McpDefaultPolicy};
use serde::{Deserialize, Serialize};

use super::cel::{CelContext, CelDecision, CelEvaluator};
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
///
/// Combines glob-based rules (simple path restrictions) with optional
/// CEL expression rules (advanced logic: payload sizes, tool name patterns, etc.).
#[derive(Debug)]
pub struct McpPolicy {
    rules: Vec<PolicyRule>,
    cel_evaluator: CelEvaluator,
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
        Self {
            rules: validated_rules,
            cel_evaluator: CelEvaluator::new(&[]),
        }
    }

    /// Create an MCP policy from configuration rules, including optional CEL rules.
    #[must_use]
    pub fn from_config_rules(
        rules: &[sanctum_types::config::McpPolicyRuleConfig],
        cel_rules: &[McpCelRule],
    ) -> Self {
        let policy_rules = rules
            .iter()
            .map(|r| PolicyRule {
                tool: r.tool.clone(),
                restricted_paths: r.restricted_paths.clone(),
            })
            .collect();
        let mut policy = Self::from_config(policy_rules);
        policy.cel_evaluator = CelEvaluator::new(cel_rules);
        policy
    }

    /// Evaluate a tool invocation against the policy.
    ///
    /// First checks all path arguments against built-in sensitive path
    /// restrictions (`.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`, etc.).
    /// Then inspects against user-defined rules. Finally, if no rules match,
    /// falls back to `default_policy`.
    #[must_use]
    pub fn evaluate(
        &self,
        tool: &str,
        args: &serde_json::Value,
        default_policy: McpDefaultPolicy,
    ) -> HookDecision {
        // Extract any path-like string values from the arguments.
        let raw_paths = extract_path_values(args);

        // Normalize paths: collapse `.`, `..` segments and lowercase for
        // case-insensitive matching (macOS APFS is case-preserving).
        let paths: Vec<String> = raw_paths.iter().map(|p| normalize_mcp_path(p)).collect();

        // Phase 1: Check built-in sensitive path restrictions.
        // These apply to ALL MCP tools regardless of user rules.
        for path in &paths {
            if matches_builtin_restriction(path) {
                return HookDecision::Block;
            }
        }

        // Phase 2: Check user-defined glob rules.
        let applicable_rules: Vec<&PolicyRule> =
            self.rules.iter().filter(|r| r.tool == tool).collect();

        // If glob rules exist for this tool, check them.
        if !applicable_rules.is_empty() {
            for rule in &applicable_rules {
                for path in &paths {
                    for pattern in &rule.restricted_paths {
                        if glob_matches(pattern, path) {
                            return HookDecision::Block;
                        }
                    }
                }
            }
            // An explicit rule with no matching restrictions is an explicit allow.
            // This prevents tools with configured (but empty) restricted_paths
            // from falling through to a `deny` default policy.
            return HookDecision::Allow;
        }

        // Phase 3: CEL expression rules (evaluated after glob matching).
        if !self.cel_evaluator.is_empty() {
            let payload_size = serde_json::to_string(args)
                .map(|s| i64::try_from(s.len()).unwrap_or(i64::MAX))
                .unwrap_or(0);

            let cel_ctx = CelContext {
                tool_name: tool.to_owned(),
                paths,
                payload_size,
            };

            match self.cel_evaluator.evaluate(&cel_ctx) {
                CelDecision::Deny => return HookDecision::Block,
                CelDecision::Warn => return HookDecision::Warn,
                CelDecision::Allow => return HookDecision::Allow,
                CelDecision::NoMatch => {} // Fall through to default
            }
        }

        // No glob or CEL rule produced a definitive match — apply default policy.
        match default_policy {
            McpDefaultPolicy::Allow => HookDecision::Allow,
            McpDefaultPolicy::Warn => HookDecision::Warn,
            McpDefaultPolicy::Deny => HookDecision::Block,
        }
    }
}

/// Built-in sensitive directory names that are always restricted for MCP tools.
///
/// Matched as path segments — both `/.ssh/` (within path) and paths ending
/// with `/.ssh` (the directory itself) are blocked.
const BUILTIN_SENSITIVE_DIRS: &[&str] = &[
    ".ssh",
    ".aws",
    ".gnupg",
    ".config/gcloud",
    ".config/gh",
    ".config/op",
    ".age",
];

/// Built-in sensitive filename suffixes / exact names that are always restricted.
///
/// Entries ending in `/` are treated as directory prefixes: any path that
/// *contains* the entry (i.e., is inside or equal to the directory) is blocked.
/// All other entries use suffix matching.
const BUILTIN_SENSITIVE_FILENAMES: &[&str] = &[
    "/.kube/config",
    "/.npmrc",
    "/.pypirc",
    "/.docker/config.json",
    "/.netrc",
    "/.pgpass",
    "/.my.cnf",
    "/.vault-token",
    "/.terraform.d/credentials.tfrc.json",
    // AI assistant config dotfiles (prompt injection / MCP config poisoning)
    "/.claude.json",
    "/.claude/settings.json",
    "/.claude/settings.local.json",
    "/.claude/commands/",
    "/.cursor/mcp.json",
    "/.cursor/rules/",
    "/.continue/config.json",
    "/.windsurf/mcp.json",
    "/.github/copilot-instructions.md",
    // AI coding assistant config directories — may contain API keys,
    // custom instructions, or session data that should not be exfiltrated.
    "/.copilot/",
    "/.aider/",
    "/.cline/",
    "/.roo/",
    "/.codeium/",
];

/// Check whether a path matches any built-in sensitive restriction.
///
/// Uses direct substring/suffix matching rather than glob patterns for
/// reliability. This is strictly more conservative than glob matching —
/// it blocks more paths, which is the safe direction for security.
fn matches_builtin_restriction(path: &str) -> bool {
    // Normalise to lowercase for case-insensitive matching. On macOS (APFS/HFS+),
    // the filesystem is case-insensitive, so /.SSH/ and /.ssh/ resolve to the
    // same directory. We must block both.
    let path_lower = path.to_lowercase();

    // Check directory segments. Match both "/.ssh/" (within path) and
    // paths ending with "/.ssh" (the directory itself, no trailing slash).
    for dir in BUILTIN_SENSITIVE_DIRS {
        let with_trailing = format!("/{dir}/");
        let as_suffix = format!("/{dir}");
        if path_lower.contains(&with_trailing) || path_lower.ends_with(&as_suffix) {
            return true;
        }
    }

    // Check filename / directory matches (case-insensitive).
    // Entries ending in '/' are directory prefixes — block any path inside
    // or equal to the directory. All other entries use suffix matching.
    for name in BUILTIN_SENSITIVE_FILENAMES {
        if let Some(without_trailing) = name.strip_suffix('/') {
            // Directory entry: match "/.copilot/" anywhere in the path
            // (covers both files inside and the directory itself with trailing slash).
            // Also match the directory without trailing slash (e.g. path ends with "/.copilot").
            if path_lower.contains(name) || path_lower.ends_with(without_trailing) {
                return true;
            }
        } else if path_lower.ends_with(name) {
            return true;
        }
    }

    // Check .env files: must match exactly "/.env" or "/.env." followed by variant
    // but NOT "/.envrc" or other non-dotenv files.
    // Also handle bare filenames and .env-backup / .env_old variants.
    if let Some(filename) = path_lower.rsplit('/').next() {
        if filename == ".env"
            || filename.starts_with(".env.")
            || filename.starts_with(".env-")
            || filename.starts_with(".env_")
        {
            return true;
        }
    }
    // Handle bare ".env" with no path separator
    if path_lower == ".env"
        || path_lower.starts_with(".env.")
        || path_lower.starts_with(".env-")
        || path_lower.starts_with(".env_")
    {
        return true;
    }

    // Check .pth files (already lowercased, so this catches .PTH too)
    #[allow(clippy::case_sensitive_file_extension_comparisons)]
    if path_lower.ends_with(".pth") {
        return true;
    }
    if let Some(filename) = path_lower.rsplit('/').next() {
        if filename == "sitecustomize.py" || filename == "usercustomize.py" {
            return true;
        }
    }

    false
}

/// Normalise an MCP path for policy matching.
///
/// Performs the following transformations:
/// 1. Expands `~` and `$HOME` at the start of the path to the user's home
///    directory (using `std::env::var("HOME")`). If `HOME` is not set,
///    expansion is skipped.
/// 2. Collapses `.` and `..` segments.
/// 3. Lowercases the result (for case-insensitive matching on macOS).
///
/// This ensures that user-defined MCP rules using `~` patterns correctly
/// match absolute paths supplied by MCP tools.
#[must_use]
pub fn normalize_mcp_path(path: &str) -> String {
    // Step 1: Expand ~ and $HOME
    let expanded = expand_home_mcp(path);

    // Step 1.5: Normalise backslashes to forward slashes (Windows-style paths).
    let expanded = expanded.replace('\\', "/");

    // Step 2: Collapse . and .. segments
    let mut components: Vec<&str> = Vec::new();
    for component in expanded.split('/') {
        match component {
            ".." => {
                components.pop();
            }
            "." | "" => {}
            _ => components.push(component),
        }
    }

    let collapsed = if expanded.starts_with('/') {
        format!("/{}", components.join("/"))
    } else {
        components.join("/")
    };

    // Step 3: Lowercase for case-insensitive matching
    collapsed.to_lowercase()
}

/// Expand `~` and `$HOME` to the actual home directory path for MCP paths.
///
/// Falls back to leaving the path unchanged if `HOME` is not set.
fn expand_home_mcp(path: &str) -> String {
    let home = match std::env::var("HOME") {
        Ok(h) if !h.is_empty() => h,
        _ => return path.to_owned(),
    };

    if path == "~" {
        return home;
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return format!("{home}/{rest}");
    }
    if path == "$HOME" {
        return home;
    }
    if let Some(rest) = path.strip_prefix("$HOME/") {
        return format!("{home}/{rest}");
    }

    path.to_owned()
}

/// Extract string values from a JSON value that look like file paths.
///
/// Recurses into objects and arrays, collecting any string that contains
/// a path separator.
/// Known-sensitive bare filenames that should be detected even without path
/// separators. Catches MCP tool arguments like `{"filename": ".env"}`.
const SENSITIVE_BARE_FILENAMES: &[&str] = &[
    ".env",
    ".netrc",
    ".pgpass",
    ".npmrc",
    ".pypirc",
    ".my.cnf",
    ".vault-token",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "credentials.json",
    "service_account.json",
    "keyfile.json",
    "token.json",
];

fn extract_path_values(value: &serde_json::Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_path_strings(value, &mut paths, 0);
    paths
}

/// Maximum recursion depth for JSON traversal (defense against stack overflow).
const MAX_JSON_DEPTH: usize = 32;

/// Object keys whose values are source code (not file paths) and should not
/// be scanned for path references.  Scanning source code for `/`-containing
/// strings produces false positives because code naturally contains URL
/// literals, regex patterns, and comments — none of which are file paths.
///
/// Applicable to sandboxed code-mode tools (e.g. Forgemax/Narsil) where the
/// `code` parameter is JavaScript executed in a V8 isolate with no filesystem
/// access.
const CODE_VALUE_KEYS: &[&str] = &["code", "script", "expression", "source"];

fn collect_path_strings(value: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
    if depth > MAX_JSON_DEPTH {
        return;
    }
    match value {
        serde_json::Value::String(s) => {
            // Heuristic: treat any string containing '/' as a potential path.
            if s.contains('/') || s.contains('\\') {
                out.push(s.clone());
            }
            // Also catch bare sensitive filenames without path separators
            let s_lower = s.to_lowercase();
            if SENSITIVE_BARE_FILENAMES.iter().any(|f| s_lower == *f) {
                out.push(s.clone());
            }
        }
        serde_json::Value::Object(map) => {
            for (key, v) in map {
                // Skip keys whose values are source code, not file paths.
                if CODE_VALUE_KEYS.contains(&key.as_str()) {
                    continue;
                }
                collect_path_strings(v, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                collect_path_strings(v, out, depth + 1);
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
        let decision = policy.evaluate(
            "any_tool",
            &json!({"path": "/etc/passwd"}),
            McpDefaultPolicy::Allow,
        );
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
            McpDefaultPolicy::Allow,
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
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn allows_different_tool() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/tmp/restricted/**".to_owned()],
        }]);
        // Rule is for read_file, not write_file — write_file should be allowed
        // (using a non-sensitive path to avoid built-in restrictions)
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/tmp/restricted/secret.dat"}),
            McpDefaultPolicy::Allow,
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
            McpDefaultPolicy::Allow,
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
            McpDefaultPolicy::Allow,
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
            McpDefaultPolicy::Allow,
        );
        let decision2 = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.aws/credentials"}),
            McpDefaultPolicy::Allow,
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
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn glob_prefix_match_works() {
        assert!(glob_matches("/home/user/.ssh/**", "/home/user/.ssh/id_rsa"));
        assert!(glob_matches(
            "/home/user/.ssh/**",
            "/home/user/.ssh/known_hosts"
        ));
        assert!(!glob_matches(
            "/home/user/.ssh/**",
            "/home/user/project/file.txt"
        ));
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

        let policy = McpPolicy::from_config_rules(&config_rules, &[]);

        // read_file accessing .ssh should be blocked
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);

        // write_file writing a .pth should be blocked
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/evil.pth"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);

        // read_file accessing a normal file should be allowed
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/main.rs"}),
            McpDefaultPolicy::Allow,
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
        assert!(glob_matches(
            "**/config*.json",
            "/home/user/config_prod.json"
        ));
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
                "/home/user/.ssh/**".to_owned(), // valid — kept
                "/foo/*/bar/*.txt".to_owned(),   // invalid — stripped
                "**/*.pth".to_owned(),           // valid — kept
            ],
        }]);
        // The invalid pattern should have been removed
        assert_eq!(policy.rules[0].restricted_paths.len(), 2);
        assert_eq!(policy.rules[0].restricted_paths[0], "/home/user/.ssh/**");
        assert_eq!(policy.rules[0].restricted_paths[1], "**/*.pth");
    }

    // ---- built-in sensitive path restriction tests ----

    #[test]
    fn builtin_blocks_ssh_with_no_rules() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "any_tool",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            "built-in should block .ssh paths even with no rules"
        );
    }

    #[test]
    fn builtin_blocks_aws_credentials() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.aws/credentials"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_gnupg() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.gnupg/secring.gpg"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_env_file() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/app/project/.env"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_env_dotfile_variants() {
        let policy = McpPolicy::from_config(vec![]);
        for env_file in &[".env.local", ".env.production", ".env.staging"] {
            let decision = policy.evaluate(
                "read_file",
                &json!({"path": format!("/app/{env_file}")}),
                McpDefaultPolicy::Allow,
            );
            assert_eq!(decision, HookDecision::Block, "should block {env_file}");
        }
    }

    #[test]
    fn builtin_blocks_pth_files() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/site-packages/evil.pth"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_sitecustomize() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/site-packages/sitecustomize.py"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_kube_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.kube/config"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_allows_normal_paths() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/src/main.rs"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Allow,
            "normal paths should not be blocked by built-in restrictions"
        );
    }

    #[test]
    fn builtin_blocks_before_user_rules() {
        // Even with user rules that would allow a path, built-in restrictions
        // take precedence.
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/tmp/**".to_owned()], // Only restricts /tmp
        }]);

        // .ssh should be blocked by built-in even though user rule doesn't mention it
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_ssh_directory_no_trailing_slash() {
        // Path to the directory itself (no trailing slash) should be blocked
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".ssh directory path without trailing slash should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_netrc() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.netrc"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_pgpass() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.pgpass"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_blocks_vault_token() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.vault-token"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_does_not_match_env_in_middle_of_filename() {
        // ".env" should only match the exact filename, not substrings like ".envrc"
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.envrc"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Allow,
            ".envrc should not be blocked by .env pattern"
        );
    }

    #[test]
    fn builtin_blocks_case_variations_on_macos() {
        // macOS APFS/HFS+ is case-insensitive. .SSH must be blocked.
        let policy = McpPolicy::from_config(vec![]);
        for path in &[
            "/home/user/.SSH/id_rsa",
            "/home/user/.Ssh/config",
            "/home/user/.AWS/credentials",
            "/home/user/.GNUPG/secring.gpg",
        ] {
            let decision =
                policy.evaluate("read_file", &json!({"path": path}), McpDefaultPolicy::Allow);
            assert_eq!(
                decision,
                HookDecision::Block,
                "case variation {path} should be blocked"
            );
        }
    }

    #[test]
    fn builtin_blocks_env_backup_variants() {
        let policy = McpPolicy::from_config(vec![]);
        for filename in &[".env-backup", ".env_old", ".env-production-bak"] {
            let decision = policy.evaluate(
                "read_file",
                &json!({"path": format!("/app/{filename}")}),
                McpDefaultPolicy::Allow,
            );
            assert_eq!(
                decision,
                HookDecision::Block,
                "{filename} should be blocked"
            );
        }
    }

    #[test]
    fn builtin_blocks_uppercase_pth() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/usr/lib/python3/evil.PTH"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".PTH (uppercase) should be blocked on case-insensitive filesystems"
        );
    }

    // ---- default MCP policy tests ----

    #[test]
    fn unmatched_tool_allowed_by_default() {
        // No rules at all, default policy is Allow — tool should be allowed.
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "some_tool",
            &json!({"arg": "value"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn unmatched_tool_warned_when_policy_warn() {
        // No rules at all, default policy is Warn — tool should get Warn.
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "some_tool",
            &json!({"arg": "value"}),
            McpDefaultPolicy::Warn,
        );
        assert_eq!(decision, HookDecision::Warn);
    }

    #[test]
    fn unmatched_tool_blocked_when_policy_deny() {
        // No rules at all, default policy is Deny — tool should be blocked.
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "some_tool",
            &json!({"arg": "value"}),
            McpDefaultPolicy::Deny,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn matched_tool_with_non_restricted_path_is_allowed() {
        // An explicit rule for a tool is an explicit allow for that tool.
        // Paths matching restricted patterns are blocked; non-matching paths
        // are allowed regardless of the default policy.  This enables the
        // pattern: `default_mcp_policy = "deny"` + explicit rules for
        // specific tools = "deny-by-default, allow configured tools."
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/home/user/.ssh/**".to_owned()],
        }]);

        // Path does NOT match restricted pattern — tool is explicitly configured → allow.
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/main.rs"}),
            McpDefaultPolicy::Deny,
        );
        assert_eq!(
            decision,
            HookDecision::Allow,
            "non-restricted path on configured tool should be allowed"
        );

        // Same with Allow default — also allowed.
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/main.rs"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Allow,
            "non-restricted path should be allowed"
        );

        // Path DOES match restricted pattern — should be blocked regardless of default.
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            "restricted path should be blocked even with Allow default"
        );
    }

    #[test]
    fn unmatched_tool_with_rules_for_other_tools_uses_default() {
        // Rules exist but for a different tool — the queried tool is unmatched.
        // Using non-sensitive paths to test default policy without built-in blocking.
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["/tmp/restricted/**".to_owned()],
        }]);

        // write_file has no rules, so default policy applies.
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/tmp/some/data.txt"}),
            McpDefaultPolicy::Warn,
        );
        assert_eq!(
            decision,
            HookDecision::Warn,
            "unmatched tool should use default policy (Warn)"
        );

        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/tmp/some/data.txt"}),
            McpDefaultPolicy::Deny,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            "unmatched tool should use default policy (Deny)"
        );
    }
}

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(6)]
    fn glob_matches_exact_match_works() {
        // Prove: for any 3-byte ASCII string, exact match (no wildcards) is
        // equivalent to string equality.
        // Bounded to 3 bytes: glob_matches involves split/starts_with/ends_with
        // which generate expensive CBMC loops with symbolic strings.
        let bytes: [u8; 3] = kani::any();
        let path_bytes: [u8; 3] = kani::any();

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

    #[test]
    fn extract_path_values_catches_bare_env_filename() {
        let val = serde_json::json!({"filename": ".env"});
        let paths = extract_path_values(&val);
        assert!(
            paths.iter().any(|p| p == ".env"),
            "should extract bare .env filename"
        );
    }

    #[test]
    fn extract_path_values_catches_bare_netrc() {
        let val = serde_json::json!({"file": ".netrc"});
        let paths = extract_path_values(&val);
        assert!(
            paths.iter().any(|p| p == ".netrc"),
            "should extract bare .netrc filename"
        );
    }

    #[test]
    fn extract_path_values_catches_bare_id_rsa() {
        let val = serde_json::json!({"filename": "id_rsa"});
        let paths = extract_path_values(&val);
        assert!(
            paths.iter().any(|p| p == "id_rsa"),
            "should extract bare id_rsa filename"
        );
    }

    #[test]
    fn extract_path_values_catches_bare_credentials_json() {
        let val = serde_json::json!({"file": "credentials.json"});
        let paths = extract_path_values(&val);
        assert!(
            paths.iter().any(|p| p == "credentials.json"),
            "should extract bare credentials.json filename"
        );
    }

    #[test]
    fn extract_path_values_ignores_normal_strings() {
        let val = serde_json::json!({"name": "hello.txt"});
        let paths = extract_path_values(&val);
        assert!(paths.is_empty(), "normal filenames should not be extracted");
    }

    #[test]
    fn extract_path_values_skips_code_key() {
        // The "code" key contains JavaScript source code, not file paths.
        // Scanning it for paths produces false positives from URL literals,
        // regex patterns, and division operators.
        let val = serde_json::json!({
            "code": "async () => { return forge.callTool('narsil', 'scan', { path: '/Users/test/.ssh/id_rsa' }); }"
        });
        let paths = extract_path_values(&val);
        assert!(
            paths.is_empty(),
            "code parameter should be skipped: {paths:?}"
        );
    }

    #[test]
    fn extract_path_values_still_checks_non_code_keys() {
        // Non-code keys containing paths should still be extracted
        let val = serde_json::json!({
            "file_path": "/home/user/.ssh/id_rsa",
            "code": "async () => { return 42; }"
        });
        let paths = extract_path_values(&val);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn collect_path_strings_respects_depth_limit() {
        // Build a deeply nested JSON structure
        let mut val = serde_json::json!("/secret/path");
        for _ in 0..50 {
            val = serde_json::json!({"nested": val});
        }
        let paths = extract_path_values(&val);
        // The path should NOT be found because it's deeper than MAX_JSON_DEPTH (32)
        assert!(
            paths.is_empty(),
            "paths beyond depth limit should not be extracted"
        );
    }

    #[test]
    fn collect_path_strings_finds_paths_within_depth_limit() {
        // Build JSON nested to depth 10 (within limit)
        let mut val = serde_json::json!("/secret/path");
        for _ in 0..10 {
            val = serde_json::json!({"nested": val});
        }
        let paths = extract_path_values(&val);
        assert!(
            paths.iter().any(|p| p == "/secret/path"),
            "paths within depth limit should be extracted"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod expanded_policy_tests {
    use super::*;
    use sanctum_types::config::McpDefaultPolicy;
    use serde_json::json;

    // ---- AI config dotfile builtin restriction tests ----

    #[test]
    fn builtin_blocks_claude_json() {
        assert!(
            matches_builtin_restriction("/home/user/.claude.json"),
            "/.claude.json should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_claude_settings_json() {
        assert!(
            matches_builtin_restriction("/home/user/.claude/settings.json"),
            "/.claude/settings.json should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_cursor_mcp_json() {
        assert!(
            matches_builtin_restriction("/home/user/.cursor/mcp.json"),
            "/.cursor/mcp.json should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_continue_config_json() {
        assert!(
            matches_builtin_restriction("/home/user/.continue/config.json"),
            "/.continue/config.json should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_windsurf_mcp_json() {
        assert!(
            matches_builtin_restriction("/home/user/.windsurf/mcp.json"),
            "/.windsurf/mcp.json should be blocked"
        );
    }

    #[test]
    fn path_traversal_blocked_by_builtin_ssh_restriction() {
        let policy = McpPolicy::from_config(vec![PolicyRule {
            tool: "read_file".to_owned(),
            restricted_paths: vec!["~/.ssh/**".to_owned()],
        }]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/project/../../.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            "path traversal containing /.ssh/ should be blocked by built-in restriction"
        );
    }

    #[test]
    fn path_normalization_collapses_traversal() {
        let normalized = normalize_mcp_path("/home/user/project/../../.ssh/id_rsa");
        assert_eq!(normalized, "/home/.ssh/id_rsa");
    }

    #[test]
    fn path_normalization_lowercases() {
        let normalized = normalize_mcp_path("/home/user/.SSH/id_rsa");
        assert_eq!(normalized, "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn path_normalization_collapses_dot() {
        let normalized = normalize_mcp_path("/home/user/./project/./../.ssh/id_rsa");
        assert_eq!(normalized, "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn builtin_blocks_claude_settings() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/home/user/.claude/settings.local.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".claude/settings.local.json should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_claude_commands() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/home/user/.claude/commands/evil.md"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".claude/commands/ should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_copilot_instructions() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/project/.github/copilot-instructions.md"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".github/copilot-instructions.md should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_cursor_rules() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/project/.cursor/rules/evil.mdc"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".cursor/rules/ should be blocked"
        );
    }

    #[test]
    fn case_insensitive_builtin_blocks_uppercase_ssh() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.SSH/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            "case-insensitive .SSH should be blocked"
        );
    }

    // ---- AI dotfile directory restriction tests ----

    #[test]
    fn builtin_blocks_copilot_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.copilot/settings.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".copilot/ directory should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_aider_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.aider/state"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".aider/ directory should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_cline_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.cline/settings.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".cline/ directory should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_roo_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.roo/keys.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".roo/ directory should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_codeium_config() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.codeium/config.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".codeium/ directory should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_ai_dotfile_dir_itself() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.copilot"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".copilot directory path (no trailing slash) should be blocked"
        );
    }

    #[test]
    fn builtin_blocks_ai_dotfile_case_insensitive() {
        let policy = McpPolicy::from_config(vec![]);
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.COPILOT/config.json"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(
            decision,
            HookDecision::Block,
            ".COPILOT (uppercase) should be blocked"
        );
    }

    // ---- normalize_mcp_path tests ----

    #[test]
    fn normalize_mcp_path_expands_tilde() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp/test".to_owned());
        let result = normalize_mcp_path("~/docs/file.txt");
        let expected = format!("{}/docs/file.txt", home.to_lowercase());
        assert_eq!(result, expected);
    }

    #[test]
    fn normalize_mcp_path_expands_dollar_home() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp/test".to_owned());
        let input = format!("{}{}", "$", "HOME/projects/code");
        let result = normalize_mcp_path(&input);
        let expected = format!("{}/projects/code", home.to_lowercase());
        assert_eq!(result, expected);
    }

    #[test]
    fn normalize_mcp_path_collapses_dot_segments() {
        let result = normalize_mcp_path("/home/user/./project/../data/key");
        assert_eq!(result, "/home/user/data/key");
    }

    #[test]
    fn normalize_mcp_path_lowercases() {
        let result = normalize_mcp_path("/Home/User/Data/Key");
        assert_eq!(result, "/home/user/data/key");
    }

    #[test]
    fn normalize_mcp_path_bare_tilde() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp/test".to_owned());
        let result = normalize_mcp_path("~");
        assert_eq!(result, home.to_lowercase());
    }

    #[test]
    fn normalize_mcp_path_absolute_unchanged() {
        let result = normalize_mcp_path("/usr/local/bin");
        assert_eq!(result, "/usr/local/bin");
    }

    #[test]
    fn normalize_mcp_path_tilde_in_middle_not_expanded() {
        let result = normalize_mcp_path("/some/path/~file");
        assert_eq!(result, "/some/path/~file");
    }

    #[test]
    fn test_normalize_mcp_path_backslash() {
        // Windows-style backslashes should be normalised to forward slashes.
        let result = normalize_mcp_path("\\.ssh\\id_rsa");
        assert!(
            !result.contains('\\'),
            "backslashes should be converted to forward slashes, got: {result}"
        );
        assert_eq!(result, "/.ssh/id_rsa");
    }

    // ── CEL policy integration tests ──────────────────────────────────────

    #[test]
    fn cel_rule_blocks_matching_tool() {
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name == "dangerous_tool""#.to_owned(),
            action: CelRuleAction::Deny,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        let decision = policy.evaluate(
            "dangerous_tool",
            &json!({"path": "/tmp/file"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn cel_rule_allows_non_matching_tool() {
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name == "dangerous_tool""#.to_owned(),
            action: CelRuleAction::Deny,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        let decision = policy.evaluate(
            "safe_tool",
            &json!({"path": "/tmp/file"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn cel_rule_warns_on_match() {
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name.startsWith("database_")"#.to_owned(),
            action: CelRuleAction::Warn,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        let decision = policy.evaluate("database_query", &json!({}), McpDefaultPolicy::Allow);
        assert_eq!(decision, HookDecision::Warn);
    }

    #[test]
    fn cel_payload_size_blocks_large_payloads() {
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: "payload_size > 100".to_owned(),
            action: CelRuleAction::Deny,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        // Large payload should be blocked
        let large_args = json!({"data": "x".repeat(200)});
        let decision = policy.evaluate("any_tool", &large_args, McpDefaultPolicy::Allow);
        assert_eq!(decision, HookDecision::Block);

        // Small payload should be allowed
        let small_args = json!({"data": "x"});
        let decision = policy.evaluate("any_tool", &small_args, McpDefaultPolicy::Allow);
        assert_eq!(decision, HookDecision::Allow);
    }

    #[test]
    fn glob_rules_evaluated_before_cel_rules() {
        use sanctum_types::config::{CelRuleAction, McpCelRule, McpPolicyRuleConfig};

        let glob_rules = vec![McpPolicyRuleConfig {
            tool: "write_file".to_owned(),
            restricted_paths: vec!["**/*.pth".to_owned()],
        }];
        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name == "write_file""#.to_owned(),
            action: CelRuleAction::Allow,
        }];
        let policy = McpPolicy::from_config_rules(&glob_rules, &cel_rules);

        // Glob block should take priority over CEL allow
        let decision = policy.evaluate(
            "write_file",
            &json!({"path": "/tmp/evil.pth"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn builtin_restrictions_override_cel_allow() {
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name == "read_file""#.to_owned(),
            action: CelRuleAction::Allow,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        // Built-in .ssh block should override CEL allow
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/home/user/.ssh/id_rsa"}),
            McpDefaultPolicy::Allow,
        );
        assert_eq!(decision, HookDecision::Block);
    }

    #[test]
    fn default_deny_applies_when_cel_rules_exist_but_dont_match() {
        // Regression test for the policy bypass bug:
        // Having CEL rules should NOT override the default deny policy
        // for tools that don't match any rule.
        use sanctum_types::config::{CelRuleAction, McpCelRule};

        let cel_rules = vec![McpCelRule {
            expression: r#"tool_name == "write_file""#.to_owned(),
            action: CelRuleAction::Deny,
        }];
        let policy = McpPolicy::from_config_rules(&[], &cel_rules);

        // "read_file" doesn't match the CEL rule -> should fall through to default
        let decision = policy.evaluate(
            "read_file",
            &json!({"path": "/tmp/safe.txt"}),
            McpDefaultPolicy::Deny,
        );
        assert_eq!(decision, HookDecision::Block); // Default deny should apply
    }
}
