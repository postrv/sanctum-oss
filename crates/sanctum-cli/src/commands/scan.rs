//! `sanctum scan` — Scan for credential exposure in the current project.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

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
pub fn run(json: bool) -> Result<(), CliError> {
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
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[allow(clippy::expect_used)]
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

    #[allow(clippy::expect_used)]
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

    #[allow(clippy::expect_used)]
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
}
