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
pub fn run() -> Result<(), CliError> {
    let cwd = std::env::current_dir()?;

    #[allow(clippy::print_stdout)]
    {
        println!("Scanning {} for credential exposure...", cwd.display());
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
                println!("    File: {}:{}", finding.file.display(), finding.line_number);
                println!("    Detail: {}", finding.detail);
                println!("    Fix: {}", finding.remediation);
            }
            println!();
        }
    }

    Ok(())
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
    let env_patterns = [".env", ".env.local", ".env.production", ".env.staging", ".env.development"];

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
                            remediation: "Use a secrets manager or environment variables at runtime".to_string(),
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
                            remediation: "Use a secrets manager or environment variables at runtime".to_string(),
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
        "py", "js", "ts", "jsx", "tsx", "rs", "go", "java", "rb",
        "php", "yaml", "yml", "toml", "json", "xml", "tf", "hcl",
    ].iter().copied().collect();

    walk_dir(dir, &mut |path: &Path| {
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
                        remediation: "Move to environment variable or secrets manager".to_string(),
                    });
                    break;
                }
            }
        }
    });
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

        if has_files && !content.lines().any(|l| {
            let trimmed = l.trim();
            trimmed == *pattern || trimmed.starts_with(pattern)
        }) {
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

fn walk_dir(dir: &Path, callback: &mut dyn FnMut(&Path)) {
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

        if path.is_dir() {
            walk_dir(&path, callback);
        } else if path.is_file() {
            callback(&path);
        }
    }
}
