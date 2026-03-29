//! Package registry existence verification for slopsquatting defence.
//!
//! Checks if a package name exists on npm or `PyPI` before allowing installation.
//! Uses HEAD requests with a configurable timeout and a 1-hour local file cache.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Result of a package existence check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageCheckResult {
    /// Package exists on the registry.
    Exists,
    /// Package does NOT exist on the registry (404).
    NotFound,
    /// Check failed (timeout, network error, etc.) -- fail-open.
    CheckFailed(String),
    /// Check is disabled by configuration.
    Disabled,
}

/// Which package registry to check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registry {
    /// npm registry.
    Npm,
    /// `PyPI` registry.
    PyPi,
}

impl Registry {
    /// Build the URL for checking package existence.
    fn check_url(self, package: &str) -> String {
        match self {
            Self::Npm => format!("https://registry.npmjs.org/{package}"),
            Self::PyPi => format!("https://pypi.org/pypi/{package}/json"),
        }
    }

    /// Short name used in cache file names and user-facing messages.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPi => "PyPI",
        }
    }
}

/// How long cached results remain valid.
const CACHE_TTL: Duration = Duration::from_secs(3600);

/// Return the cache directory path, creating it if necessary.
/// Returns `None` if the directory cannot be determined or created.
fn cache_dir() -> Option<PathBuf> {
    let tmp = std::env::temp_dir();
    let dir = tmp.join("sanctum-pkg-cache");
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Derive a deterministic cache file path for a (registry, package) pair.
fn cache_path(package: &str, registry: Registry) -> Option<PathBuf> {
    let dir = cache_dir()?;
    // Sanitise the package name: replace `/` (npm scoped packages) with `__`.
    let safe_name = package.replace('/', "__");
    Some(dir.join(format!("{}_{safe_name}", registry.name())))
}

/// Read a cached result if it exists and is still fresh (< 1 hour old).
fn read_cache(package: &str, registry: Registry) -> Option<PackageCheckResult> {
    let path = cache_path(package, registry)?;
    let metadata = fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    if age > CACHE_TTL {
        return None;
    }
    let content = fs::read_to_string(&path).ok()?;
    match content.trim() {
        "exists" => Some(PackageCheckResult::Exists),
        "notfound" => Some(PackageCheckResult::NotFound),
        _ => None,
    }
}

/// Write a result to the cache using atomic rename to avoid TOCTOU issues.
fn write_cache(package: &str, registry: Registry, result: &PackageCheckResult) {
    let Some(path) = cache_path(package, registry) else {
        return;
    };
    let value = match result {
        PackageCheckResult::Exists => "exists",
        PackageCheckResult::NotFound => "notfound",
        // Don't cache transient failures.
        PackageCheckResult::CheckFailed(_) | PackageCheckResult::Disabled => return,
    };

    // Write to a temporary file then rename for atomicity.
    let tmp_path = path.with_extension("tmp");
    let write_result = (|| -> Result<(), std::io::Error> {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(value.as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    })();

    if write_result.is_err() {
        // Best-effort cleanup of the temp file.
        let _ignored = fs::remove_file(&tmp_path);
    }
}

/// Check if a package exists on the given registry.
///
/// Uses a blocking HTTP HEAD request with the configured timeout. Fails open:
/// any network error, timeout, or unexpected status code returns `CheckFailed`
/// rather than blocking the install.
#[must_use]
pub fn check_package_exists(
    package: &str,
    registry: Registry,
    timeout: Duration,
) -> PackageCheckResult {
    // 1. Check local cache first.
    if let Some(cached) = read_cache(package, registry) {
        return cached;
    }

    // 2. Make an HTTP HEAD request.
    let url = registry.check_url(package);
    let client = match reqwest::blocking::Client::builder()
        .timeout(timeout)
        .build()
    {
        Ok(c) => c,
        Err(e) => return PackageCheckResult::CheckFailed(e.to_string()),
    };

    let response = match client.head(&url).send() {
        Ok(r) => r,
        Err(e) => return PackageCheckResult::CheckFailed(e.to_string()),
    };

    let status = response.status().as_u16();
    let result = match status {
        200 => PackageCheckResult::Exists,
        404 => PackageCheckResult::NotFound,
        other => PackageCheckResult::CheckFailed(format!("unexpected HTTP status {other}")),
    };

    // 3. Cache the result (only Exists / NotFound are cached).
    write_cache(package, registry, &result);

    result
}

/// Known flags that should be skipped when extracting package names from
/// npm/yarn/pnpm commands.
const NPM_FLAGS: &[&str] = &[
    "--save",
    "--save-dev",
    "--save-exact",
    "--save-optional",
    "--save-peer",
    "--save-prod",
    "--no-save",
    "-D",
    "-E",
    "-O",
    "-P",
    "-g",
    "--global",
    "--legacy-peer-deps",
    "--force",
    "--prefer-offline",
    "--prefer-online",
    "--ignore-scripts",
    "--no-optional",
    "--exact",
    "--tilde",
    "--dev",
    "--peer",
    "--optional",
    "--production",
    "-w",
    "--workspace",
    "--frozen-lockfile",
    "--no-lockfile",
    "--audit",
    "--no-audit",
    "--fund",
    "--no-fund",
];

/// Known flags for pip that should be skipped.
const PIP_FLAGS: &[&str] = &[
    "--user",
    "--system",
    "--target",
    "--prefix",
    "--root",
    "--upgrade",
    "-U",
    "--force-reinstall",
    "--no-deps",
    "--pre",
    "--no-cache-dir",
    "--quiet",
    "-q",
    "--verbose",
    "-v",
    "--break-system-packages",
    "--no-build-isolation",
    "--editable",
    "-e",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--trusted-host",
    "--constraint",
    "-c",
    "--requirement",
    "-r",
];

/// Install command patterns and their corresponding registries.
const INSTALL_PATTERNS: &[(&str, Registry)] = &[
    ("npm install", Registry::Npm),
    ("npm i", Registry::Npm),
    ("npm add", Registry::Npm),
    ("yarn add", Registry::Npm),
    ("pnpm add", Registry::Npm),
    ("pnpm install", Registry::Npm),
    ("pnpm i", Registry::Npm),
    ("bun add", Registry::Npm),
    ("bun install", Registry::Npm),
    ("bun i", Registry::Npm),
    ("pip install", Registry::PyPi),
    ("pip3 install", Registry::PyPi),
    ("uv pip install", Registry::PyPi),
    ("poetry add", Registry::PyPi),
    ("pdm add", Registry::PyPi),
];

/// Check if a token looks like a flag (starts with `-`).
fn is_flag(token: &str) -> bool {
    token.starts_with('-')
}

/// Check if a flag expects a following value argument.
/// These are flags like `--target <dir>`, `--index-url <url>`, etc.
fn flag_expects_value(token: &str) -> bool {
    matches!(
        token,
        "--target"
            | "--prefix"
            | "--root"
            | "--index-url"
            | "-i"
            | "--extra-index-url"
            | "--trusted-host"
            | "--constraint"
            | "-c"
            | "--requirement"
            | "-r"
            | "-w"
            | "--workspace"
            | "-t"
    )
}

/// Strip version specifiers from a package name.
///
/// Handles: `==`, `>=`, `<=`, `~=`, `!=`, `>`, `<`, `@` (pip URL specifier).
/// For npm, also handles `@version` but preserves scoped packages like `@types/node`.
fn strip_version(name: &str, registry: Registry) -> &str {
    match registry {
        Registry::PyPi => {
            // Strip extras like `requests[security]` first.
            let base = name.split('[').next().unwrap_or(name);
            // Find the first version specifier character.
            for (i, c) in base.char_indices() {
                if matches!(c, '=' | '>' | '<' | '~' | '!' | '@') {
                    return &base[..i];
                }
            }
            base
        }
        Registry::Npm => {
            // Scoped packages: @scope/name@version
            if name.starts_with('@') {
                // Find the package part after the scope.
                if let Some(slash_pos) = name.find('/') {
                    let after_slash = &name[slash_pos + 1..];
                    // Look for @version after the package name part.
                    if let Some(at_pos) = after_slash.find('@') {
                        return &name[..slash_pos + 1 + at_pos];
                    }
                    return name;
                }
                // Malformed scoped package, return as-is.
                return name;
            }
            // Unscoped: name@version
            if let Some(at_pos) = name.find('@') {
                return &name[..at_pos];
            }
            name
        }
    }
}

/// Check whether a token looks like a requirements file path (for pip).
fn is_requirements_file(token: &str) -> bool {
    let path = std::path::Path::new(token);
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("txt") || ext.eq_ignore_ascii_case("cfg"))
}

/// Extract a package name and registry from an install command string.
///
/// Returns `None` if the command is not a recognised install command or if
/// no package name can be determined (e.g., bare `npm install`).
///
/// Only extracts the **first** package name. Commands that install multiple
/// packages (e.g., `npm install lodash express`) will only check the first one.
#[must_use]
pub fn extract_package_name(command: &str) -> Option<(String, Registry)> {
    let trimmed = command.trim();

    for &(pattern, registry) in INSTALL_PATTERNS {
        // The pattern must appear at the start of the command or after a
        // chain operator (&&, ||, ;, |).
        let Some(rest) = find_install_rest(trimmed, pattern) else {
            continue;
        };

        let flags: &[&str] = match registry {
            Registry::Npm => NPM_FLAGS,
            Registry::PyPi => PIP_FLAGS,
        };

        // Walk through the remaining tokens to find the first package name.
        let mut tokens = rest.split_whitespace();
        while let Some(token) = tokens.next() {
            // Skip known flags.
            if flags.contains(&token) {
                continue;
            }
            // Skip flags with values (e.g., --target /tmp).
            if flag_expects_value(token) {
                let _value = tokens.next(); // consume the value
                continue;
            }
            // Skip any remaining unknown flags.
            if is_flag(token) {
                // If it contains `=`, the value is inline (e.g., --target=/tmp).
                // Otherwise it's a boolean flag. Either way, skip it.
                continue;
            }
            // Skip -r/--requirement file references for pip.
            if registry == Registry::PyPi && is_requirements_file(token) {
                continue;
            }
            // This should be a package name.
            let name = strip_version(token, registry);
            if name.is_empty() {
                continue;
            }
            return Some((name.to_owned(), registry));
        }

        // Matched the install command but found no package name.
        return None;
    }

    None
}

/// Find the remainder of a command after a matching install pattern.
///
/// The pattern must appear at the start of the command or after a shell
/// chain operator (`&&`, `||`, `;`, `|`). We also require a word boundary
/// after the pattern (space or end-of-string) to avoid matching `npm install-ci`
/// or similar.
fn find_install_rest<'a>(command: &'a str, pattern: &str) -> Option<&'a str> {
    // Check each position where the pattern might start.
    let mut search_start = 0;
    while let Some(pos) = command[search_start..].find(pattern) {
        let abs_pos = search_start + pos;
        let after = abs_pos + pattern.len();

        // Must be at start of command or preceded by a chain operator boundary.
        let at_start = abs_pos == 0;
        let after_chain = if abs_pos > 0 {
            let before = command[..abs_pos].trim_end();
            before.ends_with("&&")
                || before.ends_with("||")
                || before.ends_with(';')
                || before.ends_with('|')
        } else {
            false
        };

        if !at_start && !after_chain {
            search_start = abs_pos + 1;
            continue;
        }

        // Must have a word boundary after the pattern.
        if after < command.len() {
            let next = command.as_bytes()[after];
            if next != b' ' && next != b'\t' && next != b'\n' {
                search_start = abs_pos + 1;
                continue;
            }
        }

        // Return everything after the pattern.
        if after >= command.len() {
            return Some("");
        }
        return Some(&command[after..]);
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- extract_package_name tests ----

    #[test]
    fn extract_npm_install_simple() {
        let result = extract_package_name("npm install lodash");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_npm_install_scoped() {
        let result = extract_package_name("npm install @types/node");
        assert_eq!(result, Some(("@types/node".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_npm_install_with_flags() {
        let result = extract_package_name("npm install --save-dev lodash");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_pip_install_simple() {
        let result = extract_package_name("pip install requests");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pip_install_with_version() {
        let result = extract_package_name("pip install requests==2.28");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pip_install_with_extras() {
        let result = extract_package_name("pip install requests[security]");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_yarn_add() {
        let result = extract_package_name("yarn add lodash");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_pnpm_add() {
        let result = extract_package_name("pnpm add lodash");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_no_package_name() {
        let result = extract_package_name("npm install");
        assert_eq!(result, None);
    }

    #[test]
    fn extract_ignores_flags_only() {
        let result = extract_package_name("npm install -g");
        assert_eq!(result, None);
    }

    #[test]
    fn extract_bun_add() {
        let result = extract_package_name("bun add express");
        assert_eq!(result, Some(("express".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_pip3_install() {
        let result = extract_package_name("pip3 install flask");
        assert_eq!(result, Some(("flask".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_uv_pip_install() {
        let result = extract_package_name("uv pip install numpy");
        assert_eq!(result, Some(("numpy".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_poetry_add() {
        let result = extract_package_name("poetry add django");
        assert_eq!(result, Some(("django".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pdm_add() {
        let result = extract_package_name("pdm add httpx");
        assert_eq!(result, Some(("httpx".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pip_install_with_ge_version() {
        let result = extract_package_name("pip install requests>=2.20");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pip_install_with_tilde_version() {
        let result = extract_package_name("pip install requests~=2.28");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_npm_scoped_with_version() {
        let result = extract_package_name("npm install @types/node@18.0.0");
        assert_eq!(result, Some(("@types/node".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_npm_unscoped_with_version() {
        let result = extract_package_name("npm install lodash@4.17.21");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_from_chained_command() {
        let result = extract_package_name("cd /tmp && npm install lodash");
        assert_eq!(result, Some(("lodash".to_owned(), Registry::Npm)));
    }

    #[test]
    fn extract_pip_with_user_flag() {
        let result = extract_package_name("pip install --user requests");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_pip_with_upgrade_flag() {
        let result = extract_package_name("pip install --upgrade requests");
        assert_eq!(result, Some(("requests".to_owned(), Registry::PyPi)));
    }

    #[test]
    fn extract_npm_i_shorthand() {
        let result = extract_package_name("npm i express");
        assert_eq!(result, Some(("express".to_owned(), Registry::Npm)));
    }

    // ---- cache path tests ----

    #[test]
    fn cache_file_path_is_deterministic() {
        let path1 = cache_path("lodash", Registry::Npm);
        let path2 = cache_path("lodash", Registry::Npm);
        assert_eq!(path1, path2);
    }

    #[test]
    fn cache_path_differs_by_registry() {
        let npm_path = cache_path("requests", Registry::Npm);
        let pypi_path = cache_path("requests", Registry::PyPi);
        assert_ne!(npm_path, pypi_path);
    }

    #[test]
    fn cache_path_sanitises_scoped_packages() {
        let path = cache_path("@types/node", Registry::Npm);
        let path_str = path.unwrap().to_string_lossy().to_string();
        assert!(!path_str.contains("@types/node"));
        assert!(path_str.contains("@types__node"));
    }

    // ---- URL format tests ----

    #[test]
    fn check_url_npm() {
        let url = Registry::Npm.check_url("lodash");
        assert_eq!(url, "https://registry.npmjs.org/lodash");
    }

    #[test]
    fn check_url_pypi() {
        let url = Registry::PyPi.check_url("requests");
        assert_eq!(url, "https://pypi.org/pypi/requests/json");
    }

    #[test]
    fn check_url_npm_scoped() {
        let url = Registry::Npm.check_url("@types/node");
        assert_eq!(url, "https://registry.npmjs.org/@types/node");
    }

    // ---- strip_version tests ----

    #[test]
    fn strip_version_pypi_eq() {
        assert_eq!(strip_version("requests==2.28", Registry::PyPi), "requests");
    }

    #[test]
    fn strip_version_pypi_ge() {
        assert_eq!(strip_version("requests>=2.20", Registry::PyPi), "requests");
    }

    #[test]
    fn strip_version_pypi_tilde() {
        assert_eq!(strip_version("requests~=2.28", Registry::PyPi), "requests");
    }

    #[test]
    fn strip_version_pypi_extras() {
        assert_eq!(
            strip_version("requests[security]", Registry::PyPi),
            "requests"
        );
    }

    #[test]
    fn strip_version_npm_at() {
        assert_eq!(strip_version("lodash@4.17.21", Registry::Npm), "lodash");
    }

    #[test]
    fn strip_version_npm_scoped_at() {
        assert_eq!(
            strip_version("@types/node@18.0.0", Registry::Npm),
            "@types/node"
        );
    }

    #[test]
    fn strip_version_no_version() {
        assert_eq!(strip_version("lodash", Registry::Npm), "lodash");
        assert_eq!(strip_version("requests", Registry::PyPi), "requests");
    }

    // ---- Integration tests (require network) ----

    #[test]
    #[ignore = "requires network access"]
    fn check_real_npm_package_exists() {
        let result = check_package_exists("lodash", Registry::Npm, Duration::from_secs(10));
        assert_eq!(result, PackageCheckResult::Exists);
    }

    #[test]
    #[ignore = "requires network access"]
    fn check_fake_npm_package_not_found() {
        let result = check_package_exists(
            "zzz-definitely-not-a-real-pkg-9999",
            Registry::Npm,
            Duration::from_secs(10),
        );
        assert_eq!(result, PackageCheckResult::NotFound);
    }

    #[test]
    #[ignore = "requires network access"]
    fn check_real_pypi_package_exists() {
        let result = check_package_exists("requests", Registry::PyPi, Duration::from_secs(10));
        assert_eq!(result, PackageCheckResult::Exists);
    }

    #[test]
    #[ignore = "requires network access"]
    fn check_fake_pypi_package_not_found() {
        let result = check_package_exists(
            "zzz-definitely-not-a-real-pkg-9999",
            Registry::PyPi,
            Duration::from_secs(10),
        );
        assert_eq!(result, PackageCheckResult::NotFound);
    }
}
