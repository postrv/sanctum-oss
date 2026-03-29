//! Package registry checker for supply chain security.
//!
//! Validates package names, checks whether packages exist on npm or `PyPI`,
//! and caches results with integrity verification. The cache uses
//! `$XDG_CACHE_HOME/sanctum/pkg-cache/` (or `~/.cache/sanctum/pkg-cache/`)
//! with 0o700 directory and 0o600 file permissions on Unix.
//!
//! # Security properties
//!
//! - Package names are validated against strict character allowlists before
//!   any network request is made.
//! - Cache files are integrity-checked with SHA-256 and symlink-checked
//!   before reading.
//! - HTTP redirect following is limited to 3 hops (SSRF mitigation).
//! - Multi-package commands (e.g. `npm install a b c`) extract all names.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Maximum number of redirects to follow for registry checks (SSRF mitigation).
const MAX_REDIRECTS: usize = 3;

/// A package registry that can be checked for package existence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Registry {
    /// npm registry (<https://registry.npmjs.org>).
    Npm,
    /// `PyPI` registry (<https://pypi.org>).
    PyPi,
}

impl Registry {
    /// Return the base URL for this registry.
    #[must_use]
    const fn base_url(self) -> &'static str {
        match self {
            Self::Npm => "https://registry.npmjs.org",
            Self::PyPi => "https://pypi.org/pypi",
        }
    }

    /// Construct the full URL for checking a package.
    ///
    /// Returns `None` if the package name is invalid for this registry.
    #[must_use]
    fn package_url(self, name: &str) -> Option<String> {
        if !is_valid_package_name(name, self) {
            return None;
        }
        match self {
            Self::Npm => Some(format!("{}/{name}", self.base_url())),
            Self::PyPi => Some(format!("{}/{name}/json", self.base_url())),
        }
    }
}

impl std::fmt::Display for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Npm => write!(f, "npm"),
            Self::PyPi => write!(f, "pypi"),
        }
    }
}

/// Result of checking whether a package exists on a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Package exists on the registry.
    Exists,
    /// Package was not found (404).
    NotFound,
    /// Check failed due to an error.
    CheckFailed(String),
}

/// Known npm install flags that should be skipped during package name extraction.
const NPM_FLAGS: &[&str] = &[
    "-D",
    "--save-dev",
    "-S",
    "--save",
    "-O",
    "--save-optional",
    "-E",
    "--save-exact",
    "-P",
    "--save-prod",
    "--no-save",
    "-g",
    "--global",
    "--legacy-peer-deps",
    "--force",
    "--prefer-offline",
    "--prefer-online",
    "--dry-run",
    "--package-lock-only",
    "--ignore-scripts",
    "--no-optional",
    "--no-audit",
    "--no-fund",
    "--production",
    "--also=dev",
    "-B",
    "--save-bundle",
    "--no-package-lock",
    "-w",
    "--workspace",
    "--workspaces",
];

/// Validate that a package name contains only allowed characters for the given
/// registry.
///
/// - npm: `^(@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+$`
/// - `PyPI`: `^[a-zA-Z0-9._-]+$`
///
/// Additionally, names containing `..`, null bytes, `?`, or `#` are rejected.
#[must_use]
pub fn is_valid_package_name(name: &str, registry: Registry) -> bool {
    if name.is_empty() {
        return false;
    }

    // Reject null bytes, query strings, fragments, and path traversals
    if name.contains('\0') || name.contains('?') || name.contains('#') || name.contains("..") {
        return false;
    }

    match registry {
        Registry::Npm => is_valid_npm_name(name),
        Registry::PyPi => is_valid_pypi_name(name),
    }
}

/// Check if a name is valid per npm conventions.
///
/// Scoped: `@scope/name` where scope and name match `[a-zA-Z0-9._-]+`
/// Unscoped: `[a-zA-Z0-9._-]+`
fn is_valid_npm_name(name: &str) -> bool {
    if let Some(rest) = name.strip_prefix('@') {
        // Scoped package: must have exactly one `/`
        let Some((scope, pkg)) = rest.split_once('/') else {
            return false;
        };
        if scope.is_empty() || pkg.is_empty() {
            return false;
        }
        is_safe_name_chars(scope) && is_safe_name_chars(pkg)
    } else {
        // Reject unscoped names that contain `@`
        if name.contains('@') {
            return false;
        }
        is_safe_name_chars(name)
    }
}

/// Check if a name is valid per `PyPI` conventions.
fn is_valid_pypi_name(name: &str) -> bool {
    if name.contains('@') {
        return false;
    }
    is_safe_name_chars(name)
}

/// Check if a string contains only `[a-zA-Z0-9._-]`.
fn is_safe_name_chars(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

/// Detect the registry type from a command string.
///
/// Returns `Some(Registry)` if the command appears to be a package install command.
#[must_use]
fn detect_registry(command: &str) -> Option<Registry> {
    let trimmed = command.trim();
    let first_word = trimmed.split_whitespace().next()?;

    match first_word {
        "npm" | "npx" | "yarn" | "pnpm" | "bun" => Some(Registry::Npm),
        "pip" | "pip3" | "pipx" | "uv" => Some(Registry::PyPi),
        _ => None,
    }
}

/// Check if a token looks like a flag (starts with `-`).
fn is_flag(token: &str) -> bool {
    token.starts_with('-')
}

/// Check if a flag expects a following value argument.
///
/// These are flags like `--workspace <name>` that take the next token as a value.
fn flag_takes_value(flag: &str) -> bool {
    matches!(flag, "-w" | "--workspace")
}

/// Extract all package names from a shell command string.
///
/// Parses commands like `npm install lodash express react` and returns a
/// vector of `(package_name, registry)` pairs. Flags (e.g. `-D`, `--save-dev`)
/// are correctly skipped.
///
/// Also handles scoped packages (`@scope/name`) and versioned specifiers
/// (`lodash@4.17.21` strips the version suffix for the name).
///
/// # Examples
///
/// ```
/// use sanctum_firewall::registry::{extract_package_names, Registry};
///
/// let packages = extract_package_names("npm install lodash express");
/// assert_eq!(packages.len(), 2);
/// assert_eq!(packages[0], ("lodash".to_string(), Registry::Npm));
/// assert_eq!(packages[1], ("express".to_string(), Registry::Npm));
/// ```
#[must_use]
pub fn extract_package_names(command: &str) -> Vec<(String, Registry)> {
    let Some(registry) = detect_registry(command) else {
        return Vec::new();
    };

    let tokens: Vec<&str> = command.split_whitespace().collect();

    // Find the install subcommand
    let install_idx = tokens
        .iter()
        .position(|t| matches!(*t, "install" | "add" | "i" | "ci" | "update" | "upgrade"));

    let Some(idx) = install_idx else {
        return Vec::new();
    };

    let mut result = Vec::new();
    let mut skip_next = false;

    for token in &tokens[idx + 1..] {
        if skip_next {
            skip_next = false;
            continue;
        }

        if is_flag(token) {
            // Check if this flag is known
            if NPM_FLAGS.contains(token) && flag_takes_value(token) {
                skip_next = true;
            }
            continue;
        }

        // Strip version specifier: `lodash@4.17.21` -> `lodash`
        // But preserve scoped packages: `@scope/pkg@1.0` -> `@scope/pkg`
        let name = strip_version_specifier(token);

        if !name.is_empty() && is_valid_package_name(name, registry) {
            result.push((name.to_string(), registry));
        }
    }

    result
}

/// Strip a version specifier suffix from a package token.
///
/// `lodash@4.17.21` -> `lodash`
/// `@scope/pkg@1.0.0` -> `@scope/pkg`
/// `lodash` -> `lodash`
fn strip_version_specifier(token: &str) -> &str {
    token.strip_prefix('@').map_or_else(
        // Unscoped: first `@` is the version separator
        || token.split('@').next().unwrap_or(token),
        // Scoped package: find the second `@` (version separator)
        |rest| rest.find('@').map_or(token, |pos| &token[..=pos]),
    )
}

/// Backward-compatible single-package extraction.
///
/// Returns the first package name found, if any.
#[must_use]
pub fn extract_package_name(command: &str) -> Option<(String, Registry)> {
    extract_package_names(command).into_iter().next()
}

/// Resolve the cache directory path.
///
/// Uses `$XDG_CACHE_HOME/sanctum/pkg-cache/` if set, otherwise
/// `~/.cache/sanctum/pkg-cache/`.
///
/// Returns `None` if the home directory cannot be determined.
#[must_use]
pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("sanctum").join("pkg-cache"));
        }
    }

    // Fall back to ~/.cache
    home_dir().map(|h| h.join(".cache").join("sanctum").join("pkg-cache"))
}

/// Get the user home directory from `$HOME`.
fn home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

/// Ensure the cache directory exists with secure permissions (0o700).
///
/// Also verifies the directory is not a symlink.
///
/// # Errors
///
/// Returns an I/O error if directory creation fails, the path is a symlink,
/// or permissions cannot be set.
pub fn ensure_cache_dir() -> Result<PathBuf, std::io::Error> {
    let dir = cache_dir().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine cache directory (HOME not set)",
        )
    })?;

    // Create parent directories first
    if let Some(parent) = dir.parent() {
        ensure_dir_not_symlink(parent)?;
        std::fs::create_dir_all(parent)?;
    }

    // Create the final directory with secure permissions
    ensure_dir_not_symlink_if_exists(&dir)?;
    sanctum_types::fs_safety::ensure_secure_dir(&dir)?;

    Ok(dir)
}

/// Check that a path, if it exists, is not a symlink.
fn ensure_dir_not_symlink_if_exists(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("cache directory is a symlink: {}", path.display()),
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Check that a path is not a symlink (it must exist).
fn ensure_dir_not_symlink(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_symlink() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("path is a symlink: {}", path.display()),
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Compute the SHA-256 hex digest of content.
fn sha256_hex(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a safe filename from a registry + package name.
fn cache_filename(name: &str, registry: Registry) -> String {
    // Use a hash to avoid path issues with scoped package names
    let key = format!("{registry}:{name}");
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Read a cached check result, verifying integrity and rejecting symlinks.
///
/// Returns `None` if the cache entry does not exist, is invalid, or has been
/// tampered with.
#[must_use]
pub fn read_cache(name: &str, registry: Registry) -> Option<CheckResult> {
    let dir = cache_dir()?;
    let path = dir.join(cache_filename(name, registry));

    // Reject symlinks
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if meta.is_symlink() {
        tracing::warn!(path = %path.display(), "cache file is a symlink, rejecting");
        return None;
    }

    let raw = std::fs::read_to_string(&path).ok()?;

    // Parse integrity format: `content|sha256_hex`
    let (content, stored_hash) = raw.rsplit_once('|')?;
    let computed_hash = sha256_hex(content);
    if computed_hash != stored_hash {
        tracing::warn!(
            path = %path.display(),
            "cache integrity check failed (expected {stored_hash}, got {computed_hash})"
        );
        return None;
    }

    match content {
        "exists" => Some(CheckResult::Exists),
        "not_found" => Some(CheckResult::NotFound),
        _ => None,
    }
}

/// Write a check result to the cache with integrity protection.
///
/// The file is created with 0o600 permissions on Unix.
///
/// # Errors
///
/// Returns an I/O error if the file cannot be written.
pub fn write_cache(
    name: &str,
    registry: Registry,
    result: &CheckResult,
) -> Result<(), std::io::Error> {
    let dir = ensure_cache_dir()?;

    // Verify cache directory is still not a symlink before writing
    ensure_dir_not_symlink(&dir)?;

    let content = match result {
        CheckResult::Exists => "exists",
        CheckResult::NotFound => "not_found",
        CheckResult::CheckFailed(_) => return Ok(()), // Don't cache errors
    };

    let hash = sha256_hex(content);
    let payload = format!("{content}|{hash}");

    let path = dir.join(cache_filename(name, registry));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(payload.as_bytes())?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&path, &payload)?;
    }

    Ok(())
}

/// Check if a package exists on its registry.
///
/// Uses a cached result if available. Otherwise makes an HTTP HEAD request
/// to the registry with a limited redirect policy (max 3 hops).
///
/// # Errors
///
/// This function does not return errors; failures are wrapped in
/// `CheckResult::CheckFailed`.
pub async fn check_package_exists(name: &str, registry: Registry) -> CheckResult {
    // Validate name before doing anything
    if !is_valid_package_name(name, registry) {
        return CheckResult::CheckFailed(format!("invalid package name: {name}"));
    }

    // Check cache first
    if let Some(cached) = read_cache(name, registry) {
        return cached;
    }

    let Some(url) = registry.package_url(name) else {
        return CheckResult::CheckFailed(format!("could not construct URL for {name}"));
    };

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
        .build()
    {
        Ok(c) => c,
        Err(e) => return CheckResult::CheckFailed(format!("failed to build HTTP client: {e}")),
    };

    let result = match client.head(&url).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                CheckResult::Exists
            } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
                CheckResult::NotFound
            } else {
                CheckResult::CheckFailed(format!(
                    "registry returned status {} for {name}",
                    resp.status()
                ))
            }
        }
        Err(e) => CheckResult::CheckFailed(format!("HTTP request failed for {name}: {e}")),
    };

    // Cache successful lookups (ignore write errors)
    let _ = write_cache(name, registry, &result);

    result
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Mutex to serialise tests that manipulate environment variables, preventing
    /// race conditions between parallel test threads.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // --- H4: Multi-package extraction ---

    #[test]
    fn test_extract_multiple_packages() {
        let packages = extract_package_names("npm install a b c");
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0], ("a".to_string(), Registry::Npm));
        assert_eq!(packages[1], ("b".to_string(), Registry::Npm));
        assert_eq!(packages[2], ("c".to_string(), Registry::Npm));
    }

    #[test]
    fn test_extract_packages_with_flags() {
        let packages = extract_package_names("npm install -D a b --save-exact c");
        assert_eq!(packages.len(), 3);
        assert_eq!(packages[0].0, "a");
        assert_eq!(packages[1].0, "b");
        assert_eq!(packages[2].0, "c");
    }

    #[test]
    fn test_extract_scoped_packages() {
        let packages = extract_package_names("npm install @scope/pkg other");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0], ("@scope/pkg".to_string(), Registry::Npm));
        assert_eq!(packages[1], ("other".to_string(), Registry::Npm));
    }

    #[test]
    fn test_extract_versioned_packages() {
        let packages = extract_package_names("npm install lodash@4.17.21 express@latest");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].0, "lodash");
        assert_eq!(packages[1].0, "express");
    }

    #[test]
    fn test_extract_scoped_versioned_packages() {
        let packages = extract_package_names("npm install @types/node@20.0.0");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].0, "@types/node");
    }

    #[test]
    fn test_extract_yarn_add() {
        let packages = extract_package_names("yarn add react react-dom");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0].0, "react");
        assert_eq!(packages[1].0, "react-dom");
    }

    #[test]
    fn test_extract_pip_install() {
        let packages = extract_package_names("pip install requests flask");
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0], ("requests".to_string(), Registry::PyPi));
        assert_eq!(packages[1], ("flask".to_string(), Registry::PyPi));
    }

    #[test]
    fn test_extract_no_install_command() {
        let packages = extract_package_names("npm run build");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_extract_unknown_command() {
        let packages = extract_package_names("cargo install ripgrep");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_extract_empty_command() {
        let packages = extract_package_names("");
        assert!(packages.is_empty());
    }

    #[test]
    fn test_backward_compat_extract_package_name() {
        let result = extract_package_name("npm install lodash");
        assert_eq!(result, Some(("lodash".to_string(), Registry::Npm)));
    }

    #[test]
    fn test_extract_workspace_flag_with_value() {
        let packages = extract_package_names("npm install -w my-workspace lodash");
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].0, "lodash");
    }

    // --- M5+M6+M8: Cache hardening ---

    #[test]
    fn test_cache_dir_is_user_private() {
        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Clear XDG to test default
        let _xdg_guard = TempEnvGuard::new("XDG_CACHE_HOME", None);
        let _home_guard = TempEnvGuard::new("HOME", Some("/home/testuser"));

        let dir = cache_dir().expect("should resolve");
        assert_eq!(
            dir,
            PathBuf::from("/home/testuser/.cache/sanctum/pkg-cache")
        );
        // Must NOT be in TMPDIR
        assert!(
            !dir.to_string_lossy().contains("/tmp"),
            "cache dir must not be in /tmp"
        );
    }

    #[test]
    fn test_cache_dir_respects_xdg() {
        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _guard = TempEnvGuard::new("XDG_CACHE_HOME", Some("/custom/cache"));

        let dir = cache_dir().expect("should resolve");
        assert_eq!(dir, PathBuf::from("/custom/cache/sanctum/pkg-cache"));
    }

    #[test]
    #[cfg(unix)]
    fn test_cache_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = TempEnvGuard::new("XDG_CACHE_HOME", Some(tmp.path().to_str().expect("path")));

        write_cache("test-pkg", Registry::Npm, &CheckResult::Exists).expect("write");

        let cache_path = tmp
            .path()
            .join("sanctum")
            .join("pkg-cache")
            .join(cache_filename("test-pkg", Registry::Npm));

        let mode = std::fs::metadata(&cache_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "cache file must have 0o600 permissions");
    }

    #[test]
    #[cfg(unix)]
    fn test_cache_rejects_symlinks() {
        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = TempEnvGuard::new("XDG_CACHE_HOME", Some(tmp.path().to_str().expect("path")));

        // Write a valid cache entry
        write_cache("symlink-test", Registry::Npm, &CheckResult::Exists).expect("write");

        let filename = cache_filename("symlink-test", Registry::Npm);
        let cache_path = tmp.path().join("sanctum").join("pkg-cache").join(&filename);

        // Replace the file with a symlink
        let real_file = tmp.path().join("real_cache");
        std::fs::write(&real_file, "exists|deadbeef").expect("write real");
        std::fs::remove_file(&cache_path).expect("remove");
        std::os::unix::fs::symlink(&real_file, &cache_path).expect("symlink");

        // Reading should reject the symlink
        let result = read_cache("symlink-test", Registry::Npm);
        assert!(result.is_none(), "symlink cache files must be rejected");
    }

    #[test]
    fn test_cache_integrity_check() {
        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = TempEnvGuard::new("XDG_CACHE_HOME", Some(tmp.path().to_str().expect("path")));

        // Write a valid cache entry
        write_cache("integrity-test", Registry::Npm, &CheckResult::Exists).expect("write");

        // Verify it reads back correctly
        let result = read_cache("integrity-test", Registry::Npm);
        assert_eq!(result, Some(CheckResult::Exists));

        // Tamper with the content
        let filename = cache_filename("integrity-test", Registry::Npm);
        let cache_path = tmp.path().join("sanctum").join("pkg-cache").join(&filename);
        std::fs::write(&cache_path, "not_found|wrong_hash_value").expect("tamper");

        // Reading tampered content should fail
        let result = read_cache("integrity-test", Registry::Npm);
        assert!(result.is_none(), "tampered cache must be rejected");
    }

    #[test]
    fn test_cache_does_not_store_errors() {
        let _lock = ENV_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmp = tempfile::tempdir().expect("tempdir");
        let _guard = TempEnvGuard::new("XDG_CACHE_HOME", Some(tmp.path().to_str().expect("path")));

        write_cache(
            "error-test",
            Registry::Npm,
            &CheckResult::CheckFailed("timeout".to_string()),
        )
        .expect("write");

        let result = read_cache("error-test", Registry::Npm);
        assert!(result.is_none(), "errors should not be cached");
    }

    // --- Package name validation ---

    #[test]
    fn test_package_name_validation_rejects_traversal() {
        assert!(!is_valid_package_name("../etc/passwd", Registry::Npm));
        assert!(!is_valid_package_name("foo/../bar", Registry::Npm));
        assert!(!is_valid_package_name("..", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_accepts_scoped() {
        assert!(is_valid_package_name("@types/node", Registry::Npm));
        assert!(is_valid_package_name("@babel/core", Registry::Npm));
        assert!(is_valid_package_name("@angular/cli", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_accepts_normal() {
        assert!(is_valid_package_name("lodash", Registry::Npm));
        assert!(is_valid_package_name("express", Registry::Npm));
        assert!(is_valid_package_name("my-package", Registry::Npm));
        assert!(is_valid_package_name("my_package", Registry::Npm));
        assert!(is_valid_package_name("my.package", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_rejects_null_bytes() {
        assert!(!is_valid_package_name("foo\0bar", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_rejects_query_fragment() {
        assert!(!is_valid_package_name("foo?bar", Registry::Npm));
        assert!(!is_valid_package_name("foo#bar", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_rejects_empty() {
        assert!(!is_valid_package_name("", Registry::Npm));
        assert!(!is_valid_package_name("", Registry::PyPi));
    }

    #[test]
    fn test_package_name_validation_rejects_at_in_unscoped() {
        // `@` in the middle of an unscoped name is not valid
        assert!(!is_valid_package_name("foo@bar", Registry::Npm));
    }

    #[test]
    fn test_package_name_validation_rejects_incomplete_scope() {
        assert!(!is_valid_package_name("@/name", Registry::Npm));
        assert!(!is_valid_package_name("@scope/", Registry::Npm));
        assert!(!is_valid_package_name("@", Registry::Npm));
    }

    #[test]
    fn test_pypi_rejects_scoped_names() {
        assert!(!is_valid_package_name("@scope/pkg", Registry::PyPi));
    }

    #[test]
    fn test_pypi_accepts_normal_names() {
        assert!(is_valid_package_name("requests", Registry::PyPi));
        assert!(is_valid_package_name("my-package", Registry::PyPi));
        assert!(is_valid_package_name("Flask", Registry::PyPi));
    }

    // --- Redirect policy ---

    #[test]
    fn test_redirect_policy_limited() {
        // Verify the constant is sensible at compile time
        const {
            assert!(MAX_REDIRECTS <= 5, "redirect policy should be limited");
            assert!(MAX_REDIRECTS > 0, "at least one redirect should be allowed");
        }

        // Verify we can build a client with the limited redirect policy
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(MAX_REDIRECTS))
            .build();
        assert!(client.is_ok(), "client with limited redirects should build");
    }

    #[test]
    fn test_registry_url_construction() {
        let url = Registry::Npm.package_url("lodash");
        assert_eq!(url, Some("https://registry.npmjs.org/lodash".to_string()));

        let url = Registry::PyPi.package_url("requests");
        assert_eq!(url, Some("https://pypi.org/pypi/requests/json".to_string()));
    }

    #[test]
    fn test_registry_url_rejects_invalid_name() {
        let url = Registry::Npm.package_url("../etc/passwd");
        assert_eq!(url, None);
    }

    #[test]
    fn test_registry_display() {
        assert_eq!(format!("{}", Registry::Npm), "npm");
        assert_eq!(format!("{}", Registry::PyPi), "pypi");
    }

    #[test]
    fn test_strip_version_specifier() {
        assert_eq!(strip_version_specifier("lodash@4.17.21"), "lodash");
        assert_eq!(strip_version_specifier("lodash"), "lodash");
        assert_eq!(strip_version_specifier("@types/node@20.0.0"), "@types/node");
        assert_eq!(strip_version_specifier("@scope/pkg"), "@scope/pkg");
    }

    #[test]
    fn test_check_result_equality() {
        assert_eq!(CheckResult::Exists, CheckResult::Exists);
        assert_eq!(CheckResult::NotFound, CheckResult::NotFound);
        assert_ne!(CheckResult::Exists, CheckResult::NotFound);
    }

    // --- Helper for temporarily setting env vars in tests ---

    /// RAII guard that sets an environment variable for the duration of a test
    /// and restores the original value on drop.
    struct TempEnvGuard {
        key: String,
        original: Option<String>,
    }

    impl TempEnvGuard {
        fn new(key: &str, value: Option<&str>) -> Self {
            let original = std::env::var(key).ok();
            match value {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for TempEnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var(&self.key, v),
                None => std::env::remove_var(&self.key),
            }
        }
    }
}
