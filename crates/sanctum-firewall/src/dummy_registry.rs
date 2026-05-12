//! Registry for shape-valid dummy secrets used in tests and docs.
//!
//! The registry stores SHA-256 hashes of dummy values, never plaintext. A
//! registered dummy is only allowed when it is written to an approved path and,
//! by default, the write includes an explicit `SANCTUM_DUMMY_SECRET` marker.

use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Marker that proves a registered dummy value is intentionally test data.
pub const DUMMY_SECRET_MARKER: &str = "SANCTUM_DUMMY_SECRET";

/// Registry file name under Sanctum's data directory.
pub const DUMMY_REGISTRY_FILE: &str = "dummy_secrets.json";

const MAX_REGISTRY_ENTRIES: usize = 1_000;
const MAX_REGISTRY_BYTES: u64 = 1_048_576;

/// A registered dummy secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummySecretEntry {
    /// SHA-256 hex of the dummy value.
    pub hash: String,
    /// Provider family, e.g. `openai`, `anthropic`, `stripe`.
    pub provider: String,
    /// Human-friendly label used for listing/revocation.
    pub label: String,
    /// Glob-like path patterns where this dummy is permitted.
    pub allowed_paths: Vec<String>,
    /// Require an explicit marker in the path or content.
    pub require_marker: bool,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// In-memory dummy registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DummyRegistry {
    /// Registered entries.
    pub entries: Vec<DummySecretEntry>,
}

impl DummyRegistry {
    /// Create an empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Return `true` when the registry has no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Register a dummy secret value.
    ///
    /// The plaintext value is hashed immediately and is never retained.
    ///
    /// # Errors
    ///
    /// Returns an error if the registry is full, metadata is invalid, or the
    /// label/hash already exists.
    pub fn mint(
        &mut self,
        value: &str,
        provider: &str,
        label: &str,
        allowed_paths: Vec<String>,
        require_marker: bool,
    ) -> io::Result<DummySecretEntry> {
        validate_entry_fields(provider, label, &allowed_paths)?;
        if self.entries.len() >= MAX_REGISTRY_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dummy registry is full",
            ));
        }

        let hash = hash_secret(value);
        if self.entries.iter().any(|entry| entry.hash == hash) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "dummy secret hash already registered",
            ));
        }
        if self.entries.iter().any(|entry| entry.label == label) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "dummy secret label already registered",
            ));
        }

        let entry = DummySecretEntry {
            hash,
            provider: provider.to_owned(),
            label: label.to_owned(),
            allowed_paths,
            require_marker,
            created_at: Utc::now(),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Register an already-computed SHA-256 hash.
    ///
    /// Used by authenticated IPC so callers never need to send plaintext dummy
    /// values to the daemon.
    ///
    /// # Errors
    ///
    /// Returns an error if the hash or metadata is invalid, the registry is
    /// full, or the label/hash already exists.
    pub fn insert_hash(
        &mut self,
        hash: &str,
        provider: &str,
        label: &str,
        allowed_paths: Vec<String>,
        require_marker: bool,
    ) -> io::Result<DummySecretEntry> {
        validate_entry_fields(provider, label, &allowed_paths)?;
        if !is_valid_hash(hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dummy secret hash must be 64 lowercase hex characters",
            ));
        }
        if self.entries.len() >= MAX_REGISTRY_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dummy registry is full",
            ));
        }
        if self.entries.iter().any(|entry| entry.hash == hash) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "dummy secret hash already registered",
            ));
        }
        if self.entries.iter().any(|entry| entry.label == label) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "dummy secret label already registered",
            ));
        }

        let entry = DummySecretEntry {
            hash: hash.to_owned(),
            provider: provider.to_owned(),
            label: label.to_owned(),
            allowed_paths,
            require_marker,
            created_at: Utc::now(),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Revoke entries by label or hash prefix.
    ///
    /// Returns the number of removed entries.
    pub fn revoke(&mut self, label: Option<&str>, hash_prefix: Option<&str>) -> usize {
        let before = self.entries.len();
        self.entries.retain(|entry| {
            let label_match = label.is_some_and(|needle| entry.label == needle);
            let hash_match = hash_prefix.is_some_and(|needle| entry.hash.starts_with(needle));
            !(label_match || hash_match)
        });
        before.saturating_sub(self.entries.len())
    }

    /// Find an entry by plaintext value.
    #[must_use]
    pub fn find_by_value(&self, value: &str) -> Option<&DummySecretEntry> {
        let hash = hash_secret(value);
        self.entries.iter().find(|entry| entry.hash == hash)
    }

    /// Return `true` if `value` is registered and allowed in this path/content.
    #[must_use]
    pub fn is_registered_dummy_allowed(&self, value: &str, path: &str, content: &str) -> bool {
        let Some(entry) = self.find_by_value(value) else {
            return false;
        };
        entry.is_allowed_in_context(path, content)
    }
}

impl DummySecretEntry {
    /// Return a short hash prefix for display.
    #[must_use]
    pub fn hash_prefix(&self) -> &str {
        self.hash.get(..12).unwrap_or(&self.hash)
    }

    /// Return `true` when path and marker requirements are satisfied.
    #[must_use]
    pub fn is_allowed_in_context(&self, path: &str, content: &str) -> bool {
        let path_ok = self
            .allowed_paths
            .iter()
            .any(|pattern| path_matches_pattern(pattern, path));
        if !path_ok {
            return false;
        }

        !self.require_marker
            || path.contains(DUMMY_SECRET_MARKER)
            || content.contains(DUMMY_SECRET_MARKER)
    }
}

/// Resolve the default registry path from a data directory.
#[must_use]
pub fn registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DUMMY_REGISTRY_FILE)
}

/// SHA-256 hash a dummy value as lowercase hex.
#[must_use]
pub fn hash_secret(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// Load the registry from disk.
///
/// Missing files return an empty registry. Invalid JSON returns an error so
/// callers that use best-effort loading can fail closed by using an empty
/// registry.
///
/// # Errors
///
/// Returns an error if the file cannot be read, exceeds the size limit, or does
/// not contain a valid registry.
pub fn load_registry(path: &Path) -> io::Result<DummyRegistry> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(DummyRegistry::new()),
        Err(e) => return Err(e),
    };
    if metadata.len() > MAX_REGISTRY_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dummy registry exceeds size limit",
        ));
    }

    let content = std::fs::read_to_string(path)?;
    let registry: DummyRegistry = serde_json::from_str(&content).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid dummy registry JSON: {e}"),
        )
    })?;
    validate_registry(&registry)?;
    Ok(registry)
}

/// Load the registry, returning an empty registry on any error.
#[must_use]
pub fn load_registry_best_effort(path: &Path) -> DummyRegistry {
    load_registry(path).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), %e, "failed to load dummy registry; failing closed");
        DummyRegistry::new()
    })
}

/// Save the registry atomically.
///
/// # Errors
///
/// Returns an error if the registry is invalid or cannot be written to disk.
pub fn save_registry(path: &Path, registry: &DummyRegistry) -> io::Result<()> {
    validate_registry(registry)?;

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "dummy registry path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;

    let content = serde_json::to_vec_pretty(registry).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to serialise dummy registry: {e}"),
        )
    })?;

    let temp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(DUMMY_REGISTRY_FILE)
    ));
    sanctum_types::fs_safety::write_private_file(&temp_path, &content, 0o400)?;
    std::fs::rename(&temp_path, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp_path);
    })
}

fn validate_registry(registry: &DummyRegistry) -> io::Result<()> {
    if registry.entries.len() > MAX_REGISTRY_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dummy registry has too many entries",
        ));
    }
    let mut labels = std::collections::HashSet::new();
    let mut hashes = std::collections::HashSet::new();
    for entry in &registry.entries {
        validate_entry_fields(&entry.provider, &entry.label, &entry.allowed_paths)?;
        if !is_valid_hash(&entry.hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dummy registry contains invalid hash",
            ));
        }
        if !labels.insert(entry.label.as_str()) || !hashes.insert(entry.hash.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dummy registry contains duplicate labels or hashes",
            ));
        }
    }
    Ok(())
}

fn validate_entry_fields(provider: &str, label: &str, paths: &[String]) -> io::Result<()> {
    let provider_ok = !provider.is_empty()
        && provider.len() <= 64
        && provider
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let label_ok = !label.is_empty()
        && label.len() <= 128
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
    let paths_ok = !paths.is_empty()
        && paths.len() <= 32
        && paths
            .iter()
            .all(|path| !path.is_empty() && path.len() <= 512 && !path.contains('\0'));
    if provider_ok && label_ok && paths_ok {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid dummy registry entry metadata",
        ))
    }
}

fn is_valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn path_matches_pattern(pattern: &str, path: &str) -> bool {
    let normalised_pattern = pattern.replace('\\', "/");
    let normalised_path = path.replace('\\', "/");
    wildcard_match(&normalised_pattern, &normalised_path)
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut p_idx, mut t_idx) = (0_usize, 0_usize);
    let mut star_idx = None;
    let mut retry_text_idx = 0_usize;

    while t_idx < text.len() {
        if p_idx < pattern.len() && (pattern[p_idx] == '?' || pattern[p_idx] == text[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < pattern.len() && pattern[p_idx] == '*' {
            star_idx = Some(p_idx);
            p_idx += 1;
            retry_text_idx = t_idx;
        } else if let Some(star) = star_idx {
            p_idx = star + 1;
            retry_text_idx += 1;
            t_idx = retry_text_idx;
        } else {
            return false;
        }
    }

    pattern[p_idx..].iter().all(|ch| *ch == '*')
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn dummy_value() -> &'static str {
        "sk-proj-dummyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    }

    #[test]
    fn registry_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(DUMMY_REGISTRY_FILE);
        let mut registry = DummyRegistry::new();
        registry
            .mint(
                dummy_value(),
                "openai",
                "router-tests",
                vec!["tests/**".to_owned()],
                true,
            )
            .expect("mint");

        save_registry(&path, &registry).expect("save");
        let loaded = load_registry(&path).expect("load");
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].label, "router-tests");
    }

    #[test]
    fn invalid_json_fails_closed_with_best_effort_loader() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(DUMMY_REGISTRY_FILE);
        std::fs::write(&path, "{not-json").expect("write");

        assert!(load_registry(&path).is_err());
        assert!(load_registry_best_effort(&path).is_empty());
    }

    #[test]
    fn duplicate_label_is_rejected() {
        let mut registry = DummyRegistry::new();
        registry
            .mint(
                dummy_value(),
                "openai",
                "same",
                vec!["tests/**".to_owned()],
                true,
            )
            .expect("first");
        let err = registry
            .mint(
                "sk-proj-differentABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                "openai",
                "same",
                vec!["tests/**".to_owned()],
                true,
            )
            .expect_err("duplicate label");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    }

    #[test]
    fn revoke_by_label_and_hash_prefix() {
        let mut registry = DummyRegistry::new();
        let entry = registry
            .mint(
                dummy_value(),
                "openai",
                "router-tests",
                vec!["tests/**".to_owned()],
                true,
            )
            .expect("mint");
        assert_eq!(registry.revoke(Some("nope"), None), 0);
        assert_eq!(registry.revoke(None, Some(entry.hash_prefix())), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn dummy_requires_path_and_marker() {
        let mut registry = DummyRegistry::new();
        registry
            .mint(
                dummy_value(),
                "openai",
                "router-tests",
                vec!["tests/**".to_owned()],
                true,
            )
            .expect("mint");

        assert!(registry.is_registered_dummy_allowed(
            dummy_value(),
            "tests/router_test.rs",
            DUMMY_SECRET_MARKER,
        ));
        assert!(!registry.is_registered_dummy_allowed(
            dummy_value(),
            "src/router.rs",
            DUMMY_SECRET_MARKER,
        ));
        assert!(!registry.is_registered_dummy_allowed(dummy_value(), "tests/router_test.rs", "",));
    }

    #[test]
    fn registry_size_limit_is_enforced() {
        let entries = (0..=MAX_REGISTRY_ENTRIES)
            .map(|idx| DummySecretEntry {
                hash: format!("{:064x}", idx + 1),
                provider: "openai".to_owned(),
                label: format!("label-{idx}"),
                allowed_paths: vec!["tests/**".to_owned()],
                require_marker: true,
                created_at: Utc::now(),
            })
            .collect();
        let registry = DummyRegistry { entries };
        assert!(validate_registry(&registry).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_file_has_0400_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(DUMMY_REGISTRY_FILE);
        save_registry(&path, &DummyRegistry::new()).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
    }

    #[test]
    fn glob_matching_is_linear_and_handles_common_patterns() {
        assert!(path_matches_pattern("tests/**", "tests/router/unit.rs"));
        assert!(path_matches_pattern(r"tests\**", "tests/router/unit.rs"));
        assert!(path_matches_pattern(
            "fixtures/*.json",
            "fixtures/token.json"
        ));
        assert!(path_matches_pattern(
            "fixtures/*.json",
            "fixtures/nested/token.json"
        ));
        assert!(!path_matches_pattern("tests/*", "src/router.rs"));
    }

    #[test]
    fn glob_matching_handles_repeated_wildcards_without_regex() {
        let pattern = "*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?*?";
        assert!(path_matches_pattern(pattern, "abcdefghijklmnopqrstuvwxyz"));
        assert!(!path_matches_pattern(pattern, "short"));
    }
}
