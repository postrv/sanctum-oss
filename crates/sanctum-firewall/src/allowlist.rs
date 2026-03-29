//! Entropy allowlist management.
//!
//! Maintains a persistent set of SHA-256 hashes for values that should be
//! exempted from entropy-based secret detection. The hashes (not the original
//! values) are stored in a JSON file so that the allowlist itself does not
//! leak secrets.

use std::collections::HashSet;
use std::path::Path;

use sha2::{Digest, Sha256};

/// Load an entropy allowlist from a JSON file.
///
/// The file is expected to contain a JSON array of hex-encoded SHA-256 hashes.
/// Returns an empty set if the file does not exist or cannot be parsed.
#[must_use]
pub fn load_allowlist(path: &Path) -> HashSet<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };
    let Ok(hashes) = serde_json::from_str::<Vec<String>>(&content) else {
        tracing::warn!(
            path = %path.display(),
            "Failed to parse entropy allowlist JSON"
        );
        return HashSet::new();
    };
    hashes.into_iter().collect()
}

/// Save an entropy allowlist to a JSON file.
///
/// Writes the set of hex-encoded SHA-256 hashes as a JSON array. Creates
/// parent directories if they do not exist.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
#[allow(clippy::implicit_hasher)]
pub fn save_allowlist(path: &Path, allowlist: &HashSet<String>) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let sorted: Vec<&String> = {
        let mut v: Vec<_> = allowlist.iter().collect();
        v.sort();
        v
    };
    let json = serde_json::to_string_pretty(&sorted).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    })?;
    std::fs::write(path, json)
}

/// Check whether a value's SHA-256 hash is in the allowlist.
#[must_use]
#[allow(clippy::implicit_hasher)]
pub fn is_allowed(allowlist: &HashSet<String>, value: &str) -> bool {
    let hash = Sha256::digest(value.as_bytes());
    let hex_hash = hex::encode(hash);
    allowlist.contains(&hex_hash)
}

/// Compute the SHA-256 hash of a value (hex-encoded).
#[must_use]
pub fn hash_value(value: &str) -> String {
    let hash = Sha256::digest(value.as_bytes());
    hex::encode(hash)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn load_allowlist_returns_empty_for_missing_file() {
        let path = std::path::Path::new("/tmp/nonexistent_allowlist_test.json");
        let result = load_allowlist(path);
        assert!(result.is_empty());
    }

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.json");

        let mut allowlist = HashSet::new();
        let hash = hash_value("test_secret");
        allowlist.insert(hash.clone());

        save_allowlist(&path, &allowlist).expect("save");

        let loaded = load_allowlist(&path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&hash));
    }

    #[test]
    fn is_allowed_checks_hash() {
        let mut allowlist = HashSet::new();
        let hash = hash_value("my_allowed_value");
        allowlist.insert(hash);

        assert!(is_allowed(&allowlist, "my_allowed_value"));
        assert!(!is_allowed(&allowlist, "not_allowed_value"));
    }

    #[test]
    fn hash_value_is_deterministic() {
        let h1 = hash_value("test");
        let h2 = hash_value("test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_value_is_hex_encoded() {
        let h = hash_value("test");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn load_allowlist_handles_invalid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not valid json").expect("write");
        let result = load_allowlist(&path);
        assert!(result.is_empty());
    }

    #[test]
    fn save_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("dir").join("allowlist.json");
        let allowlist = HashSet::new();
        save_allowlist(&path, &allowlist).expect("save should create parent dirs");
        assert!(path.exists());
    }
}
