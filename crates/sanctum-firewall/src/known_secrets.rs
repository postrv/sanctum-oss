//! HMAC-backed denylist for known-real local secrets.
//!
//! The denylist stores HMAC-SHA256 digests so the on-disk registry cannot be
//! used as an offline oracle without the local HMAC key.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// File name for the known-real secret HMAC denylist.
pub const KNOWN_SECRETS_FILE: &str = "known_secrets_hmac.txt";

/// Linux fallback HMAC key file name.
pub const HMAC_KEY_FILE: &str = "hmac_key";

const HMAC_KEY_BYTES: usize = 32;
const MAX_DENYLIST_ENTRIES: usize = 10_000;
const MAX_DENYLIST_BYTES: u64 = 1_048_576;
const KEYRING_SERVICE: &str = "sanctum";
const KEYRING_USER: &str = "hmac-key";

type HmacSha256 = Hmac<Sha256>;

/// Known-real secret denylist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KnownSecretsDenylist {
    /// HMAC-SHA256 hashes of known-real secret values.
    pub hmac_hashes: HashSet<String>,
}

impl KnownSecretsDenylist {
    /// Create an empty denylist.
    #[must_use]
    pub fn new() -> Self {
        Self {
            hmac_hashes: HashSet::new(),
        }
    }

    /// Return the number of known hashes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hmac_hashes.len()
    }

    /// Return `true` if no hashes are registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hmac_hashes.is_empty()
    }

    /// Insert a plaintext secret value after HMAC hashing it.
    pub fn insert_value(&mut self, key: &[u8], value: &str) -> bool {
        self.hmac_hashes.insert(hmac_hash(key, value))
    }

    /// Check whether a plaintext value is known-real.
    #[must_use]
    pub fn contains_value(&self, key: &[u8], value: &str) -> bool {
        is_known_real(self, key, value)
    }
}

/// Resolve the default denylist path from a data directory.
#[must_use]
pub fn denylist_path(data_dir: &Path) -> PathBuf {
    data_dir.join(KNOWN_SECRETS_FILE)
}

/// Load or create the HMAC key.
///
/// On macOS/Windows this uses the OS keychain through the `keyring` crate. On
/// Linux it uses a `0400` file in Sanctum's data directory because no desktop
/// keychain can be assumed.
///
/// # Errors
///
/// Returns an error if the key cannot be read, created, decoded, or stored.
pub fn load_or_create_hmac_key(data_dir: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    let _ = data_dir;

    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        load_or_create_keyring_key()
    }

    #[cfg(target_os = "linux")]
    {
        load_or_create_file_key(data_dir)
    }

    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        load_or_create_file_key(data_dir)
    }
}

/// HMAC-SHA256 hash a value as lowercase hex.
#[must_use]
pub fn hmac_hash(key: &[u8], value: &str) -> String {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        std::process::abort();
    };
    mac.update(value.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Return `true` when `value` is in the known-real denylist.
#[must_use]
pub fn is_known_real(denylist: &KnownSecretsDenylist, key: &[u8], value: &str) -> bool {
    let digest = hmac_hash(key, value);
    denylist.hmac_hashes.contains(&digest)
}

/// Load a known-real denylist from disk.
///
/// # Errors
///
/// Returns an error if the file cannot be read, exceeds the size limit, or
/// contains malformed hashes.
pub fn load_denylist(path: &Path) -> io::Result<KnownSecretsDenylist> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(KnownSecretsDenylist::new()),
        Err(e) => return Err(e),
    };
    if metadata.len() > MAX_DENYLIST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "known-secret denylist exceeds size limit",
        ));
    }

    let content = std::fs::read_to_string(path)?;
    let mut denylist = KnownSecretsDenylist::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if denylist.hmac_hashes.len() >= MAX_DENYLIST_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "known-secret denylist exceeds entry limit",
            ));
        }
        if !is_valid_hex_hash(trimmed) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "known-secret denylist contains invalid hash",
            ));
        }
        denylist.hmac_hashes.insert(trimmed.to_owned());
    }
    Ok(denylist)
}

/// Load a known-real denylist, returning empty on error.
#[must_use]
pub fn load_denylist_best_effort(path: &Path) -> KnownSecretsDenylist {
    load_denylist(path).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), %e, "failed to load known-secret denylist");
        KnownSecretsDenylist::new()
    })
}

/// Save a known-real denylist atomically.
///
/// # Errors
///
/// Returns an error if the denylist is invalid or cannot be written to disk.
pub fn save_denylist(path: &Path, denylist: &KnownSecretsDenylist) -> io::Result<()> {
    if denylist.hmac_hashes.len() > MAX_DENYLIST_ENTRIES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "known-secret denylist exceeds entry limit",
        ));
    }

    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "known-secret denylist path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;

    let mut sorted: Vec<&String> = denylist.hmac_hashes.iter().collect();
    sorted.sort();
    let mut content = String::from("# Sanctum known-real secret HMAC-SHA256 denylist\n");
    for hash in sorted {
        if !is_valid_hex_hash(hash) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "known-secret denylist contains invalid hash",
            ));
        }
        content.push_str(hash);
        content.push('\n');
    }

    let temp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(KNOWN_SECRETS_FILE)
    ));
    sanctum_types::fs_safety::write_private_file(&temp_path, content.as_bytes(), 0o600)?;
    std::fs::rename(&temp_path, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&temp_path);
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn load_or_create_keyring_key() -> io::Result<Zeroizing<Vec<u8>>> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| io::Error::other(e.to_string()))?;
    if let Ok(hex_key) = entry.get_password() {
        let decoded = hex::decode(hex_key.trim()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("invalid HMAC key: {e}"))
        })?;
        if decoded.len() != HMAC_KEY_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stored HMAC key has invalid length",
            ));
        }
        return Ok(Zeroizing::new(decoded));
    }

    let key = generate_key()?;
    entry
        .set_password(&hex::encode(&*key))
        .map_err(|e| io::Error::other(e.to_string()))?;
    Ok(key)
}

#[cfg_attr(any(target_os = "macos", target_os = "windows"), allow(dead_code))]
fn load_or_create_file_key(data_dir: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    let path = data_dir.join(HMAC_KEY_FILE);
    match std::fs::read_to_string(&path) {
        Ok(content) => {
            let decoded = hex::decode(content.trim()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid HMAC key: {e}"))
            })?;
            if decoded.len() != HMAC_KEY_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stored HMAC key has invalid length",
                ));
            }
            Ok(Zeroizing::new(decoded))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = generate_key()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            sanctum_types::fs_safety::write_private_file(
                &path,
                hex::encode(&*key).as_bytes(),
                0o400,
            )?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

fn generate_key() -> io::Result<Zeroizing<Vec<u8>>> {
    let mut key = vec![0_u8; HMAC_KEY_BYTES];
    getrandom::fill(&mut key).map_err(|e| io::Error::other(e.to_string()))?;
    Ok(Zeroizing::new(key))
}

fn is_valid_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hmac_hash_is_stable_and_keyed() {
        let key_a = [1_u8; HMAC_KEY_BYTES];
        let key_b = [2_u8; HMAC_KEY_BYTES];
        let value = "sk-real-secret";

        assert_eq!(hmac_hash(&key_a, value), hmac_hash(&key_a, value));
        assert_ne!(hmac_hash(&key_a, value), hmac_hash(&key_b, value));
    }

    #[test]
    fn known_real_match_blocks_by_hmac() {
        let key = [7_u8; HMAC_KEY_BYTES];
        let value = "sk-real-secret";
        let mut denylist = KnownSecretsDenylist::new();
        denylist.insert_value(&key, value);

        assert!(is_known_real(&denylist, &key, value));
        assert!(!is_known_real(&denylist, &key, "sk-other-secret"));
    }

    #[test]
    fn denylist_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KNOWN_SECRETS_FILE);
        let key = [8_u8; HMAC_KEY_BYTES];
        let mut denylist = KnownSecretsDenylist::new();
        denylist.insert_value(&key, "sk-real-secret");

        save_denylist(&path, &denylist).expect("save");
        let loaded = load_denylist(&path).expect("load");
        assert!(loaded.contains_value(&key, "sk-real-secret"));
    }

    #[test]
    fn invalid_denylist_hash_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(KNOWN_SECRETS_FILE);
        std::fs::write(&path, "not-a-hash").expect("write");

        assert!(load_denylist(&path).is_err());
        assert!(load_denylist_best_effort(&path).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn file_key_has_0400_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let _key = load_or_create_file_key(dir.path()).expect("key");
        let path = dir.path().join(HMAC_KEY_FILE);
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
    }
}
