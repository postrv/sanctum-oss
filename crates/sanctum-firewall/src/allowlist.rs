//! Entropy allowlist management with secure file I/O.
//!
//! Maintains a persistent set of SHA-256 hashes for values that should be
//! exempted from entropy-based secret detection. The hashes (not the original
//! values) are stored in a line-oriented text file so that the allowlist itself
//! does not leak secrets.
//!
//! Uses atomic writes (write-to-temp-then-rename) and restrictive file
//! permissions (0o600 on Unix) to prevent data loss and unauthorized access.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Maximum allowlist file size in bytes (1 MiB).
const MAX_FILE_SIZE: u64 = 1_048_576;

/// Maximum number of entries in an allowlist.
const MAX_ENTRIES: usize = 10_000;

/// An in-memory allowlist of credential hash prefixes that should not be redacted.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    /// Set of SHA-256 hash prefixes (4 hex chars) for allowlisted credentials.
    entries: HashSet<String>,
}

impl Allowlist {
    /// Create a new empty allowlist.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashSet::new(),
        }
    }

    /// Check if a hash prefix is allowlisted.
    #[must_use]
    pub fn contains(&self, hash_prefix: &str) -> bool {
        self.entries.contains(hash_prefix)
    }

    /// Add a hash prefix to the allowlist.
    ///
    /// Returns `true` if the entry was newly inserted, `false` if it already existed.
    pub fn insert(&mut self, hash_prefix: String) -> bool {
        self.entries.insert(hash_prefix)
    }

    /// Remove a hash prefix from the allowlist.
    ///
    /// Returns `true` if the entry was present and removed.
    pub fn remove(&mut self, hash_prefix: &str) -> bool {
        self.entries.remove(hash_prefix)
    }

    /// Return the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Load an allowlist from a line-oriented file into an [`Allowlist`] struct.
///
/// Each line in the file is treated as one allowlist entry (hash prefix).
/// Empty lines and lines starting with `#` are ignored.
///
/// # Security limits
///
/// - Files larger than 1 MiB are rejected.
/// - Files with more than 10,000 entries are rejected.
///
/// # Errors
///
/// Returns an I/O error if the file cannot be read, exceeds size limits,
/// or exceeds entry count limits.
pub fn load_allowlist_struct(path: &Path) -> Result<Allowlist, io::Error> {
    // Check file size before reading
    let metadata = std::fs::metadata(path)?;
    if metadata.len() > MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "allowlist file exceeds maximum size of {} bytes (got {} bytes)",
                MAX_FILE_SIZE,
                metadata.len()
            ),
        ));
    }

    let content = std::fs::read_to_string(path)?;
    let mut allowlist = Allowlist::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if allowlist.entries.len() >= MAX_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "allowlist exceeds maximum of {MAX_ENTRIES} entries"
                ),
            ));
        }

        allowlist.entries.insert(trimmed.to_owned());
    }

    Ok(allowlist)
}

/// Save an [`Allowlist`] struct to a line-oriented file using atomic write.
///
/// On Unix, the file is created with 0o600 permissions. The write is atomic:
/// data is first written to a temporary file in the same directory, then
/// renamed to the target path. This prevents data loss if the process is
/// interrupted during the write.
///
/// # Errors
///
/// Returns an I/O error if the file cannot be written or renamed.
pub fn save_allowlist_struct(allowlist: &Allowlist, path: &Path) -> Result<(), io::Error> {
    // Determine the parent directory for the temp file
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "allowlist path has no parent directory",
        )
    })?;

    // Ensure the parent directory exists
    std::fs::create_dir_all(parent)?;

    // Build the content
    let mut content = String::new();
    content.push_str("# Sanctum credential allowlist\n");
    content.push_str("# Each line is a SHA-256 hash prefix of an allowlisted credential\n");

    let mut sorted_entries: Vec<&String> = allowlist.entries.iter().collect();
    sorted_entries.sort();
    for entry in sorted_entries {
        content.push_str(entry);
        content.push('\n');
    }

    // Generate temp file path in the same directory
    let temp_name = temp_filename(path);
    let temp_path = parent.join(&temp_name);

    // Write to temp file with secure permissions
    write_with_permissions(&temp_path, content.as_bytes())?;

    // Atomic rename
    std::fs::rename(&temp_path, path).inspect_err(|_| {
        // Clean up temp file on rename failure
        let _ = std::fs::remove_file(&temp_path);
    })
}

/// Check whether a string is a valid 64-character lowercase hex hash.
fn is_valid_hex_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Load an entropy allowlist from a line-oriented file.
///
/// Each line is expected to be a 64-character lowercase hex-encoded SHA-256
/// hash. Empty lines and lines starting with `#` are ignored. Lines that do
/// not match the expected format are skipped with a warning.
///
/// Returns an empty set if the file does not exist or cannot be read.
///
/// # Security limits
///
/// - Files larger than 1 MiB are rejected (returns empty set with a warning).
/// - Files with more than 10,000 entries are rejected (returns empty set with a warning).
#[must_use]
pub fn load_allowlist(path: &Path) -> HashSet<String> {
    // Check file size before reading
    match std::fs::metadata(path) {
        Ok(metadata) => {
            if metadata.len() > MAX_FILE_SIZE {
                tracing::warn!(
                    path = %path.display(),
                    size = metadata.len(),
                    max = MAX_FILE_SIZE,
                    "Entropy allowlist exceeds maximum file size, ignoring"
                );
                return HashSet::new();
            }
        }
        Err(_) => return HashSet::new(),
    }

    let Ok(content) = std::fs::read_to_string(path) else {
        return HashSet::new();
    };

    let mut result = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if result.len() >= MAX_ENTRIES {
            tracing::warn!(
                path = %path.display(),
                max = MAX_ENTRIES,
                "Entropy allowlist exceeds maximum entry count, ignoring remainder"
            );
            break;
        }

        if !is_valid_hex_hash(trimmed) {
            tracing::warn!(
                path = %path.display(),
                entry = trimmed,
                "Skipping invalid allowlist entry (expected 64-char lowercase hex)"
            );
            continue;
        }

        result.insert(trimmed.to_owned());
    }

    result
}

/// Save an entropy allowlist to a line-oriented file using atomic write.
///
/// Writes the set of hex-encoded SHA-256 hashes as one hash per line. Creates
/// parent directories if they do not exist. The write is atomic: data is first
/// written to a temporary file in the same directory, then renamed to the
/// target path. On Unix, the file is created with 0o600 permissions.
///
/// # Errors
///
/// Returns an error if the file cannot be written.
#[allow(clippy::implicit_hasher)]
pub fn save_allowlist(path: &Path, allowlist: &HashSet<String>) -> Result<(), std::io::Error> {
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "allowlist path has no parent directory",
        )
    })?;
    std::fs::create_dir_all(parent)?;

    let mut sorted: Vec<&String> = allowlist.iter().collect();
    sorted.sort();

    let mut content = String::new();
    content.push_str("# Sanctum entropy allowlist\n");
    content.push_str("# Each line is a SHA-256 hex hash of an allowlisted value\n");
    for entry in &sorted {
        content.push_str(entry);
        content.push('\n');
    }

    // Generate temp file path in the same directory
    let temp_name = temp_filename(path);
    let temp_path = parent.join(&temp_name);

    // Write to temp file with secure permissions
    write_with_permissions(&temp_path, content.as_bytes())?;

    // Atomic rename
    std::fs::rename(&temp_path, path).inspect_err(|_| {
        // Clean up temp file on rename failure
        let _ = std::fs::remove_file(&temp_path);
    })
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

/// Generate a temporary filename based on the target path.
fn temp_filename(path: &Path) -> String {
    let stem = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("allowlist");
    format!(".{stem}.tmp")
}

/// Resolve the default allowlist file path.
///
/// Uses `$XDG_CONFIG_HOME/sanctum/allowlist` if set, otherwise
/// `~/.config/sanctum/allowlist`.
///
/// Returns `None` if the home directory cannot be determined.
#[must_use]
pub fn default_allowlist_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("sanctum").join("allowlist"));
        }
    }
    // Fall back to ~/.config
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config").join("sanctum").join("allowlist"))
}

/// Write data to a file with 0o600 permissions on Unix.
///
/// Uses `create_new(true)` to prevent following symlinks (equivalent to
/// `O_EXCL`). If the file already exists (e.g. a stale temp file or a
/// symlink placed by an attacker), it is removed and the open is retried
/// once.
fn write_with_permissions(path: &Path, data: &[u8]) -> Result<(), io::Error> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let open_exclusive = || {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
        };

        let mut file = match open_exclusive() {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Remove the stale/symlinked file and retry once.
                let _ = std::fs::remove_file(path);
                open_exclusive()?
            }
            Err(e) => return Err(e),
        };
        file.write_all(data)?;
        file.sync_all()?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::fmt::Write as _;

    use super::*;

    #[test]
    fn new_allowlist_is_empty() {
        let al = Allowlist::new();
        assert!(al.is_empty());
        assert_eq!(al.len(), 0);
    }

    #[test]
    fn insert_and_contains() {
        let mut al = Allowlist::new();
        assert!(al.insert("abcd".to_string()));
        assert!(al.contains("abcd"));
        assert!(!al.contains("efgh"));
    }

    #[test]
    fn insert_duplicate_returns_false() {
        let mut al = Allowlist::new();
        assert!(al.insert("abcd".to_string()));
        assert!(!al.insert("abcd".to_string()));
        assert_eq!(al.len(), 1);
    }

    #[test]
    fn remove_entry() {
        let mut al = Allowlist::new();
        al.insert("abcd".to_string());
        assert!(al.remove("abcd"));
        assert!(!al.contains("abcd"));
        assert!(!al.remove("abcd"));
    }

    // ---- Struct-based (line-oriented) API tests ----

    #[test]
    fn struct_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist");

        let mut al = Allowlist::new();
        al.insert("a1b2".to_string());
        al.insert("c3d4".to_string());

        save_allowlist_struct(&al, &path).expect("save");
        let loaded = load_allowlist_struct(&path).expect("load");

        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains("a1b2"));
        assert!(loaded.contains("c3d4"));
    }

    #[test]
    fn struct_load_ignores_comments_and_empty_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist");

        std::fs::write(&path, "# comment\n\na1b2\n\n# another\nc3d4\n").expect("write");

        let loaded = load_allowlist_struct(&path).expect("load");
        assert_eq!(loaded.len(), 2);
        assert!(loaded.contains("a1b2"));
        assert!(loaded.contains("c3d4"));
    }

    #[test]
    #[cfg(unix)]
    fn save_creates_file_with_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.json");

        let allowlist = HashSet::new();
        save_allowlist(&path, &allowlist).expect("save");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "allowlist file must have 0o600 permissions");
    }

    #[test]
    fn struct_load_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist");

        // Create a file larger than MAX_FILE_SIZE
        #[allow(clippy::cast_possible_truncation)]
        let size = MAX_FILE_SIZE as usize + 1;
        let content = "x".repeat(size);
        std::fs::write(&path, &content).expect("write");

        let result = load_allowlist_struct(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("maximum size"),
            "Error should mention size limit: {err}"
        );
    }

    #[test]
    fn struct_load_rejects_too_many_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist");

        // Create a file with more than MAX_ENTRIES entries
        let mut content = String::new();
        for i in 0..=MAX_ENTRIES {
            let _ = writeln!(content, "entry{i:05}");
        }
        std::fs::write(&path, &content).expect("write");

        let result = load_allowlist_struct(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("maximum"),
            "Error should mention entry limit: {err}"
        );
    }

    #[test]
    fn struct_atomic_write_no_partial_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist");

        let mut al = Allowlist::new();
        al.insert("first".to_string());
        save_allowlist_struct(&al, &path).expect("first save");

        // Verify first save
        let loaded = load_allowlist_struct(&path).expect("load after first save");
        assert!(loaded.contains("first"));

        // Save again with different content
        al.insert("second".to_string());
        save_allowlist_struct(&al, &path).expect("second save");

        let loaded = load_allowlist_struct(&path).expect("load after second save");
        assert!(loaded.contains("first"));
        assert!(loaded.contains("second"));

        // Verify no temp file remains
        let temp_path = dir.path().join(".allowlist.tmp");
        assert!(
            !temp_path.exists(),
            "Temp file should not remain after successful rename"
        );
    }

    #[test]
    fn struct_save_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sub").join("dir").join("allowlist");

        let al = Allowlist::new();
        save_allowlist_struct(&al, &path).expect("save");
        assert!(path.exists());
    }

    // ---- Line-oriented (HashSet-based) API tests ----

    #[test]
    fn load_allowlist_returns_empty_for_missing_file() {
        let path = std::path::Path::new("/tmp/nonexistent_allowlist_test.txt");
        let result = load_allowlist(path);
        assert!(result.is_empty());
    }

    #[test]
    fn line_save_and_load_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        let mut allowlist = HashSet::new();
        let hash = hash_value("test_value");
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
    fn load_allowlist_skips_comments_and_empty_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        let hash = hash_value("test_value");
        let content = format!("# comment\n\n{hash}\n\n# another comment\n");
        std::fs::write(&path, &content).expect("write");

        let loaded = load_allowlist(&path);
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains(&hash));
    }

    #[test]
    fn load_allowlist_skips_invalid_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        let valid_hash = hash_value("test_value");
        // Invalid: too short, uppercase, non-hex
        let content = format!(
            "{valid_hash}\nabcd1234\nABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234\nnot-hex-at-all\n"
        );
        std::fs::write(&path, &content).expect("write");

        let loaded = load_allowlist(&path);
        assert_eq!(loaded.len(), 1, "Only the valid 64-char lowercase hex hash should be loaded");
        assert!(loaded.contains(&valid_hash));
    }

    #[test]
    fn load_allowlist_deduplicates_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        let hash = hash_value("test_value");
        let content = format!("{hash}\n{hash}\n{hash}\n");
        std::fs::write(&path, &content).expect("write");

        let loaded = load_allowlist(&path);
        assert_eq!(loaded.len(), 1, "Duplicate entries should be deduplicated");
    }

    #[test]
    fn is_valid_hex_hash_accepts_valid() {
        let h = hash_value("test");
        assert!(is_valid_hex_hash(&h));
    }

    #[test]
    fn is_valid_hex_hash_rejects_uppercase() {
        let upper = "ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234ABCD1234";
        assert!(!is_valid_hex_hash(upper));
    }

    #[test]
    fn is_valid_hex_hash_rejects_short() {
        assert!(!is_valid_hex_hash("abcd1234"));
    }

    #[test]
    fn is_valid_hex_hash_rejects_non_hex() {
        let bad = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(!is_valid_hex_hash(bad));
    }

    #[test]
    fn line_save_creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("dir").join("allowlist.txt");
        let allowlist = HashSet::new();
        save_allowlist(&path, &allowlist).expect("save should create parent dirs");
        assert!(path.exists());
    }

    #[test]
    fn line_load_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        // Create a file larger than MAX_FILE_SIZE
        #[allow(clippy::cast_possible_truncation)]
        let size = MAX_FILE_SIZE as usize + 1;
        let content = "x".repeat(size);
        std::fs::write(&path, &content).expect("write");

        let result = load_allowlist(&path);
        assert!(result.is_empty(), "Oversized file should be rejected");
    }

    #[test]
    fn line_atomic_write_no_partial_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.txt");

        let mut al = HashSet::new();
        al.insert(hash_value("first"));
        save_allowlist(&path, &al).expect("first save");

        // Verify first save
        let loaded = load_allowlist(&path);
        assert!(loaded.contains(&hash_value("first")));

        // Save again with different content
        al.insert(hash_value("second"));
        save_allowlist(&path, &al).expect("second save");

        let loaded = load_allowlist(&path);
        assert!(loaded.contains(&hash_value("first")));
        assert!(loaded.contains(&hash_value("second")));

        // Verify no temp file remains
        let temp_path = dir.path().join(".allowlist.txt.tmp");
        assert!(
            !temp_path.exists(),
            "Temp file should not remain after successful rename"
        );
    }

    #[test]
    fn default_allowlist_path_returns_some() {
        // As long as HOME is set, should return Some
        if std::env::var("HOME").is_ok() {
            assert!(default_allowlist_path().is_some());
        }
    }
}
