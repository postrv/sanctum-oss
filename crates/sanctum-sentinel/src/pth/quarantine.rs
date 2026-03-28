//! Quarantine protocol for suspicious files.
//!
//! Quarantined files are moved to a secure directory, replaced with empty
//! stubs at the original location, and tracked with metadata for review.
//!
//! # State machine
//!
//! ```text
//! Active  →  Restored  (via approve/restore)
//! Active  →  Deleted   (via delete)
//! Active  →  Active    (via report — no state change)
//! Deleted    is terminal (no further transitions)
//! ```

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use chrono::{DateTime, Utc};
use sanctum_types::errors::SentinelError;
use serde::{Deserialize, Serialize};

/// Metadata stored alongside a quarantined file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    /// Original filesystem path.
    pub original_path: PathBuf,
    /// SHA-256 hash of the original content.
    pub content_hash: String,
    /// PID of the process that created the file, if known.
    pub creator_pid: Option<u32>,
    /// Human-readable reason for quarantine.
    pub reason: String,
    /// When the file was quarantined.
    #[serde(default = "Utc::now")]
    pub quarantined_at: DateTime<Utc>,
}

/// A quarantined file entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineEntry {
    /// Unique identifier for this quarantine entry.
    pub id: String,
    /// Path where the quarantined file is stored.
    pub quarantine_path: PathBuf,
    /// Metadata about the quarantined file.
    pub metadata: QuarantineMetadata,
    /// When the file was quarantined.
    pub quarantined_at: DateTime<Utc>,
    /// Current state.
    pub state: QuarantineState,
}

/// State of a quarantine entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum QuarantineState {
    /// File is in quarantine, awaiting review.
    Active,
    /// File has been restored to its original location.
    Restored,
    /// File has been permanently deleted.
    Deleted,
}

/// Actions that can be taken on a quarantine entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum QuarantineAction {
    /// Approve: restore the file to its original location.
    Approve,
    /// Delete: permanently remove the quarantined file.
    Delete,
    /// Report: flag for further investigation (no state change).
    Report,
}

impl QuarantineState {
    /// Apply an action to this state, returning the new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the state is terminal (`Deleted`).
    pub fn apply(self, action: QuarantineAction) -> Result<Self, SentinelError> {
        if self == Self::Deleted {
            return Err(SentinelError::QuarantineEntryNotFound {
                id: "terminal state".to_string(),
            });
        }

        Ok(match action {
            QuarantineAction::Approve => Self::Restored,
            QuarantineAction::Delete => Self::Deleted,
            QuarantineAction::Report => self, // no state change
        })
    }
}

/// Validate that a user-supplied quarantine ID is safe.
///
/// Rejects IDs that contain path separators, `..` components, or are empty,
/// and verifies the resolved path stays within the quarantine directory.
///
/// # Errors
///
/// Returns [`SentinelError::InvalidQuarantineId`] if the ID is malformed or
/// would resolve outside the quarantine directory.
fn validate_id(id: &str, quarantine_dir: &Path) -> Result<(), SentinelError> {
    if id.is_empty() {
        return Err(SentinelError::InvalidQuarantineId {
            id: id.to_string(),
            reason: "ID must not be empty".to_string(),
        });
    }

    if id.contains('/') || id.contains('\\') {
        return Err(SentinelError::InvalidQuarantineId {
            id: id.to_string(),
            reason: "ID must not contain path separators".to_string(),
        });
    }

    if id.contains("..") {
        return Err(SentinelError::InvalidQuarantineId {
            id: id.to_string(),
            reason: "ID must not contain '..' components".to_string(),
        });
    }

    // Canonicalization check: the resolved path must start with the
    // quarantine directory.  We use the joined path and verify its
    // parent is exactly `quarantine_dir` (since valid IDs are plain
    // filenames).  When the quarantine directory exists on disk we
    // additionally compare canonical paths.
    let resolved = quarantine_dir.join(id);

    if let (Ok(canon_dir), Ok(canon_resolved)) =
        (quarantine_dir.canonicalize(), resolved.canonicalize())
    {
        if !canon_resolved.starts_with(&canon_dir) {
            return Err(SentinelError::InvalidQuarantineId {
                id: id.to_string(),
                reason: "resolved path escapes quarantine directory".to_string(),
            });
        }
    }

    Ok(())
}

/// Directories that are never valid restore targets.
const SENSITIVE_PREFIXES: &[&str] = &[
    "/etc",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/System",
    "/Library",
];

/// Home-directory patterns that are never valid restore targets.
/// Checked via `contains()` so they match regardless of the actual $HOME prefix.
const SENSITIVE_HOME_PATTERNS: &[&str] = &[
    "/.ssh/",
    "/.bashrc",
    "/.bash_profile",
    "/.profile",
    "/.zshrc",
    "/.config/autostart",
    "/.local/bin/",
];

/// Validate that a restore path is safe to write to.
/// Rejects paths that are non-absolute, contain traversal components,
/// or target sensitive system directories.
fn validate_restore_path(path: &Path) -> Result<(), SentinelError> {
    // Must be absolute
    if !path.is_absolute() {
        return Err(SentinelError::Quarantine {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("restore path must be absolute: {}", path.display()),
            ),
        });
    }

    // Check for path traversal components
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(SentinelError::Quarantine {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("restore path contains traversal: {}", path.display()),
                ),
            });
        }
    }

    // Reject sensitive system directories
    let path_str = path.to_string_lossy();
    for prefix in SENSITIVE_PREFIXES {
        if path_str.starts_with(prefix) {
            return Err(SentinelError::Quarantine {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "restore path targets sensitive directory: {}",
                        path.display()
                    ),
                ),
            });
        }
    }

    // Reject home-directory credential/autostart paths
    for pattern in SENSITIVE_HOME_PATTERNS {
        if path_str.contains(pattern) {
            return Err(SentinelError::Quarantine {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "restore path targets sensitive home directory location: {}",
                        path.display()
                    ),
                ),
            });
        }
    }

    Ok(())
}

/// Compare two strings in constant time to prevent timing side-channel attacks.
///
/// Returns `true` if both strings have the same length and contain identical bytes.
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes()
        .zip(b.bytes())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Write `content` to `tmp_path` (with `O_NOFOLLOW` + `O_EXCL` on Unix),
/// sync, then atomically rename to `final_path`.  Cleans up the temp file on
/// any failure.
fn write_temp_and_rename(
    tmp_path: &Path,
    content: &[u8],
    final_path: &Path,
) -> Result<(), SentinelError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(tmp_path)
            .map_err(|e| SentinelError::Quarantine {
                path: final_path.to_path_buf(),
                source: e,
            })?;
        if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(tmp_path);
            return Err(SentinelError::Quarantine {
                path: final_path.to_path_buf(),
                source: e,
            });
        }
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::File::create(tmp_path).map_err(|e| SentinelError::Quarantine {
            path: final_path.to_path_buf(),
            source: e,
        })?;
        if let Err(e) = file.write_all(content).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(tmp_path);
            return Err(SentinelError::Quarantine {
                path: final_path.to_path_buf(),
                source: e,
            });
        }
    }
    if let Err(e) = fs::rename(tmp_path, final_path) {
        let _ = fs::remove_file(tmp_path);
        return Err(SentinelError::Quarantine {
            path: final_path.to_path_buf(),
            source: e,
        });
    }
    Ok(())
}

/// Process-wide counter to ensure quarantine ID uniqueness.
static QUARANTINE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Quarantine manager.
pub struct Quarantine {
    /// Directory where quarantined files are stored.
    quarantine_dir: PathBuf,
}

impl Quarantine {
    /// Create a new quarantine manager.
    ///
    /// Creates the quarantine directory if it doesn't exist.
    #[must_use]
    pub const fn new(quarantine_dir: PathBuf) -> Self {
        Self { quarantine_dir }
    }

    /// Quarantine a file: move it to the quarantine directory and replace
    /// with an empty stub.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, moved, or the stub
    /// cannot be written (e.g., read-only directory).
    #[allow(clippy::too_many_lines)]
    pub fn quarantine_file(
        &self,
        path: &Path,
        metadata: &QuarantineMetadata,
    ) -> Result<QuarantineEntry, SentinelError> {
        /// Maximum size for a .pth file to be quarantined (1 MB).
        const MAX_PTH_FILE_SIZE: u64 = 1_048_576;

        // Ensure quarantine dir exists with secure permissions
        // Create parent directories first
        if let Some(parent) = self.quarantine_dir.parent() {
            fs::create_dir_all(parent).map_err(|e| SentinelError::Quarantine {
                path: self.quarantine_dir.clone(),
                source: e,
            })?;
        }
        // Create the final quarantine directory with restricted permissions atomically
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&self.quarantine_dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(SentinelError::Quarantine {
                        path: self.quarantine_dir.clone(),
                        source: e,
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(&self.quarantine_dir).map_err(|e| SentinelError::Quarantine {
                path: self.quarantine_dir.clone(),
                source: e,
            })?;
        }

        // Generate unique ID — use file stem (without extension) to avoid
        // conflicts with the .json metadata extension naming scheme.
        let raw_stem = path.file_stem().map_or_else(
            || "unknown".to_string(),
            |n| n.to_string_lossy().to_string(),
        );
        // Sanitize: only allow alphanumeric, dot, hyphen, underscore; cap at 64 chars
        let file_stem: String = raw_stem
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            .take(64)
            .collect();
        let file_stem = if file_stem.is_empty() {
            "unknown".to_string()
        } else {
            file_stem
        };
        let now = Utc::now();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let counter = QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let id = format!(
            "{}-{}-{:08x}-{:04x}",
            now.format("%Y%m%d-%H%M%S"),
            file_stem,
            nanos,
            counter
        );

        let quarantine_path = self.quarantine_dir.join(&id);

        // Single-fd open: use O_NOFOLLOW on Unix to prevent reading through symlinks,
        // then use the file handle for metadata + bounded read to avoid TOCTOU.
        #[cfg(unix)]
        let file = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(path)
                .map_err(|e| SentinelError::Quarantine {
                    path: path.to_path_buf(),
                    source: e,
                })?
        };
        #[cfg(not(unix))]
        let file = fs::File::open(path).map_err(|e| SentinelError::Quarantine {
            path: path.to_path_buf(),
            source: e,
        })?;
        let file_meta = file.metadata().map_err(|e| SentinelError::Quarantine {
            path: path.to_path_buf(),
            source: e,
        })?;
        let file_size = file_meta.len();
        if file_size > MAX_PTH_FILE_SIZE {
            return Err(SentinelError::Quarantine {
                path: path.to_path_buf(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("file too large for quarantine ({file_size} bytes, max {MAX_PTH_FILE_SIZE})"),
                ),
            });
        }

        // Bounded read via the same fd — no TOCTOU between size check and read
        let mut reader = std::io::Read::take(file, MAX_PTH_FILE_SIZE + 1);
        let mut content = Vec::new();
        std::io::Read::read_to_end(&mut reader, &mut content).map_err(|e| {
            SentinelError::Quarantine {
                path: path.to_path_buf(),
                source: e,
            }
        })?;

        // Read original permissions from the same metadata
        #[cfg(unix)]
        let original_permissions = Some(file_meta.permissions());

        // Write content to quarantine and fsync to ensure durability
        {
            let mut qfile =
                fs::File::create(&quarantine_path).map_err(|e| SentinelError::Quarantine {
                    path: quarantine_path.clone(),
                    source: e,
                })?;
            qfile
                .write_all(&content)
                .map_err(|e| SentinelError::Quarantine {
                    path: quarantine_path.clone(),
                    source: e,
                })?;
            qfile.sync_all().map_err(|e| SentinelError::Quarantine {
                path: quarantine_path.clone(),
                source: e,
            })?;
        }

        // Store the quarantine timestamp in metadata
        let mut metadata_with_time = metadata.clone();
        metadata_with_time.quarantined_at = Utc::now();

        // Write metadata atomically: write to temp file, sync, then rename
        let meta_path = quarantine_path.with_extension("json");
        let meta_tmp = meta_path.with_extension("tmp");
        let meta_json =
            serde_json::to_string_pretty(&metadata_with_time).unwrap_or_else(|_| "{}".to_string());
        {
            let mut mfile = fs::File::create(&meta_tmp).map_err(|e| SentinelError::Quarantine {
                path: meta_path.clone(),
                source: e,
            })?;
            mfile
                .write_all(meta_json.as_bytes())
                .map_err(|e| SentinelError::Quarantine {
                    path: meta_path.clone(),
                    source: e,
                })?;
            mfile.sync_all().map_err(|e| SentinelError::Quarantine {
                path: meta_path.clone(),
                source: e,
            })?;
        }
        if let Err(e) = fs::rename(&meta_tmp, &meta_path) {
            let _ = fs::remove_file(&meta_tmp);
            return Err(SentinelError::Quarantine {
                path: meta_path,
                source: e,
            });
        }

        // Replace original with empty stub.
        // Use O_NOFOLLOW to atomically prevent symlink-swap attacks (no TOCTOU
        // race between a symlink check and the file create).
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            match fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(path)
            {
                Ok(stub) => {
                    stub.sync_all().map_err(|e| SentinelError::Quarantine {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                    // Preserve original permissions on the stub
                    if let Some(perms) = original_permissions {
                        let _ = fs::set_permissions(path, perms);
                    }
                }
                Err(e) if e.raw_os_error() == Some(nix::libc::ELOOP) => {
                    // ELOOP means the path is a symlink — skip stub write
                    tracing::warn!(
                        path = %path.display(),
                        "original path is a symlink — skipping stub write to prevent symlink attack"
                    );
                }
                Err(e) => {
                    return Err(SentinelError::Quarantine {
                        path: path.to_path_buf(),
                        source: e,
                    });
                }
            }
        }
        #[cfg(not(unix))]
        {
            // On non-Unix platforms, fall back to check-then-create.
            let is_symlink = path
                .symlink_metadata()
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);

            if is_symlink {
                tracing::warn!(
                    path = %path.display(),
                    "original path is a symlink — skipping stub write to prevent symlink attack"
                );
            } else {
                let stub = fs::File::create(path).map_err(|e| SentinelError::Quarantine {
                    path: path.to_path_buf(),
                    source: e,
                })?;
                stub.sync_all().map_err(|e| SentinelError::Quarantine {
                    path: path.to_path_buf(),
                    source: e,
                })?;
            }
        }

        let quarantined_at = metadata_with_time.quarantined_at;
        Ok(QuarantineEntry {
            id,
            quarantine_path,
            metadata: metadata_with_time,
            quarantined_at,
            state: QuarantineState::Active,
        })
    }

    /// Restore a quarantined file to its original location.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be found or the file cannot be restored.
    pub fn restore(&self, id: &str) -> Result<(), SentinelError> {
        validate_id(id, &self.quarantine_dir)?;
        let quarantine_path = self.quarantine_dir.join(id);
        let meta_path = quarantine_path.with_extension("json");

        // Read metadata to find original path
        let meta_str = fs::read_to_string(&meta_path)
            .map_err(|_| SentinelError::QuarantineEntryNotFound { id: id.to_string() })?;
        let metadata: QuarantineMetadata = serde_json::from_str(&meta_str)
            .map_err(|_| SentinelError::QuarantineEntryNotFound { id: id.to_string() })?;

        // Read quarantined content
        let content = fs::read(&quarantine_path).map_err(|e| SentinelError::Quarantine {
            path: quarantine_path.clone(),
            source: e,
        })?;

        // Verify content integrity: SHA-256 hash must match the stored metadata hash
        // Uses constant-time comparison to prevent timing side-channels.
        let actual_hash = crate::pth::analyser::content_hash(&content);
        if !constant_time_eq(&actual_hash, &metadata.content_hash) {
            return Err(SentinelError::Quarantine {
                path: quarantine_path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "quarantined file has been tampered with: expected hash {}, got {}",
                        metadata.content_hash, actual_hash
                    ),
                ),
            });
        }

        // Validate the restore path before writing
        validate_restore_path(&metadata.original_path)?;

        // Reject restore if the target path is now a symlink (symlink-swap
        // attack prevention).  While rename() replaces a symlink rather than
        // following it, rejecting this case is defence-in-depth.
        let is_symlink = metadata
            .original_path
            .symlink_metadata()
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            return Err(SentinelError::Quarantine {
                path: metadata.original_path,
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "restore target is a symlink — aborting to prevent symlink attack",
                ),
            });
        }

        // Atomic restore: write to temp file in the quarantine directory (which
        // we control), sync, then rename into place.  Writing the temp file
        // inside the quarantine directory avoids TOCTOU races where an attacker
        // could plant a symlink at a predictable temp-file path next to the
        // original.
        let restore_tmp = self.quarantine_dir.join(format!("{id}.restore_tmp"));
        write_temp_and_rename(&restore_tmp, &content, &metadata.original_path)?;

        // Clean up quarantine files
        let _ = fs::remove_file(&quarantine_path);
        let _ = fs::remove_file(&meta_path);

        Ok(())
    }

    /// Permanently delete a quarantined file.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry cannot be found.
    pub fn delete(&self, id: &str) -> Result<(), SentinelError> {
        validate_id(id, &self.quarantine_dir)?;
        let quarantine_path = self.quarantine_dir.join(id);
        let meta_path = quarantine_path.with_extension("json");

        // Remove the quarantined file directly; treat NotFound as "entry not found"
        match fs::remove_file(&quarantine_path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(SentinelError::QuarantineEntryNotFound { id: id.to_string() });
            }
            Err(e) => {
                return Err(SentinelError::Quarantine {
                    path: quarantine_path,
                    source: e,
                });
            }
        }

        // Best-effort removal of metadata file
        let _ = fs::remove_file(&meta_path);

        Ok(())
    }

    /// List all quarantined entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the quarantine directory cannot be read.
    pub fn list(&self) -> Result<Vec<QuarantineEntry>, SentinelError> {
        if !self.quarantine_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries = Vec::new();

        let dir_entries =
            fs::read_dir(&self.quarantine_dir).map_err(|e| SentinelError::Quarantine {
                path: self.quarantine_dir.clone(),
                source: e,
            })?;

        for entry in dir_entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                match fs::read_to_string(&path) {
                    Ok(meta_str) => match serde_json::from_str::<QuarantineMetadata>(&meta_str) {
                        Ok(metadata) => {
                            let id = path
                                .file_stem()
                                .map(|s| s.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let quarantined_at = metadata.quarantined_at;
                            entries.push(QuarantineEntry {
                                id: id.clone(),
                                quarantine_path: self.quarantine_dir.join(&id),
                                metadata,
                                quarantined_at,
                                state: QuarantineState::Active,
                            });
                        }
                        Err(e) => {
                            tracing::warn!(
                                path = %path.display(),
                                %e,
                                "corrupted quarantine metadata — entry will not appear in list"
                            );
                        }
                    },
                    Err(e) => {
                        tracing::warn!(
                            path = %path.display(),
                            %e,
                            "failed to read quarantine metadata"
                        );
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn default_meta(path: &Path) -> QuarantineMetadata {
        QuarantineMetadata {
            original_path: path.to_path_buf(),
            content_hash: "sha256:test".into(),
            creator_pid: Some(12345),
            reason: "test quarantine".into(),
            quarantined_at: Utc::now(),
        }
    }

    /// Create metadata with the correct SHA-256 hash for the given content.
    fn meta_with_hash(path: &Path, content: &[u8]) -> QuarantineMetadata {
        QuarantineMetadata {
            original_path: path.to_path_buf(),
            content_hash: crate::pth::analyser::content_hash(content),
            creator_pid: Some(12345),
            reason: "test quarantine".into(),
            quarantined_at: Utc::now(),
        }
    }

    #[test]
    fn quarantine_moves_file_to_quarantine_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "import base64;exec(...)").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let result = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine should succeed");

        // Original replaced with empty stub
        assert!(pth_path.exists());
        assert_eq!(fs::read_to_string(&pth_path).expect("read"), "");

        // Quarantined copy exists
        assert!(result.quarantine_path.exists());

        // Metadata file exists
        let meta_path = result.quarantine_path.with_extension("json");
        assert!(meta_path.exists());
    }

    #[test]
    fn quarantine_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "exec(...)").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        q.quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("first quarantine");

        // Second quarantine of the now-empty stub
        let result = q.quarantine_file(&pth_path, &default_meta(&pth_path));
        assert!(result.is_ok());
    }

    #[test]
    fn quarantine_restore_puts_file_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("legit.pth");
        let content = "import setuptools";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &meta_with_hash(&pth_path, content.as_bytes()))
            .expect("quarantine");

        q.restore(&entry.id).expect("restore should succeed");
        assert_eq!(fs::read_to_string(&pth_path).expect("read"), content);
    }

    #[test]
    fn quarantine_delete_removes_quarantined_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "exec(...)").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        q.delete(&entry.id).expect("delete should succeed");
        assert!(!entry.quarantine_path.exists());
        // Original still has empty stub
        assert_eq!(fs::read_to_string(&pth_path).expect("read"), "");
    }

    #[test]
    fn quarantine_list_returns_all_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        for i in 0..3 {
            let path = dir.path().join(format!("evil_{i}.pth"));
            fs::write(&path, "exec(...)").expect("write");
            q.quarantine_file(&path, &default_meta(&path))
                .expect("quarantine");
        }

        assert_eq!(q.list().expect("list").len(), 3);
    }

    #[test]
    fn quarantine_state_transitions() {
        let active = QuarantineState::Active;

        assert_eq!(
            active.apply(QuarantineAction::Approve).expect("approve"),
            QuarantineState::Restored
        );
        assert_eq!(
            active.apply(QuarantineAction::Delete).expect("delete"),
            QuarantineState::Deleted
        );
        assert_eq!(
            active.apply(QuarantineAction::Report).expect("report"),
            QuarantineState::Active
        );

        // Deleted is terminal
        let deleted = QuarantineState::Deleted;
        assert!(deleted.apply(QuarantineAction::Approve).is_err());
    }

    #[test]
    fn restore_rejects_path_traversal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        let result = q.restore("../../etc/passwd");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::InvalidQuarantineId { .. }),
            "expected InvalidQuarantineId, got: {err:?}"
        );
    }

    #[test]
    fn delete_rejects_path_traversal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        let result = q.delete("../secret");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::InvalidQuarantineId { .. }),
            "expected InvalidQuarantineId, got: {err:?}"
        );
    }

    #[test]
    fn restore_accepts_valid_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("legit.pth");
        let content = "import setuptools";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &meta_with_hash(&pth_path, content.as_bytes()))
            .expect("quarantine");

        // A valid ID produced by quarantine_file should be accepted
        let result = q.restore(&entry.id);
        assert!(result.is_ok(), "valid ID should be accepted: {result:?}");
        assert_eq!(fs::read_to_string(&pth_path).expect("read"), content);
    }

    #[test]
    fn rejects_ids_with_backslashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        let result = q.restore("..\\..\\etc\\passwd");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::InvalidQuarantineId { .. }),
            "expected InvalidQuarantineId, got: {err:?}"
        );

        let result = q.delete("..\\secret");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::InvalidQuarantineId { .. }),
            "expected InvalidQuarantineId, got: {err:?}"
        );
    }

    #[test]
    fn rejects_empty_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        let result = q.restore("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::InvalidQuarantineId { .. }),
            "expected InvalidQuarantineId, got: {err:?}"
        );
    }

    #[test]
    fn restore_rejects_sensitive_system_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "payload").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Tamper with metadata to set original_path to /etc/passwd
        let meta_path = entry.quarantine_path.with_extension("json");
        let meta_str = fs::read_to_string(&meta_path).expect("read meta");
        let mut metadata: QuarantineMetadata = serde_json::from_str(&meta_str).expect("parse meta");
        metadata.original_path = PathBuf::from("/etc/passwd");
        let tampered = serde_json::to_string_pretty(&metadata).expect("serialize");
        fs::write(&meta_path, tampered).expect("write tampered meta");

        let result = q.restore(&entry.id);
        assert!(result.is_err(), "should reject sensitive path");
    }

    #[test]
    fn restore_rejects_relative_path_in_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "payload").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Tamper with metadata to set a relative path
        let meta_path = entry.quarantine_path.with_extension("json");
        let meta_str = fs::read_to_string(&meta_path).expect("read meta");
        let mut metadata: QuarantineMetadata = serde_json::from_str(&meta_str).expect("parse meta");
        metadata.original_path = PathBuf::from("relative/path/file.txt");
        let tampered = serde_json::to_string_pretty(&metadata).expect("serialize");
        fs::write(&meta_path, tampered).expect("write tampered meta");

        let result = q.restore(&entry.id);
        assert!(result.is_err(), "should reject relative path");
    }

    #[test]
    fn restore_rejects_path_traversal_in_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "payload").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Tamper with metadata to include traversal
        let meta_path = entry.quarantine_path.with_extension("json");
        let meta_str = fs::read_to_string(&meta_path).expect("read meta");
        let mut metadata: QuarantineMetadata = serde_json::from_str(&meta_str).expect("parse meta");
        metadata.original_path = PathBuf::from("/tmp/../../../etc/passwd");
        let tampered = serde_json::to_string_pretty(&metadata).expect("serialize");
        fs::write(&meta_path, tampered).expect("write tampered meta");

        let result = q.restore(&entry.id);
        assert!(result.is_err(), "should reject path with traversal");
    }

    #[test]
    fn restore_accepts_valid_restore_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("legit.pth");
        let content = "safe content";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &meta_with_hash(&pth_path, content.as_bytes()))
            .expect("quarantine");

        // The original_path in metadata should be valid (temp dir)
        let result = q.restore(&entry.id);
        assert!(
            result.is_ok(),
            "valid temp path should be accepted: {result:?}"
        );
        assert_eq!(fs::read_to_string(&pth_path).expect("read"), content);
    }

    #[test]
    fn quarantine_ids_are_unique_in_rapid_succession() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        let path1 = dir.path().join("file1.pth");
        let path2 = dir.path().join("file2.pth");
        fs::write(&path1, "content1").expect("write");
        fs::write(&path2, "content2").expect("write");

        let entry1 = q
            .quarantine_file(&path1, &default_meta(&path1))
            .expect("quarantine 1");
        let entry2 = q
            .quarantine_file(&path2, &default_meta(&path2))
            .expect("quarantine 2");

        assert_ne!(
            entry1.id, entry2.id,
            "IDs should differ: {} vs {}",
            entry1.id, entry2.id
        );
    }

    #[test]
    fn quarantine_ids_unique_same_stem_rapid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        // Quarantine the same file twice in rapid succession
        let path1 = dir.path().join("evil.pth");
        fs::write(&path1, "content1").expect("write");

        let entry1 = q
            .quarantine_file(&path1, &default_meta(&path1))
            .expect("quarantine 1");

        // Re-create the file for second quarantine
        fs::write(&path1, "content2").expect("write");
        let entry2 = q
            .quarantine_file(&path1, &default_meta(&path1))
            .expect("quarantine 2");

        assert_ne!(
            entry1.id, entry2.id,
            "IDs for same-stem files quarantined rapidly must differ: {} vs {}",
            entry1.id, entry2.id
        );
    }

    #[test]
    fn restore_fails_when_quarantined_content_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("victim.pth");
        fs::write(&pth_path, "original content").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Delete the quarantined content file (but leave the .json metadata).
        fs::remove_file(&entry.quarantine_path).expect("delete quarantine content");
        assert!(!entry.quarantine_path.exists());

        // Restore should fail because the quarantined content is gone.
        let result = q.restore(&entry.id);
        assert!(
            result.is_err(),
            "restore should fail when quarantined file is deleted"
        );
    }

    #[cfg(unix)]
    #[test]
    fn quarantine_dir_has_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("evil.pth");
        fs::write(&pth_path, "exec(...)").expect("write");

        let q_dir = dir.path().join("quarantine");
        let q = Quarantine::new(q_dir.clone());
        q.quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine should succeed");

        let mode = fs::metadata(&q_dir)
            .expect("quarantine dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o700,
            "quarantine dir should be owner-only (0o700), got {mode:#o}"
        );
    }

    #[test]
    fn quarantine_id_sanitizes_malicious_file_stem() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        // File with special chars that are valid on all platforms but should be stripped
        let malicious_name = "evil;rm -rf ~;echo pwned.pth";
        let pth_path = dir.path().join(malicious_name);
        fs::write(&pth_path, "payload").expect("write test file");

        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine should succeed with malicious filename");

        // The ID should contain only safe characters (alphanumeric, dot, hyphen, underscore, date separators)
        for ch in entry.id.chars() {
            assert!(
                ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_'),
                "quarantine ID contains unsafe character: {ch:?} in ID: {}",
                entry.id
            );
        }
    }

    #[test]
    fn quarantine_rejects_oversized_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("huge.pth");
        // Create a file just over 1MB
        let content = vec![b'x'; 1_048_577];
        fs::write(&pth_path, &content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let result = q.quarantine_file(&pth_path, &default_meta(&pth_path));
        assert!(result.is_err(), "should reject file larger than 1MB");
    }

    #[test]
    fn quarantine_accepts_file_at_size_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("maxsize.pth");
        // Create a file exactly at 1MB
        let content = vec![b'x'; 1_048_576];
        fs::write(&pth_path, &content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let result = q.quarantine_file(&pth_path, &default_meta(&pth_path));
        assert!(result.is_ok(), "should accept file exactly at 1MB limit");
    }

    #[test]
    fn restore_fails_when_parent_directory_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create a nested directory structure and a file inside it.
        let nested_dir = dir.path().join("subdir").join("nested");
        fs::create_dir_all(&nested_dir).expect("create dirs");
        let pth_path = nested_dir.join("target.pth");
        let content = b"payload";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &meta_with_hash(&pth_path, content))
            .expect("quarantine");

        // Remove the entire parent directory tree so the original path
        // can no longer be written to.
        fs::remove_dir_all(dir.path().join("subdir")).expect("remove parent dir");
        assert!(!nested_dir.exists());

        // Restore should fail because the parent directory is gone.
        let result = q.restore(&entry.id);
        assert!(
            result.is_err(),
            "restore should fail when parent directory is deleted"
        );
    }

    // ── F1 test: delete on non-existent ID ──────────────────────────────

    #[test]
    fn delete_nonexistent_id_returns_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q = Quarantine::new(dir.path().join("quarantine"));

        // Create the quarantine directory so the ID is technically valid
        fs::create_dir_all(dir.path().join("quarantine")).expect("mkdir");

        let result = q.delete("nonexistent-id-12345");
        assert!(result.is_err(), "delete of non-existent ID should fail");
        let err = result.unwrap_err();
        assert!(
            matches!(err, SentinelError::QuarantineEntryNotFound { .. }),
            "expected QuarantineEntryNotFound, got: {err:?}"
        );
    }

    // ── F2 test: quarantine_file reads content correctly via single fd ───

    #[test]
    fn quarantine_file_reads_content_via_single_fd() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("test.pth");
        let content = "import os; exec('malicious')";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine should succeed");

        // Verify the quarantined file has the correct content
        let quarantined_content =
            fs::read_to_string(&entry.quarantine_path).expect("read quarantined");
        assert_eq!(quarantined_content, content);

        // Verify the original was replaced with an empty stub
        let stub_content = fs::read_to_string(&pth_path).expect("read stub");
        assert!(stub_content.is_empty(), "original should be empty stub");
    }

    // ── F4 test: restore fails when content hash doesn't match ──────────

    #[test]
    fn restore_fails_when_content_hash_tampered() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pth_path = dir.path().join("target.pth");
        let content = "original payload";
        fs::write(&pth_path, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &meta_with_hash(&pth_path, content.as_bytes()))
            .expect("quarantine");

        // Tamper with the quarantined file content
        fs::write(&entry.quarantine_path, "tampered payload").expect("tamper");

        // Restore should fail because the hash no longer matches
        let result = q.restore(&entry.id);
        assert!(
            result.is_err(),
            "restore should fail when content has been tampered with"
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("tampered"),
            "error should mention tampering, got: {err_msg}"
        );
    }

    // ── M1 test: list logs warning for corrupted metadata ────────────────

    #[test]
    fn list_skips_corrupted_metadata_and_returns_valid_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let q_dir = dir.path().join("quarantine");
        fs::create_dir_all(&q_dir).expect("mkdir");

        // Create a valid quarantine entry
        let pth_path = dir.path().join("valid.pth");
        fs::write(&pth_path, "safe content").expect("write");
        let q = Quarantine::new(q_dir.clone());
        q.quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Write a corrupted metadata file alongside (invalid JSON)
        let corrupt_meta = q_dir.join("corrupted-entry.json");
        fs::write(&corrupt_meta, "this is not valid json {{{").expect("write corrupt");

        // List should succeed and return only the valid entry, skipping the corrupted one
        let entries = q.list().expect("list should succeed");
        assert_eq!(entries.len(), 1, "only the valid entry should appear");
    }

    // ── M6 test: symlink detection ───────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn quarantine_rejects_symlink_on_initial_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_file = dir.path().join("real.pth");
        let link_path = dir.path().join("link.pth");
        fs::write(&real_file, "payload").expect("write");

        // Create a symlink pointing to real_file
        std::os::unix::fs::symlink(&real_file, &link_path).expect("symlink");

        let q = Quarantine::new(dir.path().join("quarantine"));
        // Quarantine the symlink path — should fail at the initial read
        // because O_NOFOLLOW rejects symlinks with ELOOP.
        let result = q.quarantine_file(&link_path, &default_meta(&link_path));
        assert!(
            result.is_err(),
            "quarantine should reject symlink on initial read"
        );

        // The real file should not have been modified
        let real_content = fs::read_to_string(&real_file).expect("read");
        assert_eq!(real_content, "payload", "real file should not be modified");
    }

    #[cfg(unix)]
    #[test]
    fn restore_rejects_symlink_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_file = dir.path().join("real.pth");
        let content = "safe content";
        fs::write(&real_file, content).expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&real_file, &meta_with_hash(&real_file, content.as_bytes()))
            .expect("quarantine");

        // Replace the original path with a symlink (simulating a symlink-swap attack)
        let _ = fs::remove_file(&real_file);
        let target = dir.path().join("attack_target");
        fs::write(&target, "").expect("create target");
        std::os::unix::fs::symlink(&target, &real_file).expect("symlink");

        // Restore should fail because the target is now a symlink
        let result = q.restore(&entry.id);
        assert!(result.is_err(), "restore should reject symlink target");
    }

    // ── M7 test: constant-time comparison ────────────────────────────────

    #[test]
    fn constant_time_eq_matches_equal_strings() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(constant_time_eq("", ""));
        assert!(constant_time_eq("sha256:deadbeef", "sha256:deadbeef"));
    }

    #[test]
    fn constant_time_eq_rejects_different_strings() {
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("", "a"));
        assert!(!constant_time_eq("sha256:aaaa", "sha256:bbbb"));
    }

    #[test]
    fn constant_time_eq_rejects_different_lengths() {
        assert!(!constant_time_eq("short", "longer_string"));
        assert!(!constant_time_eq("longer_string", "short"));
    }
}

// ── Kani bounded model checking proofs ──────────────────────────────────────

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Proof: quarantine state machine transitions are valid.
    ///
    /// Verifies:
    /// 1. From `Active`, `Approve` -> `Restored`, `Delete` -> `Deleted`, `Report` -> `Active`
    /// 2. `Deleted` is a terminal state — applying any action returns `Err`.
    /// 3. `Restored` is not terminal — actions can still be applied.
    #[kani::proof]
    #[kani::unwind(10)]
    fn quarantine_state_transitions() {
        let state: QuarantineState = kani::any();
        let action: QuarantineAction = kani::any();

        let result = state.apply(action);

        match state {
            QuarantineState::Deleted => {
                // Terminal state: all actions must fail.
                assert!(result.is_err());
            }
            QuarantineState::Active | QuarantineState::Restored => {
                // Non-terminal: all actions must succeed.
                assert!(result.is_ok());

                let new_state = result.unwrap();
                match action {
                    QuarantineAction::Approve => {
                        assert_eq!(new_state, QuarantineState::Restored);
                    }
                    QuarantineAction::Delete => {
                        assert_eq!(new_state, QuarantineState::Deleted);
                    }
                    QuarantineAction::Report => {
                        // Report does not change state.
                        assert_eq!(new_state, state);
                    }
                }
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_id_rejects_traversal() {
        // Verify that validate_id always rejects:
        // 1. Empty strings
        // 2. Strings containing '/'
        // 3. Strings containing '\'
        // 4. Strings containing ".."
        let bytes: [u8; 4] = kani::any();
        // Only test valid UTF-8
        if let Ok(id) = std::str::from_utf8(&bytes) {
            let quarantine_dir = std::path::Path::new("/tmp/quarantine");
            let result = validate_id(id, quarantine_dir);

            // If the string is empty, must be rejected
            if id.is_empty() {
                assert!(result.is_err());
            }
            // If the string contains path separators, must be rejected
            if id.contains('/') || id.contains('\\') {
                assert!(result.is_err());
            }
            // If the string contains "..", must be rejected
            if id.contains("..") {
                assert!(result.is_err());
            }

            // Verify that the rejection and acceptance paths are both reachable.
            kani::cover!(result.is_err(), "rejection path reachable");
            kani::cover!(result.is_ok(), "acceptance path reachable");
            kani::cover!(id.is_empty(), "empty string path reachable");
            kani::cover!(id.contains('/'), "slash path reachable");
        }
    }
}
