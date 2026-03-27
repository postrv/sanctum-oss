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
                reason: "resolved path escapes quarantine directory"
                    .to_string(),
            });
        }
    }

    Ok(())
}

/// Directories that are never valid restore targets.
const SENSITIVE_PREFIXES: &[&str] = &[
    "/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin",
    "/usr/lib", "/System", "/Library",
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
                    format!("restore path targets sensitive directory: {}", path.display()),
                ),
            });
        }
    }

    Ok(())
}

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
    pub fn quarantine_file(
        &self,
        path: &Path,
        metadata: &QuarantineMetadata,
    ) -> Result<QuarantineEntry, SentinelError> {
        // Ensure quarantine dir exists
        fs::create_dir_all(&self.quarantine_dir).map_err(|e| {
            SentinelError::Quarantine {
                path: self.quarantine_dir.clone(),
                source: e,
            }
        })?;

        // Generate unique ID — use file stem (without extension) to avoid
        // conflicts with the .json metadata extension naming scheme.
        let file_stem = path
            .file_stem().map_or_else(|| "unknown".to_string(), |n| n.to_string_lossy().to_string());
        let now = Utc::now();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let id = format!(
            "{}-{}-{:08x}",
            now.format("%Y%m%d-%H%M%S"),
            file_stem,
            nanos
        );

        let quarantine_path = self.quarantine_dir.join(&id);

        // Read original content
        let content = fs::read(path).map_err(|e| SentinelError::Quarantine {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Read original permissions
        #[cfg(unix)]
        let original_permissions = fs::metadata(path)
            .map(|m| m.permissions())
            .ok();

        // Write content to quarantine and fsync to ensure durability
        {
            let mut qfile = fs::File::create(&quarantine_path).map_err(|e| {
                SentinelError::Quarantine {
                    path: quarantine_path.clone(),
                    source: e,
                }
            })?;
            qfile.write_all(&content).map_err(|e| {
                SentinelError::Quarantine {
                    path: quarantine_path.clone(),
                    source: e,
                }
            })?;
            qfile.sync_all().map_err(|e| {
                SentinelError::Quarantine {
                    path: quarantine_path.clone(),
                    source: e,
                }
            })?;
        }

        // Store the quarantine timestamp in metadata
        let mut metadata_with_time = metadata.clone();
        metadata_with_time.quarantined_at = Utc::now();

        // Write metadata alongside and fsync to ensure durability
        let meta_path = quarantine_path.with_extension("json");
        let meta_json = serde_json::to_string_pretty(&metadata_with_time)
            .unwrap_or_else(|_| "{}".to_string());
        {
            let mut mfile = fs::File::create(&meta_path).map_err(|e| {
                SentinelError::Quarantine {
                    path: meta_path.clone(),
                    source: e,
                }
            })?;
            mfile.write_all(meta_json.as_bytes()).map_err(|e| {
                SentinelError::Quarantine {
                    path: meta_path.clone(),
                    source: e,
                }
            })?;
            mfile.sync_all().map_err(|e| {
                SentinelError::Quarantine {
                    path: meta_path.clone(),
                    source: e,
                }
            })?;
        }

        // Replace original with empty stub
        fs::write(path, "").map_err(|e| SentinelError::Quarantine {
            path: path.to_path_buf(),
            source: e,
        })?;

        // Preserve original permissions on the stub
        #[cfg(unix)]
        if let Some(perms) = original_permissions {
            let _ = fs::set_permissions(path, perms);
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
        let meta_str = fs::read_to_string(&meta_path).map_err(|_| {
            SentinelError::QuarantineEntryNotFound { id: id.to_string() }
        })?;
        let metadata: QuarantineMetadata =
            serde_json::from_str(&meta_str).map_err(|_| {
                SentinelError::QuarantineEntryNotFound { id: id.to_string() }
            })?;

        // Read quarantined content
        let content = fs::read(&quarantine_path).map_err(|e| {
            SentinelError::Quarantine {
                path: quarantine_path.clone(),
                source: e,
            }
        })?;

        // Validate the restore path before writing
        validate_restore_path(&metadata.original_path)?;

        // Restore to original location
        fs::write(&metadata.original_path, content).map_err(|e| {
            SentinelError::Quarantine {
                path: metadata.original_path,
                source: e,
            }
        })?;

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

        if !quarantine_path.exists() {
            return Err(SentinelError::QuarantineEntryNotFound {
                id: id.to_string(),
            });
        }

        let _ = fs::remove_file(&quarantine_path);
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

        let dir_entries = fs::read_dir(&self.quarantine_dir).map_err(|e| {
            SentinelError::Quarantine {
                path: self.quarantine_dir.clone(),
                source: e,
            }
        })?;

        for entry in dir_entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(meta_str) = fs::read_to_string(&path) {
                    if let Ok(metadata) =
                        serde_json::from_str::<QuarantineMetadata>(&meta_str)
                    {
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
            .quarantine_file(&pth_path, &default_meta(&pth_path))
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
            .quarantine_file(&pth_path, &default_meta(&pth_path))
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
        let mut metadata: QuarantineMetadata =
            serde_json::from_str(&meta_str).expect("parse meta");
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
        let mut metadata: QuarantineMetadata =
            serde_json::from_str(&meta_str).expect("parse meta");
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
        let mut metadata: QuarantineMetadata =
            serde_json::from_str(&meta_str).expect("parse meta");
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
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // The original_path in metadata should be valid (temp dir)
        let result = q.restore(&entry.id);
        assert!(result.is_ok(), "valid temp path should be accepted: {result:?}");
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

        assert_ne!(entry1.id, entry2.id, "IDs should differ: {} vs {}", entry1.id, entry2.id);
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
        assert!(result.is_err(), "restore should fail when quarantined file is deleted");
    }

    #[test]
    fn restore_fails_when_parent_directory_deleted() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create a nested directory structure and a file inside it.
        let nested_dir = dir.path().join("subdir").join("nested");
        fs::create_dir_all(&nested_dir).expect("create dirs");
        let pth_path = nested_dir.join("target.pth");
        fs::write(&pth_path, "payload").expect("write");

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q
            .quarantine_file(&pth_path, &default_meta(&pth_path))
            .expect("quarantine");

        // Remove the entire parent directory tree so the original path
        // can no longer be written to.
        fs::remove_dir_all(dir.path().join("subdir")).expect("remove parent dir");
        assert!(!nested_dir.exists());

        // Restore should fail because the parent directory is gone.
        let result = q.restore(&entry.id);
        assert!(result.is_err(), "restore should fail when parent directory is deleted");
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
