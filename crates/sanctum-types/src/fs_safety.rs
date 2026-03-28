//! Filesystem helpers with symlink protection and TOCTOU-safe permissions.
//!
//! These helpers ensure that security-sensitive file operations:
//! - Reject symlinks via `O_NOFOLLOW` (prevents symlink-following attacks).
//! - Set permissions via `fchmod` on the file descriptor, not the path
//!   (eliminates TOCTOU race between open and chmod).
//!
//! On non-Unix platforms, the helpers fall back to standard operations.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Open a file for appending with symlink protection and 0o600 permissions.
///
/// On Unix: uses `O_NOFOLLOW` to reject symlinks at open time, and `fchmod`
/// on the file descriptor to set permissions without TOCTOU races.
///
/// # Errors
///
/// Returns `io::Error` if the path is a symlink (`ELOOP`), the file cannot
/// be opened, or permissions cannot be set.
pub fn safe_append_open(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)?;

        // fchmod on the fd itself — no TOCTOU race
        nix::sys::stat::fchmod(
            file.as_raw_fd(),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

        Ok(file)
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

/// Create a new file exclusively (`O_EXCL`) with symlink protection and 0o600
/// permissions.
///
/// Used for temporary files that will be renamed into place, or PID files that
/// must not already exist.
///
/// # Errors
///
/// Returns `io::Error` if the file already exists, the path is a symlink, or
/// the file cannot be created.
pub fn safe_create_exclusive(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
            .open(path)?;

        nix::sys::stat::fchmod(
            file.as_raw_fd(),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;

        Ok(file)
    }

    #[cfg(not(unix))]
    {
        OpenOptions::new().write(true).create_new(true).open(path)
    }
}

/// Set 0o600 permissions on an already-open file descriptor (TOCTOU-safe).
///
/// This is useful when the file was opened by another mechanism (e.g.,
/// `create_new` without `O_NOFOLLOW` because `O_EXCL` already prevents
/// symlink attacks).
///
/// # Errors
///
/// Returns `io::Error` if `fchmod` fails.
pub fn fchmod_600(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        nix::sys::stat::fchmod(
            file.as_raw_fd(),
            nix::sys::stat::Mode::from_bits_truncate(0o600),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    }

    #[cfg(not(unix))]
    {
        let _ = file;
    }

    Ok(())
}

/// Ensure a directory exists with 0o700 permissions.
///
/// Creates the directory if it does not exist. On Unix, uses `DirBuilder`
/// with mode 0o700 for atomic secure creation.
///
/// # Errors
///
/// Returns `io::Error` if directory creation fails (except `AlreadyExists`).
pub fn ensure_secure_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }

    #[cfg(not(unix))]
    {
        match std::fs::create_dir(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn safe_append_open_creates_and_appends() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.log");

        let mut f = safe_append_open(&path).expect("open");
        writeln!(f, "line 1").expect("write");
        drop(f);

        let mut f = safe_append_open(&path).expect("reopen");
        writeln!(f, "line 2").expect("write");
        drop(f);

        let content = std::fs::read_to_string(&path).expect("read");
        assert_eq!(content.lines().count(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn safe_append_open_sets_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.log");

        let f = safe_append_open(&path).expect("open");
        drop(f);

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn safe_append_open_rejects_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.log");
        let link = dir.path().join("link.log");

        // Create the target file
        std::fs::write(&target, "original").expect("write target");
        // Create a symlink
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        // Opening the symlink should fail with ELOOP
        let result = safe_append_open(&link);
        assert!(result.is_err(), "should reject symlink");

        // The target file should be unmodified
        let content = std::fs::read_to_string(&target).expect("read target");
        assert_eq!(content, "original");
    }

    #[test]
    fn safe_create_exclusive_creates_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.pid");

        let mut f = safe_create_exclusive(&path).expect("create");
        f.write_all(b"12345").expect("write");
        drop(f);

        let content = std::fs::read_to_string(&path).expect("read");
        assert_eq!(content, "12345");
    }

    #[test]
    fn safe_create_exclusive_fails_if_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("existing.pid");

        std::fs::write(&path, "old").expect("write");

        let result = safe_create_exclusive(&path);
        assert!(result.is_err(), "should fail if file exists");
    }

    #[test]
    #[cfg(unix)]
    fn safe_create_exclusive_rejects_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real.pid");
        let link = dir.path().join("link.pid");

        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        // Even though the target doesn't exist, the symlink itself exists
        // and O_NOFOLLOW + O_EXCL should reject it
        let result = safe_create_exclusive(&link);
        assert!(result.is_err(), "should reject symlink");
        assert!(!target.exists(), "target should not have been created");
    }

    #[test]
    #[cfg(unix)]
    fn safe_create_exclusive_sets_600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secure.pid");

        let f = safe_create_exclusive(&path).expect("create");
        drop(f);

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn fchmod_600_sets_permissions_on_fd() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.txt");

        // Create file with default (umask-dependent) permissions
        let f = std::fs::File::create(&path).expect("create");
        fchmod_600(&f).expect("fchmod");
        drop(f);

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn ensure_secure_dir_creates_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("secure");

        ensure_secure_dir(&sub).expect("create");
        assert!(sub.is_dir());
    }

    #[test]
    fn ensure_secure_dir_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("secure");

        ensure_secure_dir(&sub).expect("first");
        ensure_secure_dir(&sub).expect("second");
        assert!(sub.is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn ensure_secure_dir_sets_700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("secure");

        ensure_secure_dir(&sub).expect("create");

        let mode = std::fs::metadata(&sub)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
