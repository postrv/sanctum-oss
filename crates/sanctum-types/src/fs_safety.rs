//! Filesystem helpers with symlink protection and TOCTOU-safe permissions.
//!
//! These helpers ensure that security-sensitive file operations:
//! - Reject symlinks via `O_NOFOLLOW` (prevents symlink-following attacks).
//! - Set permissions via `fchmod` on the file descriptor, not the path
//!   (eliminates TOCTOU race between open and chmod).
//!
//! On non-Unix platforms, the helpers fall back to standard operations.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
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

/// Write a security-sensitive file with owner-only permissions.
///
/// On Unix, the file is created with the requested owner mode and `O_NOFOLLOW`.
/// On Windows, the parent directory and final file are restricted to the
/// current user via ACLs and reparse-point parents are rejected.
///
/// # Errors
///
/// Returns `io::Error` if the file cannot be written or permissions cannot be
/// applied.
pub fn write_private_file(path: &Path, data: &[u8], owner_mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let open_exclusive = || {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(owner_mode)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(path)
        };

        let mut file = match open_exclusive() {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(path)?;
                open_exclusive()?
            }
            Err(e) => return Err(e),
        };
        file.write_all(data)?;
        file.sync_all()?;
        fchmod_mode(&file, owner_mode)?;
    }

    #[cfg(windows)]
    {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "private file path has no parent directory",
            )
        })?;
        ensure_secure_dir(parent)?;

        let open_exclusive = || OpenOptions::new().write(true).create_new(true).open(path);

        let mut file = match open_exclusive() {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                crate::windows_security::reject_reparse_point(path)?;
                std::fs::remove_file(path)?;
                open_exclusive()?
            }
            Err(e) => return Err(e),
        };
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        crate::windows_security::reject_reparse_point(path)?;
        crate::windows_security::restrict_path_to_current_user(
            path,
            crate::windows_security::acl_access_for_owner_mode(owner_mode),
        )?;
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = owner_mode;
        std::fs::write(path, data)?;
    }

    Ok(())
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
    fchmod_mode(file, 0o600)
}

fn fchmod_mode(file: &File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;

        let mode_bits = mode.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "file mode is out of range")
        })?;
        nix::sys::stat::fchmod(
            file.as_raw_fd(),
            nix::sys::stat::Mode::from_bits_truncate(mode_bits),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
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
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                // Verify and fix permissions on the existing directory
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(path)?;
                let mode = meta.permissions().mode() & 0o777;
                if mode != 0o700 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    #[cfg(windows)]
    {
        match std::fs::create_dir_all(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        crate::windows_security::reject_reparse_point(path)?;
        crate::windows_security::restrict_path_to_current_user(
            path,
            crate::windows_security::WindowsAclAccess::DirectoryFullControl,
        )
    }

    #[cfg(not(any(unix, windows)))]
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
    fn write_private_file_sets_requested_owner_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("private.txt");
        write_private_file(&path, b"secret", 0o400).expect("write private file");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "secret");
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

    #[test]
    #[cfg(unix)]
    fn ensure_secure_dir_fixes_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let sub = dir.path().join("insecure");

        // Create directory with overly permissive mode
        std::fs::create_dir(&sub).expect("create");
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).expect("chmod");

        // Verify it's currently 0o755
        let mode = std::fs::metadata(&sub)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);

        // ensure_secure_dir should fix the permissions to 0o700
        ensure_secure_dir(&sub).expect("fix perms");

        let mode = std::fs::metadata(&sub)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
    }
}
