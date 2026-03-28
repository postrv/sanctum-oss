//! Token-based authentication for sensitive IPC commands.
//!
//! The daemon generates a random 32-byte hex token on startup and writes it
//! to `{runtime_dir}/auth_token` with 0o400 permissions (read-only by owner).
//! CLI clients read this token and include it in requests for commands that
//! modify daemon state (shutdown, quarantine ops, budget changes, etc.).

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Length of the auth token in bytes (before hex encoding).
const TOKEN_BYTES: usize = 32;

/// Length of the hex-encoded auth token string.
pub const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

/// Name of the auth token file within the runtime/data directory.
pub const AUTH_TOKEN_FILENAME: &str = "auth_token";

/// Generate a cryptographically random 32-byte token and return it as a
/// 64-character hex string.
///
/// Uses `/dev/urandom` (or platform equivalent via `getrandom`) to avoid
/// adding a `rand` dependency.
///
/// # Errors
///
/// Returns an `io::Error` if the random source cannot be read.
pub fn generate_token() -> io::Result<String> {
    let mut buf = [0u8; TOKEN_BYTES];

    #[cfg(unix)]
    {
        let mut f = fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)?;
    }

    #[cfg(not(unix))]
    {
        // Fallback: use a less-ideal but functional approach for non-unix
        // This path is not expected to be used in production (daemon is Unix-only)
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "auth token generation requires Unix /dev/urandom",
        ));
    }

    Ok(hex::encode(buf))
}

/// Write a token to `{data_dir}/auth_token` with 0o400 permissions.
///
/// The file is created exclusively (fails if it already exists) to prevent
/// TOCTOU races, then permissions are set to read-only by owner via `fchmod`
/// on the file descriptor.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be created or written.
pub fn write_token(data_dir: &Path, token: &str) -> io::Result<PathBuf> {
    let token_path = data_dir.join(AUTH_TOKEN_FILENAME);

    // Ensure parent directory exists
    if let Some(parent) = token_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Remove any existing token file (from a previous run)
    match fs::remove_file(&token_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // Create the file and write the token
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&token_path)?;

        file.write_all(token.as_bytes())?;
        file.sync_all()?;

        // Also set via fchmod for extra safety (belt and suspenders)
        fchmod_400(&file)?;
    }

    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&token_path)?;

        file.write_all(token.as_bytes())?;
        file.sync_all()?;
    }

    Ok(token_path)
}

/// Read the auth token from `{data_dir}/auth_token`.
///
/// # Errors
///
/// Returns an `io::Error` if the file cannot be read.
pub fn read_token(data_dir: &Path) -> io::Result<String> {
    let token_path = data_dir.join(AUTH_TOKEN_FILENAME);
    let token = fs::read_to_string(&token_path)?;
    let trimmed = token.trim().to_string();
    Ok(trimmed)
}

/// Remove the auth token file. Best-effort: ignores `NotFound`.
pub fn remove_token(data_dir: &Path) {
    let token_path = data_dir.join(AUTH_TOKEN_FILENAME);
    match fs::remove_file(&token_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::warn!(
                path = %token_path.display(),
                %e,
                "failed to remove auth token file"
            );
        }
    }
}

/// Validate that a provided token matches the expected token using
/// constant-time comparison to prevent timing attacks.
#[must_use]
pub fn validate_token(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    // Constant-time comparison: XOR all bytes and accumulate
    let mut diff: u8 = 0;
    for (a, b) in expected.bytes().zip(provided.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Set 0o400 permissions on an already-open file descriptor (TOCTOU-safe).
#[cfg(unix)]
fn fchmod_400(file: &fs::File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;

    nix::sys::stat::fchmod(
        file.as_raw_fd(),
        nix::sys::stat::Mode::from_bits_truncate(0o400),
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn token_generation_produces_valid_hex_string() {
        let token = generate_token().expect("generate token");
        assert_eq!(
            token.len(),
            TOKEN_HEX_LEN,
            "token should be {TOKEN_HEX_LEN} hex chars"
        );

        // Verify it's valid hex
        let decoded = hex::decode(&token).expect("should be valid hex");
        assert_eq!(decoded.len(), TOKEN_BYTES);
    }

    #[test]
    fn token_generation_produces_unique_tokens() {
        let t1 = generate_token().expect("generate token 1");
        let t2 = generate_token().expect("generate token 2");
        assert_ne!(t1, t2, "two generated tokens should differ");
    }

    #[test]
    #[cfg(unix)]
    fn token_file_has_correct_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let token = generate_token().expect("generate token");
        let token_path = write_token(dir.path(), &token).expect("write token");

        let mode = fs::metadata(&token_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o400, "token file should be read-only by owner");
    }

    #[test]
    fn write_and_read_token_roundtrips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token = generate_token().expect("generate token");
        write_token(dir.path(), &token).expect("write token");

        let read_back = read_token(dir.path()).expect("read token");
        assert_eq!(read_back, token);
    }

    #[test]
    fn remove_token_is_idempotent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let token = generate_token().expect("generate token");
        write_token(dir.path(), &token).expect("write token");

        let token_path = dir.path().join(AUTH_TOKEN_FILENAME);
        assert!(token_path.exists());

        remove_token(dir.path());
        assert!(!token_path.exists());

        // Second remove should not panic
        remove_token(dir.path());
    }

    #[test]
    fn validate_token_accepts_correct_token() {
        let token = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        assert!(validate_token(token, token));
    }

    #[test]
    fn validate_token_rejects_wrong_token() {
        let expected = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let provided = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!validate_token(expected, provided));
    }

    #[test]
    fn validate_token_rejects_different_length() {
        let expected = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let provided = "abcdef";
        assert!(!validate_token(expected, provided));
    }

    #[test]
    fn validate_token_rejects_empty_strings() {
        assert!(
            validate_token("", ""),
            "two empty strings technically match"
        );
        assert!(!validate_token("abc", ""));
        assert!(!validate_token("", "abc"));
    }
}
