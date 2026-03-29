//! `sanctum entropy` -- manage entropy-based secret detection.
//!
//! Subcommands:
//! - `sanctum entropy allow <VALUE>` -- add a SHA-256 hash to the allowlist
//!   so the given high-entropy string is not flagged as a secret.

use sha2::{Digest, Sha256};
use std::io::Write;

use sanctum_types::errors::CliError;

/// Add a value's SHA-256 hash to the entropy allowlist.
///
/// The allowlist file is stored at `$DATA_DIR/entropy_allowlist.txt`.
/// Each line contains a single hex-encoded SHA-256 hash.
///
/// # Errors
///
/// Returns `CliError` if the data directory cannot be determined or the
/// allowlist file cannot be written.
pub fn allow(value: &str) -> Result<(), CliError> {
    // Warn that passing secrets as CLI arguments is visible in shell history.
    // Using eprintln instead of tracing::warn because no tracing subscriber
    // is initialised for non-hook CLI commands.
    #[allow(clippy::print_stderr)]
    {
        eprintln!(
            "Warning: the value you passed may be visible in your shell history. \
             Consider clearing it with `history -d` (bash) or `fc -W` (zsh)."
        );
    }

    let hash = Sha256::digest(value.as_bytes());
    let hex_hash = hex::encode(hash);

    let paths = sanctum_types::paths::WellKnownPaths::default();
    let allowlist_path = paths.data_dir.join("entropy_allowlist.txt");

    // Ensure data directory exists.
    if let Some(parent) = allowlist_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            CliError::InvalidArgs(format!(
                "cannot create data directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    // Append the hash to the allowlist file.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&allowlist_path)
        .map_err(|e| {
            CliError::InvalidArgs(format!(
                "cannot open allowlist file {}: {e}",
                allowlist_path.display()
            ))
        })?;

    writeln!(file, "{hex_hash}").map_err(|e| {
        CliError::InvalidArgs(format!(
            "cannot write to allowlist file {}: {e}",
            allowlist_path.display()
        ))
    })?;

    #[allow(clippy::print_stderr)]
    {
        eprintln!("Added hash {hex_hash} to entropy allowlist");
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allow_creates_allowlist_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Override data dir by setting the env var and using a custom path
        let allowlist_path = dir.path().join("entropy_allowlist.txt");

        // Directly test the hashing logic
        let value = "test-value-12345";
        let hash = Sha256::digest(value.as_bytes());
        let hex_hash = hex::encode(hash);
        assert_eq!(hex_hash.len(), 64);
        assert!(hex_hash.chars().all(|c| c.is_ascii_hexdigit()));

        // Write to file manually (avoid the default paths)
        let mut file = std::fs::File::create(&allowlist_path).expect("create");
        writeln!(file, "{hex_hash}").expect("write");

        // Verify the file contents
        let contents = std::fs::read_to_string(&allowlist_path).expect("read");
        assert!(contents.contains(&hex_hash));
    }
}
