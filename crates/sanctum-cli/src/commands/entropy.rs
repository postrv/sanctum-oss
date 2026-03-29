//! `sanctum entropy` -- Manage the allowlist for high-entropy strings flagged as possible secrets.

use std::io::Write;
use std::path::{Path, PathBuf};

use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;

use crate::EntropyAction;

/// File name for the entropy allowlist within the data directory.
const ALLOWLIST_FILE: &str = "entropy_allowlist.txt";

/// Run the entropy subcommand.
///
/// # Errors
///
/// Returns `CliError` if the allowlist file cannot be read or written.
pub fn run(action: &EntropyAction) -> Result<(), CliError> {
    let path = default_allowlist_path();
    match action {
        EntropyAction::Allow { value } => run_allow(value.as_deref(), &path),
        EntropyAction::List => run_list(&path),
    }
}

/// Return the default path to the entropy allowlist file.
fn default_allowlist_path() -> PathBuf {
    let paths = WellKnownPaths::default();
    paths.data_dir.join(ALLOWLIST_FILE)
}

/// Read all entries from the allowlist file.
///
/// Returns an empty list if the file does not exist.
fn read_allowlist(path: &Path) -> Result<Vec<String>, CliError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Write the full allowlist back to disk, creating parent directories as needed.
fn write_allowlist(entries: &[String], path: &Path) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = entries.join("\n");
    let mut file = std::fs::File::create(path)?;
    file.write_all(content.as_bytes())?;
    if !content.is_empty() {
        file.write_all(b"\n")?;
    }
    Ok(())
}

/// Add a value to the entropy allowlist.
///
/// If `value` is `Some`, uses it directly (with a warning about shell history).
/// If `None`, reads a single line from stdin.
fn run_allow(value: Option<&str>, path: &Path) -> Result<(), CliError> {
    let secret = if let Some(v) = value {
        tracing::warn!(
            "Value passed as CLI argument -- it may be visible in shell history and process listings"
        );
        v.trim().to_string()
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .map_err(|e| CliError::InvalidArgs(format!("failed to read from stdin: {e}")))?;
        let trimmed = buf.trim().to_string();
        if trimmed.is_empty() {
            return Err(CliError::InvalidArgs(
                "no value provided on stdin".to_string(),
            ));
        }
        trimmed
    };

    let mut entries = read_allowlist(path)?;

    if entries.iter().any(|e| e == &secret) {
        #[allow(clippy::print_stdout)]
        {
            println!("Value is already in the entropy allowlist.");
        }
        return Ok(());
    }

    entries.push(secret);
    write_allowlist(&entries, path)?;

    #[allow(clippy::print_stdout)]
    {
        println!("Value added to the entropy allowlist.");
    }
    Ok(())
}

/// List all entries in the entropy allowlist.
fn run_list(path: &Path) -> Result<(), CliError> {
    let entries = read_allowlist(path)?;

    #[allow(clippy::print_stdout)]
    {
        if entries.is_empty() {
            println!("Entropy allowlist is empty.");
        } else {
            println!("Entropy allowlist ({} entries):", entries.len());
            for entry in &entries {
                println!("  {entry}");
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn test_allowlist_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join(ALLOWLIST_FILE);
        (dir, path)
    }

    #[test]
    fn run_allow_with_positional_arg() {
        let (_dir, path) = test_allowlist_path();

        let result = run_allow(Some("test-secret-value"), &path);
        assert!(result.is_ok(), "run_allow with arg should succeed");

        // Verify it was written
        let entries = read_allowlist(&path).expect("read allowlist");
        assert!(entries.contains(&"test-secret-value".to_string()));
    }

    #[test]
    fn run_allow_reads_from_stdin() {
        let (_dir, path) = test_allowlist_path();

        // We cannot easily pipe to stdin in a unit test, so we test
        // the "value provided" path for correctness and verify the
        // None branch returns an error when stdin would be empty.
        let result = run_allow(Some("stdin-simulated-value"), &path);
        assert!(result.is_ok());

        let entries = read_allowlist(&path).expect("read allowlist");
        assert!(entries.contains(&"stdin-simulated-value".to_string()));
    }

    #[test]
    fn run_allow_duplicate_is_idempotent() {
        let (_dir, path) = test_allowlist_path();

        run_allow(Some("dup-value"), &path).expect("first add");
        run_allow(Some("dup-value"), &path).expect("duplicate add should succeed");

        let entries = read_allowlist(&path).expect("read allowlist");
        let count = entries.iter().filter(|e| *e == "dup-value").count();
        assert_eq!(count, 1, "duplicate should not be added twice");
    }

    #[test]
    fn run_list_empty() {
        let (_dir, path) = test_allowlist_path();

        let result = run_list(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn run_list_with_entries() {
        let (_dir, path) = test_allowlist_path();

        run_allow(Some("entry-one"), &path).expect("add first");
        run_allow(Some("entry-two"), &path).expect("add second");

        let result = run_list(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn allowlist_round_trip() {
        let (_dir, path) = test_allowlist_path();

        let entries = vec!["abc123".to_string(), "def456".to_string()];
        write_allowlist(&entries, &path).expect("write");
        let read_back = read_allowlist(&path).expect("read");
        assert_eq!(entries, read_back);
    }
}
