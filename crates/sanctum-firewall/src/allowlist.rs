//! Entropy allowlist loading.
//!
//! Loads SHA-256 hashes from the entropy allowlist file so that known-safe
//! high-entropy strings (build hashes, UUIDs, etc.) can be excluded from
//! credential detection.

use std::path::Path;

/// Load the entropy allowlist from a file.
///
/// Each line in the file should contain a single hex-encoded SHA-256 hash.
/// Empty lines and lines starting with `#` are ignored.
///
/// Returns an empty `Vec` if the file does not exist or cannot be read
/// (fail-open for allowlist loading -- missing allowlist means nothing is
/// exempted, which is the safe default).
#[must_use]
pub fn load_allowlist(path: &Path) -> Vec<String> {
    let Ok(content) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        // Validate: SHA-256 hashes are exactly 64 hex characters
        .filter(|line| line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_lowercase)
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn load_allowlist_from_valid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("allowlist.txt");
        let mut f = std::fs::File::create(&file).expect("create");
        writeln!(f, "# comment line").expect("write");
        writeln!(
            f,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .expect("write");
        writeln!(f).expect("write");
        writeln!(
            f,
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        )
        .expect("write");

        let hashes = load_allowlist(&file);
        assert_eq!(hashes.len(), 2);
        assert_eq!(
            hashes[0],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn load_allowlist_returns_empty_for_missing_file() {
        let hashes = load_allowlist(Path::new("/nonexistent/allowlist.txt"));
        assert!(hashes.is_empty());
    }

    #[test]
    fn load_allowlist_skips_invalid_lines() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("allowlist.txt");
        let mut f = std::fs::File::create(&file).expect("create");
        writeln!(f, "too-short").expect("write");
        writeln!(f, "not-hex-chars-but-64-chars-long!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!").expect("write");
        writeln!(
            f,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .expect("write");

        let hashes = load_allowlist(&file);
        assert_eq!(hashes.len(), 1);
    }

    #[test]
    fn load_allowlist_lowercases_hashes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("allowlist.txt");
        let mut f = std::fs::File::create(&file).expect("create");
        writeln!(
            f,
            "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
        )
        .expect("write");

        let hashes = load_allowlist(&file);
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
