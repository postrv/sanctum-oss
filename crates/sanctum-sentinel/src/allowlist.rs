//! Package and content hash allowlisting.
//!
//! Maintains a list of known-safe `.pth` files by package name and
//! SHA-256 content hash. Used to suppress false positives for legitimate
//! packages that use executable `.pth` files (setuptools, editables, coverage).

use sanctum_types::config::PthAllowlistEntry;

/// Default allowlist entries for well-known packages.
///
/// These are the only packages in the top 50 `PyPI` downloads that use
/// executable `.pth` files. Each entry includes a SHA-256 hash of the
/// known-safe `.pth` content.
///
/// **Note:** Hashes vary by package version. The hashes below are
/// representative of common versions. If your installed version differs,
/// run `sha256sum <file>.pth` and update your configuration accordingly.
#[must_use]
pub fn default_allowlist() -> Vec<PthAllowlistEntry> {
    vec![
        // setuptools: "import _distutils_hack; _distutils_hack.add_shim()\n"
        PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: "sha256:87562230a1af758c6c9cafecbd52ccd5b81951c3aa8101d5aa843586bf51ff51"
                .to_string(),
        },
        // setuptools (no trailing newline variant)
        PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: "sha256:0a73401906cfb77a8fc12a1844e5ff38b181aad14f1936478d7c087d01823a61"
                .to_string(),
        },
        // editables: "import _editable_impl\n"
        PthAllowlistEntry {
            package: "editables".to_string(),
            hash: "sha256:d51a7dd7ae1fb5124f2ea0888eabf1180cc8c1a196d518bfb9a3e36004a55042"
                .to_string(),
        },
        // coverage: "import coverage; coverage.process_startup()\n"
        PthAllowlistEntry {
            package: "coverage".to_string(),
            hash: "sha256:95d25e150fb11aab7bc8dc6510d6d000ede87d2e2dd0a273b4f621ab17976201"
                .to_string(),
        },
        // _virtualenv: "import _virtualenv\n"
        PthAllowlistEntry {
            package: "_virtualenv".to_string(),
            hash: "sha256:a18ec686bd69842888e68e43eade6c26cac183a1e4c98c40ae8992349f0a1a1c"
                .to_string(),
        },
    ]
}

/// Check if a package + hash combination is allowlisted.
///
/// Both the package name and a non-empty hash must match an allowlist entry.
/// Entries with empty hashes are ignored — they cannot match anything.
#[must_use]
pub fn is_allowlisted(
    package_name: &str,
    content_hash: &str,
    allowlist: &[PthAllowlistEntry],
) -> bool {
    allowlist.iter().any(|entry| {
        !entry.hash.is_empty() && entry.package == package_name && entry.hash == content_hash
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_allowlist_contains_setuptools() {
        let list = default_allowlist();
        assert!(list.iter().any(|e| e.package == "setuptools"));
    }

    #[test]
    fn default_allowlist_has_no_empty_hashes() {
        let list = default_allowlist();
        for entry in &list {
            assert!(
                !entry.hash.is_empty(),
                "default allowlist entry for '{}' has an empty hash",
                entry.package
            );
        }
    }

    #[test]
    fn empty_hash_does_not_wildcard_match() {
        let list = vec![PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: String::new(),
        }];
        // An empty hash in the allowlist must NOT match any content hash
        assert!(!is_allowlisted("setuptools", "sha256:anything", &list));
        assert!(!is_allowlisted("setuptools", "", &list));
        assert!(!is_allowlisted(
            "setuptools",
            "87562230a1af758c6c9cafecbd52ccd5b81951c3aa8101d5aa843586bf51ff51",
            &list
        ));
    }

    #[test]
    fn correct_hash_matches() {
        let list = vec![PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: "abc123".to_string(),
        }];
        assert!(is_allowlisted("setuptools", "abc123", &list));
    }

    #[test]
    fn incorrect_hash_does_not_match() {
        let list = vec![PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: "abc123".to_string(),
        }];
        assert!(!is_allowlisted("setuptools", "wrong_hash", &list));
    }

    #[test]
    fn package_name_must_match() {
        let list = vec![PthAllowlistEntry {
            package: "setuptools".to_string(),
            hash: "abc123".to_string(),
        }];
        // Correct hash but wrong package
        assert!(!is_allowlisted("evil-package", "abc123", &list));
    }

    #[test]
    fn allowlist_rejects_unknown_package() {
        let list = default_allowlist();
        assert!(!is_allowlisted("evil-package", "sha256:abc", &list));
    }

    #[test]
    fn allowlist_matches_real_hash_from_default() {
        let list = default_allowlist();
        // The setuptools .pth hash for "import _distutils_hack; _distutils_hack.add_shim()\n"
        assert!(is_allowlisted(
            "setuptools",
            "sha256:87562230a1af758c6c9cafecbd52ccd5b81951c3aa8101d5aa843586bf51ff51",
            &list
        ));
    }

    #[test]
    fn allowlist_rejects_wrong_hash_for_known_package() {
        let list = default_allowlist();
        assert!(!is_allowlisted("setuptools", "deadbeef", &list));
    }
}
