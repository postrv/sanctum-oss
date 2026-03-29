//! `sanctum entropy` -- Manage the entropy-based secret detection allowlist.

use sanctum_firewall::allowlist;
use sanctum_types::errors::CliError;

/// Run the entropy subcommand.
pub fn run_allow(value: &str) -> Result<(), CliError> {
    let paths = sanctum_types::paths::WellKnownPaths::default();
    let allowlist_path = paths.config_dir.join("entropy_allowlist.json");

    let mut list = allowlist::load_allowlist(&allowlist_path);
    let hash = allowlist::hash_value(value);

    if list.contains(&hash) {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("Value is already in the entropy allowlist.");
        }
        return Ok(());
    }

    list.insert(hash.clone());
    allowlist::save_allowlist(&allowlist_path, &list)
        .map_err(|e| CliError::InvalidArgs(format!("Failed to save allowlist: {e}")))?;

    #[allow(clippy::print_stdout)]
    {
        println!("Added to entropy allowlist (hash: {hash})");
    }
    Ok(())
}

/// Show recently flagged high-entropy strings from the audit log.
#[allow(clippy::unnecessary_wraps)]
pub fn run_review() -> Result<(), CliError> {
    let paths = sanctum_types::paths::WellKnownPaths::default();
    let audit_path = paths.data_dir.join("audit.log");

    let Ok(content) = std::fs::read_to_string(&audit_path) else {
        #[allow(clippy::print_stdout)]
        {
            println!("No audit log found. No high-entropy events to review.");
        }
        return Ok(());
    };

    let mut count = 0_usize;
    for line in content.lines().rev().take(100) {
        if let Ok(event) = serde_json::from_str::<sanctum_types::threat::ThreatEvent>(line) {
            if event.description.contains("High-Entropy")
                || event.description.contains("entropy")
                || event.description.contains("POSSIBLE_SECRET")
            {
                #[allow(clippy::print_stdout)]
                {
                    println!(
                        "[{}] {:?} - {}",
                        event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        event.level,
                        event.description
                    );
                }
                count += 1;
            }
        }
    }

    if count == 0 {
        #[allow(clippy::print_stdout)]
        {
            println!("No high-entropy events found in recent audit log entries.");
        }
    } else {
        #[allow(clippy::print_stdout)]
        {
            println!("\n{count} high-entropy event(s) found.");
            println!("Use `sanctum entropy allow <string>` to allowlist a known-safe value.");
        }
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use sanctum_firewall::allowlist;
    use std::collections::HashSet;

    #[test]
    fn allow_adds_hash_to_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("allowlist.json");

        let mut list = allowlist::load_allowlist(&path);
        assert!(list.is_empty());

        let hash = allowlist::hash_value("test_value");
        list.insert(hash.clone());
        allowlist::save_allowlist(&path, &list).expect("save");

        let loaded = allowlist::load_allowlist(&path);
        assert!(loaded.contains(&hash));
    }

    #[test]
    fn is_allowed_works_end_to_end() {
        let mut list = HashSet::new();
        let hash = allowlist::hash_value("my_safe_string");
        list.insert(hash);
        assert!(allowlist::is_allowed(&list, "my_safe_string"));
        assert!(!allowlist::is_allowed(&list, "other_string"));
    }
}
