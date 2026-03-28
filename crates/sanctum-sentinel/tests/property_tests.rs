#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! Property-based tests for security-critical modules.
//!
//! These tests use proptest to verify invariants across thousands of
//! random inputs, catching edge cases that unit tests miss.

use proptest::prelude::*;
use sanctum_sentinel::pth::analyser::{analyse_pth_file, analyse_pth_line, content_hash};
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata};
use sanctum_types::threat::ThreatLevel;

proptest! {
    /// Property: analyse_pth_line is a total function (never panics).
    #[test]
    fn pth_analyser_total(line in ".*") {
        let _ = analyse_pth_line(&line);
    }

    /// Property: analyse_pth_line is deterministic.
    #[test]
    fn pth_analyser_deterministic(line in ".*") {
        let r1 = analyse_pth_line(&line);
        let r2 = analyse_pth_line(&line);
        prop_assert_eq!(r1.level(), r2.level());
    }

    /// Property: analyse_pth_file severity is max of line severities.
    #[test]
    fn file_severity_is_max_of_lines(lines in prop::collection::vec(".*", 1..20)) {
        let content = lines.join("\n");
        let file_result = analyse_pth_file(&content);

        let max_line_level = lines.iter()
            .map(|l| analyse_pth_line(l).level())
            .max()
            .unwrap_or(ThreatLevel::Info);

        prop_assert_eq!(file_result.verdict.level(), max_line_level);
    }

    /// Property: quarantine + restore is identity.
    #[test]
    fn quarantine_restore_roundtrip(content in "[a-zA-Z0-9/._\\-\n]{1,1000}") {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.pth");
        std::fs::write(&path, &content).expect("write");

        let meta = QuarantineMetadata {
            original_path: path.clone(),
            content_hash: content_hash(content.as_bytes()),
            creator_pid: None,
            reason: "test".into(),
            quarantined_at: chrono::Utc::now(),
        };

        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q.quarantine_file(&path, &meta).expect("quarantine");
        q.restore(&entry.id).expect("restore");

        prop_assert_eq!(std::fs::read_to_string(&path).expect("read"), content);
    }

    /// Property: SHA-256 hashes are consistent.
    #[test]
    fn content_hash_is_deterministic(content in prop::collection::vec(any::<u8>(), 0..10000)) {
        let h1 = content_hash(&content);
        let h2 = content_hash(&content);
        prop_assert_eq!(h1, h2);
    }

    /// Property: any line containing "exec(" is at least Warning level.
    #[test]
    fn exec_is_never_benign(
        prefix in "[a-zA-Z0-9 ;]{0,50}",
        suffix in "[a-zA-Z0-9 ;'\"()]{0,50}"
    ) {
        let line = format!("{prefix}exec({suffix}");
        let result = analyse_pth_line(&line);
        prop_assert!(result.level() >= ThreatLevel::Warning,
            "exec( should not be benign, got {:?} for line: {line}", result.level());
    }
}
