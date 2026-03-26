#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end tests: quarantine review flow.
//!
//! Tests the complete quarantine lifecycle: quarantine → review → approve/delete.

use std::fs;

use sanctum_sentinel::pth::analyser::content_hash;
use sanctum_sentinel::pth::quarantine::{
    Quarantine, QuarantineAction, QuarantineMetadata, QuarantineState,
};

fn setup_quarantine() -> (tempfile::TempDir, Quarantine) {
    let dir = tempfile::tempdir().expect("tempdir");
    let quarantine = Quarantine::new(dir.path().join("quarantine"));
    (dir, quarantine)
}

fn create_and_quarantine(
    dir: &std::path::Path,
    quarantine: &Quarantine,
    name: &str,
    content: &str,
) -> (std::path::PathBuf, sanctum_sentinel::pth::quarantine::QuarantineEntry) {
    let pth_path = dir.join(name);
    fs::write(&pth_path, content).expect("write");

    let metadata = QuarantineMetadata {
        original_path: pth_path.clone(),
        content_hash: content_hash(content.as_bytes()),
        creator_pid: None,
        reason: "test quarantine".to_string(),
        quarantined_at: chrono::Utc::now(),
    };

    let entry = quarantine
        .quarantine_file(&pth_path, &metadata)
        .expect("quarantine should succeed");

    (pth_path, entry)
}

#[test]
fn e2e_quarantine_review_approve() {
    let (dir, quarantine) = setup_quarantine();
    let original_content = "import base64;exec(base64.b64decode('evil'))";

    let (pth_path, entry) = create_and_quarantine(
        dir.path(),
        &quarantine,
        "evil.pth",
        original_content,
    );

    // Verify file is quarantined (original is empty stub)
    assert_eq!(fs::read_to_string(&pth_path).expect("read"), "");

    // Simulate "sanctum review" → approve (restore)
    quarantine.restore(&entry.id).expect("restore should succeed");

    // Verify file is restored to original location with original content
    let restored = fs::read_to_string(&pth_path).expect("read restored");
    assert_eq!(
        restored, original_content,
        "file should be restored to original content"
    );

    // Verify the quarantine entry is cleaned up
    let entries = quarantine.list().expect("list");
    assert!(
        !entries.iter().any(|e| e.id == entry.id),
        "restored entry should no longer be in quarantine list"
    );
}

#[test]
fn e2e_quarantine_review_delete() {
    let (dir, quarantine) = setup_quarantine();
    let malicious_content = "exec(compile(open('/tmp/evil.py').read(), '', 'exec'))";

    let (pth_path, entry) = create_and_quarantine(
        dir.path(),
        &quarantine,
        "evil.pth",
        malicious_content,
    );

    // Verify file is quarantined
    assert_eq!(fs::read_to_string(&pth_path).expect("read"), "");

    // Simulate "sanctum review" → delete
    quarantine.delete(&entry.id).expect("delete should succeed");

    // Verify quarantined copy is removed
    assert!(
        !entry.quarantine_path.exists(),
        "quarantined copy should be deleted"
    );

    // Verify original still has empty stub (safe)
    assert_eq!(
        fs::read_to_string(&pth_path).expect("read"),
        "",
        "original should still have empty stub"
    );

    // Verify the entry is removed from the list
    let entries = quarantine.list().expect("list");
    assert!(
        !entries.iter().any(|e| e.id == entry.id),
        "deleted entry should not be in quarantine list"
    );
}

#[test]
fn e2e_quarantine_state_machine_correctness() {
    // Verify the state machine transitions
    let active = QuarantineState::Active;

    // Active → Restored (via approve)
    let restored = active
        .apply(QuarantineAction::Approve)
        .expect("approve should succeed");
    assert_eq!(restored, QuarantineState::Restored);

    // Active → Deleted (via delete)
    let deleted = active
        .apply(QuarantineAction::Delete)
        .expect("delete should succeed");
    assert_eq!(deleted, QuarantineState::Deleted);

    // Active → Active (via report — no state change)
    let still_active = active
        .apply(QuarantineAction::Report)
        .expect("report should succeed");
    assert_eq!(still_active, QuarantineState::Active);

    // Deleted is terminal — all actions should fail
    assert!(deleted.apply(QuarantineAction::Approve).is_err());
    assert!(deleted.apply(QuarantineAction::Delete).is_err());
    assert!(deleted.apply(QuarantineAction::Report).is_err());
}

#[test]
fn e2e_quarantine_preserves_metadata() {
    let (dir, quarantine) = setup_quarantine();
    let content = "import subprocess; subprocess.run(['rm', '-rf', '/'])";

    let (_, entry) = create_and_quarantine(
        dir.path(),
        &quarantine,
        "rm_all.pth",
        content,
    );

    // List and verify metadata is preserved
    let entries = quarantine.list().expect("list");
    let found = entries.iter().find(|e| e.id == entry.id).expect("should find entry");

    assert_eq!(
        found.metadata.original_path,
        entry.metadata.original_path
    );
    assert_eq!(found.metadata.content_hash, entry.metadata.content_hash);
    assert_eq!(found.metadata.reason, "test quarantine");
}

#[test]
fn e2e_quarantine_roundtrip_preserves_content_exactly() {
    let (dir, quarantine) = setup_quarantine();

    // Test with various content types including binary-like content
    let test_cases = [
        ("simple.pth", "exec(open('/tmp/evil.py').read())"),
        ("unicode.pth", "import os; os.system('echo héllo')"),
        ("multiline.pth", "import os\nimport sys\nexec('...')"),
        ("empty_lines.pth", "\n\nimport os\n\n"),
    ];

    for (name, content) in &test_cases {
        let (pth_path, entry) = create_and_quarantine(
            dir.path(),
            &quarantine,
            name,
            content,
        );

        // Verify original is now empty stub
        assert_eq!(
            fs::read_to_string(&pth_path).expect("read stub"),
            "",
            "{name} should have empty stub"
        );

        // Restore and verify exact content preservation
        quarantine.restore(&entry.id).expect("restore");
        let restored = fs::read_to_string(&pth_path).expect("read restored");
        assert_eq!(
            &restored, content,
            "{name} content should be exactly preserved after quarantine roundtrip"
        );
    }
}
