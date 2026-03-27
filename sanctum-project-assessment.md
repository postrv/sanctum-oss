# Sanctum Project Assessment

**Date**: 27 March 2026  
**Scope**: Evaluation against the development plan, v0.1.0 security checklist, and highest applicable security/stability standards  
**Sources reviewed**: Workspace `Cargo.toml`, `deny.toml`, `rust-toolchain.toml`, CI workflows (`ci.yml`, `release.yml`), all 8 crate source files, CHANGELOG, SECURITY.md, THREAT_MODEL.md, ARCHITECTURE.md, DEPENDENCY_AUDIT.md, fuzz targets, Kani proofs, development plan, README, and mockup

---

## Executive summary

Sanctum is in remarkably strong shape for a pre-1.0 security tool. The core sentinel, firewall, and budget subsystems are implemented, tested (565 tests), and backed by formal verification (4 Kani proofs) and fuzz testing. The codebase enforces zero `unsafe`, zero `unwrap`/`expect`/`panic` outside tests, and zero clippy warnings at pedantic+nursery level. Supply chain hygiene is well above the industry norm for an open-source Rust project.

That said, the assessment identifies **3 blocking issues** that should be resolved before a public v0.1.0 release, **6 notable gaps** between the development plan and the current state, and **5 hardening recommendations** for pushing beyond the current bar.

---

## 1. Blocking issues

### 1.1 Toolchain version discrepancy

The `rust-toolchain.toml` pins Rust `1.93.0` and CI uses `dtolnay/rust-toolchain@1.93.0`, but the workspace `Cargo.toml` declares `rust-version = "1.85.0"`. The development plan originally specified `1.82.0`. These three different values create ambiguity about what the minimum supported Rust version (MSRV) actually is.

**Risk**: A contributor or user building with 1.85.0 (as `rust-version` promises) could hit compilation failures if any crate depends on features introduced between 1.85 and 1.93. Conversely, if the project genuinely requires 1.93, the `rust-version` field is lying to downstream consumers.

**Recommendation**: Align all three to a single version. If 1.93 features are used, set `rust-version = "1.93.0"` in the workspace. If broader compatibility is desired, verify the codebase compiles on 1.85 and keep the toolchain pin there.

### 1.2 CI fuzz duration is far below target

The development plan specifies **5+ hours of fuzz testing with zero crashes** as a release gate. The actual CI configuration runs each fuzz target for only **30 seconds** (`-max_total_time=30`).

**Risk**: 30 seconds of fuzzing provides minimal coverage. The 5-hour target exists because short fuzzing runs miss deep code paths — exactly the kind of paths an attacker would exploit in a `.pth` analyser or config parser.

**Recommendation**: Add a scheduled nightly or weekly CI job that runs each fuzz target for the full 5 hours, separate from the fast-feedback PR pipeline. Gate releases on the nightly fuzz results.

### 1.3 Reproducible builds are unverified

The security checklist requires: *"Reproducible builds verified (two independent builds produce identical hashes)."* There is no CI job, script, or documented process that performs this verification.

**Risk**: Without reproducible builds, there is no way to confirm that a release binary was built from the claimed source. This is particularly important for a security daemon that runs with filesystem access and Sigstore-signs its releases — signing a non-reproducible build attests to the wrong thing.

**Recommendation**: Add a CI step (or a Makefile target) that builds twice on the same runner and compares SHA-256 hashes. `codegen-units = 1` and `lto = "fat"` in the release profile should already make this deterministic, but it needs to be verified and enforced.

---

## 2. Security standards checklist evaluation

### Code quality

| Requirement | Status | Notes |
|---|---|---|
| `cargo clippy --all-targets` with `unwrap_used = deny` | **PASS** | Workspace lints deny `unwrap_used`, `expect_used`, `panic`, `todo`, `dbg_macro`, `print_stdout`, `print_stderr` |
| `cargo fmt --check` | **PASS** | Enforced in CI `lint` job |
| `cargo deny check` | **PASS** | Dedicated CI job; `deny.toml` is comprehensive |
| `cargo audit` zero vulnerabilities | **PASS** | `rustsec/audit-check@v2` in CI |
| Zero `unsafe` blocks | **PASS** | `unsafe_code = "deny"` at workspace level |
| All error paths return `Result`, no panics | **PASS with caveat** | The `compile_regex` fallback uses `std::process::abort()` rather than panic — technically correct given the lint rules, and unreachable for compile-time literal patterns, but should be documented in ARCHITECTURE.md as a deliberate decision |

### Testing

| Requirement | Status | Notes |
|---|---|---|
| Unit test coverage > 90% on security-critical modules | **LIKELY PASS** | 565 tests across 8 crates; heavy concentration on sentinel, firewall, and quarantine. No coverage report tool (`tarpaulin`, `llvm-cov`) visible in CI — should be added for verification |
| Property-based tests with 10,000+ cases | **PASS** | CI sets `PROPTEST_CASES: 10000`; 9 proptest harnesses (6 sentinel + 3 budget) |
| Kani proofs pass | **PASS** | 4 proofs: `pth_analyser_never_panics`, `pure_path_is_always_benign`, `exec_is_never_benign`, `quarantine_state_transitions`. CI gates builds on `kani-core` |
| Fuzz testing: 5+ hrs with zero crashes | **FAIL** | CI runs 30s per target. See §1.2 |
| E2E tests cover attack simulation + benign case | **PARTIAL** | Fixture files exist for both malicious and benign cases; `e2e_pth_detection.rs`, `e2e_daemon_lifecycle.rs`, `e2e_quarantine_flow.rs` present. Coverage of full daemon-to-notification pipeline not verified from the snapshot |
| Tests pass on Linux (x86_64) and macOS (aarch64) | **PASS** | Separate `test-linux` and `test-macos` CI jobs |

### Supply chain

| Requirement | Status | Notes |
|---|---|---|
| All dependencies in DEPENDENCY_AUDIT.md | **PASS** | Thorough per-crate breakdown with audit notes |
| Cargo.lock committed | **PASS** | Workspace root includes `Cargo.lock` |
| `cargo-deny` blocks undeclared licenses and banned crates | **PASS** | Copyleft denied, `openssl-sys`/`libz-sys` banned, unknown registries/git denied |
| Sigstore-signed release binaries | **PASS** | `release.yml` implements keyless OIDC signing with Rekor transparency log, SBOM, SHA256SUMS |
| Reproducible builds verified | **FAIL** | No verification process. See §1.3 |
| Rust toolchain pinned in `rust-toolchain.toml` | **PASS with caveat** | Pinned to 1.93.0 but version conflicts with `rust-version` in Cargo.toml. See §1.1 |

### Runtime security

| Requirement | Status | Notes |
|---|---|---|
| No secrets stored without `secrecy::SecretString` | **UNVERIFIED** | `secrecy` is listed as a dependency of `sanctum-sentinel`. Not possible to confirm from the snapshot whether all credential-handling paths actually use it — recommend a grep/audit |
| PID file and Unix socket owner-only permissions | **PASS** | Race-free PID via `O_CREAT\|O_EXCL`; socket 0o600 |
| IPC messages capped at 64KB | **PASS** | Both read and write paths enforce `MAX_MESSAGE_SIZE` before allocation |
| Daemon runs as unprivileged user | **PASS** | No root requirement; documented in THREAT_MODEL |
| SIGTERM/SIGHUP handlers clean up resources | **PASS** | Signal handling present in daemon lifecycle |
| No network connections in Phase 1 | **PASS with caveat** | Network anomaly detection module observes connections via `lsof`/`/proc/net/tcp` but does not make outbound connections itself. The distinction is correctly documented but should be made more prominent in the README since "no network connections" is a strong claim |

### Documentation

| Requirement | Status | Notes |
|---|---|---|
| SECURITY.md | **PASS** | Vulnerability reporting via GitHub private advisory; comprehensive security considerations section |
| THREAT_MODEL.md | **PASS** | Trust boundaries documented; explicit "what Sanctum does NOT protect against" section; 8 threat scenarios with mitigations and residual risks |
| ARCHITECTURE.md | **PASS** | 5+ ADRs with context/decision/rationale format |
| DEPENDENCY_AUDIT.md | **PASS** | Per-crate tables with version, purpose, audit notes |
| README.md | **PASS** | Installation, quick start, feature overview, architecture table, security summary |

---

## 3. Gaps between development plan and current state

### 3.1 Missing release engineering deliverables

The Week 6 plan called for several items that are not visible in the repository snapshot:

- **Homebrew formula / tap**: Not present. The install path is currently `cargo build --release` or the `scripts/install.sh` curl-pipe installer.
- **Starship integration**: No `sanctum` Starship prompt segment visible.
- **Blog post / documentation site**: The README references `sanctum.dev/blog/litellm` but no docs site infrastructure (e.g., `mdbook`, `zola`, Hugo) is in the repo.

**Impact**: These are distribution and adoption concerns, not security concerns. They don't block a release, but they limit the audience that can easily install and use Sanctum.

### 3.2 `criterion` benchmarks absent

The development plan specifies a performance budget (< 100ms detection latency, < 5ms IPC round-trip, < 10MB idle RSS, < 5MB binary) measured via `criterion` benchmarks and CI artifact size checks. No `criterion` dependency or benchmark files are visible.

**Impact**: Without benchmarks, there is no regression-guarded enforcement of the performance budget. This is concerning for a daemon that runs continuously.

### 3.3 aarch64-linux cross-compilation disabled

The CI matrix has a comment noting that `aarch64-unknown-linux-gnu` was removed because it requires `cross` or a linker toolchain. This target was in the original plan.

**Impact**: Linux ARM users (Raspberry Pi, Graviton instances, etc.) cannot use pre-built binaries. The macOS ARM (`aarch64-apple-darwin`) target is present, so this is a Linux-specific gap.

### 3.4 Test coverage tooling not integrated

The plan calls for "> 90% coverage on security-critical modules." The test count (565) strongly suggests this is met, but without `cargo-tarpaulin` or `llvm-cov` in CI, the percentage is not measured or enforced.

### 3.5 `secrecy` crate usage not auditable from snapshot

The dependency is declared, but the snapshot does not include the daemon's memory-handling code paths in sufficient detail to confirm that every credential-touching path wraps values in `SecretString`. This is a stated requirement.

### 3.6 Kani proof count meets but does not exceed target

The plan sets a target of "> 4" Kani proofs. The project has exactly 4. The proofs README lists 4 future proof targets (`ceiling_cost`, `validate_id`, `is_allowlisted`, `glob_matches`) that would meaningfully strengthen guarantees.

---

## 4. Hardening recommendations (beyond stated goals)

### 4.1 IPC rate limiting

The THREAT_MODEL identifies that "a rapid flood of valid-sized messages could still consume CPU; rate limiting is not implemented at the IPC layer." For a daemon with owner-only socket permissions this is low risk, but adding a simple token-bucket rate limiter (e.g., 100 messages/second) would close it completely.

### 4.2 Audit log integrity verification

The audit log is append-only NDJSON with 0o600 permissions, but a process running as the same user can tamper with it. Consider:
- An optional HMAC chain (each entry includes an HMAC of the previous entry + current content, keyed by a per-session secret), making silent deletion or modification detectable.
- Forward-sealed logging (write to a pipe read by a separate unprivileged process) for high-security deployments.

### 4.3 Glob matcher edge cases

The `glob_matches` function is intentionally minimal, but the current implementation has an edge case: patterns with multiple `*` segments beyond two-part splits fall through to exact match. Consider adding a comment or assertion documenting the supported subset, and a proptest verifying that no pattern silently passes through to exact match when it shouldn't.

### 4.4 Credential pattern coverage

The 20 credential patterns are solid, but notable gaps include: Datadog API keys (`ddapi_`), Twilio auth tokens, Azure SAS tokens, and GCP service account JSON (`"type": "service_account"`). These can be added incrementally.

### 4.5 SBOM completeness

The release workflow generates a CycloneDX SBOM, which is excellent. Consider also running `cargo-vet` or `cargo-supply-chain` to document the trust relationships with crate maintainers, not just the dependency versions.

---

## 5. Strengths worth highlighting

Several aspects of the project are uncommonly strong for an open-source security tool at this maturity level:

- **Formal verification in CI**: Kani proofs gating PR merges is rare even in production security software. The two-tier CI split (fast `kani-core` on PRs, full `kani-full` on main/nightly) is a well-designed tradeoff.

- **No-panic discipline**: The workspace-level `deny` on `unwrap_used`, `expect_used`, and `panic` is enforced rather than aspirational. The `compile_regex` abort fallback shows thoughtful navigation of the constraint.

- **Dependency ban list with C exclusion**: Banning `openssl-sys` and `libz-sys` to enforce pure-Rust eliminates the single largest class of supply-chain risk in Rust projects.

- **Overlapping credential detection priority**: The pattern registry orders Anthropic before OpenAI so that `sk-ant-` matches don't fall through to the broader `sk-` pattern. The overlapping-match test validates this.

- **Threat model with explicit residual risks**: Each mitigation in THREAT_MODEL.md is followed by a "Residual risk" paragraph acknowledging what it does *not* cover. This level of intellectual honesty is uncommon and valuable.

- **Idempotent redaction test**: Testing that `redact_credentials(redact_credentials(x)) == redact_credentials(x)` prevents the common failure mode where redaction placeholders themselves trigger pattern matches.

---

## 6. Summary scorecard

| Category | Score | Key gap |
|---|---|---|
| Code quality | 9/10 | `abort()` workaround should be documented in ARCHITECTURE.md |
| Testing | 7/10 | Fuzz duration, coverage tooling, and benchmark regression guards missing |
| Supply chain | 8/10 | Reproducible builds unverified |
| Runtime security | 8/10 | `secrecy` usage unaudited; IPC rate limiting absent |
| Documentation | 9/10 | Missing blog/docs site infrastructure |
| Formal verification | 9/10 | Meets target exactly; identified future proof targets not yet implemented |
| Release engineering | 6/10 | No Homebrew, no benchmarks, no Linux ARM, no Starship |

**Overall**: The security-critical core is ready. The release engineering and distribution layer needs the most work before a public launch.
