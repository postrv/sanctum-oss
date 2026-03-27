# Sanctum Remediation Plan

**Date**: 27 March 2026
**Basis**: Assessment validated by 6 parallel Opus subagents with Narsil code intelligence. Every claim checked against source with exact file paths and line numbers.

---

## Assessment Accuracy Report

Before remediation, the assessment itself needs correction. Of 35 distinct claims validated:

| Verdict | Count | Detail |
|---|---|---|
| **Validated** | 28 | Confirmed with exact source locations |
| **Partially validated** | 5 | Core observation correct, characterisation imprecise |
| **Invalidated** | 2 | Factually wrong |

### Invalidated claims (must be corrected in assessment)

1. **"secrecy is listed as a dependency of sanctum-sentinel"** — `secrecy` does not appear in any `Cargo.toml`, `Cargo.lock`, or `.rs` file in the workspace. It exists only in `sanctum-development-plan.md:146` as an aspirational dependency that was never added. The assessment states "the dependency is declared" — this is false.

2. **Blocking issue 1.1 characterised as "blocking"** — The MSRV (1.85.0) / build toolchain (1.93.0) split is standard Rust practice. The actual gap is a missing MSRV CI job, which is a minor enhancement, not a blocker.

### Partially validated claims (need refinement)

1. **Blocking issue 1.2**: Fuzz gap is real (30s vs 5hr target), but `release.yml` does NOT gate on fuzz — the release workflow runs its own `build-release` job with no fuzz dependency. So fuzz is a CI gate but not a release gate.

2. **Gap 3.5**: The concern about credential memory handling is valid, but the stated basis ("the dependency is declared") is wrong. The dependency was never added.

3. **Hardening 4.4**: Twilio is partially covered — `TWILIO_AUTH_TOKEN` exists in `sanctum-cli/src/commands/scan.rs:68` as a `SECRET_ENV_VARS` entry, but not as a regex pattern in the firewall.

### New issues found during validation

1. **`kani-full` schedule trigger is dead code** — `ci.yml` has no `schedule:` in its `on:` block (lines 3-6), but `kani-full` checks `github.event_name == 'schedule'` (line 78). The nightly full-bounds Kani run never executes.

2. **`release.yml` has no fuzz/kani gate** — The tag-triggered release workflow (lines 1-163) runs tests and clippy but has no dependency on fuzz or Kani results.

3. **`sanctum-proxy` missing from `DEPENDENCY_AUDIT.md`** — The newest crate has no dependency audit entry.

---

## Remediation Tiers

### Tier 0: Corrections to the assessment itself (no code changes)

The `sanctum-project-assessment.md` file should be annotated with corrections:

| Section | Correction |
|---|---|
| §1.1 | Downgrade from "blocking" to "minor hygiene". Add note about missing MSRV CI job. |
| §2 Runtime Security row | Change "secrecy is listed as a dependency" to "secrecy is NOT present; credential memory handling uses plain strings" |
| §3.5 | Rewrite: "`secrecy` was planned but never added. No `SecretString` usage exists anywhere in the codebase. Decision needed: add it or document why it's unnecessary." |
| §1.2 | Add note: "release.yml does not gate on fuzz results" |

---

### Tier 1: CI/infrastructure fixes (no runtime code changes, low risk)

#### 1A. Add `schedule:` trigger to `ci.yml`

**Why**: `kani-full` (line 78) checks `github.event_name == 'schedule'` but no schedule exists. The nightly full-bounds Kani run is dead code.

**File**: `.github/workflows/ci.yml`, lines 3-6

**Change**:
```yaml
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 3 * * *'  # 03:00 UTC daily
```

**Verification**: After push, check GitHub Actions "Scheduled" trigger appears for kani-full.

#### 1B. Add nightly extended fuzz job

**Why**: 30s fuzz runs (lines 92-93) are 600x below the 5-hour target in the dev plan (`sanctum-development-plan.md:1605`).

**File**: `.github/workflows/ci.yml`, add after `kani-full` job (after line 84)

**Change**: Add new job:
```yaml
  fuzz-extended:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - run: cargo fuzz run fuzz_pth_analyser -- -max_total_time=9000
      - run: cargo fuzz run fuzz_config_parser -- -max_total_time=9000
```

This gives 2.5 hours per target (5 hours total), running nightly via the schedule trigger from 1A.

#### 1C. Add MSRV verification job

**Why**: `rust-version = "1.85.0"` (Cargo.toml:17) is never verified. A contributor could introduce 1.86+ features and CI would not catch it.

**File**: `.github/workflows/ci.yml`, add after `lint` job

**Change**:
```yaml
  msrv:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.85.0
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --all --all-features
```

Add `msrv` to the `build-release` needs array (line 96).

#### 1D. Add reproducible build verification to CI

**Why**: Security checklist item (`sanctum-development-plan.md:1615`) is unchecked. Profile settings (`Cargo.toml:58-63`: `codegen-units=1`, `lto="fat"`, `strip=true`) make determinism likely but it's never verified.

**File**: `.github/workflows/ci.yml`, add new job

**Change**:
```yaml
  reproducible-build:
    if: github.ref == 'refs/heads/main' || github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93.0
      - run: cargo build --release --target x86_64-unknown-linux-gnu
      - run: sha256sum target/x86_64-unknown-linux-gnu/release/sanctum target/x86_64-unknown-linux-gnu/release/sanctum-daemon > /tmp/build1.sha256
      - run: cargo clean
      - run: cargo build --release --target x86_64-unknown-linux-gnu
      - run: sha256sum target/x86_64-unknown-linux-gnu/release/sanctum target/x86_64-unknown-linux-gnu/release/sanctum-daemon > /tmp/build2.sha256
      - run: diff /tmp/build1.sha256 /tmp/build2.sha256
```

#### 1E. Gate release workflow on CI status

**Why**: `release.yml` runs its own build-release (lines 17-42) with no dependency on CI fuzz or Kani results. A tagged release can ship without fuzz or Kani passing.

**File**: `.github/workflows/release.yml`

**Option A** (recommended): Add a `pre-check` job that verifies the CI workflow succeeded for the tagged commit:
```yaml
  pre-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify CI passed for this commit
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          COMMIT_SHA="${GITHUB_SHA}"
          # Check that the CI workflow completed successfully
          gh api repos/${{ github.repository }}/commits/${COMMIT_SHA}/check-runs \
            --jq '.check_runs[] | select(.name == "fuzz" or .name == "kani-core") | .conclusion' \
            | grep -v success && echo "FAIL: CI checks not passed" && exit 1 || true
```

Add `pre-check` to `build-release` needs.

**Option B** (simpler): Add fuzz and kani steps directly to release build-release. Increases release time but guarantees verification.

#### 1F. Add sanctum-proxy to DEPENDENCY_AUDIT.md

**Why**: New crate added in Phase 5E but not documented.

**File**: `docs/DEPENDENCY_AUDIT.md`, add after Budget section (after line 86)

**Change**: Add:
```markdown
## Proxy foundation: sanctum-proxy

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `tokio` | 1.x | Async runtime | RustSec clean. Industry standard. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost. |
```

---

### Tier 2: Security-critical code fixes (runtime changes, medium risk)

#### 2A. Fix `glob_matches` multi-star fallthrough

**Why**: Patterns with >1 `*` that don't match `**/suffix` or `prefix/**` silently fall through to exact match (`policy.rs:150`). A pattern like `/foo/*/bar/*.txt` would never match anything via glob — it would only match the literal string `/foo/*/bar/*.txt`.

**File**: `crates/sanctum-firewall/src/mcp/policy.rs`, lines 118-151

**Change**: Add a warning log and explicit handling for unsupported patterns:
```rust
fn glob_matches(pattern: &str, path: &str) -> bool {
    // Handle prefix glob: "/foo/bar/**"
    if let Some(prefix) = pattern.strip_suffix("/**") {
        return path.starts_with(prefix) || path == prefix;
    }

    // Handle extension glob: "**/*.pth"
    if let Some(suffix) = pattern.strip_prefix("**/") {
        if suffix.contains('*') {
            let star_parts: Vec<&str> = suffix.split('*').collect();
            if star_parts.len() == 2 {
                let after_star = star_parts.get(1).copied().unwrap_or("");
                return path.ends_with(after_star);
            }
        }
        return path.ends_with(suffix) || path.contains(&format!("/{suffix}"));
    }

    // Handle single-star within a pattern: "/foo/*/bar"
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts.first().copied().unwrap_or("");
            let suffix = parts.get(1).copied().unwrap_or("");
            return path.starts_with(prefix) && path.ends_with(suffix);
        }
        // Multiple wildcards beyond supported patterns — log and reject.
        // This prevents silent fallthrough to exact match for patterns like
        // "/foo/*/bar/*.txt" which users would expect to glob-match.
        tracing::warn!(
            pattern = pattern,
            path = path,
            "glob pattern with multiple wildcards is not supported; treating as non-match"
        );
        return false;
    }

    // Exact match fallback (only for patterns without wildcards).
    pattern == path
}
```

**Tests to add** (same file, `mod tests`):
```rust
#[test]
fn multi_star_pattern_does_not_silently_match() {
    assert!(!glob_matches("/foo/*/bar/*.txt", "/foo/x/bar/baz.txt"));
    assert!(!glob_matches("/a/*/b/*", "/a/x/b/y"));
}
```

#### 2B. Add missing credential patterns

**Why**: Assessment correctly identifies missing patterns for high-value credential types. Confirmed absent from `crates/sanctum-firewall/src/patterns.rs` (lines 44-72, 20 patterns).

**File**: `crates/sanctum-firewall/src/patterns.rs`

**Patterns to add** (insert before the generic entropy fallback, maintaining specificity ordering):

| Pattern | Regex | Position |
|---|---|---|
| Datadog API Key | `\bdd[a-z]{2}_[a-z0-9]{32,}\b` | After existing specific keys |
| Azure SAS Token | `\bsig=[A-Za-z0-9%+/=]{20,}\b` | After Datadog |
| Twilio Auth Token | `\b[0-9a-f]{32}\b` (only in context of `TWILIO`) | Consider env-var-only detection |

**Note**: Twilio auth tokens are bare 32-char hex strings — adding a standalone regex would cause massive false positives. Better to add `TWILIO_AUTH_TOKEN` to the env var detection in the hook handlers (already partially present in `scan.rs:68`). Datadog and Azure SAS are safe to add as regex patterns.

**GCP service account JSON**: The file pattern `service-account.json` is already detected in `scan.rs:21` and `init.rs:237`. Adding JSON content detection (`"type": "service_account"`) would require multi-line matching, which is a larger change. Defer to a dedicated PR.

#### 2C. Decision: secrecy crate

**Why**: The dev plan (`sanctum-development-plan.md:146,1620`) requires wrapping credentials in `SecretString`. The crate was never added. No credential-handling path in the codebase uses memory-safe secret types.

**Options**:

| Option | Effort | Benefit |
|---|---|---|
| A: Add `secrecy` and wrap credential paths | Medium (touch redaction.rs, patterns.rs, hooks) | Prevents credentials from lingering in memory after redaction |
| B: Document as "not applicable" | Low | The firewall processes strings transiently; no long-lived credential storage |
| C: Defer to proxy phase | Low | The proxy will handle raw API keys; that's where secrecy matters most |

**Recommendation**: Option C. The current firewall receives strings from Claude Code hooks, redacts them, and returns. There's no persistent credential storage. When `sanctum-proxy` does TLS MITM (Phase 5E sub-phase 2+), it will handle API keys in transit — that's where `secrecy::SecretString` + zeroize-on-drop matters. Document this decision in ARCHITECTURE.md.

---

### Tier 3: Enhancements (lower priority, independently shippable)

#### 3A. Add coverage tooling to CI

**File**: `.github/workflows/ci.yml`

**Change**: Add `coverage` job using `cargo-llvm-cov`:
```yaml
  coverage:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.93.0
        with:
          components: llvm-tools-preview
      - uses: taiki-e/install-action@cargo-llvm-cov
      - run: cargo llvm-cov --workspace --all-features --lcov --output-path lcov.info
      - uses: codecov/codecov-action@v4
        with:
          files: lcov.info
```

Not a gate — informational only. Validates the "likely >90%" claim.

#### 3B. Add criterion benchmarks for performance budget

**Why**: Dev plan specifies <100ms detection latency, <5ms IPC, <10MB RSS, <5MB binary. No benchmarks exist.

**Files**: New `benches/` directory with:
- `benches/pth_analysis.rs` — benchmark `analyse_pth_line` and `analyse_pth_file`
- `benches/credential_redaction.rs` — benchmark `redact_credentials` with various input sizes
- `benches/ipc_roundtrip.rs` — benchmark IPC serialize/deserialize cycle

**Dependency**: Add `criterion` to workspace dev-dependencies.

#### 3C. Add aarch64-linux cross-compilation

**File**: `.github/workflows/ci.yml`, lines 98-107 and `.github/workflows/release.yml`, lines 19-26

**Change**: Uncomment/add the `aarch64-unknown-linux-gnu` target with `cross`:
```yaml
- target: aarch64-unknown-linux-gnu
  os: ubuntu-latest
  use_cross: true
```

Add a step that conditionally uses `cross` instead of `cargo`:
```yaml
- run: |
    if [ "${{ matrix.use_cross }}" = "true" ]; then
      cargo install cross
      cross build --release --target ${{ matrix.target }}
    else
      cargo build --release --target ${{ matrix.target }}
    fi
```

#### 3D. Add IPC rate limiting

**Why**: THREAT_MODEL.md line 74 identifies this as a residual risk.

**File**: `crates/sanctum-daemon/src/ipc.rs`

**Change**: Add a simple token-bucket rate limiter per connection:
```rust
struct RateLimiter {
    tokens: u32,
    max_tokens: u32,
    refill_rate: u32, // tokens per second
    last_refill: std::time::Instant,
}
```

Reject with an IPC error response when tokens exhausted. Default: 100 messages/second.

#### 3E. Additional Kani proofs (bringing count from 4 to 8)

**Targets** (from `proofs/README.md:56-63`):

| Proof | File | Property |
|---|---|---|
| `ceiling_cost_no_overflow` | `sanctum-budget/src/pricing.rs:67` | Zero tokens = zero cost; no overflow for any u64 input |
| `validate_id_rejects_traversal` | `sanctum-sentinel/src/pth/quarantine.rs:105` | Rejects `/`, `\`, `..`, empty; accepted IDs stay within quarantine_dir |
| `glob_matches_exact_works` | `sanctum-firewall/src/mcp/policy.rs:118` | Exact match works; `/**` matches children; unsupported patterns return false |
| `entropy_never_panics` | `sanctum-firewall/src/entropy.rs` | Shannon entropy calculation never panics for any input |

---

### Tier 4: Documentation updates

#### 4A. Update ARCHITECTURE.md

Add ADR documenting:
- The `compile_regex` -> `abort()` decision (why abort instead of panic, why it's unreachable)
- The `secrecy` deferral decision (Option C from §2C)
- The glob_matches supported subset and why it's intentionally minimal

#### 4B. Update assessment document

Annotate `sanctum-project-assessment.md` with corrections per the Accuracy Report above.

#### 4C. Document the `kani-full` schedule in README or SECURITY.md

Mention that full Kani proofs run nightly (once the schedule trigger from 1A is added).

---

## Implementation Order

```
Tier 1 (CI/infrastructure) — can be done in a single PR, zero runtime risk:
  1A → 1B (schedule enables extended fuzz)
  1C, 1D, 1E, 1F (independent of each other)

Tier 2 (security code) — separate PRs for review:
  2A (glob_matches fix — small, targeted)
  2B (credential patterns — additive)
  2C (secrecy decision — document only for now)

Tier 3 (enhancements) — independent PRs:
  3A, 3B, 3C, 3D, 3E (all independent)

Tier 4 (docs) — can accompany any tier:
  4A, 4B, 4C (no code changes)
```

## Verification

After all Tier 1+2 changes:
```bash
cargo test --workspace                    # 565+ tests pass
cargo clippy --workspace --all-targets    # 0 warnings
cargo build --workspace                   # Clean build
cargo deny check                          # No violations
```

After Tier 1A lands, verify on GitHub:
- Actions tab shows scheduled runs
- `kani-full` executes on schedule
- `fuzz-extended` executes on schedule

---

## Summary Scorecard (current → after remediation)

| Category | Current | After Tier 1+2 | Key change |
|---|---|---|---|
| Code quality | 9/10 | 9/10 | glob_matches fix, abort() documented |
| Testing | 7/10 | 9/10 | Nightly 5hr fuzz, MSRV job, repro builds, coverage |
| Supply chain | 8/10 | 9/10 | Reproducible builds verified, proxy audit added |
| Runtime security | 8/10 | 8/10 | secrecy deferred (justified), IPC rate limiting in Tier 3 |
| Documentation | 9/10 | 10/10 | Assessment corrections, ADRs added |
| Formal verification | 9/10 | 9/10 | 4 proofs (8 after Tier 3E) |
| Release engineering | 6/10 | 7/10 | Release gates fuzz/kani, aarch64-linux in Tier 3 |
