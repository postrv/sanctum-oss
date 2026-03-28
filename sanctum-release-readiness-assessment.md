# Sanctum v0.1.0 Release Readiness Assessment

**Assessor:** Claude (Opus 4.6), Anthropic  
**Date:** 28 March 2026  
**Scope:** Code completeness, feature completeness, end-to-end UX, ease of use, security posture, integration correctness, and re-scoping of deferred items  
**Inputs reviewed:** Full codebase (sanctum.txt), development plan, competitive analysis (sanctum-final-v3.md), supply chain research paper, CI/CD workflows, release workflow, changelog, all ADRs, and current Claude Code hooks API documentation

---

## Executive Summary

Sanctum's security-critical core is exceptionally well-engineered. The codebase demonstrates discipline rarely seen in pre-v1 projects: zero `unsafe`, no-panic enforcement, 827 tests, 8 Kani proofs, property-based testing, fuzz targets, Sigstore signing, reproducible build verification, and a comprehensive `cargo-deny` configuration. The architecture is sound, the threat model is well-researched, and the competitive positioning is defensible.

However, this assessment has uncovered **one critical integration defect** that would cause Sanctum's flagship AI Firewall feature to silently fail in production, along with several significant gaps in release readiness. Shipping without addressing at least the critical and high-severity items below would undermine the project's credibility with the exact audience — security-conscious developers — who will scrutinise it most carefully.

**Overall verdict: NOT READY for public release. Estimated work to release-ready: 5–8 focused days after addressing the items below.**

---

## CRITICAL — Claude Code Hooks JSON Format Is Wrong

**Severity: CRITICAL — the AI Firewall will not function.**

This is the single most important finding in this assessment. The `build_hooks_json()` function in `crates/sanctum-cli/src/commands/hooks.rs` generates hooks in a **deprecated flat format** that does not match the current Claude Code hooks API:

**What Sanctum generates (WRONG):**
```json
{
  "PreToolUse": [
    {
      "matcher": "Bash",
      "command": "sanctum hook pre-bash"
    }
  ]
}
```

**What Claude Code currently expects (CORRECT):**
```json
{
  "PreToolUse": [
    {
      "matcher": "Bash",
      "hooks": [
        {
          "type": "command",
          "command": "sanctum hook pre-bash"
        }
      ]
    }
  ]
}
```

The current API uses a three-level nesting structure: **hook event → matcher group → hook handler array**. Each handler requires a `type` field (one of `"command"`, `"prompt"`, `"agent"`, or `"http"`). The flat format Sanctum generates will cause Claude Code to either silently ignore the hooks or fail to parse them. Either way, the security gates don't fire. A security tool that silently doesn't work is worse than no tool at all — it creates a false sense of protection.

**Additionally, the PreToolUse decision protocol has changed.** Sanctum currently uses `exit 2` for blocks and writes the reason to stderr, which still works. However, the official API now supports richer JSON output via `hookSpecificOutput` with `permissionDecision: "deny"` and `permissionDecisionReason`. While `exit 2` + stderr is still functional, the newer format provides better integration (Claude receives structured reasons and can explain blocks to users more clearly). This is a worthwhile upgrade but not blocking.

**What must change before release:**

1. Fix `build_hooks_json()` to use the nested `hooks: [{ type: "command", command: "..." }]` format
2. Update all tests that validate the hooks JSON structure
3. Update the `sanctum doctor` check to validate the installed hooks format
4. Add a migration path: if `sanctum hooks install claude` detects old-format hooks, upgrade them automatically
5. Consider (non-blocking): output structured JSON via stdout for PreToolUse decisions instead of relying solely on exit codes and stderr

**New hook events to consider for v0.1.0 or shortly after:**

The Claude Code API now exposes 12+ lifecycle events beyond PreToolUse/PostToolUse, including `PermissionRequest` (fires when a permission dialog appears — Sanctum could auto-deny sensitive operations), `SessionStart` (inject security context), and `SubagentStop` (ensure subagents are also covered). These represent opportunities to deepen the integration, though they're not blocking for v0.1.0.

---

## Section 1: Code Completeness

### 1.1 What's implemented and solid

The core security engine is production-quality across all three pillars:

**Sentinel** is the most mature module. The `.pth` analyser covers benign, suspicious, and critical classifications with evasion resistance (Unicode homoglyphs, null bytes, mixed case, megabyte lines). Process lineage tracing walks `/proc` on Linux with depth-limited traversal and mock support for testing. The quarantine protocol uses atomic metadata writes (write-temp-then-rename), symlink detection, and path traversal validation. Credential file monitoring covers SSH, AWS, GCP, K8s, Docker, npm, PyPI paths. Network anomaly detection provides platform-specific connection collection (macOS `lsof`, Linux `/proc/net/tcp`) with baseline learning and configurable allow/blocklists.

**AI Firewall** has comprehensive credential pattern coverage (28 patterns), Shannon entropy analysis for unknown secret formats, and MCP policy enforcement with glob-based path restrictions. The hook handlers cover pre-bash (blocks credential reads via `cat`, `less`, `head`, `tail`, `scp`, `rsync`, `tar`, `zip`, `7z`, `diff`, `bat`, and more), pre-write (credential content scanning), pre-read (sensitive path blocking), pre-mcp (policy evaluation with audit logging), and post-bash (`.pth` creation warnings, crontab/systemd persistence detection, network listener detection, budget usage extraction).

**Budget Controller** provides per-provider, per-session, and per-day spend limits with three API response parsers (OpenAI, Anthropic, Google). The `sanctum-proxy` crate has provider identification and config schema, though the actual TLS MITM proxy is correctly deferred.

**Infrastructure** is thorough: 827 tests, 8 Kani proofs, 2 fuzz targets, 9 proptest harnesses, IPC rate limiting (100 msg/s token bucket), fail-closed config loading, project-local config hardening (security-critical settings can't be weakened by per-repo config), async event loop safety (blocking I/O offloaded to `spawn_blocking`), and comprehensive IPC command coverage (15+ commands including the `sanctum fix` remediation workflow).

### 1.2 Code gaps

**Missing `criterion` benchmarks.** The development plan specifies benchmarks for IPC round-trip (<5ms) and watcher detection latency (<100ms). No `criterion` benchmark code exists in the codebase. The performance budget table in the plan is comprehensive (6 metrics with targets), but without benchmarks you can't prove you meet the targets or detect regressions. This should be added before v0.1.0 since "< 100ms detection latency" is a headline claim.

**No coverage tooling in CI.** The plan requires >90% coverage on security-critical modules. Without measurement, this is an unverifiable assertion. Adding `cargo-llvm-cov` or `tarpaulin` to CI with an enforced threshold would make this claim credible.

**Linux ARM cross-compilation removed.** The CI matrix comment says "aarch64-unknown-linux-gnu removed: cross-compilation requires `cross` or a linker toolchain." This is documented honestly, but it means Linux ARM users (Raspberry Pi, Graviton instances, ARM cloud VMs) have no binary. For v0.1.0 this is acceptable if documented, but it should be on the short-term roadmap.

---

## Section 2: Feature Completeness

### 2.1 Plan vs. implementation delta

Mapping the development plan's Phase 1–3 deliverables against the codebase:

**Fully implemented:** `sanctum init` (with shell hook generation for bash/zsh/fish), `sanctum status`, `sanctum review` (with `--approve`/`--delete`/`--json`), `sanctum scan`, `sanctum run` (with `--sandbox` nono integration), `sanctum config` (with `--edit`/`--recommended`), `sanctum budget` (set/extend/reset), `sanctum audit` (with `--last`/`--level`/`--json`), `sanctum fix` (list/resolve/all), `sanctum hook` (pre-bash/pre-write/pre-read/pre-mcp/post-bash), `sanctum hooks install/remove claude`, `sanctum daemon start/stop/restart`, `sanctum doctor`.

**Not implemented — plan specifies but code absent:**

1. **Starship prompt segment.** The plan lists "Starship integration" as a Week 6 deliverable and shows a shield icon (`🛡️`) in the prompt. The shell hooks export `SANCTUM_ACTIVE=1`, which Starship could read via a custom module, but no Starship configuration file, module definition, or documentation exists. This is a UX gap — the "zero-command daily workflow" promise relies on the prompt indicator for ambient awareness.

2. **Homebrew formula.** Listed as a primary distribution channel and a Week 6 deliverable. No formula file exists. The install script (`scripts/install.sh`) exists and handles signature verification, but `brew install sanctum` doesn't work. For developer adoption, this is significant — Homebrew is the expected installation method for macOS developers.

3. **Documentation site.** The plan lists "docs site" as a Week 6 deliverable. Individual doc files exist (README, GETTING_STARTED, ARCHITECTURE, THREAT_MODEL, SECURITY, DEPENDENCY_AUDIT), but there's no static site generator config, no hosted docs, no `sanctum.dev` content.

4. **Blog post / launch content.** Week 6 deliverable: "blog post draft, HN submission, changelog." The changelog exists (`CHANGELOG.md`), but no launch blog post or HN submission draft.

### 2.2 Features that exceed the plan

The codebase includes several features that weren't in the original development plan, indicating scope has grown productively:

- `sanctum fix` guided remediation (content-addressed threat IDs, resolution log, batch processing)
- Network anomaly detection module
- `sanctum doctor` health checks
- `sanctum daemon start/stop/restart` explicit management commands
- Project-local config hardening (security-critical settings pinned to global config)
- IPC rate limiting
- Config version field for future migrations
- Fail-closed config loading in hook handler
- Budget usage extraction from post-bash output

---

## Section 3: End-to-End UX

### 3.1 The happy path

The intended UX flow is well-designed:

```
brew install sanctum          → (doesn't work yet)
sanctum init                  → shell hook, auto-detect environment
(new terminal)                → daemon auto-starts via shell hook
sanctum hooks install claude  → (hooks format is wrong — see critical finding)
sanctum scan                  → credential exposure report
sanctum status                → daemon health
```

The shell hook generation is clean and handles bash, zsh, and fish correctly. The daemon auto-start logic (`sanctum daemon start >/dev/null 2>&1 &`) is correct. The `SANCTUM_ACTIVE` environment variable prevents double-start.

### 3.2 UX issues

**The `sanctum init` output doesn't match the plan.** The design doc shows a rich detection summary (nono version, Python version, `.env` file warnings, Claude Code detection with next-steps). The actual `init` command generates shell hooks and config, but doesn't perform environment detection or show the planned onboarding output. This is a significant gap — the onboarding experience is the user's first impression.

**The `sanctum hooks install claude` writes to `~/.claude/settings.json`.** This is a global setting. If a user has project-level hooks in `.claude/settings.json` (within their repo), Sanctum's hooks won't be visible at project scope. The install command should either detect both locations and advise, or offer `--scope project|user` options.

**No `sanctum hooks status claude` command** to verify hooks are installed and working. The `doctor` command checks this, but a dedicated hooks-status subcommand would be more discoverable.

**Two separate binary names.** The project builds both `sanctum` (CLI) and `sanctum-daemon` (daemon). This means `sanctum daemon start` spawns `sanctum-daemon` as a separate binary. Users need both in PATH. The install script handles this, but building from source and `cargo install` may confuse users who only get one binary. Documentation should be very explicit about this.

---

## Section 4: Security Posture

### 4.1 Strengths (exceptional)

The security posture is the project's strongest dimension:

- **Zero `unsafe` code** enforced by workspace lint — not just a claim, but a compiler-enforced invariant
- **No-panic discipline** via `clippy::unwrap_used`, `clippy::expect_used`, `clippy::panic` all denied at workspace level
- **`compile_regex` uses `abort()` not `panic!()`** with sound justification (ADR-013)
- **Fail-closed security model:** hook config parse errors apply all protections (ADR documented)
- **Project-local config hardening:** malicious repos can't weaken `claude_hooks`, `redact_credentials`, `watch_pth`, or `pth_response` via `.sanctum/config.toml`
- **Race-free PID file** via `O_CREAT|O_EXCL`
- **IPC hardening:** 64KB message cap, 0o600 socket permissions, 100 msg/s rate limiting, max 32 concurrent connections
- **Quarantine integrity:** atomic metadata writes, symlink detection, path traversal validation, sensitive directory protection on restore
- **AppleScript injection prevention** in macOS notifications
- **Budget state files** with 0o600 permissions
- **Formal verification:** 8 Kani proofs (analyser panic-freedom, path classification, exec detection, quarantine state machine, ceiling cost no overflow, validate ID rejects traversal, Shannon entropy never panics, glob matches exact match works)
- **`cargo-deny`** bans C dependencies, undeclared licenses, and known vulnerable crates
- **Dependency audit** with justification for every direct dependency
- **Sigstore keyless signing** with Rekor transparency log
- **Signed CycloneDX SBOM**
- **Reproducible build verification** in CI (build twice, compare SHA-256)
- **Build hardening:** PIE, overflow checks, abort-on-panic (release only), fat LTO

### 4.2 Security items to address

**ADR-014: `secrecy` crate deferred is sound but needs documentation.** The ADR correctly argues that transient hook invocations don't benefit from `SecretString` zeroize-on-drop. However, the development plan's security checklist item "No secrets ever stored in daemon memory without `secrecy::SecretString`" is listed as a pre-release gate. Either satisfy it or formally waive it with a note in the checklist explaining why the ADR-014 rationale applies. Don't ship with an unchecked item on your own security checklist — it looks like you forgot.

**Fuzz duration discrepancy.** The CI workflow has both a standard fuzz job (300 seconds = 5 minutes per target) and a nightly `fuzz-extended` job (9000 seconds = 2.5 hours per target). The plan requires "5+ hours with zero crashes on each target." The nightly job provides 2.5 hours per target, not 5. Either the plan's 5-hour target should be revised to match the 2.5-hour nightly run, or the nightly fuzz duration should be increased to 18000 seconds (5 hours) per target.

**The glob matcher is intentionally minimal (ADR-015) but needs edge case documentation.** The `glob_matches` function supports `**/*.ext`, `**/filename`, and `prefix/**/suffix` patterns. Multi-star patterns beyond supported forms return `false` with a warning. This is the safe direction (over-blocking), but the THREAT_MODEL or configuration documentation should explicitly list which glob patterns are supported, since users writing MCP policy rules need to know the effective expressiveness.

---

## Section 5: Integration Correctness Deep Dive

### 5.1 Claude Code Hooks (CRITICAL — see above)

Beyond the JSON format issue already detailed:

**The hook handler reads from stdin correctly.** The `hook.rs` command reads `HookInput` from stdin via `serde_json::from_reader(std::io::stdin())`, which matches how Claude Code passes tool input to command hooks. This is correct.

**Exit code semantics are correct.** Exit 0 = allow, exit 2 = block. This matches the current Claude Code API.

**The stderr output on block is correct.** Claude Code reads stderr from blocked hooks and incorporates the message into its reasoning. Sanctum's `eprintln!("sanctum: {msg}")` format is appropriate.

**The `pre-mcp` matcher value needs verification.** Sanctum uses `"mcp"` as the matcher for MCP tool hooks. The Claude Code API documentation indicates MCP tools can be matched with patterns like `mcp__servername__toolname` or regex patterns. A plain `"mcp"` matcher may not match MCP tool invocations — it might need to be a regex like `mcp__.*` or `mcp` depending on how Claude Code evaluates matchers against MCP tool names. This needs testing against a live Claude Code installation.

**Missing `MultiEdit` matcher.** Sanctum hooks `Write|Edit` for pre-write checks, but Claude Code also has a `MultiEdit` tool (for multi-location edits within a file). The matcher should be `Write|Edit|MultiEdit` to avoid a bypass where Claude uses MultiEdit to write credential content without triggering the pre-write hook.

### 5.2 nono Integration

The `sanctum run --sandbox` integration is straightforward: check if `nono` is in PATH via `which nono`, and if so, prepend the command with `nono -- <command>`. This is minimal but functional.

**Gap:** The `sanctum run --sandbox` doesn't pass nono profile options. The design doc shows `nono run --profile claude-code --allow-cwd -- claude`, but the implementation just does `nono -- <args>`. Users who want profile-specific sandboxing would need to invoke nono directly. Consider adding `--nono-profile` or using environment variables.

**Gap:** The `sanctum init` output doesn't detect whether nono is installed, despite the design doc showing `✓ nono v0.2.1 installed — will integrate for sandbox + phantom proxy`. This detection should be part of the `init` onboarding experience.

### 5.3 Budget Proxy Integration

The `sanctum-proxy` crate exists with provider identification, config schema, and error types, but the actual TLS MITM proxy is correctly deferred. The ADR-014 rationale for deferring `secrecy` to this phase is sound. The config schema (listen port, enforce budget, enforce allowed models, CA validity, max response body size) is well-designed.

**Note:** Until the proxy ships, budget tracking only works through the post-bash hook's output parsing (extracting usage from Claude Code's stdout/stderr). This is fragile — it depends on the LLM provider's response format appearing in the tool output. For v0.1.0, this limitation should be documented clearly.

### 5.4 Shell Hook Integration

Shell hooks for bash, zsh, and fish are well-implemented. The zsh hook uses `&!` for backgrounding (zsh-specific, avoids "job terminated" messages). The bash hook uses `& disown`. The fish hook uses `& disown`. All three check `SANCTUM_ACTIVE` to prevent double-start.

**Minor issue:** The zsh hook has a `# Starship integration` comment followed by `export SANCTUM_ACTIVE=1`, but there's no actual Starship integration code. This comment is misleading.

---

## Section 6: Deferred Items Re-scoping

The following items were tracked as post-v0.1.0. Here's the recommended re-classification based on the goal of shipping "the best, most stable/reliable/secure, most effective mitigation":

### Pull INTO v0.1.0

1. **Fix Claude Code hooks JSON format** — CRITICAL. Without this, the AI Firewall doesn't function. (Est: 1 day)

2. **Add `MultiEdit` to write-hook matchers** — HIGH. Without it, there's a trivial bypass for credential-content checks. (Est: 1 hour)

3. **Verify `mcp` matcher against live Claude Code** — HIGH. The MCP policy engine is a core differentiator; if the matcher doesn't fire, the MCP audit and policy features are dead code. (Est: 2 hours)

4. **Homebrew formula** — HIGH for adoption. The target audience expects `brew install`. (Est: 1 day)

5. **`criterion` benchmarks for headline performance claims** — MEDIUM-HIGH. If you claim "<100ms detection latency" you must be able to prove it. Ship at least the IPC round-trip and detection latency benchmarks. (Est: 1 day)

6. **Enrich `sanctum init` onboarding output** — MEDIUM-HIGH. First impression matters enormously. Detect Python version, nono presence, Claude Code installation, existing `.env` files, and show the designed onboarding summary. (Est: 1 day)

7. **Starship prompt segment** — MEDIUM. The "ambient awareness" UX depends on this. A simple custom Starship module definition in the docs is minimal effort. (Est: 2 hours)

8. **Formally close the security checklist** — MEDIUM. Walk through every item in §8 of the plan and mark it ✓ or document why it's waived. Don't ship with unchecked security gates. (Est: 2 hours)

### Keep DEFERRED (correct scoping)

1. **`secrecy` crate integration** — Correctly deferred to proxy phase per ADR-014. The transient hook invocation model means credentials don't persist in memory.

2. **Linux ARM cross-compilation** — Nice to have, but x86_64-linux + both macOS arches cover the primary audience. Document the gap.

3. **Coverage tooling in CI** — Useful for ongoing development, not required for a launch where you already have 827 tests and can visually verify coverage of security-critical paths.

4. **Documentation site** — The markdown docs in the repo are comprehensive. A hosted site is a polish item, not a gate.

5. **VS Code / Cursor extension** — Phase 4 feature, correctly deferred.

6. **SBOM trust relationship tooling** — Future hardening, not v0.1.0 scope.

7. **Audit log integrity chaining** — Valuable for tamper detection, but the current 0o600-permission append-only NDJSON log is adequate for v0.1.0.

8. **HTTP hooks type support** — Claude Code now supports `type: "http"` hooks that POST to a URL. Sanctum could run a local HTTP endpoint for faster hook evaluation without fork/exec overhead per invocation. This is a performance optimisation for a future release.

### New items identified by this assessment (consider for v0.1.0 or v0.1.1)

1. **Hook format auto-migration** — When `sanctum hooks install claude` detects old-format hooks in settings.json, upgrade them. (Est: 2 hours)

2. **`sanctum hooks status claude`** — Quick check showing whether hooks are installed, which format they're in, and whether they're firing. More discoverable than `sanctum doctor`. (Est: 2 hours)

3. **`--scope project|user` for hooks install** — Let users choose between `~/.claude/settings.json` (global) and `.claude/settings.json` (project). Default to user-level. (Est: 1 hour)

4. **`PermissionRequest` hook event** — Claude Code fires this when a permission dialog appears. Sanctum could auto-deny access to sensitive paths at the permission level, not just at the tool-use level. This is a strictly stronger guarantee. (Est: 4 hours)

5. **Cursor hooks support** — Cursor has had hooks since v1.7 (October 2025) with `beforeShellExecution`, `beforeMCPExecution`, `beforeReadFile`, `afterFileEdit`. Adding `sanctum hooks install cursor` would significantly expand the addressable audience. (Est: 1–2 days)

---

## Section 7: Release Engineering Checklist

Items that must be completed for a credible v0.1.0 release:

| Item | Status | Blocking? |
|---|---|---|
| Fix Claude Code hooks JSON format | ❌ NOT DONE | YES |
| Add `MultiEdit` to write matchers | ❌ NOT DONE | YES |
| Verify MCP matcher against live Claude Code | ❌ NOT DONE | YES |
| `cargo clippy --all-targets` clean | ✅ DONE | — |
| `cargo fmt --check` clean | ✅ DONE | — |
| `cargo deny check` clean | ✅ DONE | — |
| `cargo audit` zero vulnerabilities | ✅ DONE | — |
| Zero `unsafe` blocks | ✅ DONE (workspace lint) | — |
| All error paths return `Result` | ✅ DONE (lint enforced) | — |
| Kani proofs pass | ✅ 8 proofs | — |
| Fuzz testing (nightly 2.5hr/target) | ✅ DONE | — |
| Property-based tests pass | ✅ 9 harnesses | — |
| Tests pass Linux + macOS | ✅ CI matrix | — |
| Cargo.lock committed | ✅ DONE | — |
| Dependency audit documented | ✅ DEPENDENCY_AUDIT.md | — |
| Sigstore signing workflow | ✅ release.yml | — |
| Reproducible build verification | ✅ CI job | — |
| Toolchain pinned | ✅ rust-toolchain.toml (1.94.0) | — |
| Homebrew formula | ❌ NOT DONE | Recommended |
| `criterion` benchmarks | ❌ NOT DONE | Recommended |
| Enrich `sanctum init` output | ❌ NOT DONE | Recommended |
| Starship segment documented | ❌ NOT DONE | Recommended |
| Security checklist formally closed | ❌ NOT DONE | Recommended |
| CHANGELOG.md current | ✅ DONE | — |
| README with quickstart | ✅ DONE | — |
| SECURITY.md | ✅ DONE | — |
| THREAT_MODEL.md | ✅ DONE | — |
| ARCHITECTURE.md with ADRs | ✅ 15 ADRs | — |
| Install script with sig verification | ✅ scripts/install.sh | — |

---

## Section 8: Competitive Positioning Validation

The competitive moat is well-validated: nono/API Stronghold own the phantom proxy space; Sanctum's defensible position is runtime integrity monitoring + AI agent firewall + budget enforcement. No existing tool provides all three. The positioning statement — "nono keeps untrusted code from reaching your credentials; Sanctum watches what happens when code runs" — is crisp and accurate.

The one risk: **if the Claude Code hooks don't actually work at launch, the "AI Firewall" pillar collapses**. The Sentinel (.pth monitoring) and Budget Controller work independently of the hooks integration. But the AI Firewall is the most marketable differentiator — "the tool that protects your Claude Code sessions" — and it's the hook format bug that threatens this narrative.

---

## Recommendations Summary

**Do these before tagging v0.1.0 (5–8 days of work):**

1. Fix Claude Code hooks JSON format (CRITICAL — 1 day)
2. Add `MultiEdit` to write-hook matchers (1 hour)
3. Verify MCP matcher against a live Claude Code session (2 hours)
4. Create Homebrew formula and tap (1 day)
5. Add `criterion` benchmarks for detection latency and IPC round-trip (1 day)
6. Enrich `sanctum init` with environment detection (1 day)
7. Add Starship custom module documentation (2 hours)
8. Walk through the §8 security checklist and formally close every item (2 hours)
9. Add hook format migration logic to `sanctum hooks install claude` (2 hours)

**Do these in v0.1.1 (next 2 weeks):**

1. Add `PermissionRequest` hook support
2. Add `sanctum hooks install cursor`
3. Add `--scope` flag to hooks install
4. Add `sanctum hooks status` diagnostic command
5. Increase nightly fuzz duration to 5 hours per target (to match plan)
6. Add `cargo-llvm-cov` to CI

**The security-critical core is ready. The integration layer needs one critical fix and several polish items. Ship once the hooks format is fixed and tested against a live Claude Code installation.**
