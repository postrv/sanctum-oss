# Sanctum: Next-Phases Development Plan

## Arbiter Security — March 2026

---

## 1. Current State Assessment

### What exists (confirmed from codebase review)

The workspace spans 8 crates (`sanctum-types`, `sanctum-sentinel`, `sanctum-daemon`, `sanctum-cli`, `sanctum-notify`, `sanctum-firewall`, `sanctum-budget`, `sanctum-proxy`) with the following verified properties:

- **1,201 tests** across all crates (the plan targeted >100; exceeded by 12×)
- **8 Kani bounded model checking proofs** (plan targeted >4; doubled)
- **9 proptest harnesses** (6 sentinel + 3 budget)
- **2 fuzz targets** (`fuzz_pth_analyser`, `fuzz_config_parser`)
- **37 compiled credential regex patterns** covering OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Stripe, Slack, SendGrid, npm, PyPI, DigitalOcean, Datadog, Azure SAS, Vercel, Docker Hub, Hashicorp Vault, Hugging Face, and others
- **Zero `unsafe` code** (workspace-level `deny`)
- **Zero `unwrap`/`expect`/`panic`** outside test code (workspace-level clippy lints)
- **Toolchain pinned to 1.94.0** via `rust-toolchain.toml`
- **`cargo-deny` enforced**: C system deps banned, copyleft denied, only crates.io registry
- **22 ADRs** documenting architectural decisions

### Sentinel (operational)

- `.pth` content analyser with Unicode homoglyph detection, continuation-line support, 14 critical keywords (`getattr(`, `importlib`, `open(`, `codecs.`, `ctypes`, `eval(`, `child_process`, `.unref()`, `process.env`, `fs.readFile`, `base64`, `curl `, `wget `, `.npmrc`)
- Credential file watcher covering `.ssh/`, `.aws/`, `.config/gcloud/`, `.azure/`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.kube/config`, `.vault-token`, `.my.cnf`, `.boto`, `application-default-credentials.json`
- Process lineage tracing via `/proc/<pid>/exe`
- Quarantine protocol with atomic metadata writes, O_NOFOLLOW, constant-time hash comparison
- Network anomaly detection (blocklisted destinations, unusual ports)

### AI Firewall (operational)

- Claude Code PreToolUse/PostToolUse hooks: `pre_bash`, `post_bash`, `pre_read`, `pre_write`, `pre_mcp_tool_use`
- Fail-closed hook handler (exit code 2 on errors, not 1)
- Credential redaction with Shannon entropy analysis
- MCP policy engine with glob-based path restrictions and configurable default policy
- Built-in sensitive path restrictions on all MCP tools regardless of user rules
- Security floor enforcement: `claude_hooks`, `redact_credentials`, `mcp_audit` cannot be disabled
- Project-local config hardening: security-critical settings pinned to global values
- Environment dump detection (Python `os.environ`, Node `process.env`, `declare -p`, `declare -x`, `env`, `printenv`)
- 25 credential paths in D7 catch-all, 37 indirect read commands, `exec` detection

### Budget Controller (operational, partially wired)

- Per-session and per-day budgets with hard stops
- Provider identification (OpenAI, Anthropic, Google — including standalone model names `o1`, `o3`, `o4`)
- `sanctum budget record` for manual/scripted usage reporting
- Periodic budget persistence (every 5 minutes)
- **Gap**: `post_bash` extracts usage data but never sends it via IPC `RecordUsage`. Automatic capture is limited to API responses visible in bash output.

### Proxy (foundation only)

- Provider identification, config schema, error types
- No actual HTTP proxy. ADR-014 defers `secrecy` crate to this phase.

### CI Pipeline (operational)

- `lint`, `deny`, `test-linux`, `test-macos`, `property-tests`, `audit`, `fuzz` (30s per target), `kani-core`, `reproducible-build`, `build-release`
- Scheduled `fuzz-extended` (2.5 hours per target via cron)
- Release workflow: `verify-ci` → `build-release` → `sign` (Sigstore keyless OIDC)
- **Three CI targets**: `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`

### Doctor (8 checks)

`sanctum binary`, `sanctum-daemon binary`, `Daemon`, `Config`, `Data directories`, `Python`, `nono`, `Claude hooks`

---

## 2. Blocking Issues for v0.1.0 Public Release

### Resolved

| Issue | Original Problem | Resolution |
|---|---|---|
| Toolchain version discrepancy | Plan specified 1.82.0; codebase uses 1.94.0 | Resolved in favour of 1.94.0 (Cargo.toml `rust-version = "1.94.0"`, `rust-toolchain.toml` matches) |
| CI fuzz duration | PR-gating fuzz runs at 30s; plan targets 5 hours | Resolved: `fuzz-extended` job on cron schedule runs 2.5 hours per target (5 hours total). PR fuzz is a smoke gate. |
| Reproducible builds | Unverified at time of assessment | Resolved: `reproducible-build` CI job builds twice and diffs SHA-256 hashes |

### Remaining v0.1.0 blockers (pre-public-release)

These are items the plan and security checklist mandate before tagging v0.1.0:

| # | Blocker | Severity | Work Required |
|---|---|---|---|
| B1 | No `criterion` benchmarks | Medium | Benchmark IPC round-trip (<5ms), `.pth` detection latency (<100ms), daemon memory footprint (<10MB RSS), cold start (<200ms). The plan specifies these as acceptance criteria. |
| B2 | Missing distribution infrastructure | High | Homebrew formula/tap, `install.sh` (exists but unverified in CI), documentation site, Starship prompt integration. Without Homebrew, the PLG funnel has no entry point for macOS developers. |
| B3 | Linux ARM cross-compilation absent | Medium | `aarch64-unknown-linux-gnu` target removed from CI with note: "Re-add when cross setup is in place." Needed for Linux ARM servers and Raspberry Pi developer environments. |
| B4 | No coverage tooling in CI | Low | Plan specifies ">90% coverage on security-critical modules." No `llvm-cov` or `tarpaulin` job exists. |
| B5 | Budget IPC not wired | Resolved | Budget IPC wired via `send_usage_ipc_best_effort()` in `hook.rs`. `post_bash` now sends extracted usage data to the daemon via IPC `RecordUsage`. Falls back gracefully when the daemon is unavailable. |
| B6 | `sanctum-notify` thinner than planned | Low | Shell-based fallback (`notify-send`/`osascript`) works but lacks the planned richness. ADR explains `notify-rust` 4.x → `zbus` 5.x incompatibility. Functional but minimal. |

**Recommendation**: B1, B2, and B5 are hard blockers. B3 and B4 can ship as known limitations in v0.1.0 release notes. B6 is acceptable as-is.

---

## 3. Phased Development Plan

### Phase 0: v0.1.0 Release Gate (1-2 weeks)

**Goal**: Clear remaining blockers, tag v0.1.0, ship.

#### 0.1 Criterion benchmarks

Add `criterion` dependency to `sanctum-sentinel` and `sanctum-daemon` dev-dependencies.

Benchmarks to implement:

```
benches/
├── pth_analyser.rs        # analyse_pth_line() on benign, warning, critical inputs
├── pth_file.rs            # analyse_pth_file() on fixture files
├── credential_redaction.rs # redact_credentials() on varying input sizes
├── ipc_roundtrip.rs       # Full IPC status query cycle
└── config_parse.rs        # SanctumConfig deserialization
```

Acceptance thresholds (from plan):

| Metric | Target |
|---|---|
| `.pth` detection latency (file create → alert) | < 100ms |
| IPC round-trip (status query) | < 5ms |
| Daemon memory footprint (idle) | < 10MB RSS |
| Cold start time (daemon launch) | < 200ms |
| Binary size (stripped, release) | < 5MB |

CI job: Run benchmarks on `main` push, store results as artifacts. No regression gating initially — establish baselines first.

#### 0.2 Wire budget IPC

In `post_bash`, after `extract_budget_usage()` returns `Some(usage_summary)`, send an IPC `RecordUsage` command to the daemon. This requires the hook process to connect to the daemon socket. If the socket is unavailable (daemon not running), log and continue — budget tracking is best-effort in hook mode.

Decision point: The hook process currently runs as a standalone binary invoked by Claude Code. Opening an IPC connection adds latency to every `post_bash` call. Measure the added latency via criterion before committing. If >50ms, defer to proxy phase where budget tracking is inline.

#### 0.3 Distribution infrastructure

**Homebrew**:
- Create `homebrew-sanctum` tap repository
- Formula installs `sanctum` and `sanctum-daemon` binaries from GitHub release assets
- Formula runs `sanctum hooks install claude` as a post-install caveats suggestion (not automatic — respect user agency)
- CI job: `brew install --build-from-source` on macOS runner to verify formula

**Install script**:
- `install.sh` exists. Add CI job that runs it in a clean Ubuntu container and verifies: binary on PATH, daemon starts, status returns, daemon stops cleanly.

**Starship**:
- Implement custom command segment or environment variable (`SANCTUM_ACTIVE=1`) that Starship reads
- Shell hooks already set `SANCTUM_ACTIVE` — verify Starship configuration snippet in README

**Documentation**:
- README.md quickstart (exists, verify completeness)
- `docs/` directory already has SECURITY.md, THREAT_MODEL.md, ARCHITECTURE.md, DEPENDENCY_AUDIT.md
- Defer full docs site (mdbook/Docusaurus) to post-launch — README is sufficient for v0.1.0

#### 0.4 Release checklist execution

Walk through the security standards checklist from the plan. Mark each item with current status:

- [x] `cargo clippy --all-targets` with `unwrap_used = deny` passes
- [x] `cargo fmt --check` passes
- [x] `cargo deny check` passes
- [x] `cargo audit` reports zero vulnerabilities
- [x] Zero `unsafe` blocks
- [x] All error paths return `Result`, no panics
- [x] Property-based tests with 10,000+ cases pass
- [x] Kani proofs pass (8 proofs, exceeds >4 target)
- [x] Fuzz testing: extended runs on schedule (2.5h per target)
- [x] Tests pass on Linux (x86_64) and macOS (aarch64)
- [x] All direct dependencies in DEPENDENCY_AUDIT.md
- [x] Cargo.lock committed
- [x] Release binaries signed with Sigstore
- [x] Reproducible builds verified
- [x] Toolchain pinned
- [x] PID file and Unix socket 0o600/0o700
- [x] IPC messages capped at 64KB
- [x] Daemon runs as unprivileged user
- [x] SIGTERM/SIGHUP handlers clean up resources
- [x] No network connections in Phase 1 (except opt-in network anomaly detection)
- [x] SECURITY.md, THREAT_MODEL.md, ARCHITECTURE.md, DEPENDENCY_AUDIT.md
- [ ] `criterion` benchmarks (Phase 0.1 above)
- [ ] Homebrew formula (Phase 0.3 above)
- [ ] Budget IPC wired (Phase 0.2 above)

---

### Phase 1: npm Ecosystem Integration (2-3 weeks)

**Goal**: Extend Sanctum's detection surface to cover npm/JavaScript supply chain attacks at parity with the Python `.pth` coverage. This is the highest-value expansion identified by the research.

**Rationale**: The npm attack surface is vastly larger than Python `.pth`. Shai-Hulud compromised packages with 2.6 billion weekly downloads. The attack patterns converge: malicious code executes during dependency installation, harvests credentials, and propagates. Sanctum's existing architecture (credential file watching, AI Firewall hooks, budget control) is ecosystem-agnostic — the gaps are in npm-specific detection.

#### 1.1 Extend `INSTALL_COMMANDS` to cover npm/yarn/pnpm/bun (Day 1) -- COMPLETE

**Current state**: `INSTALL_COMMANDS` in `sanctum-firewall/src/hooks/claude.rs` only covers Python:

```rust
const INSTALL_COMMANDS: &[&str] = &[
    "pip install",
    "pip3 install",
    "uv pip install",
    "poetry add",
    "pdm add",
];
```

**Change**: Add JavaScript package manager commands:

```rust
const INSTALL_COMMANDS: &[&str] = &[
    // Python
    "pip install", "pip3 install", "uv pip install",
    "poetry add", "pdm add",
    // JavaScript
    "npm install", "npm i ", "npm ci",
    "yarn add", "yarn install",
    "pnpm add", "pnpm install", "pnpm i ",
    "bun add", "bun install", "bun i ",
    "npx ", // npx can install and execute in one step
];
```

**Tests (RED first)**:

```rust
#[test]
fn post_bash_warns_npm_install_with_lifecycle_scripts() {
    let input = make_input("bash", json!({
        "command": "npm install some-package",
        "stdout": "added 1 package\n> some-package@1.0.0 postinstall\n> node setup.js",
        "stderr": ""
    }));
    let output = post_bash(&input);
    assert_eq!(output.decision, HookDecision::Warn);
}

#[test]
fn post_bash_warns_yarn_add_with_lifecycle_scripts() {
    let input = make_input("bash", json!({
        "command": "yarn add some-package",
        "stdout": "➤ YN0007: some-package@npm:1.0.0 must be built\n",
        "stderr": ""
    }));
    let output = post_bash(&input);
    assert_eq!(output.decision, HookDecision::Warn);
}

#[test]
fn post_bash_allows_npm_install_without_lifecycle() {
    let input = make_input("bash", json!({
        "command": "npm install lodash",
        "stdout": "added 1 package in 2s",
        "stderr": ""
    }));
    let output = post_bash(&input);
    assert_eq!(output.decision, HookDecision::Allow);
}
```

#### 1.2 Post-bash npm lifecycle script detection (Days 1-3) -- COMPLETE

**Current state**: `post_bash` checks for `.pth` in output of install commands. No npm lifecycle script detection exists.

**Change**: Add a parallel check for npm lifecycle script indicators in command output. The detection targets:

**Lifecycle execution indicators** (patterns in stdout/stderr that indicate a lifecycle script ran):

```rust
const NPM_LIFECYCLE_INDICATORS: &[&str] = &[
    "postinstall",
    "preinstall",
    "install script",
    "> node ",         // npm prints "> <script>" when running lifecycle
    "lifecycle script",
    "node-gyp rebuild",
    "node-pre-gyp",
    "prebuild-install",
    "node setup",
];
```

**Known-safe lifecycle packages** (allowlist — these legitimately need lifecycle hooks):

```rust
const SAFE_LIFECYCLE_PACKAGES: &[&str] = &[
    "esbuild",
    "puppeteer",
    "node-gyp",
    "sharp",
    "canvas",
    "sqlite3",
    "bcrypt",
    "grpc",
    "fsevents",
    "electron",
];
```

**Logic**: If an npm/yarn/pnpm/bun install command's output contains lifecycle indicators AND the package name is not in the safe list, emit a warning. If the output also contains indicators of credential access (`cat`, `.ssh`, `.env`, `curl`, network exfiltration patterns), escalate to a block-level event and write a `ThreatEvent` to the audit log.

**Suspicious lifecycle content patterns** (escalate from warn to critical):

```rust
const SUSPICIOUS_LIFECYCLE_CONTENT: &[&str] = &[
    "base64",
    "eval(",
    "child_process",
    ".unref()",       // Detached process — Shai-Hulud signature
    "process.env",
    "fs.readFile",
    ".ssh",
    ".aws",
    ".npmrc",
    "curl ",
    "wget ",
    "http://",
    "https://",       // Network in lifecycle is suspicious
];
```

**Tests**: Write at minimum 12 tests covering benign lifecycle (esbuild), suspicious lifecycle (unknown package with `eval`), npm/yarn/pnpm/bun variants, and the allowlist mechanism.

#### 1.3 Pre-bash `npm install --ignore-scripts` suggestion (Days 3-4) -- COMPLETE

**Current state**: `pre_bash` warns on `pip install` and `curl` POST commands. No npm-specific guidance.

**Change**: When `pre_bash` sees an `npm install` (or `yarn add`, `pnpm add`, `bun add`) command, check whether `--ignore-scripts` is present. If not, emit a warning (not a block) suggesting:

```
"Warning: npm install without --ignore-scripts may execute lifecycle hooks 
from untrusted packages. Consider: npm install --ignore-scripts <package>"
```

This is a warn, not a block, because many legitimate packages require lifecycle hooks. The warning is informational — consistent with the `pip install` warn behaviour.

**Tests**:

```rust
#[test]
fn pre_bash_warns_npm_install_without_ignore_scripts() {
    let output = pre_bash(&bash_input("npm install some-package"));
    assert_eq!(output.decision, HookDecision::Warn);
    assert!(output.message.as_deref().unwrap_or("").contains("ignore-scripts"));
}

#[test]
fn pre_bash_allows_npm_install_with_ignore_scripts() {
    let output = pre_bash(&bash_input("npm install --ignore-scripts some-package"));
    // Should not warn about lifecycle scripts (other warnings may still fire)
    let msg = output.message.as_deref().unwrap_or("");
    assert!(!msg.contains("ignore-scripts"));
}

#[test]
fn pre_bash_allows_npm_ci_with_ignore_scripts() {
    let output = pre_bash(&bash_input("npm ci --ignore-scripts"));
    let msg = output.message.as_deref().unwrap_or("");
    assert!(!msg.contains("ignore-scripts"));
}
```

#### 1.4 Sentinel: `.npmrc` credential file monitoring enhancement (Days 4-5) -- COMPLETE

**Current state**: `.npmrc` is already in `SENSITIVE_READ_PATHS` and the credential watcher monitors it. The Shai-Hulud worm's propagation depends on harvesting npm tokens from `.npmrc` and `NPM_CONFIG_TOKEN`.

**Verification needed**: Confirm `.npmrc` is in the Sentinel's `credential_paths` list (the one used by `CredentialWatcher::start()`). The `pre_read` and `pre_bash` hooks block access, but the Sentinel's filesystem watcher provides defense-in-depth for non-AI-tool access (direct malware execution).

**Enhancement**: Add `NPM_CONFIG_TOKEN` to the `SENSITIVE_ENV_VARS` list in the AI Firewall hooks if not already present. Verify:

```rust
#[test]
fn pre_bash_blocks_echo_npm_config_token() {
    let output = pre_bash(&bash_input("echo $NPM_CONFIG_TOKEN"));
    assert_eq!(output.decision, HookDecision::Block);
}
```

Also add to pre-bash: detection of `npm whoami` and `npm token list` as credential-revealing commands (these expose registry authentication state).

#### 1.5 `sanctum doctor` npm hygiene checks (Days 5-7) -- COMPLETE

**Current state**: Doctor checks: binary, daemon, config, data dirs, Python, nono, Claude hooks. No JavaScript ecosystem checks.

**New checks**:

```rust
Check {
    name: "Node.js",
    result: check_node(),
},
Check {
    name: "npm ignore-scripts",
    result: check_npm_ignore_scripts(),
},
```

**`check_node()`**: Run `node --version`. Pass if found, Warn if not (optional).

**`check_npm_ignore_scripts()`**: Run `npm config get ignore-scripts`. If the result is `"true"`, Pass. If `"false"` or missing, Warn with message: `"npm lifecycle scripts are enabled — consider 'npm config set ignore-scripts true'"`.

**Rationale**: The PackageGate research found zero-day vulnerabilities across npm, pnpm, vlt, and Bun that bypass script blocking. `ignore-scripts=true` is an imperfect but meaningful defense layer. The doctor check raises awareness without mandating it.

**Tests**:

```rust
#[test]
fn doctor_runs_all_checks() {
    // Verify the new checks are included in the check list
    // (integration test — may need to mock npm availability)
}
```

#### 1.6 `sanctum init` npm/Node.js environment detection (Days 7-8) -- COMPLETE

**Current state**: `sanctum init` creates `.sanctum/config.toml` with sensible defaults. It does not detect the project's ecosystem.

**Enhancement**: During `sanctum init`, detect the presence of `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, or `bun.lockb` in the working directory. If found:

- Add a `[sentinel.npm]` section to the generated config with `watch_lifecycle = true`
- Set `ignore_scripts_warning = true` (enables the pre-bash lifecycle warning)
- Add the project's `node_modules` path to the Sentinel's watch candidates (for Phase 2 filesystem-level monitoring)

This makes Sanctum npm-aware on first run without requiring manual configuration.

#### 1.7 Threat model and documentation updates (Days 8-9)

Update `THREAT_MODEL.md`:
- Add npm lifecycle hooks (preinstall/postinstall) as a monitored threat vector
- Document Shai-Hulud attack pattern and how Sanctum detects it
- Add `UNTRUSTED: Packages installed via npm/yarn/pnpm/bun` to trust boundaries (currently only mentions `pip/npm/etc` generically)
- Document the Clinejection vector and how MCP policy + pre-bash hooks mitigate it

Update `ARCHITECTURE.md`:
- ADR-016: npm lifecycle hook detection strategy
- ADR-017: `INSTALL_COMMANDS` expansion rationale and allowlist design

Update README:
- Add npm/JavaScript to the "What Sanctum Protects" section
- Add `--ignore-scripts` guidance to the security recommendations

---

### Phase 2: Local HTTP Gateway Proxy (3-4 weeks)

**Goal**: Implement the v0.2.0 proxy described in ADR and codebase notes. This is the critical missing piece for automatic budget tracking and transparent credential handling.

**Architecture** (from codebase ADR): Local HTTP gateway, not TLS MITM. AI tools configure `OPENAI_BASE_URL=http://127.0.0.1:PORT/v1` etc. The proxy makes upstream HTTPS calls, extracts usage from responses, and records via the budget tracker. This is how LiteLLM, Helicone, and OpenRouter work — avoids CA certificate generation, TLS termination, and HTTP/2 complexity.

#### 2.1 Proxy core (Week 1)

- HTTP listener on configurable localhost port (default: `127.0.0.1:7842`)
- Request routing based on path prefix to upstream providers
- Transparent request forwarding with `Authorization` header passthrough
- Response streaming (SSE support for streaming completions)
- `secrecy::SecretString` for API keys in memory (per ADR-014)

**Security constraints**:
- Bind to localhost only — no external interface
- Socket permissions: if Unix socket mode is offered as alternative, 0o600
- No credential logging — `Authorization` header values must never appear in logs or audit trail
- Request/response size limits consistent with IPC (64KB for metadata, but streaming bodies are unbounded)

#### 2.2 Usage extraction (Week 2)

- Parse `usage` field from OpenAI, Anthropic, and Google API responses
- Map token counts to cost via pricing tables
- Send `RecordUsage` IPC to daemon automatically on every response
- Handle streaming responses: accumulate usage from final SSE event (`data: [DONE]` for OpenAI, `message_stop` for Anthropic)

#### 2.3 Credential redaction in proxy (Week 2-3)

- Apply the existing 37-pattern credential scanner to request bodies before forwarding
- This provides defense-in-depth: even if the AI tool sends credentials in a prompt, the proxy redacts them before they leave the machine
- Log redaction events to the audit trail

#### 2.4 Budget enforcement at proxy level (Week 3)

- Before forwarding a request, check `check_budget()` for the target provider
- If budget exceeded, return HTTP 429 with a JSON body explaining the limit
- If approaching budget (alert threshold), add an `X-Sanctum-Budget-Warning` header to the response

#### 2.5 `sanctum proxy` CLI commands (Week 3-4)

```
sanctum proxy start [--port 7842] [--socket /path/to/socket]
sanctum proxy stop
sanctum proxy status
```

- Proxy lifecycle managed by the daemon (or standalone if daemon is not running)
- `sanctum init` generates `*_BASE_URL` export statements for shell profile

#### 2.6 Integration testing (Week 4)

- E2E test: start proxy, send mock OpenAI completion request, verify response, verify budget recorded
- E2E test: send request with embedded credential, verify redaction, verify upstream receives clean request
- E2E test: exceed budget, verify 429 response
- Security test: attempt to connect from non-localhost, verify rejection

---

### Phase 3: npm Sentinel — Filesystem-Level Monitoring (2-3 weeks)

**Goal**: Extend the Sentinel's filesystem watcher to provide `.pth`-equivalent monitoring for `node_modules`. This is the direct analogue to the Python `.pth` watcher — proactive detection of malicious packages at the filesystem level, independent of AI tool hooks.

**Rationale**: Phase 1 detects npm threats via AI Firewall hooks (pre-bash/post-bash). Phase 3 detects them at the filesystem level — catching attacks from direct `npm install` commands run outside of Claude Code, from CI/CD scripts, or from IDE-integrated package managers.

#### 3.1 `node_modules` lifecycle script scanner

When the Sentinel detects changes in a `node_modules` directory (via `notify` crate's filesystem watcher), scan newly-added packages for:

1. **`package.json` with lifecycle scripts**: Check for `preinstall`, `postinstall`, `install`, `preuninstall`, `postuninstall` fields in `scripts`
2. **Script content analysis**: If lifecycle scripts exist, read the script file and scan for suspicious patterns (same `SUSPICIOUS_LIFECYCLE_CONTENT` from Phase 1.2)
3. **Allowlist**: Known-safe packages (esbuild, puppeteer, etc.) are allowlisted by name + version + integrity hash from `package-lock.json`

**Detection heuristic** (from the npm research):

The universal structural signature of npm supply chain attacks is a tarball that introduces a new `bundle.js` or equivalent entry point file alongside a `postinstall`/`preinstall` entry in `package.json` where none existed previously. Specifically:

- New package with `preinstall` that spawns a detached child process → Critical
- Existing package version bump that adds lifecycle scripts not present in prior version → Critical
- Lifecycle script that contains `child_process.spawn` with `.unref()` → Critical (Shai-Hulud signature)
- Lifecycle script that reads `process.env` or credential file paths → Critical
- Lifecycle script that makes network requests → Warning
- Lifecycle script that uses `eval()` or `vm.Script` → Critical (React Native attack signature)

#### 3.2 Watch path management

- Auto-discover `node_modules` directories in the project root and configured watch paths
- Use `notify` crate's recursive watcher with file extension filtering (`.json`, `.js`)
- Debounce: `npm install` creates thousands of filesystem events. Debounce to 2-second windows before scanning
- Memory budget: do not hold `node_modules` contents in memory. Scan on-demand when events fire.

#### 3.3 Lockfile integrity monitoring

Monitor `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` for unexpected modifications:

- If a lockfile changes and no `npm install`/`yarn add` command was recently run (check process lineage), emit a warning
- This catches the Clinejection attack pattern where a poisoned cache overwrites `node_modules` without a visible install command

#### 3.4 Config and policy

```toml
[sentinel.npm]
watch_lifecycle = true           # Monitor node_modules for lifecycle scripts
watch_lockfile = true            # Monitor lockfile integrity
lifecycle_response = "alert"     # quarantine | alert | log

# Known-safe packages with lifecycle hooks
lifecycle_allowlist = [
    { package = "esbuild", version = ">=0.17.0" },
    { package = "puppeteer", version = ">=19.0.0" },
    { package = "sharp", version = ">=0.32.0" },
]
```

---

### Phase 4: Slopsquatting Defence (1-2 weeks)

**Goal**: When Claude Code (or any AI tool via hooks) suggests installing an npm or PyPI package, verify the package exists and has meaningful provenance before allowing the install.

**Rationale**: Nearly 20% of AI-generated code includes recommendations for non-existent packages. Over 58% of hallucinated names recur across multiple generation runs. This is a high-confidence detection with low false-positive risk.

#### 4.1 Registry existence check in `pre_bash`

When `pre_bash` detects an `npm install <package>` or `pip install <package>` command:

1. Extract the package name from the command
2. Query the registry API:
   - npm: `https://registry.npmjs.org/<package>` (HEAD request — 404 = doesn't exist)
   - PyPI: `https://pypi.org/pypi/<package>/json` (HEAD request — 404 = doesn't exist)
3. If 404: **Block** with message: `"Package '<package>' does not exist on <registry>. This may be an AI hallucination (slopsquatting risk). Verify the package name before installing."`
4. If the package exists but has <100 weekly downloads and was created within the last 30 days: **Warn** with message: `"Package '<package>' is very new (<30 days old) with minimal downloads. Verify this is the intended package."`

**Security constraint**: This introduces a network call from the hook process. The call must:
- Use HTTPS only
- Have a 3-second timeout (fail-open if registry is unreachable — we don't break developer workflow)
- Cache results for 1 hour in a local file to avoid repeated lookups
- Never send any developer data to the registry — only the package name

**Privacy note**: Package name queries to public registries are not sensitive (the package is about to be installed from the same registry). Document this in THREAT_MODEL.md.

#### 4.2 Configuration

```toml
[ai_firewall]
check_package_existence = true    # Enable slopsquatting detection
package_check_timeout_ms = 3000   # Fail-open after 3 seconds
package_check_cache_ttl = 3600    # Cache results for 1 hour
```

Default: enabled. Can be disabled for air-gapped environments.

---

### Phase 5: Release Engineering Hardening (1-2 weeks)

**Goal**: Close the remaining plan-vs-implementation gaps that don't block v0.1.0 but are needed for production maturity.

#### 5.1 Linux ARM cross-compilation

- Add `aarch64-unknown-linux-gnu` back to CI matrix
- Use `cross` tool or install `gcc-aarch64-linux-gnu` linker toolchain
- Verify binary runs on ARM64 Linux (can use QEMU in CI)

#### 5.2 Coverage tooling

- Add `llvm-cov` or `cargo-tarpaulin` CI job
- Generate coverage reports as CI artifacts
- Set warning threshold at 80%, target 90% on security-critical modules
- Do not gate on coverage — use it as a visibility tool

#### 5.3 SBOM generation

- Add CycloneDX SBOM generation to release workflow
- `cargo cyclonedx` produces the SBOM from `Cargo.lock`
- Attach SBOM as release asset alongside binaries and signatures

#### 5.4 Changelog automation

- `git-cliff` config exists (`cliff.toml`). Wire it into the release workflow.
- Auto-generate changelog from conventional commits on tag push
- Include changelog in GitHub Release body

---

## 4. Security Considerations for npm Expansion

### Network calls from hooks (Phase 4)

The slopsquatting defence introduces the first network call from a hook process. This is a significant architectural change. The Sentinel and AI Firewall were designed as pure-local with no network dependencies. Mitigations:

- Fail-open: if the registry is unreachable, allow the install with a warning
- Timeout: 3 seconds maximum
- No state: the hook process does not persist across invocations
- No credentials: only the package name is sent
- HTTPS only: certificate validation via rustls (no openssl-sys)
- Audit: log the registry query to the audit trail

### `node_modules` watcher performance (Phase 3)

`node_modules` directories can contain tens of thousands of files. The filesystem watcher must not:

- Consume >10MB additional RSS (performance budget from plan)
- Add >100ms to daemon startup
- Block the async event loop (use `spawn_blocking` for filesystem scans, consistent with existing quarantine operations)

Debouncing is critical. A single `npm install` can generate 10,000+ filesystem events. The watcher should collect events for 2 seconds, then batch-process all new/modified `package.json` files in a single scan pass.

### Trust boundary implications

Extending Sanctum to npm does not change the trust model. `node_modules` content is already classified as `UNTRUSTED` in `THREAT_MODEL.md`. The new npm monitoring extends the Sentinel's coverage of untrusted package content to a second ecosystem. The trust boundary remains: Sanctum daemon (trusted) monitors untrusted packages and semi-trusted AI tools.

---

## 5. Hardening Backlog (Future Consideration)

These items from the prior assessment remain tracked but are not prioritised for the next 3-4 months:

| Item | Priority | Notes |
|---|---|---|
| IPC rate limiting | Medium | Prevents DoS via rapid IPC connections. Not urgent — socket is 0o600. |
| Audit log integrity chaining | Low | HMAC chain on NDJSON entries for tamper detection. Valuable for enterprise but not needed for v0.1.x. |
| Glob matcher edge case documentation | Low | ADR-015 documents the intentional minimalism. No functional gap. |
| Expanded credential pattern coverage | Ongoing | New provider API key formats appear regularly. Maintain a process for community-contributed patterns. |
| SBOM trust relationship tooling | Low | Beyond SBOM generation — modeling trust relationships between dependencies. Research phase. |
| VS Code extension vetting | Low | Out of current scope (IDE-level threat). Revisit if/when Sanctum ships a VS Code extension (Phase 4 of original plan). |
| Network egress monitoring during npm install | Medium | Phase 3+ work. Detection heuristic: child process of `npm` makes outbound HTTPS to domains not in `package-lock.json`. Requires network monitoring capability that the Sentinel does not yet have for non-AI-tool processes. |

---

## 6. Sequencing Summary

| Phase | Duration | Deliverable | Depends On |
|---|---|---|---|
| **Phase 0**: v0.1.0 Release Gate | 1-2 weeks | Tagged v0.1.0 release, Homebrew formula, benchmarks, budget IPC | Nothing |
| **Phase 1**: npm Ecosystem Integration | 2-3 weeks | npm lifecycle detection in hooks, doctor checks, init detection, threat model update (1.1-1.6 complete, 1.7 in progress) | Phase 0 |
| **Phase 2**: Local HTTP Gateway Proxy | 3-4 weeks | `sanctum-proxy` with usage extraction, credential redaction, budget enforcement | Phase 0 |
| **Phase 3**: npm Sentinel Filesystem Monitoring | 2-3 weeks | `node_modules` lifecycle scanner, lockfile integrity, config | Phase 1 |
| **Phase 4**: Slopsquatting Defence | 1-2 weeks | Registry existence check in `pre_bash` | Phase 1 |
| **Phase 5**: Release Engineering Hardening | 1-2 weeks | ARM cross-compilation, coverage, SBOM, changelog | Phase 0 |

**Critical path**: Phase 0 → Phase 1 → Phase 3 (npm detection depth)
**Parallel track**: Phase 2 (proxy) can proceed in parallel with Phase 1 once Phase 0 ships.
**Quick win**: Phase 5 items can be interleaved opportunistically.

Total estimated calendar time to Phase 4 completion: **10-14 weeks** (aligns with original plan's Phase 2-3 timeline of weeks 6-16).
