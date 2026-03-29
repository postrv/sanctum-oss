# Architecture

## Design decisions

### ADR-001: Rust, single static binary

**Context**: Sanctum is a security tool. The tool itself must not be a supply chain risk.

**Decision**: Rust with `panic = "abort"`, LTO, single binary output.

**Rationale**:
- Memory safety without GC eliminates an entire vulnerability class
- Single binary = no runtime dependencies = no supply chain for the tool itself
- `panic = "abort"` prevents unwinding-based attacks and reduces binary size

### ADR-002: Workspace with eight crates

**Context**: The project has clear module boundaries with different dependency needs.

**Decision**: Cargo workspace with `sanctum-types`, `sanctum-sentinel`, `sanctum-daemon`, `sanctum-cli`, `sanctum-notify`, `sanctum-firewall`, `sanctum-budget`, `sanctum-proxy`.

**Rationale**:
- `sanctum-types` centralises shared types with core dependencies (serde, toml, chrono, sha2, nix, tokio, tracing)
- `sanctum-sentinel` contains the security-critical code — auditing a smaller crate is easier
- `sanctum-daemon` pulls in tokio (large dependency) — isolated from the analyser
- `sanctum-cli` depends on clap — not needed in the daemon
- `sanctum-notify` depends on platform-specific notification crates
- `sanctum-firewall` isolates AI hook logic and credential pattern matching from the daemon
- `sanctum-budget` encapsulates pricing tables and cost arithmetic independently

### ADR-003: No `unsafe` code

**Context**: Security tools handle adversarial input.

**Decision**: `unsafe_code = "deny"` at workspace level. Zero exceptions.

**Rationale**: If unsafe is needed (e.g., for a /proc reader), it should be in a separately audited micro-crate, not in the main codebase.

### ADR-004: `unwrap_used = "deny"` and `expect_used = "deny"`

**Context**: A background daemon must never crash on malformed input.

**Decision**: All fallible operations return `Result`. No panics on any code path.

**Rationale**: A `.pth` file could contain arbitrary bytes. The config file could be corrupted. IPC messages could be malformed. Every input boundary must handle errors gracefully.

### ADR-005: IPC via Unix domain sockets (not TCP)

**Context**: The daemon needs a control channel for the CLI.

**Decision**: Unix domain sockets with filesystem permissions for authentication.

**Rationale**:
- No network exposure (TCP would create an attack surface)
- Filesystem permissions (0o600) on the socket file provide authentication by OS user
- Lower latency than TCP loopback
- Length-prefixed JSON with 64KB cap prevents DoS

### ADR-006: Process lineage via /proc (Linux) and sysctl (macOS)

**Context**: We need to know *who* created a `.pth` file.

**Decision**: Read `/proc/<pid>/status` on Linux, `sysctl` kern.proc on macOS.

**Rationale**:
- No additional dependencies required
- Works without elevated privileges
- The `nix` crate provides safe wrappers
- Depth-limited traversal (max 64) prevents infinite loops from malformed /proc

### ADR-007: Quarantine replaces with empty stub, not deletion

**Context**: Deleting a `.pth` file might break Python startup.

**Decision**: Move to quarantine dir, replace original with empty file.

**Rationale**:
- Python won't crash when it encounters an empty `.pth` file
- The developer can restore via `sanctum review`
- Original permissions are preserved on the stub
- Full content and metadata are preserved in quarantine for forensic analysis

### ADR-008: AI Firewall via Claude Code hooks

**Context**: AI coding assistants can read credential files and exfiltrate secrets through tool calls.

**Decision**: Implement `PreToolUse` / `PostToolUse` hooks invoked by Claude Code. The CLI entry point (`sanctum hook <action>`) reads tool invocation JSON from stdin, evaluates it against firewall policy, and signals the decision via exit code: 0 for allow/warn, 2 for block. Messages are written to stderr.

**Rationale**:
- Hook actions (`pre-bash`, `pre-write`, `pre-read`, `pre-mcp`, `post-bash`) cover all tool call surfaces
- The stdin JSON / exit code protocol requires no daemon round-trip — the hook binary runs in-process
- Block rules cover credential file reads, `.pth` / `sitecustomize.py` writes, env-var dumping, and high-entropy secret detection in file content
- Warn rules flag risky-but-legitimate operations (e.g., `pip install`, outbound `curl POST`)

### ADR-009: Integer cents for budget arithmetic

**Context**: Floating-point money arithmetic causes rounding errors that can silently undercount spend.

**Decision**: All monetary values are stored as `u64` cents. `BudgetAmount` parses dollar strings (e.g., `"$50"`) at config deserialisation time and converts to cents immediately. Pricing tables in `sanctum-budget` express prices as integer cents per million tokens. Cost calculation uses ceiling division (`(tokens * price + 999_999) / 1_000_000`) via `saturating_mul` and `saturating_add` to prevent overflow.

**Rationale**:
- Integer arithmetic eliminates floating-point drift across accumulated API calls
- Ceiling division ensures spend is never undercounted — partial-cent amounts round up
- Saturating ops prevent panic on pathological inputs while still denying the lint for `unwrap`/`expect`

### ADR-010: Credential pattern matching with compiled regexes

**Context**: The firewall must detect credentials in tool call content without noticeable latency.

**Decision**: All credential patterns are compiled once into `Regex` objects via `LazyLock` statics, using a `static_regex!` macro. Patterns are ordered from most-specific to least-specific (e.g., `sk-ant-` before `sk-`) so the first match wins. A Shannon entropy calculator (`entropy.rs`) supplements pattern matching to catch unknown high-entropy secrets (threshold > 4.5 bits/char, >= 70% alphanumeric).

**Rationale**:
- `LazyLock` compiles each regex exactly once, paying the cost only on first use
- Patterns are designed to be ReDoS-safe (no nested quantifiers or catastrophic backtracking)
- Entropy-based detection provides a safety net for credential formats not yet in the pattern list

### ADR-011: NDJSON audit log

**Context**: Threat events must be persisted for forensic review and `sanctum audit` queries.

**Decision**: `ThreatEvent` structs are serialised as one JSON object per line (NDJSON) and appended to the audit log file. The file is created with 0o600 permissions. Write errors are logged via tracing but never propagated — audit logging must not crash the daemon.

**Rationale**:
- NDJSON is trivially appendable without parsing the existing file
- One line per event makes streaming reads and `grep`/`jq` filtering straightforward
- Swallowing write errors ensures the daemon stays up even if the filesystem is full

### ADR-012: IPC type centralisation

**Context**: Both the daemon and CLI need identical definitions for IPC commands, responses, and framing.

**Decision**: All IPC types (`IpcCommand`, `IpcResponse`, `ProviderBudgetInfo`, `QuarantineListItem`) and the length-prefixed frame helpers (`read_frame`, `write_frame`) live in `sanctum-types::ipc`. Both `sanctum-daemon` and `sanctum-cli` depend on this shared module.

**Rationale**:
- Single source of truth prevents serialisation mismatches between daemon and CLI
- Frame helpers enforce the 64KB message cap in one place
- Adding a new IPC command only requires changing `sanctum-types`; both ends pick it up automatically

### ADR-013: `compile_regex` uses `abort()` instead of `panic!()`

**Context**: Workspace lints deny `panic!`, `unwrap_used`, and `expect_used`. The `compile_regex` helper in `sanctum-firewall/src/patterns.rs` compiles credential regexes from compile-time literal patterns. On failure (unreachable in practice), it needs to terminate the process.

**Decision**: Use `std::process::abort()` instead of `panic!()`. Print a diagnostic message to stderr (with an `#[allow(clippy::print_stderr)]` annotation) before aborting.

**Rationale**:
- `panic!()` is denied by workspace lints; `abort()` respects the lint constraint
- All 37 patterns are compile-time string literals — the error branch is unreachable
- `abort()` is semantically correct for a "this should never happen" invariant violation
- The `#[allow]` annotation is scoped to the single `eprintln!` call, not the entire function

### ADR-014: `secrecy` crate deferred to proxy phase

**Context**: The development plan (`sanctum-development-plan.md:146`) lists the `secrecy` crate for wrapping credential values in `SecretString` (zeroize-on-drop). The current firewall receives strings from Claude Code hooks, redacts them, and returns — there is no persistent credential storage.

**Decision**: Defer adding `secrecy` until the `sanctum-proxy` crate implements TLS MITM interception. The proxy will handle raw API keys in transit, which is where memory-safe secret types provide the most value.

**Rationale**:
- The firewall processes strings transiently: receive from stdin, scan, redact, return via stdout. No credential value persists in memory beyond a single hook invocation.
- The proxy will hold API keys (from intercepted `Authorization` headers) in memory for the duration of each request. `SecretString` with zeroize-on-drop is directly valuable there.
- Adding `secrecy` to the firewall now would add complexity without meaningfully reducing risk, since the hook process exits after each invocation.
- When `secrecy` is added to the proxy, it should also wrap the CA private key material.

### ADR-015: Glob matcher intentionally minimal

**Context**: The MCP policy engine uses a `glob_matches` function to evaluate restricted paths against policy rules. A full glob implementation (e.g., the `glob` crate) would introduce ReDoS risk and unnecessary complexity.

**Decision**: Support only three glob forms: `prefix/**` (directory tree), `**/suffix` (extension/filename match), and `prefix*suffix` (single wildcard). Patterns with multiple wildcards beyond these forms return `false` with a `tracing::warn!`. Patterns without wildcards use exact match.

**Rationale**:
- All real-world policy rules use `/**` or `**/*` forms (e.g., `/home/user/.ssh/**`, `**/*.pth`)
- The single-star form matches any substring (not just a single path segment), which is the safe direction for a security blocklist — it blocks more paths, not fewer
- Unsupported patterns returning `false` (with a warning) is safer than silently falling through to exact match, which would make glob patterns appear to work but never actually match real paths

### ADR-016: Hook audit event persistence via direct file write

**Context**: Claude Code hooks (`sanctum hook pre-bash/pre-write/pre-read/pre-mcp/post-bash`) are short-lived synchronous processes invoked by Claude Code for each tool call. When a hook blocks a credential leak or warns about a risky operation, that security event is not recorded anywhere persistent. The daemon maintains an NDJSON audit log, but hooks have no communication channel to the daemon. This means `sanctum audit` and `sanctum fix` are blind to hook-detected threats.

**Decision**: Hooks write `ThreatEvent` records directly to the shared NDJSON audit log file, using the same `append_audit_event` function the daemon uses. The audit write module is extracted from `sanctum-daemon` into `sanctum-types` so both the daemon and CLI can use it without circular dependencies.

**Rationale**:
- **POSIX atomicity**: `O_APPEND` writes under `PIPE_BUF` (4KB on all platforms) are atomic. `ThreatEvent` JSON lines are well under 4KB, so concurrent writes from hooks and the daemon are safe without locking.
- **Zero daemon dependency**: Hooks already work without the daemon running. Direct file write preserves this property. IPC-based alternatives would fail (and trigger fail-closed blocking) when the daemon is down.
- **Fail-closed safety**: Audit write errors are swallowed (logged via tracing, never propagated). A failed audit write must not change the hook's allow/block decision and must not cause `exit(2)`.
- **No new dependencies**: No tokio runtime needed in the CLI (audit writes are synchronous). No new IPC commands, no second socket, no async complexity.
- **Alternatives considered**: (a) Synchronous IPC to daemon — rejected because daemon-down causes IPC failure, which under fail-closed semantics would block tool calls. (b) Fire-and-forget Unix datagram — rejected because it adds a second socket and the daemon wouldn't persist the event durably. (c) Separate hook audit log — rejected because two log files fragment the security picture.

### ADR-017: Budget pipeline wiring strategy

**Context**: The `RecordUsage` IPC command is fully implemented in the daemon but has zero callers. The `post_bash` hook extracts API usage data via `extract_budget_usage()` but never sends it. Documentation falsely claims budget tracking is wired into hooks. The `sanctum-proxy` crate contains only foundation code (provider identification); no actual HTTP proxy exists.

**Decision**: Three-phase approach:
1. **v0.1.0** (current): Wire `post_bash` hook usage extraction to IPC `RecordUsage`. Add `sanctum budget record` CLI subcommand for manual/scripted usage reporting. Fix false documentation. Document that automatic capture is limited to API responses visible in bash output.
2. **v0.2.0**: Implement a local HTTP gateway proxy (not TLS MITM). Tools configure `OPENAI_BASE_URL=http://127.0.0.1:PORT/v1` etc. — all major AI SDKs support base URL override. The proxy makes upstream HTTPS calls, extracts usage from responses, and records via the budget tracker. Dramatically simpler than TLS interception.
3. **v0.3.0**: Full TLS MITM proxy for tools that don't support base URL override.

**Rationale**:
- The `post_bash` hook captures API responses visible in command output (e.g., explicit `curl` calls). This is rare but honest — it makes existing code functional rather than dead.
- The `sanctum budget record` command provides a scriptable endpoint for CI/CD and advanced users.
- The local HTTP gateway approach (v0.2.0) is how LiteLLM, Helicone, and OpenRouter work. It avoids CA certificate generation, TLS termination, certificate pinning issues, and HTTP/2 complexity.
- The false documentation is a security tool credibility issue and must be fixed immediately.

### ADR-018: MCP policy — allow-by-default with configurable default and built-in path restrictions

**Context**: The MCP policy engine uses a path-based blocklist model: rules restrict what paths specific tools can access. With no rules defined, all MCP tool calls are allowed. Industry consensus (ToolHive, Cerbos, MCP spec) recommends deny-by-default. However, Sanctum is a secondary enforcement layer — Claude Code already requires user approval for MCP tools at the host level.

**Decision**: Keep the allow-by-default blocklist model but add three enhancements:
1. A `default_mcp_policy` config field (`"allow"` | `"warn"` | `"deny"`) that controls the decision for tools with no matching rules.
2. `Warn` decision for unmatched tools when policy is `"warn"` — gives visibility without breaking anything.
3. Built-in default path restrictions that apply to all MCP tools regardless of user-defined rules, covering sensitive paths (`.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`).

**Rationale**:
- Sanctum is not the primary gate. Claude Code already deny-by-defaults MCP tools (user approval required). Adding another deny-by-default would create redundant double-gating friction.
- The current path-based blocklist answers the right question for Sanctum's domain: "should this tool touch this path?" vs Claude Code's "should this tool run at all?"
- The `default_mcp_policy` field gives security-conscious users the option to tighten the policy without forcing it on everyone.
- Built-in path restrictions ensure zero-config Sanctum still blocks MCP tools from accessing credential paths.

### ADR-019: macOS credential access tracing — accept limitation with best-effort lsof

**Context**: On Linux, `try_find_accessor_info` scans `/proc/*/fd/` to identify which process accessed a credential file. On macOS, it returns `(None, None)`. The Endpoint Security Framework (ESF) would provide process attribution but requires root, `unsafe` code (C FFI), an Apple-provisioned entitlement, and App Bundle packaging — all incompatible with Sanctum's constraints (`unsafe_code = "deny"`, no root, no C dependencies).

**Decision**: Accept the platform limitation. Optionally add a best-effort `lsof <path>` probe that mirrors the existing network collector pattern. Document the difference.

**Rationale**:
- Sanctum's constraints (no unsafe, no root, no C deps, SIP enabled) eliminate all high-fidelity options: ESF, DTrace, fs_usage, proc_pidinfo FFI.
- `lsof <path>` is the only option that works within constraints. It will usually miss short-lived reads (credential reads are typically open-read-close) but may catch longer-held files (editors, scripts).
- The existing network collector already uses `lsof` on macOS, so this is an established pattern in the codebase.
- Credential access detection still works on macOS via FSEvents — users get the security value of knowing *a file was accessed*, even without process attribution.
- Full process attribution on macOS would require a privileged helper daemon with ESF — a potential v0.3.0+ architectural expansion.

### ADR-020: Wire dead threat categories and make credential scanning unconditional

**Context**: Three `ThreatCategory` variants (`SiteCustomize`, `McpViolation`, `BudgetOverrun`) are defined in the type system but never produced as `ThreatEvent` records. Each has a natural emission point: `pre_write` blocks `sitecustomize.py` writes, `pre_mcp_tool_use` blocks policy violations, budget enforcement returns `Blocked`. Additionally, two `ResolutionAction` variants (`PolicyUpdated`, `BudgetAdjusted`) are defined but never constructed.

Separately, `redact_credentials` gates credential scanning in `pre_write` but `pre_bash` credential blocking is unconditional. The config hardening forces `redact_credentials = true` for project-local configs, making the gate effectively dead code.

**Decision**: Wire all three categories to emit `ThreatEvent` records at their natural emission points (via the hook audit write mechanism from ADR-016). Make credential scanning unconditional in `pre_write` — remove the `should_redact` gate. Keep the `redact_credentials` config field for schema stability.

**Rationale**:
- These categories represent real security events that Sanctum already detects and blocks. The gap is only that the detection is not recorded. Wiring them up makes `sanctum audit` and `sanctum fix` aware of the full threat picture.
- Removing them would waste existing work (notify display strings, resolution actions) and create unnecessary churn when they're re-added later.
- Keeping them as dead code erodes trust in the type system and creates confusion about what the audit log records.
- Credential scanning should always be on (defense-in-depth). The config hardening that forces `redact_credentials = true` already signals this is the intended posture. Removing the gate eliminates the asymmetry between `pre_bash` (always scans) and `pre_write` (conditionally scans).

### ADR-021: npm lifecycle hook detection strategy

**Context**: npm lifecycle scripts (`preinstall`, `postinstall`) are the primary attack vector for JavaScript supply chain compromises. The Shai-Hulud worm used `postinstall` to spawn detached credential-harvesting processes. Sanctum needs to detect these attacks for AI-tool-initiated installs.

**Decision**: Detect npm lifecycle script execution through `post_bash` output analysis, not filesystem monitoring. Filesystem-level `node_modules` monitoring is deferred to Phase 3.

**Rationale**:
- Hook-based detection covers AI-tool-initiated installs immediately with no new infrastructure
- `post_bash` already analyses command output for `.pth` creation; adding lifecycle script detection is a natural extension
- Filesystem monitoring of `node_modules` requires solving debouncing (a single `npm install` generates thousands of events), allowlist management by version, and `package.json` parsing -- significant engineering that should not block initial npm coverage
- The two approaches are complementary: hooks catch AI-tool installs (Phase 1), filesystem monitoring catches direct terminal installs (Phase 3)

**Consequences**: Detection is limited to commands visible through Claude Code hooks. Direct terminal `npm install` commands, CI/CD installs, and IDE-integrated package manager invocations are not caught until Phase 3 filesystem monitoring is implemented.

### ADR-022: INSTALL_COMMANDS expansion and allowlist design

**Context**: The `INSTALL_COMMANDS` constant (in `sanctum-firewall/src/hooks/claude.rs`) originally covered only Python package managers. Extending Sanctum to the npm ecosystem requires recognising npm, yarn, pnpm, and bun install commands. When lifecycle scripts are detected during these installs, the system must distinguish legitimate lifecycle usage (native addon compilation, binary downloads) from malicious usage (credential harvesting, C2 beaconing).

**Decision**: Extend `INSTALL_COMMANDS` to cover `npm install`, `npm i`, `npm ci`, `yarn add`, `yarn install`, `pnpm add`, `pnpm install`, `pnpm i`, `bun add`, `bun install`, `bun i`, and `npx`. Use an allowlist of known-safe lifecycle packages (esbuild, puppeteer, sharp, node-gyp, canvas, sqlite3, bcrypt, grpc, fsevents, electron) rather than a blocklist of known-malicious packages.

**Rationale**:
- An allowlist is the safer design for a security tool: unknown packages trigger warnings, and only verified-safe packages are exempted. A blocklist would miss newly published attack packages (which is the common case -- attackers create new packages, not reuse known-bad ones)
- The allowlist is intentionally short. Most npm packages do not need lifecycle scripts. The few that do are well-known native addon packages with established trust
- Allowlist maintenance is a lower burden than blocklist maintenance: new safe packages are added infrequently and upon user report, while new malicious packages appear continuously

**Consequences**: Users may see warnings for legitimate packages not yet on the allowlist. This is the intended trade-off -- false positives on unknown lifecycle packages are preferable to false negatives on malicious ones. Users can report legitimate packages for inclusion in the allowlist.
