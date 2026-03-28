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
- `sanctum-types` has no heavy dependencies (just serde, thiserror)
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
- Hook actions (`pre-bash`, `pre-write`, `pre-read`, `post-bash`) cover all tool call surfaces
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
