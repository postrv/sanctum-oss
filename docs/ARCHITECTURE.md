# Architecture

## Design decisions

### ADR-001: Rust, single static binary

**Context**: Sanctum is a security tool. The tool itself must not be a supply chain risk.

**Decision**: Rust with `panic = "abort"`, LTO, single binary output.

**Rationale**:
- Memory safety without GC eliminates an entire vulnerability class
- Single binary = no runtime dependencies = no supply chain for the tool itself
- `panic = "abort"` prevents unwinding-based attacks and reduces binary size
- The `secrecy` crate ensures sensitive values are zeroised on drop

### ADR-002: Workspace with five crates

**Context**: The project has clear module boundaries with different dependency needs.

**Decision**: Cargo workspace with `sanctum-types`, `sanctum-sentinel`, `sanctum-daemon`, `sanctum-cli`, `sanctum-notify`.

**Rationale**:
- `sanctum-types` has no heavy dependencies (just serde, thiserror)
- `sanctum-sentinel` contains the security-critical code — auditing a smaller crate is easier
- `sanctum-daemon` pulls in tokio (large dependency) — isolated from the analyser
- `sanctum-cli` depends on clap — not needed in the daemon
- `sanctum-notify` depends on platform-specific notification crates

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
- Filesystem permissions (0o700) provide authentication by OS user
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
