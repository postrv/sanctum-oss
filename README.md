# Sanctum

**The developer security daemon for the AI coding era.**

Runtime integrity monitoring, AI credential firewall, and LLM spend enforcement. Catches `.pth` injection attacks, redacts credentials from AI prompts, and prevents runaway API bills — without interrupting your flow.

## The problem

The [TeamPCP/LiteLLM supply chain attack](https://sanctum.dev/blog/litellm) (CVE-2026-33634) exploited Python's `.pth` file mechanism to execute malicious code on every interpreter startup. MITRE ATT&CK classifies this as [T1546.018](https://attack.mitre.org/techniques/T1546/018/) and notes it "cannot be easily mitigated with preventive controls."

Sanctum mitigates it.

## Quick start

```bash
# Install
brew install sanctum          # macOS
curl -fsSL https://sanctum.dev/install | sh  # Linux

# Initialise
sanctum init

# That's it. The daemon auto-starts with your shell.
```

## What it does

### Phase 1: The Sentinel (current)

- **`.pth` file monitoring** — Watches all Python `site-packages` directories for new or modified `.pth` files. Content analysis classifies each line as benign, suspicious, or critical.
- **Process lineage tracing** — Determines *who* created the file by tracing the parent process chain. pip → expected. Python startup creating more `.pth` files → suspicious.
- **Quarantine protocol** — Critical files are moved to quarantine and replaced with empty stubs. Review with `sanctum review`.
- **Credential file monitoring** — Alerts when unexpected processes access SSH keys, cloud credentials, or API tokens.

### Phase 2: AI Firewall (planned)

- Prompt credential redaction before data leaves your machine
- Claude Code PreToolUse/PostToolUse hooks
- MCP tool auditing with policy-based restrictions

### Phase 3: Budget Controller (planned)

- Per-session and per-provider LLM spend limits
- Real-time cost tracking from API response metadata
- Hard stops before runaway bills

## Usage

```bash
sanctum status          # Show daemon status
sanctum review          # Review quarantined items
sanctum scan            # Scan project for credential exposure
sanctum run -- cmd      # Run command with protections
sanctum budget          # View spend (Phase 3)
sanctum config edit     # Edit configuration
```

## Configuration

```toml
# .sanctum/config.toml

[sentinel]
watch_pth = true
watch_credentials = true
pth_response = "quarantine"   # quarantine | alert | log

[ai_firewall]
redact_credentials = true
claude_hooks = true

[budgets]
default_session = "$50"
alert_at_percent = 75
```

## Composable architecture

Sanctum composes with [nono.sh](https://nono.sh) for kernel-level sandboxing:

```bash
# nono provides: kernel sandbox + phantom proxy
# sanctum provides: .pth watch + AI firewall + budget control
nono run --profile claude-code -- claude
```

Sanctum does **not** require nono. It provides independent value as a runtime monitor.

## Building from source

```bash
# Requires Rust 1.82.0+
git clone https://github.com/arbiter-security/sanctum
cd sanctum
cargo build --release
# Binary: target/release/sanctum
```

## Security

Sanctum is a security tool. Its own security standards are documented in:

- [SECURITY.md](docs/SECURITY.md) — Vulnerability reporting
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) — What Sanctum does and doesn't protect against
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) — Design decisions with rationale
- [DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) — Every dependency justified

Key guarantees:
- **Zero `unsafe` code** in the entire codebase
- **No panics on any input** (`unwrap` and `expect` are denied by clippy)
- **All dependencies audited** and version-pinned
- **Sigstore attestation** on release binaries
- **Fuzz tested** and **formally verified** (Kani) on security-critical paths

## License

MIT — see [LICENSE](LICENSE).

An [Arbiter Security](https://arbiter.security) project.
