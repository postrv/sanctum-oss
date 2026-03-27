# Sanctum

**The developer security daemon for the AI coding era.**

Runtime integrity monitoring, AI credential firewall, and LLM spend enforcement. Catches `.pth` injection attacks, redacts credentials from AI prompts, and prevents runaway API bills -- without interrupting your flow.

## The problem

The [TeamPCP/LiteLLM supply chain attack](https://sanctum.dev/blog/litellm) (CVE-2026-33634) exploited Python's `.pth` file mechanism to execute malicious code on every interpreter startup. MITRE ATT&CK classifies this as [T1546.018](https://attack.mitre.org/techniques/T1546/018/) and notes it "cannot be easily mitigated with preventive controls."

Sanctum mitigates it.

## Quick start

```bash
# Build from source (see below)
sanctum init
# The daemon auto-starts with your shell.
```

## What it does

### Phase 1: The Sentinel (current)

- **`.pth` file monitoring** -- Watches all Python `site-packages` directories for new or modified `.pth` files. Content analysis classifies each line as benign, suspicious, or critical.
- **Process lineage tracing** -- Determines *who* created the file by tracing the parent process chain. pip -> expected. Python startup creating more `.pth` files -> suspicious.
- **Quarantine protocol** -- Critical files are moved to quarantine and replaced with empty stubs. Review with `sanctum review`.
- **Credential file monitoring** -- Alerts when unexpected processes access SSH keys, cloud credentials, or API tokens.

### Phase 2: AI Firewall (current)

- **Credential redaction** -- Scans outbound content against 20 credential patterns (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, and more) before data leaves your machine.
- **Shannon entropy analysis** -- Detects high-entropy strings that look like randomly-generated secrets, even when they don't match a known pattern.
- **Claude Code hook handlers** -- PreToolUse/PostToolUse hooks for pre-bash, pre-write, pre-read, and post-bash actions.
- **MCP policy engine** -- Audits MCP tool calls with policy-based restrictions.

### Phase 3: Budget Controller (current)

- **Per-provider, per-session, and per-day spend limits** -- Set budgets globally or per provider with `sanctum budget set`.
- **3 provider parsers** -- Extracts cost data from OpenAI, Anthropic, and Google API responses.
- **Model allowlists** -- Restrict which models each provider may use.
- **Budget extend and reset** -- Extend a session budget or reset counters without reconfiguring limits.

## Usage

```bash
sanctum init              # Initialise Sanctum in current directory
sanctum status            # Show daemon status
sanctum review            # Review quarantined items
sanctum scan              # Scan project for credential exposure
sanctum run -- cmd        # Run command with protections
sanctum config            # View configuration (--edit to open in $EDITOR)
sanctum budget            # View spend budgets
sanctum budget set        # Set session/daily limits
sanctum budget extend     # Extend current session budget
sanctum budget reset      # Reset budget counters
sanctum audit             # View threat event audit log (--last, --level, --json)
sanctum hook <action>     # Claude Code hook handler (pre-bash, pre-write, etc.)
sanctum hooks install     # Install Claude Code hooks
sanctum hooks remove      # Remove Claude Code hooks
sanctum daemon start      # Start the daemon
sanctum daemon stop       # Stop the daemon
sanctum daemon restart    # Restart the daemon
```

## Configuration

```toml
# .sanctum/config.toml

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = false
pth_response = "quarantine"   # quarantine | alert | log

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 75

[budgets.providers.openai]
session = "$30"
daily = "$100"
allowed_models = ["gpt-4o", "o3-mini"]
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
# Requires Rust 1.93.0+ (see rust-toolchain.toml)
git clone https://github.com/postrv/sanctum
cd sanctum
cargo build --release
# Binary: target/release/sanctum
```

## Architecture

A workspace of 7 crates:

| Crate | Purpose |
|-------|---------|
| `sanctum-cli` | CLI interface (clap) |
| `sanctum-daemon` | Background daemon and IPC |
| `sanctum-sentinel` | `.pth` monitoring and quarantine |
| `sanctum-firewall` | Credential redaction, entropy analysis, MCP policy |
| `sanctum-budget` | Spend tracking and provider parsers |
| `sanctum-types` | Shared types and configuration |
| `sanctum-notify` | Desktop notifications |

## Security

Sanctum is a security tool. Its own security standards are documented in:

- [SECURITY.md](docs/SECURITY.md) -- Vulnerability reporting
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) -- What Sanctum does and doesn't protect against
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) -- Design decisions with rationale
- [DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) -- Every dependency justified

Key guarantees:

- **Zero `unsafe` code** in the entire codebase (denied by workspace lint)
- **No panics on any input** (`unwrap` and `expect` are denied by clippy)
- **All dependencies audited** and version-pinned
- **456 tests**, 0 clippy warnings (pedantic + nursery)

## License

MIT -- see [LICENSE](LICENSE).
