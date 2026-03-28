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

See the [Getting Started guide](docs/GETTING_STARTED.md) for a complete 5-minute walkthrough.

## What it does

### Phase 1: The Sentinel (current)

- **`.pth` file monitoring** -- Watches all Python `site-packages` directories for new or modified `.pth` files. Content analysis classifies each line as benign, suspicious, or critical.
- **Process lineage tracing** -- Determines *who* created the file by tracing the parent process chain. pip -> expected. Python startup creating more `.pth` files -> suspicious.
- **Quarantine protocol** -- Critical files are moved to quarantine and replaced with empty stubs. Review with `sanctum review`.
- **Credential file monitoring** -- Alerts when unexpected processes access SSH keys, cloud credentials, or API tokens.

### Phase 2: AI Firewall (current)

- **Credential redaction** -- Scans outbound content against 37 credential patterns (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, Vercel, Docker Hub, Hashicorp Vault, and more) before data leaves your machine.
- **Shannon entropy analysis** -- Detects high-entropy strings that look like randomly-generated secrets, even when they don't match a known pattern.
- **Claude Code hook handlers** -- PreToolUse/PostToolUse hooks for pre-bash, pre-write, pre-read, and post-bash actions.
- **MCP policy engine** -- Audits MCP tool calls with policy-based restrictions.

### Phase 3: Budget Controller (current)

- **Per-provider, per-session, and per-day spend limits** -- Set budgets globally or per provider with `sanctum budget set`.
- **3 provider parsers** -- Extracts cost data from OpenAI, Anthropic, and Google API responses.
- **Model allowlists** -- Restrict which models each provider may use.
- **Budget extend and reset** -- Extend a session budget or reset counters without reconfiguring limits.
- **HTTP budget proxy** (foundation) -- `sanctum-proxy` crate with provider identification for transparent API interception (TLS MITM implementation in progress).

### Phase 4: Production Hardening (current)

- **Guided threat remediation** -- `sanctum fix list/resolve/all` with content-addressed threat IDs and a separate resolution log.
- **Network anomaly detection** -- Monitors outbound connections for unusual ports, blocklisted destinations, and unexpected processes. Platform-specific collection (macOS `lsof`, Linux `/proc/net/tcp`).
- **Formal verification** -- 8 Kani bounded model checking proofs (analyser panic-freedom, path classification, exec detection, quarantine state machine) with CI enforcement.
- **Sigstore binary signing** -- Keyless OIDC signing via GitHub Actions, signed SBOM, Rekor transparency log.

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
sanctum fix list          # List unresolved threats (--category, --level, --json)
sanctum fix resolve <id>  # Remediate a specific threat (--action restore|delete|dismiss)
sanctum fix all --yes     # Batch-remediate all unresolved threats
sanctum hook <action>     # Claude Code hook handler (pre-bash, pre-write, etc.)
sanctum hooks install claude  # Install Claude Code hooks
sanctum hooks remove claude  # Remove Claude Code hooks
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
watch_network = false           # enable network anomaly detection
pth_response = "quarantine"     # quarantine | alert | log
credential_allowlist = []       # process names to trust with credential access

[sentinel.network]
poll_interval_secs = 30
learning_period_days = 7
transfer_threshold_bytes = 104857600  # 100 MB
process_allowlist = ["Dropbox", "rsync", "TimeMachine"]
destination_blocklist = []
safe_ports = [80, 443, 22, 53, 8080, 3000, 5432, 3306, 6379]

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[[ai_firewall.mcp_rules]]
tool = "filesystem_write"
restricted_paths = ["/etc/*", "/usr/*"]

[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 75

[budgets.providers.openai]
session = "$30"
daily = "$100"
allowed_models = ["gpt-4o", "o3-mini"]

[proxy]
enabled = false
listen_port = 9847
enforce_budget = true
enforce_allowed_models = true
```

Budget usage can be reported via `sanctum budget record` or through post-bash hook detection when API responses are visible in command output.

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
# Requires Rust 1.94.0+ (see rust-toolchain.toml)
git clone https://github.com/postrv/sanctum
cd sanctum
cargo build --release
# Binary: target/release/sanctum
```

## Architecture

A workspace of 8 crates (~26,400 lines of Rust):

| Crate | Purpose |
|-------|---------|
| `sanctum-cli` | CLI interface (13 commands, clap) |
| `sanctum-daemon` | Background daemon, IPC server (14 commands), event loop |
| `sanctum-sentinel` | `.pth` monitoring, quarantine, credential watching, network anomaly detection |
| `sanctum-firewall` | Credential redaction (37 patterns), entropy analysis, MCP policy engine |
| `sanctum-budget` | Spend tracking, 3 provider parsers, budget enforcement |
| `sanctum-proxy` | HTTP budget proxy foundation (provider identification) |
| `sanctum-types` | Shared types, config schema (12 structs), threat model (6 categories) |
| `sanctum-notify` | Cross-platform desktop notifications |

## Security

Sanctum is a security tool. Its own security standards are documented in:

- [SECURITY.md](docs/SECURITY.md) -- Vulnerability reporting
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) -- What Sanctum does and doesn't protect against
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) -- Design decisions with rationale
- [DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) -- Every dependency justified

Key guarantees:

- **Zero `unsafe` code** in the entire codebase (denied by workspace lint)
- **No panics on any input** (`unwrap` and `expect` are denied by clippy)
- **All dependencies audited** and version-pinned (193 deps, 0 known CVEs)
- **1,085 tests**, 0 clippy warnings (pedantic + nursery)
- **8 Kani bounded model checking proofs** with CI enforcement
- **2 fuzz targets** for security-critical parsers
- **9 property-based tests** verifying core invariants
- **Sigstore-signed release binaries** with SBOM and Rekor transparency log

## License

MIT -- see [LICENSE](LICENSE).
