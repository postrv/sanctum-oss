# Sanctum

**Runtime security for developers who ship with AI.**

Your AI coding assistant can read your SSH keys, leak your AWS credentials, and run up a $10,000 API bill before you notice. Sanctum watches for all of it -- silently, in the background, without slowing you down.

```bash
curl -fsSL https://sanctum.dev/install | sh
sanctum init
# That's it. The daemon starts with your shell.
```

## Why this exists

In January 2026, a [supply chain attack on LiteLLM](https://sanctum.dev/blog/litellm) (CVE-2026-33634) injected a malicious `.pth` file into Python's `site-packages`. Every time the interpreter started -- even `python3 --version` -- it ran attacker code. Credentials were exfiltrated. MITRE ATT&CK classifies this as [T1546.018](https://attack.mitre.org/techniques/T1546/018/) and notes it "cannot be easily mitigated with preventive controls."

That attack worked because nothing was watching.

Sanctum watches.

## What it catches

### Supply chain attacks

Monitors every Python `site-packages` directory for new or modified `.pth` files. Each line is classified as benign (`import`-only), suspicious (dynamic code), or critical (exec/eval/network). Critical files are quarantined immediately and replaced with empty stubs.

When a `.pth` file appears, Sanctum traces the process lineage to determine *who* created it. `pip install` creating a `.pth`? Expected. Python startup silently writing new `.pth` files? That's [the attack](https://sanctum.dev/blog/litellm).

```
$ sanctum review
Quarantined items:
  1. evil-package.pth  [CRITICAL]
     exec(open('/tmp/.payload').read())
     Quarantined: 2026-03-28 14:23:01
     Creator: python3 (PID 48291) via zsh -> Terminal
```

### npm lifecycle hook attacks

Monitors npm, yarn, pnpm, and bun install commands for lifecycle script execution. Unknown packages running `postinstall` or `preinstall` scripts trigger warnings. Scripts containing `eval()`, `child_process`, `.unref()`, or credential access patterns are blocked immediately.

```
$ echo '{"command":"npm install evil-pkg"}' | sanctum hook post-bash
{"decision":"block","reason":"Critical: npm lifecycle script executed suspicious code during install."}
```

Sanctum also suggests `--ignore-scripts` when you run `npm install` without it.

### Credential leaks to AI tools

Scans all content passing through AI tool hooks against 37 credential patterns -- OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, GCP, Azure, Docker Hub, Vault, and more. Catches secrets before they leave your machine, not after they're in a training set.

Also runs Shannon entropy analysis to detect high-entropy strings that *look* like secrets, even when they don't match a known pattern.

```
$ echo '{"command": "cat ~/.aws/credentials"}' | sanctum hook pre-bash
{"decision":"block","reason":"Reads sensitive credential path: ~/.aws/credentials"}
```

### Runaway AI spend

Tracks per-provider, per-session, and daily spend across OpenAI, Anthropic, and Google APIs. Set budget thresholds, get alerts at configurable percentages, restrict which models each provider can use.

```
$ sanctum budget
Session: $12.40 / $50.00 (24%)
  openai:    $8.20 / $30.00
  anthropic: $4.20 / $20.00
```

### Credential file access

Monitors access to `~/.ssh`, `~/.aws/credentials`, `~/.kube/config`, and other sensitive paths. When an unexpected process touches your credentials, you'll know.

### Network anomalies

Detects outbound connections on unusual ports, to blocklisted destinations, or from unexpected processes. Uses a learning period to establish baselines, then alerts on deviations.

## Claude Code integration

Sanctum provides pre- and post-tool hooks for [Claude Code](https://claude.ai/code):

```bash
sanctum hooks install claude
```

This installs five hook handlers:

| Hook | What it does |
|------|-------------|
| `pre-bash` | Blocks credential access, env var exfiltration, dangerous commands |
| `pre-write` | Prevents writes to sensitive paths, detects credential injection |
| `pre-read` | Blocks reads of SSH keys, cloud credentials, private keys |
| `pre-mcp` | Enforces MCP tool policies, audits all invocations |
| `post-bash` | Scans command output for leaked credentials, extracts API spend |

A malicious repo config cannot disable these protections -- Sanctum enforces a security floor that project-local configs cannot lower.

## Usage

```bash
sanctum init                 # Set up Sanctum in your project
sanctum status               # Daemon status (works offline too)
sanctum doctor               # Health check your installation
sanctum scan                 # Scan project for credential exposure
sanctum review               # Review quarantined threats
sanctum run -- <cmd>         # Run a command with protections active

sanctum config               # View config (--edit to modify, --recommended for defaults)
sanctum audit                # Threat event log (--last 10, --level critical, --json)

sanctum fix list             # Unresolved threats (--category, --level, --json)
sanctum fix resolve <id>     # Remediate a threat (--action restore|delete|dismiss)
sanctum fix all --yes        # Batch-remediate all unresolved threats

sanctum budget               # View current spend
sanctum budget set           # Set session/daily limits
sanctum budget extend        # Extend session budget
sanctum budget reset         # Reset counters

sanctum hook <action>        # Hook handler (called by Claude Code, not you)
sanctum hooks install claude # Install Claude Code hooks
sanctum hooks remove claude  # Remove Claude Code hooks

sanctum daemon start|stop|restart
```

## Configuration

```toml
# .sanctum/config.toml

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = false             # network anomaly detection (opt-in)
pth_response = "quarantine"       # quarantine | alert | log

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[[ai_firewall.mcp_rules]]
tool = "filesystem_write"
restricted_paths = ["/etc/*", "/usr/*", "~/.ssh/*"]

[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 75

[budgets.providers.openai]
session = "$30"
daily = "$100"
allowed_models = ["gpt-4o", "o3-mini"]
```

Generate a recommended starting config with `sanctum config --recommended`.

Full configuration reference: see `sanctum config --recommended` for annotated defaults.

## Installation

### From source (recommended for security-conscious users)

```bash
git clone https://github.com/postrv/sanctum-oss
cd sanctum-oss
cargo build --release
# Binaries: target/release/sanctum, target/release/sanctum-daemon
```

Requires Rust 1.94.0+ (pinned in `rust-toolchain.toml`).

### Script installer

```bash
curl -fsSL https://sanctum.dev/install | sh
```

The installer verifies SHA-256 checksums (mandatory) and Sigstore signatures (if `cosign` is installed). See [SECURITY.md](docs/SECURITY.md) for the verification model.

### Then

```bash
# Add to your ~/.zshrc (or ~/.bashrc, ~/.config/fish/config.fish):
eval "$(sanctum init --shell zsh)"

# Install Claude Code hooks:
sanctum hooks install claude
```

See the [Getting Started guide](docs/GETTING_STARTED.md) for a complete walkthrough.

## How it works

Sanctum runs as a background daemon that starts with your shell. The daemon watches the filesystem, monitors processes, and serves an IPC socket for the CLI and hook handlers.

```
  Claude Code                    Your shell
      |                              |
  [pre-bash hook]              [shell hook]
      |                              |
  sanctum hook ----IPC----> sanctum-daemon
                                |    |    |
                          .pth watch | credential watch
                                     |
                              network monitor
```

The CLI is stateless -- it talks to the daemon over a Unix socket. Hook handlers are fast (single IPC round-trip) so they don't slow down your AI coding session.

## Composable with nono

Sanctum composes with [nono.sh](https://nono.sh) for kernel-level sandboxing:

```bash
# nono: kernel sandbox + phantom proxy
# sanctum: runtime monitoring + AI firewall + budget control
nono run --profile claude-code -- claude
```

Sanctum does **not** require nono. Each tool provides independent value.

## Architecture

8 crates, ~29,300 lines of Rust:

| Crate | Purpose |
|-------|---------|
| `sanctum-cli` | CLI interface -- 13 commands via clap |
| `sanctum-daemon` | Background daemon, IPC server (14 commands), event loop |
| `sanctum-sentinel` | `.pth` monitoring, quarantine, credential watching, network anomaly detection |
| `sanctum-firewall` | Credential redaction (37 patterns), Shannon entropy, MCP policy engine, npm lifecycle detection |
| `sanctum-budget` | Spend tracking, 3 provider parsers (OpenAI, Anthropic, Google) |
| `sanctum-proxy` | HTTP budget proxy foundation (provider identification) |
| `sanctum-types` | Shared types, config schema, threat model, platform paths |
| `sanctum-notify` | Cross-platform desktop notifications (macOS + Linux) |

## Security posture

Sanctum is a security tool. It holds itself to a higher standard than the code it protects.

**Compile-time guarantees** (enforced by workspace lints -- not conventions, *compiler errors*):
- Zero `unsafe` code
- No `unwrap()`, `expect()`, or `panic!()` outside tests
- No `print!()` / `println!()` / `eprint!()` -- all output goes through structured channels

**Testing**:
- 1,170 tests (unit, integration, end-to-end)
- 8 Kani bounded model checking proofs (panic-freedom, state machine correctness, overflow safety)
- 2 fuzz targets on security-critical parsers (CI runs 30s per target on PRs, 2.5h nightly)
- 9 property-based tests verifying core invariants across random inputs
- 0 clippy warnings (pedantic + nursery lints enabled)

**Supply chain**:
- All 193 dependencies audited and version-pinned
- `cargo-deny` enforces license policy and advisory database checks in CI
- Sigstore-signed release binaries with SBOM and Rekor transparency log
- Reproducible builds verified in CI (build twice, compare SHA-256)

**Documentation**:
- [SECURITY.md](docs/SECURITY.md) -- Vulnerability reporting and security guarantees
- [THREAT_MODEL.md](docs/THREAT_MODEL.md) -- What Sanctum does and doesn't protect against
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) -- Design decisions with security rationale
- [DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md) -- Every dependency justified

## Contributing

Sanctum is open source under the MIT license. Contributions are welcome.

Before submitting a PR, ensure:
```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features   # must be 0 warnings
cargo test --all --all-features             # must pass
```

The workspace lint configuration is strict by design. If clippy complains, fix the code -- don't suppress the lint.

## License

MIT -- see [LICENSE](LICENSE).
