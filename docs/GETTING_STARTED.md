# Getting Started with Sanctum

Get from zero to a fully protected AI coding session in under 5 minutes.

## Prerequisites

- macOS (ARM or Intel) or Linux (x86_64)
- Python 3.x (for `.pth` file monitoring)

## Step 1: Install

### From source

```bash
git clone https://github.com/postrv/sanctum
cd sanctum
cargo build --release
# Copy both binaries to your PATH:
sudo cp target/release/sanctum target/release/sanctum-daemon /usr/local/bin/
```

### Via install script

```bash
curl -fsSL https://sanctum.dev/install | sh
```

The installer verifies SHA-256 checksums and, if [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is available, Sigstore signatures. See [SECURITY.md](SECURITY.md) for details.

### Verify

```bash
sanctum --version
# sanctum 0.1.0
```

## Step 2: Initialise

```bash
cd ~/your-project
sanctum init
```

This detects your Python installations, checks for Claude Code and nono, scans for credential exposure, and creates a `.sanctum/config.toml` configuration file.

## Step 3: Start the daemon

```bash
sanctum daemon start
sanctum status
```

Expected output:
```
Sanctum daemon v0.1.0
  Uptime:     0h 0m 1s
  Watchers:   2 active
  Quarantine: 0 items
```

### Automatic startup

Add shell integration so the daemon starts automatically:

```bash
# For zsh (add to ~/.zshrc):
eval "$(sanctum init --shell zsh)"

# For bash (add to ~/.bashrc):
eval "$(sanctum init --shell bash)"

# For fish (add to ~/.config/fish/config.fish):
sanctum init --shell fish | source
```

## Step 4: Install Claude Code hooks

```bash
sanctum hooks install claude
```

This configures Claude Code to route tool calls through Sanctum's AI firewall. The hooks intercept:
- **pre-bash**: blocks credential exfiltration via shell commands
- **pre-write**: blocks credentials from being written to files
- **pre-read**: blocks reading of sensitive files (SSH keys, `.env`, etc.)
- **post-bash**: monitors command output for credential leakage

## Step 5: Verify your setup

```bash
sanctum doctor
```

All checks should show `[PASS]` or `[WARN]` (warnings are for optional components).

## Configuration

View your current configuration:

```bash
sanctum config
```

Generate an opinionated production configuration:

```bash
sanctum config --recommended > .sanctum/config.toml
```

Edit configuration in your preferred editor:

```bash
sanctum config --edit
```

## Common commands

| Command | Purpose |
|---------|---------|
| `sanctum status` | Show daemon status and active protections |
| `sanctum scan` | Scan current directory for credential exposure |
| `sanctum review` | Review quarantined files |
| `sanctum audit --last 24h` | View recent threat events |
| `sanctum fix list` | List unresolved threats |
| `sanctum budget set --daily "$100"` | Set daily spend limit |
| `sanctum run --sandbox -- claude` | Run Claude with full protections |

## Troubleshooting

**"daemon is not running"**
```bash
sanctum daemon start
```

**"sanctum-daemon: command not found"**
Both `sanctum` and `sanctum-daemon` must be in your PATH. If you built from source, copy both binaries:
```bash
sudo cp target/release/sanctum target/release/sanctum-daemon /usr/local/bin/
```

**Hook not firing**
Verify hooks are installed:
```bash
cat ~/.claude/settings.json | grep sanctum
```
If missing, reinstall: `sanctum hooks install claude`

**Config issues**
Validate your configuration:
```bash
sanctum doctor
```

## Next steps

- Read the [threat model](THREAT_MODEL.md) to understand what Sanctum protects against
- Review the [architecture](ARCHITECTURE.md) for design decisions
- Configure [budget limits](../README.md) for LLM spend control
- Set up [network anomaly detection](SECURITY.md) with `watch_network = true`
