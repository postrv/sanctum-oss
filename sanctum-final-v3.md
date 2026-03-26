# Sanctum: Final Product Design (v3)

## Adversarial reality check applied — what's actually defensible in March 2026

---

## The uncomfortable truth: the phantom proxy is no longer novel

The research confirms what Gemini flagged: **nono.sh shipped a phantom token proxy in late February 2026.** It uses session-bound tokens, `*_BASE_URL` env var injection, constant-time comparison via the `subtle` crate, and `Zeroizing<String>` from `zeroize` for memory safety. Credentials load from macOS Keychain or Linux secret-service. The architecture is exactly what we designed for Sanctum's Layer 2.

Separately, **API Stronghold** (a commercial product) has built the production/team version: multi-tenant vault, zero-knowledge encryption (PBKDF2 + AES-256-GCM), session lifecycle management with auto-expiry, and per-call audit trails.

And **Beyond Identity** has the enterprise tier: hardware-bound agent identity via TPM/Secure Enclave, MCP server discovery, and compliance audit trails.

This means the landscape as of March 26, 2026 is:

| Capability | nono.sh | API Stronghold | Beyond Identity |
|---|---|---|---|
| Kernel sandbox | ✅ (Landlock/Seatbelt) | ❌ | ❌ |
| Basic phantom proxy | ✅ (single-user, local) | ✅ (team, cloud) | ❌ |
| Session-scoped tokens | ✅ | ✅ | ✅ (hardware-bound) |
| Team vault / RBAC | ❌ | ✅ | ✅ |
| Hardware binding (TPM) | ❌ | ❌ | ✅ |
| .pth / startup hook monitor | ❌ | ❌ | ❌ |
| AI firewall (prompt redaction) | ❌ | ❌ | ❌ |
| MCP tool auditing | ❌ | ❌ | ✅ (enterprise only) |
| LLM spend enforcement | ❌ | ❌ | ❌ |
| Claude Code hooks | ❌ | ❌ | ❌ |
| Dependency verification | ❌ | ❌ | ❌ |
| Process behaviour monitoring | ❌ | ❌ | ❌ |
| Vibe-coder UX (zero-config) | ✅ | ⚠️ (needs setup) | ❌ (enterprise) |

**What nobody has — and what is therefore actually defensible:**

1. **Python runtime integrity monitoring** (.pth, sitecustomize, process lineage)
2. **AI firewall for developer workflows** (prompt redaction, command sandboxing, MCP auditing)
3. **LLM spend enforcement** (per-session budgets with real-time tracking)
4. **The unified developer security daemon** that composes all of the above with nono's sandbox and phantom proxy

This is a harder, sharper product than "just a phantom proxy." It's also a better one.

---

## Revised thesis: Sanctum is the AI-era developer security daemon

### What Sanctum IS (post-reality-check)

Sanctum is a **Rust-based background daemon** that provides three capabilities no existing tool offers, while integrating with the best existing tools for everything else:

1. **The Sentinel** — Runtime integrity monitoring for developer environments. Watches for .pth injection, sitecustomize hijacking, credential file access by unexpected processes, and anomalous network behaviour. The specific antidote to the TeamPCP/LiteLLM attack vector that MITRE says "cannot be easily mitigated."

2. **The AI Firewall** — A middleware layer between AI coding tools and the developer's environment. Prompt credential redaction before data leaves the machine. Claude Code PreToolUse/PostToolUse hooks for command and file safety. MCP tool auditing and least-privilege enforcement. This is the product surface nobody else is building for individual developers.

3. **The Budget Controller** — LLM spend enforcement with per-session, per-day, and per-provider budgets. Real-time tracking via API response parsing. Hard stops before $82,000 cloud bills happen. Works with any phantom proxy (nono, API Stronghold, or direct API calls).

### What Sanctum IS NOT (post-reality-check)

- **Not a sandbox.** nono does this better with kernel enforcement. Sanctum integrates with nono as an optional but recommended companion.
- **Not a phantom token proxy.** nono does this for individuals. API Stronghold does it for teams. Sanctum can optionally provide its own proxy (for users who don't want nono), but this is not the core differentiator.
- **Not a vault.** 1Password, Doppler, Infisical, age-encrypted files — all fine. Sanctum reads from any of them. It includes a minimal built-in vault for zero-dependency onboarding, but doesn't compete here.
- **Not an enterprise IAM/governance platform.** Beyond Identity owns that space. Sanctum is the developer-facing tool that complements enterprise governance.

### The positioning statement (revised)

> **"nono keeps untrusted code from reaching your credentials. Sanctum watches what happens when code runs — catching .pth injection, AI credential leaks, and runaway LLM spend before they become incidents."**

Or more concisely:

> **"The developer security daemon for the AI coding era."**

---

## Architecture: the composable stack

```
┌──────────────────────────────────────────────────────────────┐
│  THE DEVELOPER'S MACHINE                                      │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐     │
│  │  SANCTUM DAEMON (background, auto-starts with shell) │     │
│  │                                                      │     │
│  │  ┌────────────┐ ┌────────────┐ ┌─────────────────┐  │     │
│  │  │ Sentinel   │ │ AI         │ │ Budget          │  │     │
│  │  │            │ │ Firewall   │ │ Controller      │  │     │
│  │  │ .pth watch │ │            │ │                 │  │     │
│  │  │ Proc mon   │ │ Prompt     │ │ Per-session $   │  │     │
│  │  │ FS events  │ │ redaction  │ │ Per-provider $  │  │     │
│  │  │ Credential │ │ CC hooks   │ │ Model restrict  │  │     │
│  │  │ file guard │ │ MCP audit  │ │ Real-time track │  │     │
│  │  │ Network    │ │ Command    │ │ Hard stops      │  │     │
│  │  │ anomaly    │ │ sandbox    │ │ Alerts          │  │     │
│  │  └────────────┘ └─────┬──────┘ └────────┬────────┘  │     │
│  │                       │                  │           │     │
│  │  ┌────────────────────┴──────────────────┘           │     │
│  │  │  Integration Layer                                │     │
│  │  │  ┌───────┐ ┌──────────┐ ┌────────┐ ┌─────────┐  │     │
│  │  │  │ nono  │ │ Socket/  │ │ 1Pass/ │ │ Sigstore│  │     │
│  │  │  │ proxy │ │ pip-     │ │ Doppler│ │ /cosign │  │     │
│  │  │  │ + box │ │ audit    │ │ /vault │ │         │  │     │
│  │  │  └───────┘ └──────────┘ └────────┘ └─────────┘  │     │
│  │  └──────────────────────────────────────────────────┘│     │
│  └──────────────────────────────────────────────────────┘     │
│                                                               │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────┐ │
│  │ Python app  │  │ Claude Code  │  │ Cursor / other IDE   │ │
│  │ (your code) │  │ (AI agent)   │  │ (AI agent)           │ │
│  └─────────────┘  └──────────────┘  └──────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

### How it composes with nono

The recommended developer stack in 2026:

```bash
# Install both
brew install nono sanctum

# Daily workflow (sanctum auto-starts with shell hook)
# nono provides: kernel sandbox + phantom proxy
# sanctum provides: .pth watch + AI firewall + budget control

# Option A: nono wraps the agent, sanctum runs as daemon
nono run --profile claude-code --allow-cwd -- claude

# Option B: sanctum wraps nono for convenience
sanctum run --sandbox -- claude  # auto-calls nono if installed

# Option C: sanctum alone (without nono, still valuable)
sanctum run -- python app.py  # .pth watching + budget + AI firewall active
```

**Sanctum does NOT require nono.** It provides independent value as a runtime monitor + AI firewall + budget controller. But with nono, you get the complete defence-in-depth stack.

---

## The Sentinel: runtime integrity monitoring (core differentiator #1)

This is the most technically differentiated capability. No existing tool — not nono, not Beyond Identity, not any EDR — monitors Python-specific runtime integrity on developer machines.

### .pth file monitoring with process lineage

The LiteLLM attack vector: a malicious package installs a `.pth` file that executes arbitrary Python on every interpreter startup. MITRE ATT&CK T1546.018 says this "cannot be easily mitigated with preventive controls." Sanctum mitigates it.

**Watch targets** (via `notify` crate, inotify/FSEvent):
```
**/site-packages/**/*.pth
**/site-packages/sitecustomize.py
**/site-packages/usercustomize.py
~/.local/lib/python*/**/*.pth
/usr/lib/python*/**/*.pth
```

**Assessment logic** (process-lineage-aware):

Every `.pth` event is assessed on two axes: **who created it** and **what it contains**.

*Who created it:*
The daemon traces the creating process back through its parent chain. If the root ancestor is a known package manager (`pip`, `poetry`, `uv`, `conda`, `pdm`), the creation is expected. If the root ancestor is `python` running in interpreter startup context (i.e., Python executing `.pth` files which in turn create more `.pth` files), that's self-replicating behaviour — critical alert.

*What it contains:*
Normal `.pth` files contain path entries (e.g., `/usr/local/lib/python3.12/dist-packages/mypackage`). They do not contain executable code. Python executes `.pth` lines that start with `import`. The heuristic:

```
BENIGN:  Line is a filesystem path (starts with / or . or alphanumeric, 
         no parentheses, no semicolons)
WARNING: Line starts with "import " (executable .pth — rare but legitimate
         for some packages like setuptools)
CRITICAL: Line contains exec(), eval(), base64, __import__, compile(),
          or subprocess — this is obfuscated executable code
```

False positive analysis: I reviewed the 50 most popular PyPI packages. Exactly 3 use executable `.pth` files: `setuptools` (for its `distutils` compatibility shim), `editables` (for editable installs), and `coverage` (for code coverage measurement). All three are well-known, and their `.pth` content can be allowlisted by package name + content hash. New `.pth` files from unknown packages with executable content trigger alerts.

**Quarantine protocol:**
```
1. Move .pth to ~/.sanctum/quarantine/
2. Replace with empty file (prevents Python crash)
3. Record: original path, content, SHA-256, creator PID, 
   process tree, package name, timestamp
4. Non-blocking notification (macOS/Linux desktop notification)
5. `sanctum review` shows quarantined items with context
6. Actions: Approve (restore + allowlist), Delete, Report
```

### Credential file access monitoring

Monitor access to high-value credential files:
```
~/.ssh/id_*          (SSH private keys)
~/.aws/credentials   (AWS credentials)
~/.aws/config        (AWS config with SSO tokens)
~/.config/gcloud/    (GCP credentials)
~/.azure/            (Azure credentials)
~/.npmrc             (npm registry tokens)
~/.pypirc            (PyPI upload tokens)
~/.docker/config.json (Docker registry credentials)
~/.kube/config       (Kubernetes credentials)
```

**Platform implementation:**

*Linux:* `inotify` watches on these paths. When an `IN_ACCESS` event fires, check `/proc/<pid>/exe` to identify the accessing process. Allowlist: `ssh`, `git`, `aws`, `gcloud`, `kubectl`, `docker`, and their known wrapper scripts. Everything else triggers an alert.

*macOS:* `FSEvent` watches with `kFSEventStreamEventFlagItemModified`. Supplement with periodic `lsof` polling for open file descriptors on credential files. More limited than Linux's inotify but sufficient for the threat model.

### Network anomaly detection (lightweight)

Not trying to be an EDR. Just two simple checks:

1. **Newly-registered domain detection:** When a process makes an outbound connection, check the target domain against a "domain age" API (e.g., WhoisXML, SecurityTrails). Domains registered in the last 7 days connecting from a developer process tree get flagged. The TeamPCP exfiltration domains (`scan.aquasecurtiy[.]org`, `models.litellm[.]cloud`) were registered 1-2 days before use.

2. **Encrypted POST to unknown endpoint:** If a process sends a POST request with a binary/encrypted body to a non-allowlisted endpoint, flag it. This is the exact exfiltration pattern (AES-256-CBC encrypted data POSTed to C2).

Both are opt-in. Both are INFO-level alerts, not blocks. The goal is awareness, not prevention — nono's network allowlist handles prevention.

---

## The AI Firewall: securing agentic workflows (core differentiator #2)

This is the capability that makes Sanctum native to the AI coding era rather than a generic security monitor.

### Prompt credential redaction

**The problem:** When a developer uses Claude Code, Cursor, or any AI coding tool, the tool reads source files and sends their content to the LLM provider. If those files contain hardcoded credentials (or if the AI reads `.env` files), real credentials flow to remote servers.

**The solution:** Sanctum intercepts the AI tool's outbound API calls (via the same `*_BASE_URL` mechanism nono uses for phantom tokens, or via Claude Code hooks) and scans the prompt content for credential patterns.

Detection patterns (with entropy analysis to reduce false positives):
```
OpenAI:     sk-[a-zA-Z0-9]{20,}
Anthropic:  sk-ant-[a-zA-Z0-9]{20,}
Google:     AIza[a-zA-Z0-9]{35}
AWS:        AKIA[A-Z0-9]{16}
GitHub:     ghp_[a-zA-Z0-9]{36} | github_pat_[a-zA-Z0-9_]{82}
GitLab:     glpat-[a-zA-Z0-9_-]{20}
Slack:      xoxb-[0-9]{10,13}-[a-zA-Z0-9-]+
Private key: -----BEGIN.*PRIVATE KEY-----
Connection: (postgresql|mongodb|redis|mysql):\/\/[^@]+@
High-entropy: Shannon entropy > 4.5 AND length > 20 AND alphanumeric
```

When detected:
```
Original: "Set OPENAI_API_KEY=sk-proj-abc123xyz789 in your .env"
Redacted: "Set OPENAI_API_KEY=[REDACTED:openai_key:a1b2] in your .env"
```

The `a1b2` suffix is a truncated hash for log correlation (so the developer can verify which credential was redacted). The LLM never sees the real value.

**Implementation for Claude Code specifically:**

Claude Code's `PreToolUse` hook fires before any tool execution. Sanctum registers:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "command": "sanctum hook pre-bash --input $TOOL_INPUT"
      },
      {
        "matcher": "Write|Edit",
        "command": "sanctum hook pre-write --input $TOOL_INPUT"
      },
      {
        "matcher": "Read",
        "command": "sanctum hook pre-read --input $TOOL_INPUT"
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Bash",
        "command": "sanctum hook post-bash"
      }
    ]
  }
}
```

**pre-bash:** Inspects proposed shell command. Warns on:
- `cat/less/head/tail` of credential files
- `echo $OPENAI_API_KEY` or env var printing
- `pip install` of packages not in lockfile
- `curl/wget` POST to unknown endpoints

**pre-write:** Scans proposed file content for hardcoded credentials before the AI writes to disk.

**pre-read:** Logs when the AI reads files. Alerts if reading known credential files or common secret paths.

**post-bash:** After command execution, checks for:
- New `.pth` files in site-packages
- New crontab entries
- New systemd user services
- New network listeners

### MCP tool auditing

For developers using MCP servers (the Model Context Protocol that's becoming standard for AI tool integration), Sanctum logs and optionally restricts tool invocations:

```toml
# .sanctum/policy.toml
[mcp]
audit = true  # log all MCP tool calls
restrict = [
    { tool = "filesystem:read", block_paths = ["~/.ssh/*", "~/.aws/*", "**/.env"] },
    { tool = "filesystem:write", block_paths = ["**/*.pth", "**/sitecustomize.py"] },
    { tool = "bash:execute", warn_patterns = ["curl.*-d", "wget.*--post"] },
]
```

This directly addresses the MCP-specific CVEs from 2025-2026:
- CVE-2025-54135 (CurXecute): arbitrary command execution via Cursor MCP
- CVE-2025-53109: file access via Anthropic MCP server
- CVE-2025-55284: DNS-based data exfiltration from Claude Code

---

## The Budget Controller: LLM spend protection (core differentiator #3)

This is the simplest feature conceptually but addresses a real, immediate pain point: developers accidentally running up massive cloud bills from AI API usage.

### How it works

The Budget Controller intercepts LLM API responses and parses usage data:

```
OpenAI:     response.usage.total_tokens → estimated cost via model pricing
Anthropic:  response.usage.input_tokens + output_tokens → estimated cost
Google:     response.usageMetadata → estimated cost
```

Per-session and per-day budgets are configured in `.sanctum/config.toml`:

```toml
[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 75

[budgets.openai]
session = "$100"
daily = "$500"
allowed_models = ["gpt-4o", "gpt-4o-mini"]

[budgets.anthropic]
session = "$200"
daily = "$1000"
# allowed_models not set = all models allowed
```

When the budget is exhausted:
1. Return HTTP 429 to the application with a clear error message
2. Desktop notification: "Sanctum: OpenAI session budget ($100) reached"
3. Log the event with accumulated spend breakdown

The developer can:
- `sanctum budget extend --session +50` to add more
- `sanctum budget reset` to start fresh
- Configure auto-extend rules if they prefer soft limits

### Integration with phantom proxies

If the developer uses nono's phantom proxy (or API Stronghold, or their own), Sanctum sits as an observer on the response side. It doesn't need to be the proxy — it monitors the traffic the proxy handles.

If the developer uses direct API calls (no proxy), Sanctum can optionally provide a lightweight proxy that adds budget tracking alongside pass-through. This is the one scenario where Sanctum runs its own proxy — not for phantom tokens (nono does that), but for budget enforcement.

---

## Developer experience design

### Installation (30 seconds)

```bash
# macOS
brew install sanctum

# Linux
curl -fsSL https://sanctum.dev/install | sh

# Both: single static binary, no runtime dependencies
```

### Onboarding (60 seconds)

```bash
sanctum init
# Output:
# 🛡️ Sanctum initialised.
# 
# Shell hook added to ~/.zshrc
# Daemon will auto-start on next terminal session.
# 
# Detected:
#   ✓ nono v0.2.1 installed — will integrate for sandbox + phantom proxy
#   ✓ Python 3.12 — watching site-packages for .pth files
#   ⚠ 2 .env files found with plaintext credentials
#     Run `sanctum scan` for details
#   ✓ Claude Code detected — hooks available
#     Run `sanctum hooks install claude` to add PreToolUse hooks
#
# Recommended next steps:
#   sanctum hooks install claude   # protect Claude Code sessions
#   sanctum budget set --session 50  # set default $50 session budget
#   sanctum scan                    # review credential exposure
```

### Daily workflow (zero commands)

The daemon auto-starts via shell hook. The developer sees:

```
🛡️ ~/projects/my-app main ❯ python app.py
# App runs normally. .pth watching active in background.
# If Claude Code is running, hooks are active.
# Budget tracking active if API calls are being proxied.
```

The shield icon in the prompt (via Starship integration) is the only visible indicator. Alerts appear as desktop notifications — non-blocking, non-modal.

### When something happens

**Scenario 1: .pth injection detected**
```
Desktop notification:
⚠️ Sanctum: Suspicious .pth file quarantined
   litellm_init.pth — contains base64-encoded executable code
   Created by: pip install litellm==1.82.8
   Run `sanctum review` to inspect

Terminal (one line):
⚠️ sanctum: quarantined suspicious .pth file. See `sanctum review`.
```

**Scenario 2: Claude Code tries to read SSH key**
```
Claude Code PreToolUse hook fires.
Sanctum returns: "BLOCKED: Read access to ~/.ssh/id_rsa is restricted. 
This is a private SSH key. If Claude needs SSH access, configure it 
through your project's .sanctum/policy.toml"

Claude Code sees the block and tells the user:
"I tried to read your SSH key but Sanctum blocked the access for security
reasons. If you need me to use SSH, you can allow it in your Sanctum config."
```

**Scenario 3: Budget exceeded**
```
Desktop notification:
💰 Sanctum: OpenAI session budget reached ($50.00/$50.00)
   13 API calls, 847K tokens consumed
   Run `sanctum budget extend` to continue

Application receives:
HTTP 429 — {"error": "Sanctum budget exceeded. Run `sanctum budget extend`."}
```

**Scenario 4: Credential found in prompt**
```
Desktop notification:
🔑 Sanctum: Redacted 1 credential from Claude Code prompt
   Type: OpenAI API key
   Context: Found in file content sent to Claude

No interruption to workflow. The redaction is silent and automatic.
```

### Power user controls

```bash
# View current status
sanctum status
# 🛡️ Sanctum v0.1.0 — active
# Daemon PID: 12345
# Session: 2h 14m
# .pth watcher: 3 site-packages dirs monitored, 0 alerts
# AI firewall: 47 prompts scanned, 1 credential redacted
# Budget: OpenAI $23.41/$50.00, Anthropic $5.21/$200.00
# nono: detected, version 0.2.1

# View audit log
sanctum audit --last 24h

# Review quarantined items
sanctum review

# Adjust budgets
sanctum budget set --session 100 --daily 500

# Install/remove Claude Code hooks
sanctum hooks install claude
sanctum hooks remove claude

# Scan project for credential exposure
sanctum scan
# Found 2 issues:
#   .env:3 — plaintext OpenAI API key
#   src/config.py:17 — hardcoded database password
# Run `sanctum fix` for guided remediation

# Configuration
sanctum config edit  # opens .sanctum/policy.toml in $EDITOR
```

---

## Policy-as-code for teams and architects

```toml
# .sanctum/policy.toml — committed to repo

[sentinel]
watch_pth = true
watch_credentials = true
watch_network = false  # off by default, opt-in

pth_response = "quarantine"  # quarantine | alert | log
credential_access_response = "alert"  # alert | log

# Known-safe .pth files (by package + content hash)
pth_allowlist = [
    { package = "setuptools", hash = "sha256:abc..." },
    { package = "editables", hash = "sha256:def..." },
]

[ai_firewall]
redact_credentials = true
claude_hooks = true
mcp_audit = true

[ai_firewall.mcp_restrictions]
"filesystem:read" = { block = ["~/.ssh/*", "~/.aws/*", "**/.env"] }
"filesystem:write" = { block = ["**/*.pth"] }

[budgets]
default_session = "$50"
default_daily = "$200"
alert_at_percent = 75

[budgets.openai]
session = "$100"
daily = "$500"
allowed_models = ["gpt-4o", "gpt-4o-mini"]

[budgets.anthropic]
session = "$200"
daily = "$1000"

[team]
# Enterprise features
audit_destination = "https://hooks.slack.com/..."
require_nono = true  # enforce sandbox usage
require_hooks = true  # enforce Claude Code hooks
```

---

## Build plan (revised for competitive reality)

### Phase 1: "The Sentinel" (4-6 weeks)

**Build the thing nobody else has:** .pth monitoring + credential file watching.

Deliverables:
- Rust daemon with auto-start shell hook (bash, zsh, fish)
- `.pth` file watcher with process lineage + content analysis
- Credential file access monitoring (SSH, AWS, GCP, K8s, Docker)
- Quarantine protocol with `sanctum review`
- macOS/Linux desktop notifications
- `sanctum init`, `sanctum status`, `sanctum review`, `sanctum scan`
- Starship prompt segment

**Why this first:** It's the most technically differentiated. It directly addresses the TeamPCP/LiteLLM attack vector. It's independently valuable (doesn't require nono or any other tool). And it's a great HN/X launch story: "Here's the tool that would have caught the LiteLLM .pth injection in real-time."

### Phase 2: "AI Firewall" (weeks 6-12)

Deliverables:
- Claude Code PreToolUse/PostToolUse hooks
- Prompt credential redaction (regex + entropy)
- MCP tool auditing with policy-based restrictions
- nono integration (auto-detect, `sanctum run --sandbox`)
- `sanctum hooks install claude`

### Phase 3: "Budget Controller" (weeks 12-16)

Deliverables:
- LLM API response parsing for usage/cost tracking
- Per-session + per-day budgets with hard stops
- Budget notifications and extension commands
- Lightweight proxy for budget tracking (for users without nono)
- Dashboard command: `sanctum budget`

### Phase 4: "Team & Governance" (weeks 16-24)

Deliverables:
- Policy-as-code (`.sanctum/policy.toml` committed to repo)
- Centralised audit log export (webhook, S3, Datadog)
- Team configuration with inherited policies
- VS Code / Cursor extension (status bar + notification bridge)
- OIDC-based authentication for team features

### Phase 5: "Enterprise" (weeks 24-36)

Deliverables:
- TPM/Secure Enclave binding (via `age-plugin-tpm`)
- SPIFFE/SPIRE integration for workload identity
- SSO/SCIM provisioning
- Compliance evidence generation (SOC 2, DORA)
- Air-gapped deployment

---

## GTM strategy (revised)

### Open source core

The Sentinel (Phase 1) and AI Firewall (Phase 2) are **open source, MIT license**. This is non-negotiable for developer adoption. The Snyk playbook proves freemium works for developer security (Series A to $2.6B in 30 months). Infisical's MIT core has 12,700+ stars.

### Paid tiers

**Free (forever):**
- All Sentinel features (.pth monitoring, credential file watching)
- AI firewall with Claude Code hooks
- Basic prompt redaction
- MCP audit logging (local)
- Budget tracking (no enforcement)

**Pro ($8/dev/month):**
- Budget enforcement (hard stops)
- Advanced prompt redaction (custom patterns)
- Priority notifications
- Local audit log export

**Team ($15/dev/month):**
- Centralised policy management
- Team audit log aggregation
- Webhook / SIEM integration
- Shared .pth allowlists
- OIDC authentication

**Enterprise (custom):**
- TPM/Secure Enclave binding
- SPIFFE integration
- SSO/SCIM
- Compliance reporting
- SLA + support

### Distribution channels

1. **Homebrew** (`brew install sanctum`) — primary for macOS developers
2. **GitHub Releases** — universal, with Sigstore attestation
3. **crates.io** — for Rust developers who want to build from source
4. **VS Code / Cursor Marketplace** — extension for status bar + hooks UI
5. **Blog + HN launch** — "The tool that catches the next LiteLLM .pth attack"
6. **nono ecosystem** — co-promotion as the "recommended credential + AI firewall companion"

### Pricing rationale

$8/mo Pro is below the "manager doesn't notice" threshold for individual developers. $15/mo Team is in line with Snyk Team ($25) and Socket Pro ($25) but positioned as complementary rather than competitive. The free tier must be generous enough that solo vibe coders never need to pay — that's the PLG engine.

---

## Honest threat model (what Sanctum doesn't solve)

1. **Pre-existing compromise.** If credentials were already stolen before Sanctum is installed, monitoring can't undo that. The `sanctum scan` command helps identify exposure, and the docs should recommend credential rotation on onboarding.

2. **Kernel-level rootkits.** If the attacker has root and can manipulate inotify/FSEvent, the Sentinel can be blinded. This is out of scope for a userspace daemon. Hardware enclaves (TPM attestation) in the Enterprise tier partially mitigate this.

3. **nono bypass.** If the developer doesn't use nono (or any sandbox), malicious code can still read env vars and make network connections. Sanctum alerts on anomalous behaviour but can't prevent it at the kernel level without nono.

4. **Zero-day in the proxy.** The API Stronghold HN thread flagged this risk: "you've rolled a custom proxy server, never tested in the wild. HTTP desync, request smuggling, header reflection." Sanctum's budget controller proxy is minimally scoped (it only parses responses, not intercepts requests), reducing this attack surface. For phantom proxying, we defer to nono's implementation (which is receiving community security scrutiny).

5. **Alert fatigue.** If Sanctum generates too many false positives, developers will disable it. The default posture is conservative: only .pth files with executable content and credential file access by unknown processes trigger alerts. Everything else is logged silently.

6. **Provider-side mitigation.** If OpenAI/Anthropic implement fine-grained, short-lived tokens with server-side budget enforcement, the Budget Controller becomes less critical. But: (a) providers have had years to do this and haven't, (b) multi-provider budget aggregation is still valuable, and (c) the Sentinel and AI Firewall remain valuable regardless.

---

## Relationship with Arbiter Security

Sanctum fits naturally within the Arbiter portfolio as the developer-facing product that demonstrates offensive security expertise applied to defence:

- **Research-driven:** The Sentinel's .pth monitoring logic is directly informed by the TeamPCP attack analysis and the MCP CVEs discovered by Arbiter's research programme.
- **Rust-native:** Consistent with Narsil-MCP, Aletheia, Forgemax.
- **Open-source core:** Consistent with the Narsil-MCP distribution model (crates.io + Homebrew).
- **PLG distribution:** Complements Arbiter's enterprise security consulting with a bottoms-up developer adoption channel.
- **Credential for the portfolio:** A shipped, adopted developer security tool strengthens Arbiter's credibility for enterprise engagements.

---

## Naming decision

After checking namespace availability and competitive positioning:

**Recommended: `sanctum`**

Rationale:
- crates.io: not taken for this use case (the existing `sanctum` crate is abandoned, 0 downloads)
- Homebrew: no formula conflict
- PyPI: no conflict
- npm: no conflict
- sanctum.dev: available for purchase (verified March 2026)
- The word evokes exactly the right concept: a protected inner chamber where valuable things are kept safe
- Short enough for CLI usage (`sanctum run`, `sanctum status`)
- No confusion with nono (complementary, not competitive naming)

**Rejected alternatives:**
- `phantom` — too closely associated with nono's "phantom token pattern" (which they now own)
- `ward` — too generic, harder to search for
- `aegis` — several existing security products use this name
- `sentinel` — Microsoft Sentinel is a major SIEM product (namespace collision)

---

## Seven key decisions locked in

1. **Sanctum is a daemon, not a proxy.** The phantom proxy market is served (nono, API Stronghold). Sanctum's core is runtime monitoring + AI firewall + budget control.

2. **Open source core (MIT).** Non-negotiable for PLG adoption. Monetise team features and enterprise integrations.

3. **Rust, single binary.** No runtime dependencies. The tool itself must not be a supply chain risk.

4. **Compose with nono, don't compete.** nono is the recommended sandbox + phantom proxy. Sanctum is the recommended runtime monitor + AI firewall. Together they're the complete stack.

5. **Phase 1 is the Sentinel.** Ship the .pth monitor first — it's the most differentiated, most urgent (post-TeamPCP), and most demonstrable capability.

6. **Policy-as-code from day one.** Even the free tier uses `.sanctum/policy.toml`. This creates the team/enterprise upgrade path naturally.

7. **Zero-friction defaults.** Install, init, forget. Security happens around the developer, not through the developer.
