# Threat Model

## What Sanctum protects against

### 1. Python startup hook injection (MITRE ATT&CK T1546.018)

**Threat**: A malicious package installs a `.pth` file in `site-packages` that executes arbitrary code on every Python interpreter startup. This was the exact vector in the LiteLLM/TeamPCP compromise (CVE-2026-33634).

**Mitigation**: Sanctum monitors all `site-packages` directories for `.pth` file creation/modification. Content analysis classifies lines as benign (path entries), suspicious (executable imports), or critical (obfuscated execution). Process lineage tracing verifies the creator is a legitimate package manager. Critical files are quarantined immediately.

**Residual risk**: If the attacker has root access and can disable inotify/FSEvent, the watcher can be blinded.

### 2. Credential file access by unexpected processes

**Threat**: Malicious code reads SSH keys, cloud credentials, or API tokens from well-known filesystem paths.

**Mitigation**: Sanctum monitors access to credential files (~/.ssh, ~/.aws, ~/.kube, etc.) and alerts when non-allowlisted processes access them.

**Residual risk**: On macOS, FSEvent is less granular than Linux's inotify. Process identification may be imprecise.

### 3. AI tool credential leakage (Phase 2)

**Threat**: AI coding tools (Claude Code, Cursor) read source files containing credentials and send them to LLM providers.

**Mitigation**: Prompt credential redaction scans outbound content for known credential patterns and high-entropy strings. Claude Code hooks intercept tool use before execution.

**Residual risk**: Novel credential formats not matching known patterns may not be detected.

### 4. Runaway LLM spend (Phase 3)

**Threat**: AI tools consume excessive API credits through long-running sessions or loops.

**Mitigation**: Per-session and per-provider budgets with hard enforcement via HTTP 429 responses.

**Residual risk**: Cost tracking relies on API response metadata, which varies by provider.

## What Sanctum does NOT protect against

1. **Pre-existing compromise** — If credentials were already stolen, monitoring can't undo that.
2. **Kernel-level rootkits** — A userspace daemon cannot detect kernel-level tampering.
3. **Network-level exfiltration without nono** — Without kernel sandbox, Sanctum alerts but cannot prevent network access.
4. **Hardware-level attacks** — Out of scope for a software daemon.
5. **Social engineering** — Sanctum protects against automated attacks, not human deception.

## Trust boundaries

```
┌─────────────────────────────────────────────────┐
│ TRUSTED: Sanctum daemon process                  │
│  - Has filesystem read access                    │
│  - Runs as the developer's user (not root)       │
│  - Communicates only via local Unix socket        │
│  - Makes NO outbound network connections (Phase 1)│
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│ UNTRUSTED: Packages installed via pip/npm/etc    │
│  - May contain malicious .pth files              │
│  - May attempt credential exfiltration           │
│  - May create persistent backdoors               │
└─────────────────────────────────────────────────┘
```
