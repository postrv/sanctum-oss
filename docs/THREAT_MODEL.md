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

### 3. AI tool credential leakage

**Threat**: AI coding tools (Claude Code, Cursor) read source files containing credentials and send them to LLM providers.

**Mitigation**: The AI Firewall provides layered credential detection:

- **Pattern-based detection**: 37 compiled regex patterns covering API keys from major providers (OpenAI, Anthropic, Google, AWS, GitHub, GitLab, Stripe, Slack, SendGrid, npm, PyPI, DigitalOcean, Datadog, Azure SAS, Vercel, Docker Hub, Hashicorp Vault, Hugging Face, Shopify, Linear, Supabase, PlanetScale, Fly.io, Railway, Render, Terraform Cloud, Mailgun, Grafana, Neon DB, and others), plus JWTs, Bearer tokens, private key headers, and database connection strings. Patterns are ordered from most specific to least specific to avoid misclassification.
- **Shannon entropy detection**: Strings not matching known patterns are evaluated by an entropy calculator (`entropy.rs`). Strings at least N characters long with entropy above a configurable threshold and at least 70% alphanumeric characters are flagged as potential secrets.
- **Claude Code hooks** enforce security policy across five interception points:
  - **pre-bash**: Blocks reading credential files via direct commands (cat, less, head, tail, more, tac, nl, strings, rev, sort, od, hexdump, xxd, source, .) and indirect commands (grep, awk, sed, python, base64, xargs, node -e, ruby -e, perl -e, php -r, git show, git diff, git log, docker exec, kubectl exec, deno eval, openssl, gpg, ssh-keygen, age, cp, mv, dd, find, ln, rsync, scp, tar, zip, 7z, diff, bat, batcat), including tab-delimited bypass attempts, shell input redirections (`<`), curl data exfiltration (`-d @file`, `--data @file`), network exfiltration commands (nc, ncat, socat, telnet, wget --post), and indirect access constructs (eval, source, $(), backticks, exec). Blocks echoing/printing sensitive environment variables. Blocks environment-dumping commands: bare `env`, `printenv`, `declare -p`, `declare -x`, `env | grep`, `set | grep`, `export | grep`, and `printf` referencing sensitive vars. Detects `/proc/self/environ` reads. Warns on `pip install` (typosquatting risk) and outbound `curl POST` (exfiltration risk).
  - **pre-write**: Blocks writing `.pth` files and `sitecustomize.py` (supply chain attack vectors). Scans file content (including Edit tool `old_string`/`new_string` fields) for credentials using the pattern registry and blocks writes containing detected secrets. Blocks writes to high-risk paths (`authorized_keys`, cron, systemd autostart). Warns on writes to persistence paths (`.bashrc`, `.zshrc`).
  - **pre-read**: Blocks reading files under `~/.ssh/`, `~/.aws/`, `~/.gnupg/`, `~/.config/gcloud/`, `~/.config/gh/`, and `.env` files (including `.env.local`, `.env.production`, `.env.staging`, `.env.development`), shell history files, and other sensitive paths.
  - **pre-mcp**: Audits MCP tool calls against policy rules, blocks access to sensitive paths (`.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`, `sitecustomize.py`) regardless of user rules.
  - **post-bash**: Warns (never blocks) on suspicious side effects observed after command execution: `.pth` file creation during package installs, crontab modifications, systemd user service creation, and network listener activity in command output.

**Residual risk**: Novel credential formats not matching any of the 37 known patterns and falling below the entropy threshold may not be detected. Base64-encoded or split-across-multiple-writes credentials may evade pattern matching, though the entropy fallback partially mitigates this for sufficiently long encoded strings.

### 4. Runaway LLM spend

**Threat**: AI tools consume excessive API credits through long-running sessions or loops.

**Mitigation**: The Budget Controller tracks per-provider spending with session and daily limits:

- **Tracking**: A `BudgetTracker` maintains per-provider spend accumulators (in cents) for both session and daily periods. Costs are computed from token counts using per-model pricing tables. Spend is monotonically increasing within a session (uses `saturating_add`). Daily counters reset automatically at UTC day boundaries.
- **Enforcement**: `check_budget()` returns one of three decisions: `Allowed` (within budget), `Warning` (alert threshold crossed, configurable as a percentage), or `Blocked` (session or daily limit exceeded). A structured JSON 429 response body is generated for blocked requests.
- **Model allowlists**: Per-provider `allowed_models` lists restrict which models can be used (case-insensitive matching).
- **Session management**: Budgets can be extended, reset, queried, and configured via IPC commands (`BudgetStatus`, `BudgetSet`, `BudgetExtend`, `BudgetReset`).
- **Persistence**: Tracker state is serialized to disk as JSON with 0o600 permissions, allowing recovery across daemon restarts.
- **Budget recording**: Usage can be reported manually via `sanctum budget record --provider <name> --model <model> --input-tokens <n> --output-tokens <n>`. The `post-bash` hook detects API usage in command output and logs a warning. Automatic IPC-based recording from hooks is planned for a future release.

**Residual risk**: Cost tracking relies on token-based pricing tables, which must be kept in sync with provider pricing. The `sanctum-proxy` crate provides the foundation for transparent API interception; until the full MITM proxy is active, enforcement requires the AI tool to participate via hook-based IPC integration.

### 5. Quarantine metadata tampering

**Threat**: An attacker modifies quarantine metadata to cause a restore operation to overwrite a sensitive system file (e.g., `/etc/passwd`).

**Mitigation**: The quarantine restore path is validated via `validate_restore_path()`, which enforces three checks: the path must be absolute, must not contain `..` traversal components, and must not target sensitive system directories (`/etc`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/System`, `/Library`). Quarantine IDs are separately validated by `validate_id()`, which rejects empty IDs, IDs containing path separators (`/` or `\`), IDs containing `..`, and IDs that resolve outside the quarantine directory via canonicalization.

**Residual risk**: If the quarantine directory itself is on a compromised filesystem, canonicalization checks could be subverted.

### 6. Directory traversal via symlinks during scanning

**Threat**: Malicious symlinks in a project directory cause the `sanctum scan` command to follow symlinks into sensitive areas or loop infinitely.

**Mitigation**: The `walk_dir` function uses `symlink_metadata()` instead of `metadata()` to detect symlinks without following them. Symlinked directories are skipped entirely (only real directories are recursed into). A depth limit of 50 levels prevents stack exhaustion from deeply nested structures.

**Residual risk**: The depth limit is hardcoded; extremely deep legitimate directory trees beyond 50 levels will not be scanned.

### 7. IPC denial of service via oversized messages

**Threat**: A malicious process sends an oversized message to the daemon's Unix socket, exhausting memory.

**Mitigation**: All IPC communication uses a length-prefixed framing protocol (`[4 bytes big-endian length][JSON payload]`). Both `read_frame()` and `write_frame()` enforce a `MAX_MESSAGE_SIZE` of 64KB. Messages exceeding this limit are rejected with an error before any payload allocation occurs.

**Residual risk**: Rate limiting is enforced at the IPC layer via a per-connection token-bucket limiter (100 messages/second). A sustained flood from multiple connections could still consume CPU.

### 8. Audit log tampering

**Threat**: An attacker modifies or deletes audit log entries to hide evidence of a compromise.

**Mitigation**: The audit log is append-only NDJSON (one JSON object per line), opened with `O_APPEND` semantics. File permissions are set to 0o600 (owner read/write only) on creation. Audit logging errors are logged via tracing but never propagated, so a failure to write the audit log cannot crash the daemon.

**Residual risk**: A process running as the same user can still modify the file. For tamper-evident logging, an external log collector would be needed.

### 9. Network-based data exfiltration and C2 beaconing

**Threat**: Malicious code establishes outbound connections to exfiltrate data or communicate with command-and-control servers.

**Mitigation**: The network anomaly detection module (`sanctum-sentinel/src/network/`) monitors outbound connections via platform-specific collection (macOS: `lsof -i`, Linux: `/proc/net/tcp`). Detection is rule-based: connections to unusual ports (outside the configured `safe_ports` list), blocklisted destinations, and connections from processes not on the `process_allowlist` are flagged. The `learning_period_days` config field is reserved for future adaptive baseline learning but is not yet implemented — current detection relies on the static configuration.

**Residual risk**: The polling-based approach (default 30-second interval) cannot detect very short-lived connections. Detection is metadata-only (IP, port, process) -- packet contents are not inspected. An attacker using standard ports (80, 443) to known CDN endpoints would not be flagged.

### 10. npm lifecycle hook attacks

**Threat**: Malicious npm packages use `preinstall` or `postinstall` lifecycle scripts to execute arbitrary code during `npm install`, `yarn add`, `pnpm add`, or `bun add`. This is the JavaScript equivalent of Python `.pth` injection. The Shai-Hulud worm (which compromised packages with 2.6 billion weekly downloads) demonstrates the canonical attack pattern: a `postinstall` script spawns a detached child process via `child_process.spawn()` with `.unref()`, which outlives the install process and harvests credentials from `.npmrc`, `NPM_CONFIG_TOKEN`, and other sensitive paths. The detached process evades simple parent-process monitoring because it is no longer a child of `npm`.

**Mitigation**: Sanctum detects npm lifecycle hook attacks through three complementary mechanisms:

- **post_bash lifecycle script detection**: After any npm/yarn/pnpm/bun install command, `post_bash` scans command output for lifecycle script execution indicators (`postinstall`, `preinstall`, `node-gyp rebuild`, etc.). Unknown packages running lifecycle scripts trigger warnings. Scripts containing `eval()`, `child_process`, `.unref()`, `process.env`, credential path access, or network exfiltration patterns are escalated to critical threat events and written to the audit log.
- **pre_bash `--ignore-scripts` suggestion**: When `pre_bash` detects an npm install command without `--ignore-scripts`, it emits a warning suggesting the safer invocation. This is informational (warn, not block) because many legitimate packages require lifecycle hooks.
- **Credential path monitoring**: The existing credential file watcher and pre_read/pre_bash hooks block access to `.npmrc`, `~/.ssh/`, `~/.aws/`, and other sensitive paths. The `NPM_CONFIG_TOKEN` environment variable is included in the sensitive environment variable blocklist. This neutralises the exfiltration stage of lifecycle hook attacks even if the script executes.

An allowlist of known-safe lifecycle packages (esbuild, puppeteer, sharp, node-gyp, etc.) suppresses warnings for packages that legitimately require build-time scripts. Unknown packages are warned; only verified-safe packages are exempted.

**Residual risk**: Detection via `post_bash` is limited to install commands visible through Claude Code hooks. Direct terminal `npm install` commands run outside of an AI tool session are not caught until Phase 3 filesystem-level monitoring is active. Lifecycle scripts that avoid all suspicious content patterns may produce false negatives.

### 11. Clinejection via poisoned project configurations

**Threat**: An attacker crafts a project repository with malicious configuration files (e.g., `.clinerules`, `.cursorrules`, MCP server configs) that inject commands when an AI coding tool processes the repository. The AI tool reads the poisoned config, interprets embedded instructions, and executes attacker-controlled commands through its tool-calling interface. This is a prompt injection attack that uses project files as the injection vector.

**Mitigation**: Sanctum mitigates Clinejection through three layers:

- **MCP policy engine**: The `pre_mcp` hook audits all MCP tool calls against policy rules. Built-in path restrictions block MCP tools from accessing sensitive paths (`.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`) regardless of user-defined rules. Configurable `default_mcp_policy` allows users to set deny-by-default for MCP tools.
- **pre_bash hook**: All commands suggested by the AI tool pass through `pre_bash`, which blocks credential access, environment variable exfiltration, and dangerous commands. A poisoned config that instructs the AI to `cat ~/.ssh/id_rsa` is blocked by the same rules that protect against any other credential access attempt.
- **Security floor enforcement**: Project-local Sanctum configs cannot lower the security posture. `claude_hooks`, `redact_credentials`, and `mcp_audit` are pinned to global values and cannot be disabled by a malicious `.sanctum/config.toml` in the repository.

**Residual risk**: If the AI tool executes a command that Sanctum does not recognise as dangerous (novel exfiltration technique, indirect data access), the injected command may succeed. Sanctum's blocklist-based approach cannot anticipate every possible injected command, though the credential path monitoring provides defense-in-depth.

### 12. Unresolved threats accumulating without remediation

**Threat**: Threats are detected and logged but never reviewed, leading to alert fatigue and unaddressed security events.

**Mitigation**: The `sanctum fix` command provides guided remediation with content-addressed threat IDs. Each threat in the audit log receives a deterministic ID (SHA-256 of timestamp, category, and source path). Resolutions are tracked in a separate `resolutions.log` (NDJSON, 0o600 permissions), preserving the audit log's append-only integrity. Remediation actions include restore, delete, dismiss, allowlist, and policy update.

**Residual risk**: The `--yes` flag in batch mode defaults to "dismiss", which resolves threats without addressing root causes. Critical threat restoration requires explicit confirmation.

## What Sanctum does NOT protect against

1. **Pre-existing compromise** -- If credentials were already stolen, monitoring cannot undo that.
2. **Kernel-level rootkits** -- A userspace daemon cannot detect kernel-level tampering.
3. **Network-level blocking** -- Without a kernel sandbox, Sanctum alerts on suspicious connections but cannot block them. Network anomaly detection is observe-only.
4. **Hardware-level attacks** -- Out of scope for a software daemon.
5. **Social engineering** -- Sanctum protects against automated attacks, not human deception.

## Trust boundaries

```
+----------------------------------------------------------+
| TRUSTED: Sanctum daemon process                          |
|  - Has filesystem read access                            |
|  - Runs as the developer's user (not root)               |
|  - Communicates only via local Unix socket (0o600)       |
|  - Makes NO outbound network connections                 |
|  - Audit log is append-only NDJSON with 0o600 perms      |
|  - PID file uses race-free exclusive creation (O_CREAT   |
|    | O_EXCL via create_new)                              |
+----------------------------------------------------------+

+----------------------------------------------------------+
| UNTRUSTED: Packages installed via pip/npm/yarn/pnpm/bun  |
|  - May contain malicious .pth files (Python)             |
|  - May execute lifecycle hooks (npm preinstall/           |
|    postinstall) that spawn detached processes             |
|  - May attempt credential exfiltration                   |
|  - May create persistent backdoors                       |
+----------------------------------------------------------+

+----------------------------------------------------------+
| SEMI-TRUSTED: AI tools (Claude Code, Cursor, etc.)       |
|  - May read source files containing credentials          |
|  - Send content to external LLM providers                |
|  - Subject to AI Firewall hook enforcement               |
|  - Budget-controlled via IPC                             |
+----------------------------------------------------------+

+----------------------------------------------------------+
| UNTRUSTED: LLM providers (OpenAI, Anthropic, Google)     |
|  - Receive tool call content from AI tools               |
|  - Credential redaction happens BEFORE content reaches   |
|    the provider                                          |
|  - Budget tracking monitors costs per provider           |
+----------------------------------------------------------+
```
