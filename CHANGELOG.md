# Changelog

All notable changes to Sanctum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Sigstore binary signing**: Release workflow with keyless OIDC signing via GitHub Actions, Rekor transparency log entries, signed SHA256SUMS, and signed CycloneDX SBOM
- **Install script verification**: `scripts/install.sh` verifies Sigstore signatures when cosign is available
- **Kani proof integration**: 4 bounded model checking proofs integrated as `#[cfg(kani)]` modules (analyser panic-freedom, path classification, exec detection, quarantine state machine), CI with fast/nightly split
- **`sanctum fix` command**: Guided threat remediation with content-addressed threat IDs, separate resolution log, `list`/`resolve`/`all` subcommands, 5 new IPC commands
- **Network anomaly detection**: New `network/` module in sanctum-sentinel with platform-specific connection collection (macOS lsof, Linux /proc/net/tcp), rule-based anomaly detection (unusual port, blocklisted destination, unexpected process), configurable allowlists and blocklists
- **HTTP budget proxy foundation**: New `sanctum-proxy` crate with provider identification, config schema, error types (actual TLS MITM proxy deferred to next sub-phase)
- **New threat categories**: `McpViolation` and `BudgetOverrun` added to `ThreatCategory`
- **Credential allowlist**: Configurable `credential_allowlist` in `SentinelConfig`
- **IPC rate limiting**: Per-connection token-bucket rate limiter (100 messages/second) closes IPC DoS residual risk
- **Credential patterns**: 37 credential patterns total (Vercel, Docker Hub, Hashicorp Vault, Hugging Face, Shopify, Linear, Supabase, PlanetScale, Fly.io, Railway, Render, Terraform Cloud, Mailgun, Grafana, Neon DB added), plus Twilio/Datadog/Azure env var detection in hooks
- **Glob matcher safety**: Multi-star patterns now return false with a warning instead of silently falling through to exact match
- **4 new Kani proofs**: `ceiling_cost_no_overflow`, `validate_id_rejects_traversal`, `shannon_entropy_never_panics`, `glob_matches_exact_match_works` (8 proofs total)
- **Reproducible build verification**: CI job builds twice and compares SHA-256 hashes
- **Nightly extended fuzz testing**: 5-hour fuzz runs via cron schedule (2.5 hours per target)
- **Release workflow gates**: `verify-ci` job checks CI status before building release artifacts
- **Config version field**: `config_version` added to `SanctumConfig` for future migration support
- **Hook audit event persistence**: Hooks now write `ThreatEvent` records directly to the shared NDJSON audit log on block/warn decisions, making hook-detected threats visible in `sanctum audit` and `sanctum fix`
- **Shared audit module**: `sanctum-types::audit` extracted from daemon, enabling both daemon and CLI to write to the same audit log with POSIX atomic guarantees
- **`sanctum budget record` command**: Manual/scripted budget usage reporting (`--provider`, `--model`, `--input-tokens`, `--output-tokens`)
- **MCP configurable default policy**: `default_mcp_policy` config field (`allow`/`warn`/`deny`) controls decisions for tools with no matching rules
- **MCP built-in sensitive path restrictions**: All MCP tools are blocked from accessing `.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`, `sitecustomize.py`, and other sensitive paths, regardless of user rules
- **macOS credential access tracing**: Best-effort `lsof` probe identifies which process accessed credential files (previously returned no process info on macOS)
- **BudgetOverrun threat events**: Budget limit exceedances now emit `ThreatEvent` records to the audit log
- **1,170 tests** across 8 crates (up from 899)

### Fixed
- **`sanctum scan` exit code**: Returns non-zero exit code when credential findings are detected, enabling CI/CD gate checks
- **`sanctum doctor` exit code**: Returns non-zero exit code when health checks fail
- **`BudgetSet` preserves unspecified limits**: `sanctum budget set --session $50` no longer silently clears the daily limit
- **Budget display `daily_exceeded` flag**: `sanctum budget` now shows `[DAILY EXCEEDED]` when the daily budget is exceeded
- **`hooks install claude` preserves existing hooks**: Merges Sanctum hooks with existing Claude Code hooks instead of overwriting them
- **`python3 -u -c` bypass**: Script environment access detection no longer requires `-c` flag to be adjacent to the interpreter name
- **`infer_provider` standalone models**: `o1`, `o3`, `o4` model names without trailing dash now correctly map to OpenAI
- **Claude Code hooks JSON format**: Migrated from deprecated flat format to current three-level nested format (`hooks: [{ type: "command", command }]`) — without this fix, hooks were silently ignored by Claude Code
- **Write-hook matcher**: Added `NotebookEdit` tool to pre-write matcher (`Write|Edit|MultiEdit|NotebookEdit`) — prevents credential-content bypass via NotebookEdit/MultiEdit tools
- **MCP hook matcher**: Changed from `"mcp"` (literal, never matched) to `"mcp__.*"` (regex, matches all MCP tool invocations)
- **Hook handler fail-closed**: All hook errors now exit with code 2 (block) instead of code 1 (allow) — prevents fail-open on stdin/JSON parse errors
- **Edit tool credential scanning**: Pre-write hook now scans `old_string`/`new_string` fields (used by Edit/MultiEdit), not just `content` — closes credential bypass via Edit tool
- **Command blocklist expansion**: Added 11 indirect read commands (`xargs`, `node -e`, `ruby -e`, `perl -e`, `php -r`, `git show`, `git diff`, `git log`, `docker exec`, `kubectl exec`, `deno eval`) and `exec` to indirect access constructs
- **curl data exfiltration**: Added `-d @file`, `--data @file`, `--data-binary @file` detection to curl upload blocking
- **Sensitive write path warnings**: Pre-write hook now warns on writes to `.bashrc`, `.zshrc`, `authorized_keys`, cron paths, systemd autostart
- **Sensitive read path expansion**: Added `.gnupg/`, `.config/gcloud/`, `.config/gh/`, `.env.local`, `.env.production`, `.bash_history`, `.zsh_history` to pre-read blocking
- **Property test fix**: `file_severity_is_max_of_lines` now correctly handles continuation-line semantics (severity >= max, not ==)
- **Credential scanning unconditional**: `pre_write` now always scans for credentials regardless of `redact_credentials` config (defense-in-depth — config hardening already forced this to `true`)
- **Dead threat categories wired**: `SiteCustomize`, `McpViolation`, and `BudgetOverrun` now emit `ThreatEvent` records at their natural detection points
- **False budget docs corrected**: Documentation no longer claims automatic IPC-based budget recording from hooks (manual recording via `sanctum budget record` is available)
- **Resolution log rotation**: Resolution log now rotates at 10MB (was unbounded)

### Security
- **Project-local config hardening**: Security-critical settings (`claude_hooks`, `redact_credentials`, `watch_pth`, `pth_response`, `mcp_audit`) are pinned to global config values and cannot be weakened by project-local `.sanctum/config.toml` — prevents malicious repos from disabling protections
- **Fail-closed config loading**: Hook config parse errors now apply restrictive defaults (all protections enabled) instead of silently running with no firewall rules
- **Async event loop safety**: Blocking file I/O, process spawning, and quarantine operations offloaded to `spawn_blocking` to prevent stalling the daemon event loop
- **Quarantine integrity**: Atomic metadata writes (write-temp-then-rename), O_NOFOLLOW on stub/restore writes (eliminates TOCTOU symlink race), restore temp files in quarantine directory (not attacker-controlled path), constant-time hash comparison, corrupted metadata warnings instead of silent skipping
- **Audit event correctness**: Quarantine failure now records `Action::Logged` instead of false `Action::Quarantined`
- **IPC response truncation**: `ListThreats` capped at 500 items to prevent exceeding 64KB frame limit
- **Resolution log durability**: Write failures now propagate as IPC errors instead of silently succeeding
- **Periodic budget persistence**: Budget state saved every 5 minutes instead of only on clean shutdown
- **Defence-in-depth expansion**: D7 catch-all extended to 20 credential paths (was 10); 9 indirect read commands added (`ln`, `rsync`, `scp`, `tar`, `zip`, `7z`, `diff`, `bat`, `batcat`)
- **PTH analyser hardening**: 5 new critical keywords (`getattr(`, `importlib`, `open(`, `codecs.`, `ctypes`), Unicode homoglyph detection expanded to all critical keywords, `\r\n` continuation line support
- **Config directory permissions**: `.sanctum/` created with 0o700, config files with 0o600
- **Temp file cleanup**: All write-temp-then-rename paths now clean up on failure
- **IPC socket directory permissions**: Failure to set 0o700 now logged as error instead of silently ignored
- **PID file fsync**: fsync after PID write for crash safety (prevents dual-daemon race)
- **IPC `id` field length validation**: `id` field capped at 128 characters to prevent oversized payloads
- **`IpcMessage` custom Debug impl**: Redacts auth token from log output
- **`RecordUsage` token count validation**: Token counts capped at 100M per field
- **`read_token()` O_NOFOLLOW**: Consistent with `write_token()`, prevents symlink-based token theft
- **Quarantine file read O_NOFOLLOW**: Prevents symlink-based content exfiltration from quarantine
- **PTH analyser whitespace detection**: Detects Python import statements using form feed, vertical tab, and carriage return whitespace
- **Extended Unicode homoglyph map**: Greek omicron, alpha, and fullwidth character variants added
- **`ensure_secure_dir` permission correction**: Verifies and corrects permissions on existing directories
- **Security floor extension**: `watch_credentials` and `credential_allowlist` cannot be weakened by project-local configs
- **Config file size limit**: 1MB maximum prevents denial-of-service via oversized config
- **Config directory 0o700 permissions**: Config directory created with restrictive permissions
- **Network exfiltration command detection**: `nc`, `ncat`, `socat`, `telnet`, `wget --post` detected with credential path blocking
- **Full environment dump detection**: Python `os.environ` dump and Node `process.env` dump detection in scripts
- **High-risk write path blocking**: `authorized_keys`, crontab, systemd autostart paths now blocked (not just warned)
- **Additional credential file patterns**: `.vault-token`, `.my.cnf`, `.boto`, `application-default-credentials.json`
- **`ListThreats` iterator optimization**: Prevents unbounded memory allocation
- **`/proc/self/environ` detection**: Commands reading process environment files are now blocked
- **`declare -p` / `declare -x` env dump detection**: Bash builtins that dump all variables are now detected
- **Crypto tool credential access**: `openssl`, `gpg`, `gpg2`, `ssh-keygen`, `age`, `age-keygen` added to indirect read command list
- **`.env-backup` / `.env_old` credential patterns**: `.env-`, `.env_`, `.env.backup`, `.env.bak`, `.env.old`, `.env.save` variants now detected
- **`ResolveThreat` action/note validation**: Action field capped at 64 chars, note at 2,048 chars
- **`default_mcp_policy` security floor**: Project-local configs can no longer set MCP default policy to `allow` when global is stricter
- **`credential_allowlist` subset enforcement**: Project-local allowlist must be a strict subset of global (was length-only check)
- **`config --edit` file permissions**: Config files created via `--edit` now get 0o600 permissions
- **Package manager lineage**: `pipenv`, `hatch`, `flit` added to known package managers (prevents false positive PTH alerts)
- **Network config CIDR documentation**: Corrected doc comments to clarify that only exact IP addresses are supported (not CIDR ranges)

## [0.1.0] - 2026-03-27

### Added
- **The Sentinel**: .pth file monitoring with content analysis, process lineage tracing, and quarantine protocol
- **Credential file monitoring**: Watches ~/.ssh, ~/.aws, ~/.kube and alerts on unexpected access
- **AI Firewall**: Claude Code hook handlers (pre-bash, pre-write, pre-read, post-bash) with 20 credential patterns
- **Shannon entropy analysis**: Detects high-entropy secrets not matching known patterns
- **MCP policy engine**: Configurable tool restrictions via `[[ai_firewall.mcp_rules]]`
- **Budget Controller**: Per-provider, per-session, per-day spend limits with 3 API response parsers
- **Budget recording via IPC**: `RecordUsage` command allows hooks to report API spend to the daemon
- **Config-aware hooks**: `claude_hooks` and `redact_credentials` config flags honored at runtime
- **NDJSON audit log**: Append-only threat event persistence with 0o600 permissions
- **511 tests** across 7 crates, 0 clippy warnings (pedantic + nursery)
- **Fuzz targets**: pth_analyser and config_parser with CI integration
- **Property-based tests**: 6 sentinel + 3 budget proptest harnesses

### Security
- Zero `unsafe` code (denied by workspace lint)
- No `unwrap`/`expect`/`panic` outside test code (denied by clippy)
- Race-free PID file creation via O_CREAT|O_EXCL
- IPC messages capped at 64KB, Unix socket permissions 0o600
- Quarantine restore validates paths against traversal and sensitive system directories
- AppleScript injection prevention in macOS notifications
- Budget state files persisted with 0o600 permissions
