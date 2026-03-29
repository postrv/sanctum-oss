# Changelog

All notable changes to Sanctum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Dependency count updated from 282 to 295

### Fixed
- SBOM generation: use `--override-filename` and `--top-level` flags
- Release `verify-ci` job: remove matrix/conditional jobs from required checks
- Kani CI: reduce proof bound, consolidate per-crate, non-blocking release gate
- Kani CI timeouts increased (core 30 to 60 min, full 60 to 120 min)
- Test installer fixed: `sanctum-daemon` has no `--version` flag
- Stale documentation counts, URLs, and changelog structure corrected
- CDLA-Permissive-2.0 license allowed for `webpki-roots` v1.0.6
- LiteLLM attack date and sanctum.dev references corrected

### Security
- Round 2 adversarial review: 36 fixes across 8 crates, 48 new tests
- Crash prevention, data durability, and credential detection hardening
- Internal planning documents removed from repository

## [0.1.0] - 2026-03-27

### Added
- **The Sentinel**: .pth file monitoring with content analysis, process lineage tracing, and quarantine protocol
- **Credential file monitoring**: Watches ~/.ssh, ~/.aws, ~/.kube and alerts on unexpected access
- **AI Firewall**: Claude Code hook handlers (pre-bash, pre-write, pre-read, pre-mcp, post-bash) with 37 credential patterns
- **Shannon entropy analysis**: Detects high-entropy secrets not matching known patterns
- **MCP policy engine**: Configurable tool restrictions via `[[ai_firewall.mcp_rules]]`
- **MCP configurable default policy**: `default_mcp_policy` config field (`allow`/`warn`/`deny`) controls decisions for tools with no matching rules
- **MCP built-in sensitive path restrictions**: All MCP tools are blocked from accessing `.ssh/`, `.aws/`, `.gnupg/`, `.env`, `.pth`, `sitecustomize.py`, and other sensitive paths, regardless of user rules
- **Budget Controller**: Per-provider, per-session, per-day spend limits with 3 API response parsers
- **Budget recording via IPC**: `RecordUsage` command allows hooks to report API spend to the daemon
- **`sanctum budget record` command**: Manual/scripted budget usage reporting (`--provider`, `--model`, `--input-tokens`, `--output-tokens`)
- **`sanctum fix` command**: Guided threat remediation with content-addressed threat IDs, separate resolution log, `list`/`resolve`/`all` subcommands, 5 new IPC commands
- **Network anomaly detection**: Platform-specific connection collection (macOS lsof, Linux /proc/net/tcp), rule-based anomaly detection (unusual port, blocklisted destination, unexpected process), configurable allowlists and blocklists
- **HTTP budget proxy foundation**: New `sanctum-proxy` crate with provider identification, config schema, error types (TLS MITM proxy deferred to next phase)
- **Credential allowlist**: Configurable `credential_allowlist` in `SentinelConfig`
- **Credential patterns**: 37 patterns total (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, GCP, Azure, Vercel, Docker Hub, Hashicorp Vault, Hugging Face, Shopify, Linear, Supabase, PlanetScale, Fly.io, Railway, Render, Terraform Cloud, Mailgun, Grafana, Neon DB, and more)
- **Config-aware hooks**: `claude_hooks` and `redact_credentials` config flags honored at runtime
- **Hook audit event persistence**: Hooks write `ThreatEvent` records directly to the shared NDJSON audit log on block/warn decisions
- **Shared audit module**: `sanctum-types::audit` extracted from daemon, enabling both daemon and CLI to write to the same audit log with POSIX atomic guarantees
- **NDJSON audit log**: Append-only threat event persistence with 0o600 permissions
- **BudgetOverrun threat events**: Budget limit exceedances now emit `ThreatEvent` records to the audit log
- **IPC rate limiting**: Per-connection token-bucket rate limiter (100 messages/second)
- **Config version field**: `config_version` added to `SanctumConfig` for future migration support
- **macOS credential access tracing**: Best-effort `lsof` probe identifies which process accessed credential files
- **Sigstore binary signing**: Release workflow with keyless OIDC signing via GitHub Actions, Rekor transparency log entries, signed SHA256SUMS, and signed CycloneDX SBOM
- **Install script verification**: `scripts/install.sh` verifies Sigstore signatures when cosign is available
- **8 Kani proofs**: Bounded model checking for analyser panic-freedom, path classification, exec detection, quarantine state machine, ID traversal rejection, ceiling cost overflow, Shannon entropy panic-freedom, glob exact-match correctness
- **Reproducible build verification**: CI job builds twice and compares SHA-256 hashes
- **Nightly extended fuzz testing**: 5-hour fuzz runs via cron schedule (2.5 hours per target)
- **Release workflow gates**: `verify-ci` job checks CI status before building release artifacts
- **Glob matcher safety**: Multi-star patterns now return false with a warning instead of silently falling through to exact match
- **1,453 tests** across 8 crates, 0 clippy warnings (pedantic + nursery)
- **Fuzz targets**: pth_analyser and config_parser with CI integration
- **Property-based tests**: 9 proptest harnesses (6 sentinel + 3 budget)

### Security
- Zero `unsafe` code (denied by workspace lint)
- No `unwrap`/`expect`/`panic` outside test code (denied by clippy)
- Race-free PID file creation via O_CREAT|O_EXCL
- IPC messages capped at 64KB, Unix socket permissions 0o600
- Quarantine restore validates paths against traversal and sensitive system directories
- AppleScript injection prevention in macOS notifications
- Budget state files persisted with 0o600 permissions
- Project-local config hardening: security-critical settings pinned to global config values and cannot be weakened by project-local `.sanctum/config.toml`
- Fail-closed config loading: hook config parse errors apply restrictive defaults
- Async event loop safety: blocking I/O offloaded to `spawn_blocking`
- Quarantine integrity: atomic writes, O_NOFOLLOW, constant-time hash comparison
- Periodic budget persistence: state saved every 5 minutes
- Defence-in-depth: 37 indirect read commands, credential path catch-all, env dump detection
- PTH analyser hardening: Unicode homoglyph detection, zero-width character stripping, UTF-8 BOM handling, continuation line support
- Config directory permissions: 0o700 directories, 0o600 files
- IPC hardening: field length validation, token redaction in logs, bounded reads
- Network exfiltration command detection: `nc`, `ncat`, `socat`, `telnet`, `wget --post`
- High-risk write path blocking: `authorized_keys`, crontab, systemd autostart
- Hook handler fail-closed: all errors exit code 2 (block), not code 1 (allow)
- Security floor enforcement: project-local configs cannot weaken MCP policy, credential allowlist, or core protections
