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
- **Network anomaly detection**: New `network/` module in sanctum-sentinel with platform-specific connection collection (macOS lsof, Linux /proc/net/tcp), anomaly detection heuristics (unusual port, blocklisted destination, unexpected process), baseline learning, configurable allowlists and blocklists
- **HTTP budget proxy foundation**: New `sanctum-proxy` crate with provider identification, config schema, error types (actual TLS MITM proxy deferred to next sub-phase)
- **New threat categories**: `McpViolation` and `BudgetOverrun` added to `ThreatCategory`
- **Credential allowlist**: Configurable `credential_allowlist` in `SentinelConfig`
- **IPC rate limiting**: Per-connection token-bucket rate limiter (100 messages/second) closes IPC DoS residual risk
- **Credential patterns**: Added Datadog API/App Key and Azure SAS Token detection (22 patterns total), plus Twilio/Datadog/Azure env var detection in hooks
- **Glob matcher safety**: Multi-star patterns now return false with a warning instead of silently falling through to exact match
- **4 new Kani proofs**: `ceiling_cost_no_overflow`, `validate_id_rejects_traversal`, `shannon_entropy_never_panics`, `glob_matches_exact_match_works` (8 proofs total)
- **Reproducible build verification**: CI job builds twice and compares SHA-256 hashes
- **Nightly extended fuzz testing**: 5-hour fuzz runs via cron schedule (2.5 hours per target)
- **Release workflow gates**: `verify-ci` job checks CI status before building release artifacts
- **580 tests** across 8 crates (up from 511)

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
