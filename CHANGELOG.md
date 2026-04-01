# Changelog

All notable changes to Sanctum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.1] - 2026-03-31

### Fixed
- **pip `--only-binary`/`--no-binary` extracted as package names**: These flags take a value argument (e.g., `:all:`) that was being treated as a package name and failing registry validation. Added to `value_flags` list so the argument is correctly consumed.

## [0.4.0] - 2026-03-31

### Added
- **Rust/Cargo slopsquatting detection**: `cargo add` and `cargo install` commands checked against crates.io sparse index (RFC 2789) before execution. No rate limits, no User-Agent requirement, CDN-backed.
- **`Registry::CratesIo`** variant with sparse index path computation (1/2/3/4+-char name routing)
- **Crate name validation**: 1-64 ASCII chars, alphanumeric + `-`/`_`, must start with letter
- **Cargo `build.rs` awareness**: `post_bash` detects newly downloaded crates and warns about build script execution risk with actionable next steps
- **Docker image safety checks**: `pre_bash` warns on `:latest`/untagged images and untrusted registries; supports `docker pull/run/create/build`, `podman`, and `docker compose`
- **Dockerfile linting in `pre_write`**: Detects unpinned `FROM` images, `ADD` with remote URLs, and `curl|sh` pipe-to-shell patterns (with multi-line backslash continuation support)
- **`DockerConfig`** with `trusted_registries` (default: docker.io, ghcr.io, gcr.io, public.ecr.aws, registry.k8s.io), `warn_latest`, `warn_remote_add`, `warn_pipe_install`
- **pip source install enforcement**: `warn_source_installs` (default: on) warns about `setup.py` execution risk; `require_binary_only` (default: off) blocks `pip install` without `--only-binary :all:`
- **`PipConfig`** with separate allowlist (previously shared npm's), `warn_source_installs`, `require_binary_only`
- **`CargoConfig`** with `allowlist` and `warn_build_scripts`
- **Go module slopsquatting detection**: `go get` and `go install` commands checked against `proxy.golang.org` before execution
- **`GoConfig`** with `allowlist` (exact match) and `trusted_prefixes` (prefix match, default: `golang.org/x/`, `google.golang.org/`, etc.)
- **Shell-aware command splitting**: Package extraction splits compound commands on shell operators (`&&`, `||`, `;`, `|`, etc.) with quote tracking
- **HTTP 451 (Unavailable For Legal Reasons)** handling for crates.io legal removals (treated as NotFound)
- **Security floor for project-local configs**: Per-ecosystem warning flags (`warn_build_scripts`, `warn_source_installs`, `warn_latest`, `warn_remote_add`, `warn_pipe_install`) pinned to `true` for project-local configs; allowlist sizes capped at 50 entries
- **MCP code-key skip**: `code`, `script`, `expression`, `source` parameters excluded from path extraction in MCP policy evaluation, preventing false positives from sandboxed code tools (Forgemax/Narsil)
- **~109 new tests** for Cargo, Docker, pip, MCP policy, cross-ecosystem integration

### Fixed
- **MCP explicit-rule semantics**: Tools with explicit rules (including empty `restricted_paths`) are now treated as explicitly allowed, not falling through to a `deny` default. Enables `default_mcp_policy = "deny"` with per-tool allowlisting.
- **Shell chain slopsquatting bypass**: Commands chained with `&&`, `;`, `||`, etc. now correctly extract packages from all sub-commands
- **Chained command Docker check bypass**: Docker image checks now run even when package manager checks pass in the same chained command
- **pip `--only-binary` check too permissive**: Now requires `:all:` specifically (previously `--only-binary numpy` was accepted)
- **pip `-e`/`--editable` flag handling**: Editable installs no longer extract VCS URLs as package names
- **Docker port-in-registry false negative**: `evil.com:8080/malware` (untagged) now correctly triggers the "no tag" warning (port colon no longer confused with tag colon)
- **Dockerfile curl/wget case sensitivity**: `Curl`, `WGET` variants now detected in pipe-to-shell patterns
- **Detection/extraction consistency**: All `is_*_install_command` functions use shell-aware splitting
- 2,031 tests (up from 1,922): Cargo, Docker, pip enforcement, MCP policy, Dockerfile linting, cross-ecosystem integration

### Changed
- `PackageManagerConfigs` expanded: now bundles `NpmConfig`, `GoConfig`, `CargoConfig`, `PipConfig`, `DockerConfig`
- pip allowlist separated from npm allowlist (previously shared)
- `AiFirewallConfig` gains `docker: DockerConfig` field
- `SentinelConfig` gains `cargo: CargoConfig` and `pip: PipConfig` fields
- Block messages now include `https://` URLs (clickable in terminals) and allowlist guidance for all ecosystems

## [0.3.0] - 2026-03-31

### Added
- **Volume-based exfiltration alerting**: Per-host byte tracking with configurable thresholds (5MB warn / 20MB block / 60s window), alert suppression, 10K host cap
- **`ThreatCategory::DataExfiltration`** threat category with desktop notifications and audit logging
- **CEL (Common Expression Language) policy engine** for advanced MCP tool rules
- **`[[ai_firewall.mcp_cel_rules]]`** config section with `expression` and `action` fields
- **CEL context variables**: `tool_name`, `paths`, `payload_size`
- **Kani proof for exfiltration counter overflow safety** (9 total proofs)
- **`sanctum config --recommended`** includes CEL rule examples
- **Exfiltration config validation**: window clamped to 1-3600s, warn/block thresholds auto-swapped if inverted

### Fixed
- **MCP default policy bypass**: `default_mcp_policy = "deny"` was silently overridden when CEL/glob rules existed but didn't match
- **`sanctum fix list --category`** now accepts all 8 threat categories with backward-compatible short aliases
- Removed stale RUSTSEC-2024-0384 advisory ignore (instant crate removed in v0.2.2)

### Changed
- `ExfiltrationTracker::record_bytes` returns accumulated total bytes (not per-connection estimate)
- Warning alerts now suppressed within time window (matching Critical suppression behavior)
- 1,837 tests (up from 1,811): exfiltration alerting, CEL policy engine, default policy fix

## [0.2.2] - 2026-03-31

### Added
- **End-to-end IPC integration tests**: 5 tests exercising full daemon→IPC→response path (startup/status, budget recording, malformed input resilience, auth rejection, graceful shutdown). Platform-aware test harness works on both macOS and Linux CI. Stale test directory cleanup prevents orphaned daemon processes.
- **Loom concurrency tests**: 3 tests for `PendingCostGuard` atomic pattern (counter-returns-to-zero, defuse-retains-value, multiple-guards-per-thread), 3 tests for `Mutex<HashMap>` spend accumulation pattern, all gated behind `#[cfg(loom)]`
- **Loom CI job**: New `loom` job in CI runs concurrency tests on every push/PR
- **Dependency audit entries**: `loom`, `generator`, `scoped-tls` documented in `DEPENDENCY_AUDIT.md`

### Changed
- Repository URLs migrated from `postrv/sanctum` to `postrv/sanctum-oss` across all files (Cargo.toml, README, install script, cosign identity patterns, docs, CLI source)
- Added `cfg(loom)` to workspace `check-cfg` list
- 1,811 tests (up from 1,794): 1,800 unit + 5 E2E integration + 6 loom concurrency

## [0.2.1] - 2026-03-31

### Added
- **SSE streaming budget tracking**: New `sse.rs` module parses Server-Sent Event streams from OpenAI (final chunk usage), Anthropic (split `message_start` + `message_delta`), and Google (last `usageMetadata` chunk). Streaming LLM calls now have full budget enforcement — previously they bypassed tracking entirely.
- **npx package extraction**: `extract_npx_package()` handles positional args, `--package`/`--package=`/`-p` flags, scoped packages (`@angular/cli`), version stripping, and `-y`/`--yes` flags. Integrated into slopsquatting detection.
- **npm ci recognition**: `npm ci` recognised as an install command (lockfile-only, no package args). Added to `NPM_INSTALL_PATTERNS` for lifecycle script warnings.

### Fixed
- **Critical**: SSE extractors used `?` operator inside loops, causing a single malformed or missing-key chunk to abort the entire search instead of continuing to the next event
- **SSE spec compliance**: Parser stripped all leading spaces after `data:` colon instead of exactly one per the SSE spec

### Changed
- **Kani CI timeouts**: `kani-core` 45 → 60 min, `kani-full` 120 → 180 min
- 1,794 tests (up from 1,742)

## [0.2.0] - 2026-03-30

### Security
- **IPv6 SSRF hardening**: Block 6to4 (`2002::/16`), Teredo (`2001:0::/32`), IPv4-compatible (`::x.x.x.x`), documentation prefix (`2001:db8::/32`), and multicast (`ff00::/8`) in proxy SSRF validation
- **Memory leak fix**: Replace `Box::leak` with `Cow<'static, str>` in credential base64 rescan path (unbounded memory growth)
- **Symlink attack prevention**: Temp files use `create_new(true)` (O_EXCL) in allowlist and entropy writes
- **MCP bare filename detection**: SSH keys (`id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`), credential files (`credentials.json`, `service_account.json`, `keyfile.json`, `token.json`) now blocked by MCP policy
- **API surface restriction**: `redact_credentials_no_entropy` reduced to `pub(crate)` to prevent bypass
- **Blind tunnel timeout**: 10-second connect timeout for proxy blind tunnels (was unbounded)
- 5 rounds of adversarial review: 75+ findings, 90+ new tests, full remediation

### Added
- **`ignore_scripts_required` enforcement**: When `true`, blocks `npm install`/`yarn add`/`pnpm install` without `--ignore-scripts` (was parsed but unwired)
- **MCP audit logging**: `mcp_audit = true` now produces `mcp_audit.log` via `McpAuditLog` (was completely unwired)
- **IPC client timeout**: CLI IPC operations bounded to 10 seconds (was unbounded)

### Changed
- **NpmDebouncer bounded capacity**: Pending-path set capped at 10,000 entries to prevent OOM from malicious event floods
- **Dead code removal**: Removed unused `NpmLifecycleEvent` channel, `sanctum_firewall::registry` module
- **Kani CI**: Added `--default-unwind 20` to kani-core, reduced proof bounds for CI feasibility (16-byte PTH, 4-byte prefix/suffix)
- **CI audit**: Added `issues: write` permission for advisory issue creation
- **CI reproducible-build**: Wired into `build-release` dependency chain
- **Deprecated**: `transfer_threshold_bytes` config field (volume-based alerting not yet implemented)
- **deny.toml**: Removed stale `bitflags v1` and `windows-sys v0.52` skip entries

### Fixed
- Kani CI timeout/failure caused by unbounded stdlib loop unwinding
- Status exit code for shell hook auto-start detection
- Daemon log suppression on auto-start
- Proxy status output to stdout
- Model names updated to current IDs
- Documentation: LOC (~44K), dependency count (253), test count (~1,741)

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
- **~1,700 tests** across 8 crates, 0 clippy warnings (pedantic + nursery)
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
