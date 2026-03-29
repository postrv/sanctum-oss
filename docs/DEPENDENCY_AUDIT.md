# Dependency Audit

Every direct dependency is justified, version-pinned, and audited. No transitive dependency is accepted without review.

## Shared types: sanctum-types

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `serde` | 1.x | Serialisation for shared types | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation for IPC messages | RustSec clean. Ubiquitous. |
| `toml` | 0.8.x | TOML parsing for config files | RustSec clean. Official TOML parser for Rust. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost (proc macro only). |
| `chrono` | 0.4.x | Timestamp handling for events and audit logs | RustSec clean. Well-established. |
| `tokio` | 1.x | Async I/O utilities and Unix socket types for IPC framing | RustSec clean. Industry standard. |
| `sha2` | 0.10.x | SHA-256 for content hashing (audit log, quarantine) | RustCrypto project. Multiple independent audits. |
| `hex` | 0.4.x | Hex encoding for hash display | Trivial crate, no unsafe, no dependencies. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `nix` | 0.29.x | Unix filesystem safety (O_NOFOLLOW, fchmod) | RustSec clean. Core Rust ecosystem crate. Contains unsafe but well-audited. |

## Core library: sanctum-sentinel

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `notify` | 7.0.x | Cross-platform filesystem events (inotify/FSEvent) | RustSec clean. Used by deno, zed, rust-analyzer. No unsafe in public API. |
| `nix` | 0.29.x | Unix process management (/proc, signals, PID files) | RustSec clean. Core Rust ecosystem crate. Contains unsafe but well-audited. |
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `sha2` | 0.10.x | SHA-256 for content hashing | RustCrypto project. Multiple independent audits. |
| `hex` | 0.4.x | Hex encoding for hash display | Trivial crate, no unsafe, no dependencies. |
| `chrono` | 0.4.x | Timestamp handling for audit logs | RustSec clean. Well-established. |
| `tokio` | 1.x | Async runtime | RustSec clean. Industry standard. |

## Daemon: sanctum-daemon

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `tokio` | 1.x | Async runtime (fs events, IPC, signals) | RustSec clean. Industry standard. Large dependency tree but well-audited. |
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `toml` | 0.8.x | TOML config parsing | RustSec clean. Official TOML parser for Rust. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `tracing-subscriber` | 0.3.x | Log formatting and filtering | RustSec clean. Tokio project companion. |
| `chrono` | 0.4.x | Timestamp handling | RustSec clean. Well-established. |
| `nix` | 0.29.x | Unix process management (signals, PID files) | RustSec clean. Core Rust ecosystem crate. Contains unsafe but well-audited. |

## CLI: sanctum-cli

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `clap` | 4.x | CLI argument parsing | RustSec clean. Standard CLI framework. |
| `tokio` | 1.x | Async runtime for IPC communication | RustSec clean. Industry standard. |
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `toml` | 0.8.x | TOML config parsing | RustSec clean. Official TOML parser for Rust. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `chrono` | 0.4.x | Timestamp handling | RustSec clean. Well-established. |
| `sha2` | 0.10.x | SHA-256 for content hashing | RustCrypto project. Multiple independent audits. |
| `hex` | 0.4.x | Hex encoding for hash display | Trivial crate, no unsafe, no dependencies. |
| `nix` | 0.29.x | Unix process/signal handling | RustSec clean. Core Rust ecosystem crate. Contains unsafe but well-audited. |
| `tracing-subscriber` | 0.3.x | Log formatting for --verbose hook mode | RustSec clean. Tokio project companion. |

## Notifications: sanctum-notify

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |

Note: `notify-rust` is commented out due to upstream zbus/Rust edition incompatibility. Notifications use shell fallback commands (osascript on macOS, notify-send on Linux).

## Firewall: sanctum-firewall

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `regex` | 1.x | Pattern matching for firewall rules | RustSec clean. Core Rust ecosystem crate. Well-audited. |
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `sha2` | 0.10.x | SHA-256 for content hashing | RustCrypto project. Multiple independent audits. |
| `hex` | 0.4.x | Hex encoding for hash display | Trivial crate, no unsafe, no dependencies. |
| `chrono` | 0.4.x | Timestamp handling | RustSec clean. Well-established. |
| `reqwest` | 0.12.x | HTTP HEAD requests to npm/PyPI registries for slopsquatting detection | Uses rustls-tls (no OpenSSL). Fail-open: network errors allow install with warning. Adds ~50 transitive deps via hyper/rustls. RustSec clean. |

Note: `sanctum-firewall` makes outbound HTTPS HEAD requests to `registry.npmjs.org` and `pypi.org` during `pre-bash` hook slopsquatting checks. These are fail-open with a configurable timeout (default 3s). No request bodies are sent; only HTTP status codes are inspected.

## Budget: sanctum-budget

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `serde` | 1.x | Serialisation | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation | RustSec clean. Ubiquitous. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `chrono` | 0.4.x | Timestamp handling | RustSec clean. Well-established. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost (proc macro only). |

## HTTP gateway proxy: sanctum-proxy

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `sanctum-types` | workspace | Shared IPC/config types | Internal crate. |
| `sanctum-budget` | workspace | Budget enforcement logic | Internal crate. |
| `sanctum-firewall` | workspace | Credential redaction for outbound request bodies | Internal crate. |
| `serde` | 1.x | Serialisation for proxy config | RustSec clean. Ubiquitous. |
| `serde_json` | 1.x | JSON serialisation for API payloads and usage extraction | RustSec clean. Ubiquitous. |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `tokio` | 1.x | Async runtime for proxy server | RustSec clean. Industry standard. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost. |
| `hyper` | 1.6.x | HTTP/1.1 server for accepting local proxy connections | RustSec clean. Tokio project. Industry-standard HTTP implementation. |
| `hyper-util` | 0.1.x | Connection serving utilities for hyper (server-auto, TokioIo) | RustSec clean. Tokio project companion to hyper. |
| `http-body-util` | 0.1.x | Body adapters (Full, Empty, BodyExt) for hyper request/response bodies | RustSec clean. Tokio project. Minimal crate. |
| `reqwest` | 0.12.x | HTTPS client for forwarding requests to upstream LLM API providers | RustSec clean. Uses rustls-tls (no OpenSSL). Well-established HTTP client. |
| `bytes` | 1.x | Efficient byte buffer for request/response body handling | RustSec clean. Tokio project. Zero-copy buffer primitive. |

## Dev/test only

| Crate | Version | Purpose | Used by |
|---|---|---|---|
| `tempfile` | 3.x | Temporary directories for integration tests | sanctum-types, sanctum-sentinel, sanctum-daemon, sanctum-cli, sanctum-firewall, sanctum-budget |
| `proptest` | 1.x | Property-based testing | sanctum-types, sanctum-sentinel, sanctum-firewall, sanctum-budget |
| `assert_cmd` | 2.x | CLI integration testing | sanctum-cli |
| `predicates` | 3.x | Assertion predicates for CLI output | sanctum-cli |

## CI-only tools (not shipped in binaries)

| Tool | Version | Purpose | Notes |
|---|---|---|---|
| `cargo-llvm-cov` | 0.6.x | Code coverage via LLVM instrumentation | Not compiled into any binary |
| `cargo-cyclonedx` | 0.5.x | CycloneDX SBOM from Cargo.lock | Not compiled into any binary |
| `git-cliff` | 2.8.x | Changelog from conventional commits | Not compiled into any binary |
| `criterion` | 0.5.x | Benchmarking (dev-dependency) | Not compiled into release binaries |

## Banned crates (enforced by cargo-deny)

- `openssl-sys` -- No C crypto dependencies. We use pure-Rust RustCrypto.
- `libz-sys` -- No C compression dependencies.

## Audit process

1. Check RustSec Advisory Database (`cargo audit`)
2. Review crate source for unsafe blocks
3. Verify crate is actively maintained (commits in last 6 months)
4. Check download count and community usage
5. Review transitive dependencies for unexpected additions
6. Document justification in this file

## Update policy

- Dependencies are updated monthly via `cargo update`
- Each update is reviewed for changelog entries
- `cargo deny check` and `cargo audit` run on every CI build
- Major version bumps require re-audit
