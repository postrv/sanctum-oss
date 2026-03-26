# Dependency Audit

Every direct dependency is justified, version-pinned, and audited. No transitive dependency is accepted without review.

## Core library: sanctum-sentinel

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `notify` | 7.0.x | Cross-platform filesystem events (inotify/FSEvent) | RustSec clean. Used by deno, zed, rust-analyzer. No unsafe in public API. |
| `nix` | 0.29.x | Unix process management (/proc, signals, PID files) | RustSec clean. Core Rust ecosystem crate. Contains unsafe but well-audited. |
| `serde` | 1.x | TOML/JSON serialisation | RustSec clean. Ubiquitous. |
| `toml` | 0.8.x | TOML parsing for config files | RustSec clean. Official TOML parser for Rust. |
| `thiserror` | 2.x | Derive macro for error types | RustSec clean. Zero runtime cost (proc macro only). |
| `tracing` | 0.1.x | Structured logging | RustSec clean. Tokio project. |
| `secrecy` | 0.10.x | Zeroising wrapper for sensitive values | RustSec clean. Purpose-built for secrets in memory. |
| `sha2` | 0.10.x | SHA-256 for content hashing | RustCrypto project. Multiple independent audits. |
| `hex` | 0.4.x | Hex encoding for hash display | Trivial crate, no unsafe, no dependencies. |
| `chrono` | 0.4.x | Timestamp handling for audit logs | RustSec clean. Well-established. |

## Daemon: sanctum-daemon

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `tokio` | 1.x | Async runtime (fs events, IPC, signals) | RustSec clean. Industry standard. Large dependency tree but well-audited. |
| `tracing-subscriber` | 0.3.x | Log formatting and filtering | RustSec clean. Tokio project companion. |

## CLI: sanctum-cli

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `clap` | 4.x | CLI argument parsing | RustSec clean. Standard CLI framework. |

## Notifications: sanctum-notify

| Crate | Version | Purpose | Audit notes |
|---|---|---|---|
| `notify-rust` | 4.x | Desktop notifications (D-Bus/macOS native) | RustSec clean. Lightweight. |

## Dev/test only

| Crate | Version | Purpose |
|---|---|---|
| `tempfile` | 3.x | Temporary directories for integration tests |
| `proptest` | 1.x | Property-based testing |
| `assert_cmd` | 2.x | CLI integration testing |
| `predicates` | 3.x | Assertion predicates for CLI output |

## Banned crates (enforced by cargo-deny)

- `openssl-sys` — No C crypto dependencies. We use pure-Rust RustCrypto.
- `libz-sys` — No C compression dependencies.

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
