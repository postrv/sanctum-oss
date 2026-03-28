# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Current |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities via one of:

1. **GitHub Private Advisory**: [Create a private advisory](https://github.com/postrv/sanctum/security/advisories/new) on this repository.
2. **Email**: security@sanctum.dev (PGP key available at sanctum.dev/.well-known/security.txt)

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if you have one)

### Response timeline

- **Acknowledgement**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix timeline**: Depends on severity
  - Critical: patch within 72 hours
  - High: patch within 7 days
  - Medium/Low: next scheduled release

### Disclosure policy

We follow coordinated disclosure. We will:
1. Confirm the vulnerability and determine its scope
2. Develop and test a fix
3. Release the fix and publish a security advisory
4. Credit the reporter (unless they prefer anonymity)

We ask that you give us reasonable time to address the issue before public disclosure.

## Security considerations

Sanctum is a security tool with elevated filesystem access. We take its own security extremely seriously:

### Code quality

- **Zero `unsafe` code** in the entire codebase
- **No `unwrap`/`expect`/`panic`** outside test code (enforced by workspace-level clippy lints)
- **Zero clippy warnings** across 1,170 tests
- **Rust toolchain pinned** to 1.94.0 via `rust-toolchain.toml` for reproducible builds

### Dependency management

- **`cargo-deny` enforced** via `deny.toml`:
  - Known vulnerabilities denied
  - Yanked crates denied
  - Only permissive licenses allowed (MIT, Apache-2.0, BSD, ISC, Unicode)
  - Copyleft dependencies denied
  - Multiple versions of the same crate denied
  - C system dependencies (`openssl-sys`, `libz-sys`) explicitly banned -- pure Rust only
  - Only crates.io registry allowed; unknown registries and git sources denied
- **All dependencies audited** and documented in `docs/DEPENDENCY_AUDIT.md`

### Runtime security

- **Race-free PID file creation** using `O_CREAT | O_EXCL` semantics (`create_new(true)`) to prevent TOCTOU races between checking for an existing daemon and starting a new one
- **AppleScript injection prevention** in macOS notifications -- all user-controlled strings are sanitized before embedding in AppleScript literals to prevent code injection via `osascript`
- **IPC messages capped at 64KB** (`MAX_MESSAGE_SIZE`) -- both read and write paths enforce the limit before allocating payload buffers
- **Unix socket permissions set to 0o600** -- only the owning user can connect to the daemon
- **Audit log with 0o600 permissions** -- append-only NDJSON format; audit logging failures are logged but never crash the daemon
- **Budget state files persisted with 0o600 permissions**

### Testing

- **1,170 tests** covering all eight workspace crates
- **Fuzz testing targets** for security-critical parsers (PTH file analyser, config parser) in `fuzz/fuzz_targets/`
- **9 property-based tests** using proptest (6 sentinel + 3 budget) that verify invariants such as analyser totality, determinism, quarantine roundtrip identity, pricing overflow safety, and spend monotonicity
- **8 Kani bounded model checking proofs** for core algorithms (analyser panic-freedom, path classification, exec detection, quarantine state machine, ID traversal rejection, ceiling cost overflow, Shannon entropy panic-freedom, glob exact-match correctness) — integrated as `#[cfg(kani)]` modules with CI enforcement

### Binary verification

Release binaries are signed with [Sigstore](https://sigstore.dev) using keyless OIDC signing via GitHub Actions. Each release includes `.sig` (signature) and `.cert` (certificate) files alongside the binaries, plus a signed `SHA256SUMS` file and a signed CycloneDX SBOM.

**Verify a binary:**

```bash
cosign verify-blob \
  --signature sanctum-x86_64-unknown-linux-gnu.sig \
  --certificate sanctum-x86_64-unknown-linux-gnu.cert \
  --certificate-identity-regexp "^https://github\\.com/postrv/sanctum/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sanctum-x86_64-unknown-linux-gnu
```

**Verify the checksums file:**

```bash
cosign verify-blob \
  --signature SHA256SUMS.sig \
  --certificate SHA256SUMS.cert \
  --certificate-identity-regexp "^https://github\\.com/postrv/sanctum/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
sha256sum -c SHA256SUMS
```

### Checksum-only installs

When installing via `scripts/install.sh` without cosign available, binaries are
verified using SHA-256 checksums only. This protects against download corruption
and CDN-level tampering, but not against a compromised GitHub release where an
attacker replaces both the binary and the SHA256SUMS file.

For production environments, we recommend installing
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) and
enabling full Sigstore verification.

No private signing keys exist. The signing identity is the GitHub Actions release workflow itself, verified via Fulcio certificate and logged to the Rekor transparency log.
