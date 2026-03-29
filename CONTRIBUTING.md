# Contributing to Sanctum

Thanks for your interest in contributing. Sanctum is a security tool, so contributions are held to a high bar -- but that doesn't mean they need to be complicated.

## Getting started

```bash
git clone https://github.com/postrv/sanctum
cd sanctum
cargo build --workspace
cargo test --workspace --all-features
```

Requires Rust 1.94.0+ (pinned in `rust-toolchain.toml`).

## Before submitting a PR

Every PR must pass:

```bash
cargo fmt --all -- --check          # formatting
cargo clippy --all-targets --all-features  # 0 warnings required
cargo test --workspace --all-features      # all tests pass
```

The workspace enforces strict lints at the compiler level:

- `unsafe_code = "deny"` -- no unsafe, period
- `unwrap_used = "deny"`, `expect_used = "deny"`, `panic = "deny"` -- no panics in production code
- `print_stdout = "deny"`, `print_stderr = "deny"` -- all output through structured channels
- `pedantic = "warn"`, `nursery = "warn"` -- clippy's strictest lint groups

If clippy complains, fix the code -- don't suppress the lint unless there's a documented reason.

## What makes a good contribution

**Bug fixes** with a regression test are always welcome.

**Security improvements** -- new credential patterns, better detection heuristics, hardening -- are especially valued. If you find a security issue, please report it privately first (see [SECURITY.md](docs/SECURITY.md)).

**Tests** -- more coverage is always good. Property-based tests (proptest) and Kani proofs for security-critical invariants are particularly valuable.

**Documentation** -- if something confused you, it'll confuse others. Fix it.

## What to avoid

- Don't add dependencies without strong justification. Every dependency is audited (see [DEPENDENCY_AUDIT.md](docs/DEPENDENCY_AUDIT.md)).
- Don't add features speculatively. Build what's needed now, not what might be needed later.
- Don't suppress lints without a comment explaining why.
- Don't add `unsafe` code. There are no exceptions.

## Code style

Follow the existing patterns. The codebase is consistent -- match what's already there rather than introducing new conventions. Key patterns:

- Error handling via `thiserror` enums, propagated with `?`
- Structured logging via `tracing`, not `println!`
- Platform-specific code gated with `#[cfg(target_os = "...")]`
- Test code may use `#[allow(clippy::unwrap_used)]` -- production code may not

## Commit messages

Write clear, concise commit messages. One sentence is fine. The diff tells the story -- the message explains *why*.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
