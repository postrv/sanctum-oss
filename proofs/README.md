# Formal Verification Proofs

This directory documents the bounded model checking proofs for [Kani](https://model-checking.github.io/kani/), a Rust verification tool backed by CBMC.

## What Kani proves (vs. what tests check)

| Technique | Scope | Confidence |
|---|---|---|
| Unit tests | Specific inputs | Those exact cases work |
| Property tests (proptest) | ~10,000 random inputs | Probabilistic coverage |
| Fuzz testing | Millions of random inputs | High confidence, not proof |
| **Kani proofs** | **All inputs within bounds** | **Mathematical certainty** |

## Architecture

Proof harnesses live **inline** in the crate source files, gated by `#[cfg(kani)]`. This is the Kani project's recommended approach. The `#[cfg(kani)]` blocks are completely invisible to normal `cargo build` and `cargo test`.

The `proofs/kani/pth_analyser.rs` file is retained as a historical specification document.

## CI integration

| Job | Trigger | Proofs | Timeout |
|-----|---------|--------|---------|
| `kani-core` | Every PR | 5 fast proofs (see below) | 10 min |
| `kani-full` | Push to `main` / nightly schedule | All 8 proofs (`cargo kani --workspace`) | 60 min |

`kani-core` gates the `build-release` job.

## Running proofs

```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs
cargo kani --workspace

# Run a specific proof
cargo kani --harness pth_analyser_never_panics -p sanctum-sentinel
cargo kani --harness ceiling_cost_no_overflow -p sanctum-budget
```

## Active proofs (8 total)

### In `sanctum-sentinel/src/pth/analyser.rs`

1. **`pth_analyser_never_panics`** — Proves `analyse_pth_line` never panics for any UTF-8 string up to 32 bytes (PR) / 256 bytes (nightly).
2. **`pure_path_is_always_benign`** — Proves path-safe characters (`a-z`, `0-9`, `/`, `.`, `_`, `-`) always yield `ThreatLevel::Info`.
3. **`exec_is_never_benign`** — Proves any ASCII string containing `exec(` is classified at least `Warning`.

### In `sanctum-sentinel/src/pth/quarantine.rs`

4. **`quarantine_state_transitions`** — Proves the quarantine state machine has valid transitions: `Active` accepts all actions, `Deleted` is terminal, `Approve` -> `Restored`, `Delete` -> `Deleted`, `Report` preserves state.
5. **`validate_id_rejects_traversal`** — Proves `validate_id` rejects empty strings, strings containing `/` or `\`, and strings containing `..` for all 4-byte UTF-8 inputs.

### In `sanctum-budget/src/pricing.rs`

6. **`ceiling_cost_no_overflow`** — Proves `ceiling_cost` never overflows for any `u64` inputs, and that zero tokens or zero price always yields zero cost.

### In `sanctum-firewall/src/entropy.rs`

7. **`shannon_entropy_never_panics`** — Proves `shannon_entropy` never panics for any valid UTF-8 input up to 8 bytes, and that the result is always non-negative (zero for empty strings).

### In `sanctum-firewall/src/mcp/policy.rs`

8. **`glob_matches_exact_match_works`** — Proves that for any 4-byte printable ASCII pattern without wildcards, `glob_matches` is equivalent to string equality.

## `kani-core` proofs (PR gate)

The following 5 proofs run on every PR and gate `build-release`:

| Proof | Crate | Rationale for fast gate |
|-------|-------|------------------------|
| `quarantine_state_transitions` | sanctum-sentinel | Core state machine correctness |
| `pure_path_is_always_benign` | sanctum-sentinel | Path classification soundness |
| `validate_id_rejects_traversal` | sanctum-sentinel | Quarantine traversal prevention |
| `ceiling_cost_no_overflow` | sanctum-budget | Budget arithmetic safety |
| `glob_matches_exact_match_works` | sanctum-firewall | MCP policy correctness |

The remaining 3 proofs (`pth_analyser_never_panics`, `exec_is_never_benign`, `shannon_entropy_never_panics`) run only on `main` push and nightly schedule via `kani-full`, due to their larger unwind bounds.

## Bounds and limitations

Kani uses bounded model checking. The `#[kani::unwind(N)]` annotation limits loop iterations and string length. Proofs are valid up to the specified bound. Kani does **not** support:
- `async`/`await` or the Tokio runtime
- Standard I/O operations (`std::fs`, `std::net`)
- The `regex` crate (SIMD internals)
- Dynamic dispatch (`dyn Trait`) has limited support

Proof harnesses are restricted to pure, synchronous functions.
