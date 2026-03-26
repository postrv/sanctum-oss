# Formal Verification Proofs

This directory contains bounded model checking harnesses for [Kani](https://model-checking.github.io/kani/), a Rust verification tool backed by CBMC.

## What Kani proves (vs. what tests check)

| Technique | Scope | Confidence |
|---|---|---|
| Unit tests | Specific inputs | Those exact cases work |
| Property tests (proptest) | ~10,000 random inputs | Probabilistic coverage |
| Fuzz testing | Millions of random inputs | High confidence, not proof |
| **Kani proofs** | **All inputs within bounds** | **Mathematical certainty** |

## Running proofs

```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs
cargo kani --workspace

# Run a specific proof
cargo kani --harness pth_analyser_never_panics
```

## Current proofs

### `pth_analyser.rs`

1. **`pth_analyser_never_panics`** — Proves that `analyse_pth_line` never panics for any UTF-8 string up to 256 bytes.
2. **`pure_path_is_always_benign`** — Proves that a string containing only path-safe characters (`a-z`, `0-9`, `/`, `.`, `_`, `-`) always receives a `Benign` verdict.
3. **`exec_is_never_benign`** — Proves that any string containing the substring `exec(` receives at least `Warning` level.

### `quarantine_state.rs`

4. **`quarantine_state_transitions`** — Proves that the quarantine state machine has valid transitions and that `Deleted` is a terminal state.

## Bounds and limitations

Kani uses bounded model checking. The `#[kani::unwind(N)]` annotation limits loop iterations and string length. Proofs are valid up to the specified bound. For `pth_analyser_never_panics`, we prove correctness for all inputs up to 256 bytes — longer inputs use the same code paths, so this provides high confidence for all practical inputs.
