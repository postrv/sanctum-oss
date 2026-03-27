# Formal Verification Proofs

This directory contains bounded model checking harnesses for [Kani](https://model-checking.github.io/kani/), a Rust verification tool backed by CBMC.

## What Kani proves (vs. what tests check)

| Technique | Scope | Confidence |
|---|---|---|
| Unit tests | Specific inputs | Those exact cases work |
| Property tests (proptest) | ~10,000 random inputs | Probabilistic coverage |
| Fuzz testing | Millions of random inputs | High confidence, not proof |
| **Kani proofs** | **All inputs within bounds** | **Mathematical certainty** |

## CI status

Kani proofs are not yet integrated into CI. They can be run manually.

## Running proofs

Once harnesses are uncommented and wired into the crate structure:

```bash
# Install Kani
cargo install --locked kani-verifier
cargo kani setup

# Run all proofs
cargo kani --workspace

# Run a specific proof
cargo kani --harness pth_analyser_never_panics
```

## Current status

There are no active proof harnesses yet. The file `proofs/kani/pth_analyser.rs` contains commented-out specifications for future proofs. These are blocked on wiring the harnesses into the crate structure so that Kani's compilation model can resolve the `sanctum-sentinel` imports.

## Planned proofs

### `pth_analyser.rs`

The following harnesses are specified (commented out) in `proofs/kani/pth_analyser.rs`:

1. **`pth_analyser_never_panics`** — Will prove that `analyse_pth_line` never panics for any UTF-8 string up to 256 bytes.
2. **`pure_path_is_always_benign`** — Will prove that a string containing only path-safe characters (`a-z`, `0-9`, `/`, `.`, `_`, `-`) always receives a `Benign` verdict.
3. **`exec_is_never_benign`** — Will prove that any string containing the substring `exec(` receives at least `Warning` level.
4. **`quarantine_state_transitions`** — Will prove that the quarantine state machine has valid transitions and that `Deleted` is a terminal state. (Stub only; no implementation body yet.)

## Bounds and limitations

Kani uses bounded model checking. The `#[kani::unwind(N)]` annotation limits loop iterations and string length. Proofs are valid up to the specified bound. For example, `pth_analyser_never_panics` is designed to prove correctness for all inputs up to 256 bytes — longer inputs use the same code paths, so this would provide high confidence for all practical inputs.
