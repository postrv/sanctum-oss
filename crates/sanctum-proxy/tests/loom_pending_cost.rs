//! Loom concurrency tests for `PendingCostGuard`.
//!
//! `PendingCostGuard` is the only lock-free primitive in the codebase. It uses
//! `AtomicU64` with `fetch_add` on creation and `fetch_sub` on drop (unless defused).
//! These tests exercise every interleaving that loom discovers to verify correctness.
//!
//! **Limitation**: The real `PendingCostGuard` uses `&'a AtomicU64` (borrowed reference),
//! tying the guard's lifetime to the counter. This loom version uses `Arc<AtomicU64>`
//! because loom threads require `'static` data. Lifetime-related bugs (guard outliving
//! counter) are caught by the Rust compiler at the real call site, not by these loom tests.
//!
//! The real code and these tests both use `Ordering::SeqCst`. If the production code
//! ever relaxes to weaker orderings, these tests must be updated to match.

#![cfg(loom)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;

use loom::sync::atomic::{AtomicU64, Ordering};
use loom::thread;

/// Mirror of `PendingCostGuard` from `handler.rs`, adapted for loom.
///
/// Differences from production:
/// - Uses `Arc<AtomicU64>` instead of `&'a AtomicU64` (loom requires `'static`).
/// - Uses `loom::sync::atomic::AtomicU64` instead of `std::sync::atomic::AtomicU64`.
///
/// The logic (fetch_add on new, conditional fetch_sub on drop, defuse by value)
/// is identical to production (`handler.rs:66-103`).
struct PendingCostGuard {
    counter: Arc<AtomicU64>,
    amount: u64,
    defused: bool,
}

impl PendingCostGuard {
    fn new(counter: &Arc<AtomicU64>, amount: u64) -> Self {
        counter.fetch_add(amount, Ordering::SeqCst);
        Self {
            counter: Arc::clone(counter),
            amount,
            defused: false,
        }
    }

    /// Defuse the guard so it does not decrement on drop.
    ///
    /// Takes `self` by value, matching the real `PendingCostGuard::defuse(mut self)`
    /// at `handler.rs:92`. The guard is consumed; `Drop` runs immediately with
    /// `defused = true`, so no decrement occurs.
    fn defuse(mut self) {
        self.defused = true;
    }
}

impl Drop for PendingCostGuard {
    fn drop(&mut self) {
        if !self.defused {
            self.counter.fetch_sub(self.amount, Ordering::SeqCst);
        }
    }
}

/// Two threads create and drop guards concurrently; the counter must return to zero.
#[test]
fn test_guard_counter_returns_to_zero() {
    loom::model(|| {
        let counter = Arc::new(AtomicU64::new(0));

        let c1 = Arc::clone(&counter);
        let t1 = thread::spawn(move || {
            let _guard = PendingCostGuard::new(&c1, 100);
        });

        let c2 = Arc::clone(&counter);
        let t2 = thread::spawn(move || {
            let _guard = PendingCostGuard::new(&c2, 100);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    });
}

/// Defusing a guard prevents decrement. The counter retains the added value.
///
/// After `defuse()` the guard is consumed and `Drop` fires with `defused = true`,
/// so the counter stays at `amount`.
#[test]
fn test_guard_defuse_retains_value() {
    loom::model(|| {
        let counter = Arc::new(AtomicU64::new(0));

        let guard = PendingCostGuard::new(&counter, 42);
        // defuse() consumes the guard — Drop runs immediately with defused=true.
        guard.defuse();

        assert_eq!(counter.load(Ordering::SeqCst), 42);
    });
}

/// Multiple guards per thread: tests that stacking guards in a single thread
/// correctly accumulates and then fully decrements the counter when combined
/// with a guard from another thread.
#[test]
fn test_multiple_guards_per_thread() {
    loom::model(|| {
        let counter = Arc::new(AtomicU64::new(0));

        let c1 = Arc::clone(&counter);
        let t1 = thread::spawn(move || {
            let _g1 = PendingCostGuard::new(&c1, 10);
            let _g2 = PendingCostGuard::new(&c1, 20);
            // both drop in reverse order
        });

        let c2 = Arc::clone(&counter);
        let t2 = thread::spawn(move || {
            let _g = PendingCostGuard::new(&c2, 30);
        });

        t1.join().unwrap();
        t2.join().unwrap();

        assert_eq!(counter.load(Ordering::SeqCst), 0);
    });
}
