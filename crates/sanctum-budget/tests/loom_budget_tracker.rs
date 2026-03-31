//! Loom concurrency smoke tests for the `Mutex<HashMap>` access pattern.
//!
//! These tests validate the `Mutex<HashMap>` access pattern used by the proxy handler
//! (`handler.rs:57`) when wrapping `BudgetTracker`. While Mutex correctness is trivially
//! guaranteed, these tests serve as a compile-time and runtime smoke test that the
//! accumulation and read patterns work correctly under concurrent access.
//!
//! Note: The daemon wraps `BudgetTracker` in `tokio::sync::Mutex` (async), which loom
//! cannot model. These tests only cover the `std::sync::Mutex` pattern used in the proxy.

#![cfg(loom)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::Arc;

use loom::sync::Mutex;
use loom::thread;

/// Two threads accumulate spend into a shared `Mutex<HashMap>`, mirroring the
/// pattern in `HandlerState::budget_tracker`. Final total must equal the sum
/// of all individual additions.
#[test]
fn test_concurrent_accumulation() {
    loom::model(|| {
        let map: Arc<Mutex<HashMap<&str, u64>>> = Arc::new(Mutex::new(HashMap::new()));

        let m1 = Arc::clone(&map);
        let t1 = thread::spawn(move || {
            let mut guard = m1.lock().unwrap();
            let entry = guard.entry("openai").or_insert(0);
            *entry += 100;
        });

        let m2 = Arc::clone(&map);
        let t2 = thread::spawn(move || {
            let mut guard = m2.lock().unwrap();
            let entry = guard.entry("openai").or_insert(0);
            *entry += 200;
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let guard = map.lock().unwrap();
        assert_eq!(guard.get("openai").copied().unwrap_or(0), 300);
    });
}

/// One thread writes while another reads, verifying that reads always see a
/// consistent state (either before or after the write, never partial).
#[test]
fn test_concurrent_read_write() {
    loom::model(|| {
        let map: Arc<Mutex<HashMap<&str, u64>>> = Arc::new(Mutex::new(HashMap::new()));

        let m1 = Arc::clone(&map);
        let t1 = thread::spawn(move || {
            let mut guard = m1.lock().unwrap();
            guard.insert("anthropic", 500);
        });

        let m2 = Arc::clone(&map);
        let t2 = thread::spawn(move || {
            let guard = m2.lock().unwrap();
            let val = guard.get("anthropic").copied().unwrap_or(0);
            // Must see either 0 (write hasn't happened) or 500 (write completed)
            assert!(val == 0 || val == 500);
        });

        t1.join().unwrap();
        t2.join().unwrap();
    });
}

/// Two threads accumulate spend for different providers concurrently,
/// verifying independent per-provider tracking through the mutex.
#[test]
fn test_concurrent_multi_provider() {
    loom::model(|| {
        let map: Arc<Mutex<HashMap<&str, u64>>> = Arc::new(Mutex::new(HashMap::new()));

        let m1 = Arc::clone(&map);
        let t1 = thread::spawn(move || {
            let mut guard = m1.lock().unwrap();
            let entry = guard.entry("openai").or_insert(0);
            *entry += 150;
        });

        let m2 = Arc::clone(&map);
        let t2 = thread::spawn(move || {
            let mut guard = m2.lock().unwrap();
            let entry = guard.entry("anthropic").or_insert(0);
            *entry += 250;
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let guard = map.lock().unwrap();
        assert_eq!(guard.get("openai").copied().unwrap_or(0), 150);
        assert_eq!(guard.get("anthropic").copied().unwrap_or(0), 250);
    });
}
