//! Volume-based exfiltration alerting.
//!
//! Tracks per-host outbound byte counts within time windows and raises alerts
//! when configurable thresholds are exceeded.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use sanctum_types::config::NetworkConfig;

/// Alert level from exfiltration tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExfiltrationAlert {
    /// Bytes exceeded warning threshold.
    Warning,
    /// Bytes exceeded critical/block threshold.
    Critical,
}

/// Per-host byte accumulation with time-windowed reset.
struct HostCounter {
    bytes: u64,
    window_start: Instant,
    /// True once a `Warning` alert has been emitted in the current window.
    warned: bool,
    /// True once a `Critical` alert has been emitted in the current window.
    alerted: bool,
}

/// Maximum number of hosts tracked simultaneously.
///
/// Prevents unbounded memory growth from IP-flooding attacks. When the cap
/// is reached, expired entries are cleaned up first; if still over the limit,
/// new hosts are silently dropped.
const MAX_TRACKED_HOSTS: usize = 10_000;

/// Tracks per-host outbound transfer volumes and alerts when thresholds are exceeded.
///
/// Design: simple threshold model (NOT EWMA). Alert if >N bytes leave to a single
/// non-allowlisted host within M seconds. Counters reset after the time window.
pub struct ExfiltrationTracker {
    /// Per-host byte counters, keyed by destination IP.
    counters: HashMap<IpAddr, HostCounter>,
    /// Bytes that trigger a warning alert.
    warn_bytes: u64,
    /// Bytes that trigger a critical alert.
    block_bytes: u64,
    /// Time window in seconds before counters reset.
    window_secs: u64,
    /// IPs exempt from exfiltration checks.
    host_allowlist: Vec<IpAddr>,
    /// Override for `Instant::now()` during tests.
    #[cfg(test)]
    now_override: Option<Instant>,
}

impl ExfiltrationTracker {
    /// Create a new tracker from the sentinel network configuration.
    ///
    /// If `warn_bytes > block_bytes`, the values are swapped and a warning is
    /// logged so that detection still works correctly.
    #[must_use]
    pub fn new(config: &NetworkConfig) -> Self {
        let host_allowlist: Vec<IpAddr> = config
            .exfiltration_host_allowlist
            .iter()
            .filter_map(|s| match s.parse::<IpAddr>() {
                Ok(addr) => Some(addr),
                Err(e) => {
                    tracing::warn!(
                        entry = %s,
                        error = %e,
                        "ignoring unparseable exfiltration allowlist entry"
                    );
                    None
                }
            })
            .collect();

        let (warn_bytes, block_bytes) =
            if config.exfiltration_warn_bytes > config.exfiltration_block_bytes {
                tracing::warn!(
                    warn_bytes = config.exfiltration_warn_bytes,
                    block_bytes = config.exfiltration_block_bytes,
                    "exfiltration_warn_bytes > exfiltration_block_bytes — swapping values"
                );
                (
                    config.exfiltration_block_bytes,
                    config.exfiltration_warn_bytes,
                )
            } else {
                (
                    config.exfiltration_warn_bytes,
                    config.exfiltration_block_bytes,
                )
            };

        Self {
            counters: HashMap::new(),
            warn_bytes,
            block_bytes,
            window_secs: config.exfiltration_window_secs,
            host_allowlist,
            #[cfg(test)]
            now_override: None,
        }
    }

    /// Record `bytes` outbound to `dest` and return an alert if a threshold is
    /// crossed.
    ///
    /// Returns `Some((alert, accumulated_bytes))` when a threshold is newly
    /// crossed, or `None` for allowlisted hosts, transfers below the warning
    /// threshold, hosts that have already triggered the same alert level in the
    /// current window, or when the tracker is at capacity.
    pub fn record_bytes(&mut self, dest: IpAddr, bytes: u64) -> Option<(ExfiltrationAlert, u64)> {
        if self.host_allowlist.contains(&dest) {
            return None;
        }

        // Enforce maximum tracked hosts to prevent unbounded memory growth.
        if !self.counters.contains_key(&dest) && self.counters.len() >= MAX_TRACKED_HOSTS {
            self.cleanup_expired();
            if self.counters.len() >= MAX_TRACKED_HOSTS {
                tracing::warn!(
                    dest = %dest,
                    tracked = self.counters.len(),
                    "exfiltration tracker at capacity — skipping new host"
                );
                return None;
            }
        }

        let now = self.now();
        let window_dur = Duration::from_secs(self.window_secs);

        let counter = self.counters.entry(dest).or_insert_with(|| HostCounter {
            bytes: 0,
            window_start: now,
            warned: false,
            alerted: false,
        });

        // Reset if the window has expired.
        if now.duration_since(counter.window_start) >= window_dur {
            counter.bytes = 0;
            counter.window_start = now;
            counter.warned = false;
            counter.alerted = false;
        }

        counter.bytes = counter.bytes.saturating_add(bytes);

        if counter.alerted {
            return None;
        }

        if counter.bytes >= self.block_bytes {
            counter.alerted = true;
            Some((ExfiltrationAlert::Critical, counter.bytes))
        } else if counter.bytes >= self.warn_bytes {
            if counter.warned {
                return None;
            }
            counter.warned = true;
            Some((ExfiltrationAlert::Warning, counter.bytes))
        } else {
            None
        }
    }

    /// Remove counters whose time window has expired.
    ///
    /// Call this periodically to prevent unbounded memory growth.
    pub fn cleanup_expired(&mut self) {
        let now = self.now();
        let window_dur = Duration::from_secs(self.window_secs);
        self.counters
            .retain(|_ip, counter| now.duration_since(counter.window_start) < window_dur);
    }

    /// Number of hosts currently being tracked.
    #[must_use]
    pub fn active_host_count(&self) -> usize {
        self.counters.len()
    }

    /// Current timestamp — overridable in tests to simulate time advancement.
    #[cfg(not(test))]
    #[allow(clippy::unused_self)]
    fn now(&self) -> Instant {
        Instant::now()
    }

    /// Current timestamp — overridable in tests to simulate time advancement.
    #[cfg(test)]
    fn now(&self) -> Instant {
        self.now_override.unwrap_or_else(Instant::now)
    }

    /// Override the value returned by `now()` for deterministic tests.
    #[cfg(test)]
    const fn set_now(&mut self, now: Instant) {
        self.now_override = Some(now);
    }
}

// ---------------------------------------------------------------------------
// Kani bounded model checking proofs
// ---------------------------------------------------------------------------

#[cfg(kani)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod kani_proofs {
    use super::*;
    use std::net::Ipv4Addr;

    /// Proof: `record_bytes` never panics regardless of byte count.
    ///
    /// This proves that the `saturating_add` on line 107 prevents overflow
    /// and that no other arithmetic operation can panic. The proof covers
    /// two consecutive calls with arbitrary u64 values.
    #[kani::proof]
    fn exfiltration_record_bytes_never_panics() {
        let warn: u64 = kani::any();
        let block: u64 = kani::any();
        let window: u64 = kani::any();

        // Constrain to reasonable ranges to keep proof tractable
        kani::assume(warn > 0 && warn <= u64::MAX / 2);
        kani::assume(block >= warn && block <= u64::MAX);
        kani::assume(window > 0 && window <= 3600);

        let config = NetworkConfig {
            exfiltration_warn_bytes: warn,
            exfiltration_block_bytes: block,
            exfiltration_window_secs: window,
            exfiltration_host_allowlist: Vec::new(),
            ..NetworkConfig::default()
        };

        let mut tracker = ExfiltrationTracker::new(&config);
        let dest = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let bytes1: u64 = kani::any();
        let bytes2: u64 = kani::any();

        // Two calls with arbitrary byte counts must not panic
        let _ = tracker.record_bytes(dest, bytes1);
        let _ = tracker.record_bytes(dest, bytes2);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: build a minimal `NetworkConfig` with custom thresholds.
    fn test_config(
        warn_bytes: u64,
        block_bytes: u64,
        window_secs: u64,
        allowlist: Vec<&str>,
    ) -> NetworkConfig {
        NetworkConfig {
            exfiltration_warn_bytes: warn_bytes,
            exfiltration_block_bytes: block_bytes,
            exfiltration_window_secs: window_secs,
            exfiltration_host_allowlist: allowlist.into_iter().map(String::from).collect(),
            ..NetworkConfig::default()
        }
    }

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn remote() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
    }

    fn other_remote() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
    }

    // 1. Allowlisted host is never tracked.
    #[test]
    fn test_allowlisted_host_not_tracked() {
        let cfg = test_config(100, 200, 60, vec!["127.0.0.1"]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let result = tracker.record_bytes(localhost(), 9999);
        assert_eq!(result, None);
        assert_eq!(tracker.active_host_count(), 0);
    }

    // 2. Below warning threshold => no alert.
    #[test]
    fn test_below_warn_threshold_no_alert() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let result = tracker.record_bytes(remote(), 999);
        assert_eq!(result, None);
    }

    // 3. Exactly at warn_bytes => Warning.
    #[test]
    fn test_warn_threshold_triggers_warning() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let result = tracker.record_bytes(remote(), 1000);
        assert_eq!(result, Some((ExfiltrationAlert::Warning, 1000)));
    }

    // 4. Exactly at block_bytes => Critical.
    #[test]
    fn test_block_threshold_triggers_critical() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let result = tracker.record_bytes(remote(), 5000);
        assert_eq!(result, Some((ExfiltrationAlert::Critical, 5000)));
    }

    // 5. Multiple small records that accumulate past the warning threshold.
    #[test]
    fn test_accumulation_across_calls() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        assert_eq!(tracker.record_bytes(remote(), 400), None);
        assert_eq!(tracker.record_bytes(remote(), 400), None);
        // 800 + 300 = 1100 >= 1000 => Warning
        assert_eq!(
            tracker.record_bytes(remote(), 300),
            Some((ExfiltrationAlert::Warning, 1100))
        );
        // Warning already fired in this window — suppressed.
        assert_eq!(tracker.record_bytes(remote(), 100), None);
    }

    // 6. Window expiry resets the counter so the same host starts fresh.
    #[test]
    fn test_window_reset_clears_counter() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let t0 = Instant::now();
        tracker.set_now(t0);

        // Record enough to trigger a warning.
        assert_eq!(
            tracker.record_bytes(remote(), 1500),
            Some((ExfiltrationAlert::Warning, 1500))
        );

        // Advance past the 60-second window.
        tracker.set_now(t0 + Duration::from_secs(61));

        // Same amount should NOT trigger because counter was reset.
        // 500 < 1000, so None.
        assert_eq!(tracker.record_bytes(remote(), 500), None);
    }

    // 7. Critical alert does not repeat within the same window.
    #[test]
    fn test_critical_alert_does_not_repeat_within_window() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let t0 = Instant::now();
        tracker.set_now(t0);

        assert_eq!(
            tracker.record_bytes(remote(), 5000),
            Some((ExfiltrationAlert::Critical, 5000))
        );

        // Subsequent call in the same window => None (suppressed).
        assert_eq!(tracker.record_bytes(remote(), 1000), None);
        assert_eq!(tracker.record_bytes(remote(), 1000), None);

        // After window resets, alerting resumes.
        tracker.set_now(t0 + Duration::from_secs(61));
        assert_eq!(
            tracker.record_bytes(remote(), 5000),
            Some((ExfiltrationAlert::Critical, 5000))
        );
    }

    // 8. Warning upgrades to Critical when more bytes arrive.
    #[test]
    fn test_warning_upgrades_to_critical() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        // First call: triggers Warning (1500 >= 1000, < 5000).
        assert_eq!(
            tracker.record_bytes(remote(), 1500),
            Some((ExfiltrationAlert::Warning, 1500))
        );

        // Second call: total 1500 + 4000 = 5500 >= 5000 => Critical.
        assert_eq!(
            tracker.record_bytes(remote(), 4000),
            Some((ExfiltrationAlert::Critical, 5500))
        );
    }

    // 9. cleanup_expired removes entries whose window has lapsed.
    #[test]
    fn test_cleanup_removes_expired_entries() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let t0 = Instant::now();
        tracker.set_now(t0);

        tracker.record_bytes(remote(), 100);
        assert_eq!(tracker.active_host_count(), 1);

        // Advance past the window.
        tracker.set_now(t0 + Duration::from_secs(61));
        tracker.cleanup_expired();
        assert_eq!(tracker.active_host_count(), 0);
    }

    // 10. Two hosts tracked independently; only one exceeds threshold.
    #[test]
    fn test_multiple_hosts_tracked_independently() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        // Host A: below threshold.
        assert_eq!(tracker.record_bytes(remote(), 500), None);
        // Host B: above warning threshold.
        assert_eq!(
            tracker.record_bytes(other_remote(), 1500),
            Some((ExfiltrationAlert::Warning, 1500))
        );

        // Host A still below.
        assert_eq!(tracker.record_bytes(remote(), 200), None);
        assert_eq!(tracker.active_host_count(), 2);
    }

    // 11. Saturating add prevents overflow.
    #[test]
    fn test_saturating_add_prevents_overflow() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        // First call will trigger Critical (u64::MAX >> both thresholds).
        let result = tracker.record_bytes(remote(), u64::MAX);
        assert_eq!(result, Some((ExfiltrationAlert::Critical, u64::MAX)));

        // Second call: saturating_add(u64::MAX) should not panic.
        let result = tracker.record_bytes(remote(), u64::MAX);
        // Already alerted Critical in this window, so suppressed.
        assert_eq!(result, None);
    }

    // 12. Unparseable allowlist entries are silently ignored.
    #[test]
    fn test_unparseable_allowlist_entries_ignored() {
        let cfg = test_config(1000, 5000, 60, vec!["not-an-ip", "127.0.0.1", "also_bad"]);
        let tracker = ExfiltrationTracker::new(&cfg);

        // Only the valid entry should survive.
        assert_eq!(tracker.host_allowlist.len(), 1);
        assert_eq!(tracker.host_allowlist[0], localhost());
    }

    // 13. warn_bytes > block_bytes is auto-swapped.
    #[test]
    fn test_warn_above_block_swapped() {
        // Intentionally pass warn > block.
        let cfg = test_config(5000, 1000, 60, vec![]);
        let tracker = ExfiltrationTracker::new(&cfg);

        // After swap: warn=1000, block=5000.
        assert_eq!(tracker.warn_bytes, 1000);
        assert_eq!(tracker.block_bytes, 5000);
    }

    // 14. Warning suppression: repeated warnings in the same window are suppressed.
    #[test]
    fn test_warning_suppressed_within_window() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        let t0 = Instant::now();
        tracker.set_now(t0);

        // First call triggers Warning.
        assert_eq!(
            tracker.record_bytes(remote(), 1500),
            Some((ExfiltrationAlert::Warning, 1500))
        );

        // Second call still in warning band — suppressed.
        assert_eq!(tracker.record_bytes(remote(), 500), None);

        // After window reset, warning fires again.
        tracker.set_now(t0 + Duration::from_secs(61));
        assert_eq!(
            tracker.record_bytes(remote(), 1500),
            Some((ExfiltrationAlert::Warning, 1500))
        );
    }

    // 15. Max tracked hosts cap prevents unbounded growth.
    #[test]
    fn test_max_tracked_hosts_cap() {
        let cfg = test_config(1000, 5000, 60, vec![]);
        let mut tracker = ExfiltrationTracker::new(&cfg);

        // Fill up to MAX_TRACKED_HOSTS unique IPs.
        for i in 0..MAX_TRACKED_HOSTS {
            #[allow(clippy::cast_possible_truncation)]
            let ip = IpAddr::V4(Ipv4Addr::new(
                10,
                ((i >> 16) & 0xFF) as u8,
                ((i >> 8) & 0xFF) as u8,
                (i & 0xFF) as u8,
            ));
            let _ = tracker.record_bytes(ip, 100);
        }
        assert_eq!(tracker.active_host_count(), MAX_TRACKED_HOSTS);

        // One more new host should be rejected (all entries are still live).
        let extra = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let result = tracker.record_bytes(extra, 9999);
        assert_eq!(result, None);
        // Count stays at MAX_TRACKED_HOSTS (extra was not added).
        assert_eq!(tracker.active_host_count(), MAX_TRACKED_HOSTS);
    }
}
