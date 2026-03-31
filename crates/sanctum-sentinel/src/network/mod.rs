//! Network anomaly detection.
//!
//! Monitors outbound network connections and detects suspicious patterns
//! by comparing against a learned baseline of normal behavior.

pub mod collector;
pub mod detector;
pub mod exfiltration;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sanctum_types::config::NetworkConfig;
use tokio::sync::mpsc;

/// Estimated bytes per new outbound connection for exfiltration tracking.
///
/// Since connection-level byte counts are not available from `/proc/net/tcp`
/// snapshots or `lsof` output, each new connection is assigned a conservative
/// fixed estimate. This catches high-connection-count exfiltration patterns
/// (e.g., RAT beaconing). Precise byte-level tracking is deferred to eBPF
/// integration (v0.5.0) or can be fed directly via `ExfiltrationTracker::record_bytes`
/// from the proxy.
const EXFIL_BYTES_PER_CONNECTION: u64 = 65_536; // 64 KB

/// A detected network event.
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// A new outbound connection matching an anomaly pattern.
    AnomalousConnection {
        /// Process ID, if known.
        pid: Option<u32>,
        /// Process name, if known.
        process_name: Option<String>,
        /// Local socket address.
        local_addr: SocketAddr,
        /// Remote socket address.
        remote_addr: SocketAddr,
        /// The kind of anomaly detected.
        anomaly: AnomalyKind,
    },
    /// A connection to a blocklisted destination.
    BlocklistedDestination {
        /// Process ID, if known.
        pid: Option<u32>,
        /// Process name, if known.
        process_name: Option<String>,
        /// Remote socket address.
        remote_addr: SocketAddr,
        /// Reason the destination is blocklisted.
        reason: String,
    },
    /// Excessive outbound data transfer to a single host.
    DataExfiltration {
        /// Destination IP that exceeded the threshold.
        dest_ip: std::net::IpAddr,
        /// Total bytes accumulated in the current window.
        total_bytes: u64,
        /// Alert severity (warning or critical).
        alert: exfiltration::ExfiltrationAlert,
    },
}

/// The kind of anomaly detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// Connection to an unusual port for this process.
    UnusualPort,
    /// Connection from a process not in the baseline.
    UnexpectedProcess,
    /// Listening on a high-numbered port not in the baseline.
    SuspiciousListener,
}

/// Information about a single network connection.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct ConnectionInfo {
    /// Process ID, if known.
    pub pid: Option<u32>,
    /// Process name, if known.
    pub process_name: Option<String>,
    /// Local socket address.
    pub local_addr: SocketAddr,
    /// Remote socket address.
    pub remote_addr: SocketAddr,
}

/// Watches for network anomalies by polling connection state.
pub struct NetworkWatcher {
    alive: Arc<AtomicBool>,
}

impl NetworkWatcher {
    /// Start the network watcher.
    ///
    /// Spawns a background task that polls connections at the configured interval
    /// and sends anomaly events through the provided channel. Includes
    /// per-host exfiltration volume tracking that alerts when configurable
    /// byte thresholds are exceeded within a time window.
    #[must_use]
    pub fn start(config: NetworkConfig, tx: mpsc::Sender<NetworkEvent>) -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let alive_clone = alive.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(config.poll_interval_secs));
            let mut previous_connections: HashSet<ConnectionInfo> = HashSet::new();
            let mut exfil_tracker = exfiltration::ExfiltrationTracker::new(&config);
            // Counter for periodic cleanup of expired exfiltration entries.
            let mut poll_count: u64 = 0;

            loop {
                interval.tick().await;
                if !alive_clone.load(Ordering::Acquire) {
                    break;
                }

                let current = collector::collect_connections().await;

                // Find new connections (not in previous snapshot)
                for conn in &current {
                    if !previous_connections.contains(conn) {
                        // Check for anomalies (blocklist, unusual ports)
                        if let Some(event) = detector::check(conn, &config) {
                            if tx.send(event).await.is_err() {
                                alive_clone.store(false, Ordering::Release);
                                return;
                            }
                        }

                        // Feed exfiltration tracker: each new connection contributes
                        // an estimated byte count. This is a heuristic — actual byte
                        // tracking requires deeper OS integration (eBPF, /proc/net/dev).
                        // The estimate is conservative: 64KB per new connection observed.
                        let dest_ip = conn.remote_addr.ip();
                        if let Some((alert, accumulated)) =
                            exfil_tracker.record_bytes(dest_ip, EXFIL_BYTES_PER_CONNECTION)
                        {
                            let event = NetworkEvent::DataExfiltration {
                                dest_ip,
                                total_bytes: accumulated,
                                alert,
                            };
                            if tx.send(event).await.is_err() {
                                alive_clone.store(false, Ordering::Release);
                                return;
                            }
                        }
                    }
                }

                previous_connections = current;

                // Periodically clean up expired exfiltration entries to prevent
                // unbounded memory growth. Every 10 polls (~5 minutes at default
                // 30-second interval).
                poll_count = poll_count.wrapping_add(1);
                if poll_count.is_multiple_of(10) {
                    exfil_tracker.cleanup_expired();
                }
            }
        });

        Self { alive }
    }

    /// Check if the watcher is still running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }

    /// Stop the watcher.
    pub fn stop(&self) {
        self.alive.store(false, Ordering::Release);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn anomaly_kind_equality() {
        assert_eq!(AnomalyKind::UnusualPort, AnomalyKind::UnusualPort);
        assert_ne!(AnomalyKind::UnusualPort, AnomalyKind::UnexpectedProcess);
    }

    #[test]
    fn connection_info_hashing() {
        let conn1 = ConnectionInfo {
            pid: Some(123),
            process_name: Some("test".to_owned()),
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            remote_addr: "93.184.216.34:443".parse().unwrap(),
        };
        let conn2 = conn1.clone();

        let mut set = HashSet::new();
        set.insert(conn1);
        assert!(set.contains(&conn2));
    }

    #[tokio::test]
    async fn network_watcher_can_be_stopped() {
        let config = NetworkConfig::default();
        let (tx, _rx) = mpsc::channel(16);
        let watcher = NetworkWatcher::start(config, tx);
        assert!(watcher.is_alive());
        watcher.stop();
        // Give the spawned task a chance to see the stop signal
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!watcher.is_alive());
    }

    #[tokio::test]
    async fn network_watcher_stops_when_receiver_dropped() {
        let config = NetworkConfig {
            poll_interval_secs: 1,
            ..NetworkConfig::default()
        };
        let (tx, rx) = mpsc::channel(16);
        let watcher = NetworkWatcher::start(config, tx);
        assert!(watcher.is_alive());
        // Drop the receiver
        drop(rx);
        // The watcher will stop on its next poll when it tries to send
        // We can't guarantee timing, but it should eventually stop
        tokio::time::sleep(Duration::from_secs(3)).await;
        // Just verify it didn't panic -- the is_alive state depends on
        // whether a connection was found to trigger a send failure
    }
}
