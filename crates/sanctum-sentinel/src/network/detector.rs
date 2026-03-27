//! Network anomaly detection heuristics.
//!
//! Checks individual connections against the configured rules to
//! detect blocklisted destinations and unusual port usage.

use sanctum_types::config::NetworkConfig;

use super::{AnomalyKind, ConnectionInfo, NetworkEvent};

/// Check a connection for anomalies.
///
/// Returns `Some(NetworkEvent)` if an anomaly is detected, `None` otherwise.
/// Checks are ordered by priority: blocklist first, then port heuristics.
#[must_use]
pub fn check(conn: &ConnectionInfo, config: &NetworkConfig) -> Option<NetworkEvent> {
    // Check blocklist first (highest priority)
    if let Some(event) = check_blocklist(conn, config) {
        return Some(event);
    }

    // Check for unusual port
    if let Some(event) = check_unusual_port(conn, config) {
        return Some(event);
    }

    None
}

/// Check if `remote_addr.ip()` matches any entry in `config.destination_blocklist`.
fn check_blocklist(conn: &ConnectionInfo, config: &NetworkConfig) -> Option<NetworkEvent> {
    let remote_ip = conn.remote_addr.ip().to_string();

    for entry in &config.destination_blocklist {
        if remote_ip == *entry {
            return Some(NetworkEvent::BlocklistedDestination {
                pid: conn.pid,
                process_name: conn.process_name.clone(),
                remote_addr: conn.remote_addr,
                reason: format!("destination IP {remote_ip} is blocklisted"),
            });
        }
    }

    None
}

/// Check if a connection uses an unusual port.
///
/// A port is considered unusual if:
/// - It is NOT in `config.safe_ports`, AND
/// - The process is NOT in `config.process_allowlist`
fn check_unusual_port(conn: &ConnectionInfo, config: &NetworkConfig) -> Option<NetworkEvent> {
    let remote_port = conn.remote_addr.port();

    // If the port is in the safe list, no alert
    if config.safe_ports.contains(&remote_port) {
        return None;
    }

    // If the process is in the allowlist, no alert
    if let Some(ref name) = conn.process_name {
        if config.process_allowlist.iter().any(|a| a == name) {
            return None;
        }
    }

    Some(NetworkEvent::AnomalousConnection {
        pid: conn.pid,
        process_name: conn.process_name.clone(),
        local_addr: conn.local_addr,
        remote_addr: conn.remote_addr,
        anomaly: AnomalyKind::UnusualPort,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn make_conn(process_name: Option<&str>, remote: &str) -> ConnectionInfo {
        ConnectionInfo {
            pid: Some(1234),
            process_name: process_name.map(ToOwned::to_owned),
            local_addr: "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
            remote_addr: remote.parse::<SocketAddr>().unwrap(),
        }
    }

    fn default_config() -> NetworkConfig {
        NetworkConfig::default()
    }

    #[test]
    fn safe_port_no_alert() {
        let conn = make_conn(Some("chrome"), "93.184.216.34:443");
        let config = default_config();
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn safe_port_22_no_alert() {
        let conn = make_conn(Some("ssh"), "10.0.0.1:22");
        let config = default_config();
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn unusual_port_triggers_alert() {
        let conn = make_conn(Some("suspicious"), "10.0.0.1:4444");
        let config = default_config();
        let event = check(&conn, &config);
        assert!(event.is_some());
        match event.unwrap() {
            NetworkEvent::AnomalousConnection { anomaly, .. } => {
                assert_eq!(anomaly, AnomalyKind::UnusualPort);
            }
            NetworkEvent::BlocklistedDestination { .. } => {
                panic!("expected AnomalousConnection");
            }
        }
    }

    #[test]
    fn allowlisted_process_unusual_port_no_alert() {
        let conn = make_conn(Some("Dropbox"), "10.0.0.1:4444");
        let config = default_config();
        // Dropbox is in the default process allowlist
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn blocklisted_destination_triggers_alert() {
        let conn = make_conn(Some("curl"), "10.0.0.99:443");
        let mut config = default_config();
        config.destination_blocklist = vec!["10.0.0.99".to_owned()];
        let event = check(&conn, &config);
        assert!(event.is_some());
        match event.unwrap() {
            NetworkEvent::BlocklistedDestination { reason, .. } => {
                assert!(reason.contains("10.0.0.99"));
                assert!(reason.contains("blocklisted"));
            }
            NetworkEvent::AnomalousConnection { .. } => {
                panic!("expected BlocklistedDestination");
            }
        }
    }

    #[test]
    fn blocklist_takes_priority_over_port_check() {
        // Even on a safe port, blocklist should fire
        let conn = make_conn(Some("curl"), "10.0.0.99:443");
        let mut config = default_config();
        config.destination_blocklist = vec!["10.0.0.99".to_owned()];
        let event = check(&conn, &config);
        assert!(event.is_some());
        assert!(matches!(
            event.unwrap(),
            NetworkEvent::BlocklistedDestination { .. }
        ));
    }

    #[test]
    fn non_blocklisted_destination_no_blocklist_alert() {
        let conn = make_conn(Some("curl"), "93.184.216.34:443");
        let mut config = default_config();
        config.destination_blocklist = vec!["10.0.0.99".to_owned()];
        // Not blocklisted AND on safe port -> no alert
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn unknown_process_unusual_port_triggers_alert() {
        // No process name at all -> should still alert on unusual port
        let conn = make_conn(None, "10.0.0.1:4444");
        let config = default_config();
        let event = check(&conn, &config);
        assert!(event.is_some());
        match event.unwrap() {
            NetworkEvent::AnomalousConnection { anomaly, .. } => {
                assert_eq!(anomaly, AnomalyKind::UnusualPort);
            }
            NetworkEvent::BlocklistedDestination { .. } => {
                panic!("expected AnomalousConnection");
            }
        }
    }

    #[test]
    fn empty_blocklist_no_blocklist_alerts() {
        let conn = make_conn(Some("curl"), "10.0.0.99:443");
        let config = default_config();
        // Default config has empty blocklist
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn custom_safe_ports_are_respected() {
        let conn = make_conn(Some("myapp"), "10.0.0.1:9999");
        let mut config = default_config();
        config.safe_ports.push(9999);
        assert!(check(&conn, &config).is_none());
    }
}
