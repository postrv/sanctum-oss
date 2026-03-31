//! Network anomaly detection heuristics.
//!
//! Checks individual connections against the configured rules to
//! detect blocklisted destinations and unusual port usage.

use sanctum_types::config::NetworkConfig;

use super::{AnomalyKind, ConnectionInfo, NetworkEvent};

/// Check a connection for anomalies.
///
/// Returns `Some(NetworkEvent)` if an anomaly is detected, `None` otherwise.
///
/// **Precedence**: Allowlisted destinations skip all anomaly checks
/// including blocklist checks. To block an allowlisted destination,
/// remove it from the allowlist first.
///
/// After the allowlist, checks are: blocklist, then port heuristics.
#[must_use]
pub fn check(conn: &ConnectionInfo, config: &NetworkConfig) -> Option<NetworkEvent> {
    // Allowlisted destinations skip all anomaly checks including blocklist
    // checks. To block an allowlisted destination, remove it from the
    // allowlist first.
    if is_destination_allowlisted(conn, config) {
        return None;
    }

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

/// Check if a destination IP is in the configured allowlist.
///
/// Allowlisted destinations skip all anomaly checks including blocklist
/// checks. To block an allowlisted destination, remove it from the
/// allowlist first.
fn is_destination_allowlisted(conn: &ConnectionInfo, config: &NetworkConfig) -> bool {
    let remote_ip = conn.remote_addr.ip().to_string();
    config.destination_allowlist.contains(&remote_ip)
}

/// Check if `remote_addr.ip()` matches any entry in `config.destination_blocklist`.
///
/// Uses exact IP string comparison only (no CIDR matching). Each blocklist
/// entry must be a single IP address string, not a subnet.
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
            other => panic!("expected AnomalousConnection, got: {other:?}"),
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
            other => panic!("expected BlocklistedDestination, got: {other:?}"),
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
            other => panic!("expected AnomalousConnection, got: {other:?}"),
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

    // ============================================================
    // DESTINATION ALLOWLIST (W5)
    // ============================================================

    #[test]
    fn allowlisted_destination_not_flagged_on_unusual_port() {
        // Without allowlist, an unusual port triggers an alert
        let conn = make_conn(Some("myapp"), "10.0.0.50:4444");
        let config = default_config();
        assert!(check(&conn, &config).is_some());

        // With allowlist, the same destination should be skipped
        let mut config_with_al = default_config();
        config_with_al.destination_allowlist = vec!["10.0.0.50".to_owned()];
        assert!(check(&conn, &config_with_al).is_none());
    }

    #[test]
    fn allowlisted_destination_overrides_blocklist() {
        // If a destination is both allowlisted and blocklisted,
        // the allowlist wins (checked first)
        let conn = make_conn(Some("curl"), "10.0.0.99:443");
        let mut config = default_config();
        config.destination_blocklist = vec!["10.0.0.99".to_owned()];
        config.destination_allowlist = vec!["10.0.0.99".to_owned()];
        assert!(check(&conn, &config).is_none());
    }

    #[test]
    fn non_allowlisted_destination_still_flagged() {
        let conn = make_conn(Some("suspicious"), "10.0.0.1:4444");
        let mut config = default_config();
        config.destination_allowlist = vec!["10.0.0.50".to_owned()];
        // 10.0.0.1 is NOT in the allowlist, should still be flagged
        assert!(check(&conn, &config).is_some());
    }
}
