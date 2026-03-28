//! Platform-specific network connection collection.
//!
//! Collects current network connections from OS-specific sources.
//! On macOS: parses `lsof -i -n -P -F pcnPt` output.
//! On Linux: parses `/proc/net/tcp` and `/proc/net/tcp6`.
//! On unsupported platforms: returns an empty set.

use std::collections::HashSet;
use std::net::SocketAddr;

use super::ConnectionInfo;

/// Collect current network connections.
pub async fn collect_connections() -> HashSet<ConnectionInfo> {
    #[cfg(target_os = "macos")]
    {
        collect_macos().await
    }
    #[cfg(target_os = "linux")]
    {
        collect_linux()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        HashSet::new()
    }
}

/// Collect network connections on macOS using `lsof`.
///
/// Uses `tokio::process::Command` with a 30-second timeout to prevent
/// the daemon from hanging indefinitely if `lsof` stalls.
#[cfg(target_os = "macos")]
async fn collect_macos() -> HashSet<ConnectionInfo> {
    use tokio::process::Command;
    use tokio::time::{timeout, Duration};

    let result = timeout(
        Duration::from_secs(30),
        Command::new("lsof")
            .args(["-i", "-n", "-P", "-F", "pcnPt"])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output(),
    )
    .await;

    match result {
        Ok(Ok(out)) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            parse_lsof_output(&stdout)
        }
        Ok(Err(e)) => {
            tracing::warn!(%e, "failed to run lsof for network collection");
            HashSet::new()
        }
        Err(_elapsed) => {
            tracing::warn!("lsof timed out after 30s during network collection");
            HashSet::new()
        }
    }
}

/// Parse lsof `-F pcnPt` field-mode output into connection info.
///
/// The lsof `-F` output uses single-character field identifiers:
/// - `p` = PID
/// - `c` = command name
/// - `n` = connection name (e.g., `127.0.0.1:8080->93.184.216.34:443`)
/// - `P` = protocol (TCP/UDP)
/// - `t` = type (IPv4/IPv6)
///
/// Records are delimited by `p` lines (new process) and `f` lines (new file descriptor).
/// We only care about TCP connections that have both local and remote addresses.
#[must_use]
fn parse_lsof_output(output: &str) -> HashSet<ConnectionInfo> {
    let mut connections = HashSet::new();
    let mut current_pid: Option<u32> = None;
    let mut current_command: Option<String> = None;
    let mut current_protocol: Option<String> = None;

    for line in output.lines() {
        if line.is_empty() {
            continue;
        }

        // Safe to index: we checked the line is non-empty
        let field_id = line.as_bytes()[0];
        // Use safe slicing to avoid panic on unexpected multi-byte UTF-8 first char
        let value = line.get(1..).unwrap_or("");

        match field_id {
            b'p' => {
                current_pid = value.parse::<u32>().ok();
                current_command = None;
            }
            b'c' => {
                current_command = Some(value.to_owned());
            }
            b'P' => {
                current_protocol = Some(value.to_owned());
            }
            b'n' => {
                // Only process TCP connections
                let is_tcp = current_protocol
                    .as_deref()
                    .is_some_and(|p| p.eq_ignore_ascii_case("tcp"));
                if !is_tcp {
                    continue;
                }

                // Parse connection string like "127.0.0.1:8080->93.184.216.34:443"
                // or "[::1]:8080->[::1]:443" for IPv6
                if let Some(conn) = parse_connection_name(value, current_pid, current_command.as_deref()) {
                    connections.insert(conn);
                }
            }
            _ => {}
        }
    }

    connections
}

/// Parse a connection name string from lsof into a `ConnectionInfo`.
///
/// Expected formats:
/// - `local_ip:port->remote_ip:port` (established connection)
/// - `*:port` (listening, no remote -- skipped)
/// - `local_ip:port` (listening or partial -- skipped)
fn parse_connection_name(
    name: &str,
    pid: Option<u32>,
    command: Option<&str>,
) -> Option<ConnectionInfo> {
    // We need the "->" separator for an established connection
    let (local_str, remote_str) = name.split_once("->")?;

    let local_addr = parse_socket_addr(local_str)?;
    let remote_addr = parse_socket_addr(remote_str)?;

    Some(ConnectionInfo {
        pid,
        process_name: command.map(ToOwned::to_owned),
        local_addr,
        remote_addr,
    })
}

/// Parse a socket address string, handling both IPv4 and IPv6 lsof formats.
///
/// IPv4: `127.0.0.1:8080`
/// IPv6: `[::1]:8080` or `::1:8080` (lsof sometimes omits brackets)
fn parse_socket_addr(s: &str) -> Option<SocketAddr> {
    // Try direct parse first (handles standard formats)
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }

    // lsof IPv6 format without brackets: `::1:8080` or `2001:db8::1:443`
    // Find the last colon, split into host and port
    let last_colon = s.rfind(':')?;
    let host = &s[..last_colon];
    let port_str = &s[last_colon + 1..];
    let port: u16 = port_str.parse().ok()?;

    // Try parsing as IPv6 address
    let ipv6: std::net::Ipv6Addr = host.parse().ok()?;
    Some(SocketAddr::from((ipv6, port)))
}

/// Collect network connections on Linux by parsing `/proc/net/tcp` and `/proc/net/tcp6`.
#[cfg(target_os = "linux")]
fn collect_linux() -> HashSet<ConnectionInfo> {
    let mut connections = HashSet::new();

    for path in &["/proc/net/tcp", "/proc/net/tcp6"] {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let parsed = parse_proc_net_tcp(&contents, *path == "/proc/net/tcp6");
                connections.extend(parsed);
            }
            Err(e) => {
                tracing::warn!(path, %e, "failed to read proc net tcp");
            }
        }
    }

    connections
}

/// Parse `/proc/net/tcp` or `/proc/net/tcp6` format.
///
/// Each line (after the header) has fields:
/// ```text
///   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
///   0: 0100007F:1F90 0100007F:0050 01 00000000:00000000 ...
/// ```
///
/// Addresses are in hex: `AABBCCDD:PORT` for IPv4.
/// State 01 = ESTABLISHED.
#[must_use]
#[cfg(any(target_os = "linux", test))]
#[allow(clippy::similar_names)]
fn parse_proc_net_tcp(contents: &str, is_ipv6: bool) -> HashSet<ConnectionInfo> {
    let mut connections = HashSet::new();

    for line in contents.lines().skip(1) {
        // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }

        let local_str = fields[1];
        let remote_str = fields[2];
        let state_str = fields[3];

        // Only interested in ESTABLISHED (01) connections
        if state_str != "01" {
            continue;
        }

        let local_addr = if is_ipv6 {
            parse_proc_hex_addr_v6(local_str)
        } else {
            parse_proc_hex_addr_v4(local_str)
        };
        let remote_addr = if is_ipv6 {
            parse_proc_hex_addr_v6(remote_str)
        } else {
            parse_proc_hex_addr_v4(remote_str)
        };

        if let (Some(local), Some(remote)) = (local_addr, remote_addr) {
            connections.insert(ConnectionInfo {
                pid: None, // /proc/net/tcp doesn't include PID
                process_name: None,
                local_addr: local,
                remote_addr: remote,
            });
        }
    }

    connections
}

/// Parse a hex address from `/proc/net/tcp` format: `0100007F:1F90`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_hex_addr_v4(hex_addr: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = hex_addr.split_once(':')?;
    let addr_u32 = u32::from_str_radix(addr_hex, 16).ok()?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    // /proc/net/tcp stores addresses in native byte order (little-endian on x86)
    let ip = std::net::Ipv4Addr::from(addr_u32.to_be());
    Some(SocketAddr::from((ip, port)))
}

/// Parse a hex IPv6 address from `/proc/net/tcp6` format.
///
/// Format: `00000000000000000000000001000000:1F90`
/// The address is 32 hex chars (128 bits) followed by `:PORT`.
#[cfg(any(target_os = "linux", test))]
fn parse_proc_hex_addr_v6(hex_addr: &str) -> Option<SocketAddr> {
    let (addr_hex, port_hex) = hex_addr.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    if addr_hex.len() != 32 {
        return None;
    }

    // Parse as 4 groups of 4 bytes (32-bit words), each in native byte order
    let mut octets = [0u8; 16];
    for i in 0..4 {
        let start = i * 8;
        let word = u32::from_str_radix(addr_hex.get(start..start + 8)?, 16).ok()?;
        let word_bytes = word.to_be_bytes();
        // Each 32-bit word is stored in host byte order in /proc, but we read as big-endian
        // and need to swap to get the actual bytes
        octets[i * 4] = word_bytes[3];
        octets[i * 4 + 1] = word_bytes[2];
        octets[i * 4 + 2] = word_bytes[1];
        octets[i * 4 + 3] = word_bytes[0];
    }

    let ip = std::net::Ipv6Addr::from(octets);
    Some(SocketAddr::from((ip, port)))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_lsof_basic_tcp_connection() {
        let output = "\
p1234
cchrome
PTCP
tIPv4
n127.0.0.1:52341->93.184.216.34:443
";
        let connections = parse_lsof_output(output);
        assert_eq!(connections.len(), 1);

        let conn = connections.iter().next().unwrap();
        assert_eq!(conn.pid, Some(1234));
        assert_eq!(conn.process_name.as_deref(), Some("chrome"));
        assert_eq!(
            conn.local_addr,
            "127.0.0.1:52341".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            conn.remote_addr,
            "93.184.216.34:443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn parse_lsof_multiple_processes() {
        let output = "\
p1234
cchrome
PTCP
tIPv4
n127.0.0.1:52341->93.184.216.34:443
p5678
cfirefox
PTCP
tIPv4
n192.168.1.10:43210->10.0.0.1:8080
";
        let connections = parse_lsof_output(output);
        assert_eq!(connections.len(), 2);
    }

    #[test]
    fn parse_lsof_skips_udp() {
        let output = "\
p1234
cdns
PUDP
tIPv4
n127.0.0.1:53->8.8.8.8:53
";
        let connections = parse_lsof_output(output);
        assert_eq!(connections.len(), 0);
    }

    #[test]
    fn parse_lsof_skips_listening_sockets() {
        let output = "\
p1234
cnginx
PTCP
tIPv4
n*:80
";
        let connections = parse_lsof_output(output);
        assert_eq!(connections.len(), 0);
    }

    #[test]
    fn parse_lsof_realistic_fixture() {
        let output = "\
p502
cloginwindow
PUDP
tIPv4
n*:*
p1001
cGoogle Chrome
PTCP
tIPv4
n192.168.1.5:52341->142.250.80.46:443
PTCP
tIPv4
n192.168.1.5:52342->151.101.1.69:443
p1002
cslack
PTCP
tIPv4
n192.168.1.5:52400->34.120.208.132:443
p1003
cpython3
PTCP
tIPv4
n127.0.0.1:5000->127.0.0.1:52500
";
        let connections = parse_lsof_output(output);
        // Should have 4 TCP connections (loginwindow UDP is skipped)
        assert_eq!(connections.len(), 4);

        // Verify Chrome connections
        let chrome_conns: Vec<&ConnectionInfo> = connections
            .iter()
            .filter(|c| c.process_name.as_deref() == Some("Google Chrome"))
            .collect();
        assert_eq!(chrome_conns.len(), 2);
        assert!(chrome_conns.iter().all(|c| c.pid == Some(1001)));
    }

    #[test]
    fn parse_lsof_ipv6_connection() {
        let output = "\
p1234
cnode
PTCP
tIPv6
n[::1]:3000->[::1]:52500
";
        let connections = parse_lsof_output(output);
        assert_eq!(connections.len(), 1);

        let conn = connections.iter().next().unwrap();
        assert_eq!(conn.pid, Some(1234));
        assert_eq!(conn.process_name.as_deref(), Some("node"));
    }

    #[test]
    fn parse_lsof_empty_output() {
        let connections = parse_lsof_output("");
        assert!(connections.is_empty());
    }

    #[test]
    fn parse_proc_net_tcp_basic() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346
";
        let connections = parse_proc_net_tcp(contents, false);
        // Only state 01 (ESTABLISHED) connections
        assert_eq!(connections.len(), 1);

        let conn = connections.iter().next().unwrap();
        // 0100007F = 127.0.0.1 (in /proc's byte order)
        assert_eq!(conn.local_addr.port(), 8080); // 0x1F90 = 8080
        assert_eq!(conn.remote_addr.port(), 80); // 0x0050 = 80
    }

    #[test]
    fn parse_proc_net_tcp_empty() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
";
        let connections = parse_proc_net_tcp(contents, false);
        assert!(connections.is_empty());
    }

    #[test]
    fn parse_proc_net_tcp_no_established() {
        let contents = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
";
        // State 0A = LISTEN, should be skipped
        let connections = parse_proc_net_tcp(contents, false);
        assert!(connections.is_empty());
    }

    #[test]
    fn parse_socket_addr_ipv4() {
        let addr = parse_socket_addr("127.0.0.1:8080").unwrap();
        assert_eq!(addr, "127.0.0.1:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_socket_addr_ipv6_bracketed() {
        let addr = parse_socket_addr("[::1]:8080").unwrap();
        assert_eq!(addr, "[::1]:8080".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn parse_socket_addr_ipv6_unbracketed() {
        let addr = parse_socket_addr("::1:8080");
        // This should parse as IPv6 address ::1 with port 8080
        // or as IPv6 address ::0.1.1f.90 depending on parsing
        // In practice, lsof uses bracketed format for IPv6
        // The unbracketed parser splits on last colon
        assert!(addr.is_some());
    }

    #[test]
    fn parse_connection_name_established() {
        let conn = parse_connection_name(
            "192.168.1.5:52341->93.184.216.34:443",
            Some(1234),
            Some("chrome"),
        );
        assert!(conn.is_some());
        let conn = conn.unwrap();
        assert_eq!(conn.pid, Some(1234));
        assert_eq!(conn.process_name.as_deref(), Some("chrome"));
        assert_eq!(conn.remote_addr.port(), 443);
    }

    #[test]
    fn parse_connection_name_no_arrow() {
        // Listening socket, no remote address
        let conn = parse_connection_name("*:80", Some(1234), Some("nginx"));
        assert!(conn.is_none());
    }
}
