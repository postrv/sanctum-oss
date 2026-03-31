#![cfg(unix)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
//! End-to-end IPC integration tests.
//!
//! These tests spawn a real `sanctum-daemon` binary and communicate with it
//! over Unix domain sockets using the length-prefixed JSON protocol.
//!
//! Run with: `cargo test -p sanctum-daemon --test e2e_ipc_integration -- --ignored`

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use std::{fs, thread};

use sanctum_types::ipc::{IpcCommand, IpcMessage, IpcResponse};

/// Global counter to ensure each `DaemonProcess::start()` gets a unique home dir,
/// even when tests run in parallel within the same process.
static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

// ============================================================
// Platform-conditional path construction
// ============================================================

/// Returns `(data_dir, config_dir)` matching `sanctum_types::paths::platform_dirs`.
#[cfg(target_os = "macos")]
fn platform_paths(home: &Path) -> (PathBuf, PathBuf) {
    let dir = home.join("Library/Application Support/sanctum");
    (dir.clone(), dir)
}

/// Returns `(data_dir, config_dir)` matching `sanctum_types::paths::platform_dirs`.
#[cfg(not(target_os = "macos"))]
fn platform_paths(home: &Path) -> (PathBuf, PathBuf) {
    let data_dir = home.join(".local/share/sanctum");
    let config_dir = home.join(".config/sanctum");
    (data_dir, config_dir)
}

// ============================================================
// Stale test directory cleanup
// ============================================================

/// Clean up stale `/tmp/sd-e2e-*` directories from previous test runs whose
/// owning process is no longer alive.
fn cleanup_stale_test_dirs() {
    let Ok(entries) = fs::read_dir("/tmp") else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            continue;
        };
        if !name_str.starts_with("sd-e2e-") {
            continue;
        }
        // Extract PID from directory name: sd-e2e-<PID>-<suffix>
        let parts: Vec<&str> = name_str.splitn(4, '-').collect();
        if parts.len() < 3 {
            continue;
        }
        let Ok(pid) = parts[2].parse::<i32>() else {
            continue;
        };
        // Check if the process is still alive
        let alive = nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_ok();
        if !alive {
            let path = entry.path();
            let _ = fs::remove_dir_all(&path);
        }
    }
}

// ============================================================
// Daemon process wrapper
// ============================================================

struct DaemonProcess {
    child: Option<Child>,
    home_dir: PathBuf,
    data_dir: PathBuf,
    _config_dir: PathBuf,
}

impl DaemonProcess {
    fn start() -> Self {
        // Clean up stale directories from previous (possibly killed) runs
        cleanup_stale_test_dirs();

        let seq = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let test_id = format!("sd-e2e-{}-{seq}", std::process::id());
        let home = PathBuf::from(format!("/tmp/{test_id}"));
        fs::create_dir_all(&home).expect("create test home dir");

        let (data_dir, config_dir) = platform_paths(&home);
        fs::create_dir_all(&data_dir).expect("create data dir");
        fs::create_dir_all(&config_dir).expect("create config dir");

        // Write a minimal config so the daemon starts without errors
        let config_file = config_dir.join("config.toml");
        fs::write(
            &config_file,
            r#"
[sentinel]
watch_pth = true
pth_response = "quarantine"
watch_credentials = true
watch_network = false
watch_npm = false
"#,
        )
        .expect("write config");

        // Find the daemon binary
        let daemon_bin = find_daemon_binary();

        let child = Command::new(&daemon_bin)
            .arg("start")
            .env("HOME", &home)
            // Override XDG dirs on Linux to point to our test home
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("RUST_LOG", "warn")
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn daemon at {}: {e}", daemon_bin.display()));

        let socket_path = data_dir.join("sanctum.sock");

        // Wait for socket to appear (up to 10 seconds)
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if socket_path.exists() {
                // Give the daemon a moment to fully bind
                thread::sleep(Duration::from_millis(100));
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        assert!(
            socket_path.exists(),
            "daemon socket did not appear at {} within 10s",
            socket_path.display()
        );

        Self {
            child: Some(child),
            home_dir: home,
            data_dir,
            _config_dir: config_dir,
        }
    }

    fn socket_path(&self) -> PathBuf {
        self.data_dir.join("sanctum.sock")
    }

    fn auth_token(&self) -> String {
        let token_path = self.data_dir.join("auth_token");
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Ok(token) = fs::read_to_string(&token_path) {
                let t = token.trim().to_string();
                if !t.is_empty() {
                    return t;
                }
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!(
            "auth token file did not appear at {} within 5s",
            token_path.display()
        );
    }

    fn send_command(&self, msg: &IpcMessage) -> IpcResponse {
        let socket = self.socket_path();
        let mut stream = UnixStream::connect(&socket).expect("connect to daemon socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set write timeout");

        send_message_raw(&mut stream, msg);
        read_response_raw(&mut stream)
    }

    /// Take ownership of the child, preventing Drop from killing it.
    const fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }
}

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir_all(&self.home_dir);
    }
}

// ============================================================
// Wire-protocol helpers (synchronous, blocking I/O)
// ============================================================

fn send_message_raw(stream: &mut UnixStream, msg: &IpcMessage) {
    let payload = serde_json::to_vec(msg).expect("serialise IpcMessage");
    #[allow(clippy::cast_possible_truncation)]
    let len = payload.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .expect("write length prefix");
    stream.write_all(&payload).expect("write payload");
    stream.flush().expect("flush");
}

fn read_response_raw(stream: &mut UnixStream) -> IpcResponse {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).expect("read length prefix");
    let resp_len = u32::from_be_bytes(len_buf) as usize;
    assert!(resp_len > 0, "daemon returned zero-length response");
    assert!(
        resp_len <= 64 * 1024,
        "response too large: {resp_len} bytes"
    );

    let mut payload = vec![0u8; resp_len];
    stream.read_exact(&mut payload).expect("read payload");
    serde_json::from_slice(&payload).expect("deserialise IpcResponse")
}

// ============================================================
// Binary discovery
// ============================================================

fn find_daemon_binary() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace_root = Path::new(manifest_dir)
        .parent()
        .expect("parent of manifest dir")
        .parent()
        .expect("workspace root");

    for profile in &["debug", "release"] {
        let candidate = workspace_root.join(format!("target/{profile}/sanctum-daemon"));
        if candidate.exists() {
            return candidate;
        }
    }

    panic!(
        "sanctum-daemon binary not found. Run `cargo build -p sanctum-daemon` first.\n\
         Searched in: {}/target/{{debug,release}}/sanctum-daemon",
        workspace_root.display()
    );
}

// ============================================================
// Tests
// ============================================================

#[test]
#[ignore = "spawns a real daemon process; run with --ignored"]
fn test_daemon_status_query() {
    let daemon = DaemonProcess::start();

    let msg = IpcMessage {
        command: IpcCommand::Status,
        auth_token: None,
    };
    let resp = daemon.send_command(&msg);

    match resp {
        IpcResponse::Status {
            version,
            uptime_secs,
            ..
        } => {
            assert!(!version.is_empty(), "version should be non-empty");
            assert!(
                uptime_secs < 60,
                "uptime should be < 60s for a fresh daemon"
            );
        }
        other => panic!("expected Status response, got: {other:?}"),
    }
}

#[test]
#[ignore = "spawns a real daemon process; run with --ignored"]
fn test_budget_recording_and_query() {
    let daemon = DaemonProcess::start();
    let token = daemon.auth_token();

    // Record some usage
    let record_msg = IpcMessage {
        command: IpcCommand::RecordUsage {
            provider: "anthropic".to_string(),
            model: "claude-sonnet-4-6".to_string(),
            input_tokens: 1000,
            output_tokens: 500,
        },
        auth_token: Some(token),
    };
    let resp = daemon.send_command(&record_msg);
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "RecordUsage should succeed, got: {resp:?}"
    );

    // Query budget status
    let status_msg = IpcMessage {
        command: IpcCommand::BudgetStatus,
        auth_token: None,
    };
    let resp = daemon.send_command(&status_msg);

    match resp {
        IpcResponse::BudgetStatus { providers } => {
            let anthropic = providers
                .iter()
                .find(|p| p.name == "Anthropic")
                .expect("Anthropic provider should exist after recording usage");
            // 1500 tokens should cost more than 0 but way less than $100
            assert!(
                anthropic.session_spent_cents > 0 && anthropic.session_spent_cents < 10_000,
                "session_spent_cents should be in range (0, 10000), got: {}",
                anthropic.session_spent_cents
            );
        }
        other => panic!("expected BudgetStatus response, got: {other:?}"),
    }
}

#[test]
#[ignore = "spawns a real daemon process; run with --ignored"]
fn test_malformed_input_does_not_crash_daemon() {
    let daemon = DaemonProcess::start();

    // Send garbage data to the socket
    {
        let socket = daemon.socket_path();
        let mut stream = UnixStream::connect(&socket).expect("connect for garbage write");
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .expect("set write timeout");
        let garbage = b"\x00\xff\xfe\xfd GARBAGE DATA\n\n";
        let _ = stream.write_all(garbage);
        let _ = stream.flush();
    }

    // Retry sending a valid Status command — success proves liveness
    let msg = IpcMessage {
        command: IpcCommand::Status,
        auth_token: None,
    };
    let mut last_err = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(100));
        }
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| daemon.send_command(&msg))) {
            Ok(resp) => {
                assert!(
                    matches!(resp, IpcResponse::Status { .. }),
                    "expected Status, got: {resp:?}"
                );
                return;
            }
            Err(e) => {
                last_err = format!("{e:?}");
            }
        }
    }
    panic!("daemon did not respond to Status after 3 attempts following garbage input: {last_err}");
}

#[test]
#[ignore = "spawns a real daemon process; run with --ignored"]
fn test_unauthenticated_command_rejected() {
    let daemon = DaemonProcess::start();

    // Send BudgetSet with no auth token
    let msg_no_auth = IpcMessage {
        command: IpcCommand::BudgetSet {
            session_cents: Some(100),
            daily_cents: None,
        },
        auth_token: None,
    };
    let resp = daemon.send_command(&msg_no_auth);
    match &resp {
        IpcResponse::Error { message } => {
            assert!(
                message.to_lowercase().contains("auth"),
                "error should mention auth, got: {message}"
            );
        }
        other => panic!("expected Error for no auth, got: {other:?}"),
    }

    // Send BudgetSet with wrong auth token
    let msg_wrong_auth = IpcMessage {
        command: IpcCommand::BudgetSet {
            session_cents: Some(100),
            daily_cents: None,
        },
        auth_token: Some("wrong-token".to_string()),
    };
    let resp = daemon.send_command(&msg_wrong_auth);
    match &resp {
        IpcResponse::Error { message } => {
            assert!(
                message.to_lowercase().contains("auth"),
                "error should mention auth, got: {message}"
            );
        }
        other => panic!("expected Error for wrong auth, got: {other:?}"),
    }
}

#[test]
#[ignore = "spawns a real daemon process; run with --ignored"]
fn test_shutdown_terminates_daemon() {
    let mut daemon = DaemonProcess::start();
    let token = daemon.auth_token();

    // Send Shutdown command with valid auth
    let msg = IpcMessage {
        command: IpcCommand::Shutdown,
        auth_token: Some(token),
    };
    let resp = daemon.send_command(&msg);
    assert!(
        matches!(resp, IpcResponse::Ok { .. }),
        "Shutdown should return Ok, got: {resp:?}"
    );

    // Wait for the child process to actually exit
    let mut child = daemon.take_child().expect("child should be present");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon should have exited after Shutdown command");
        }
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => thread::sleep(Duration::from_millis(200)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("try_wait failed: {e}");
            }
        }
    }
}
