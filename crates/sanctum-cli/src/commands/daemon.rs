//! `sanctum daemon` — Daemon management (start/stop/restart).

use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;

use crate::ipc_client::{self, IpcCommand, IpcResponse};
use crate::DaemonAction;

/// Run the daemon command.
pub fn run(action: &DaemonAction) -> Result<(), CliError> {
    match action {
        DaemonAction::Start => start_daemon(),
        DaemonAction::Stop => stop_daemon(),
        DaemonAction::Restart => {
            let _ = stop_daemon();
            wait_for_shutdown();
            start_daemon()
        }
        DaemonAction::Status => crate::commands::status::run(),
        DaemonAction::InstallService => install_service(),
        DaemonAction::UninstallService => uninstall_service(),
    }
}

/// Poll until the daemon socket disappears, up to 2 seconds (20 x 100 ms).
fn wait_for_shutdown() {
    let paths = WellKnownPaths::default();
    for _ in 0..20 {
        let endpoint = paths.ipc_endpoint();
        let endpoint_gone = endpoint.as_unix_path().map_or_else(
            || ipc_client::send_command(&IpcCommand::Status).is_err(),
            |path| !path.exists(),
        );
        if endpoint_gone && !paths.pid_file.exists() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    // Timed out — proceed to start anyway; start_daemon will handle stale sockets.
}

#[cfg(windows)]
fn install_service() -> Result<(), CliError> {
    let daemon = std::env::current_exe()
        .ok()
        .and_then(|path| {
            path.parent()
                .map(|parent| parent.join("sanctum-daemon.exe"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("sanctum-daemon.exe"));
    let bin_path = format!("\"{}\" start", daemon.display());
    let status = std::process::Command::new("sc.exe")
        .args([
            "create",
            "Sanctum",
            "binPath=",
            &bin_path,
            "start=",
            "auto",
            "DisplayName=",
            "Sanctum Developer Security Daemon",
        ])
        .status()
        .map_err(CliError::Io)?;
    if status.success() {
        #[allow(clippy::print_stdout)]
        println!("Sanctum Windows service installed.");
        Ok(())
    } else {
        Err(CliError::CommandFailed(format!(
            "sc.exe create failed with status {status}"
        )))
    }
}

#[cfg(not(windows))]
fn install_service() -> Result<(), CliError> {
    Err(CliError::PreviewFeature(
        "Windows service installation is only available on Windows".to_owned(),
    ))
}

#[cfg(windows)]
fn uninstall_service() -> Result<(), CliError> {
    let status = std::process::Command::new("sc.exe")
        .args(["delete", "Sanctum"])
        .status()
        .map_err(CliError::Io)?;
    if status.success() {
        #[allow(clippy::print_stdout)]
        println!("Sanctum Windows service uninstalled.");
        Ok(())
    } else {
        Err(CliError::CommandFailed(format!(
            "sc.exe delete failed with status {status}"
        )))
    }
}

#[cfg(not(windows))]
fn uninstall_service() -> Result<(), CliError> {
    Err(CliError::PreviewFeature(
        "Windows service uninstallation is only available on Windows".to_owned(),
    ))
}

fn start_daemon() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    // Check if already running
    if let Ok(IpcResponse::Status { .. }) = ipc_client::send_command(&IpcCommand::Status) {
        #[allow(clippy::print_stdout)]
        {
            println!("Daemon is already running.");
        }
        return Ok(());
    }
    if paths.socket_path.exists() {
        // Stale socket — clean it up
        let _ = std::fs::remove_file(&paths.socket_path);
    }

    // Spawn the daemon as a background process
    let daemon_result = std::process::Command::new("sanctum-daemon")
        .arg("start")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match daemon_result {
        Ok(_child) => {
            // Wait a moment for the daemon to start, then verify
            std::thread::sleep(std::time::Duration::from_secs(1));

            if paths.socket_path.exists() || ipc_client::send_command(&IpcCommand::Status).is_ok() {
                #[allow(clippy::print_stdout)]
                {
                    println!("Daemon started.");
                }
            } else {
                #[allow(clippy::print_stdout)]
                {
                    println!("Daemon started (socket not yet available — may take a moment).");
                }
            }
            Ok(())
        }
        Err(e) => Err(CliError::CommandFailed(format!(
            "failed to start daemon: {e}. Is sanctum-daemon in your PATH?"
        ))),
    }
}

fn stop_daemon() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    let endpoint_absent = paths
        .ipc_endpoint()
        .as_unix_path()
        .is_some_and(|path| !path.exists());
    if endpoint_absent {
        // Try to find and kill via PID file
        if paths.pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&paths.pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    #[cfg(unix)]
                    {
                        let raw_pid = i32::try_from(pid).map_err(|_| {
                            CliError::InvalidArgs(format!("PID {pid} exceeds i32::MAX"))
                        })?;
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(raw_pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                    }
                    #[cfg(windows)]
                    {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/PID", &pid.to_string(), "/T"])
                            .status();
                    }
                    #[allow(clippy::print_stdout)]
                    {
                        println!("Sent SIGTERM to daemon (PID {pid}).");
                    }
                    return Ok(());
                }
            }
        }

        #[allow(clippy::print_stdout)]
        {
            println!("No daemon is running.");
        }
        return Ok(());
    }

    // Try graceful shutdown via IPC
    if let Ok(IpcResponse::Ok { message }) = ipc_client::send_command(&IpcCommand::Shutdown) {
        #[allow(clippy::print_stdout)]
        {
            println!("Daemon stopping: {message}");
        }
    } else {
        // Fallback: send SIGTERM via PID file
        if paths.pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&paths.pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    #[cfg(unix)]
                    {
                        let raw_pid = i32::try_from(pid).map_err(|_| {
                            CliError::InvalidArgs(format!("PID {pid} exceeds i32::MAX"))
                        })?;
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(raw_pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
                    }
                    #[cfg(windows)]
                    {
                        let _ = std::process::Command::new("taskkill")
                            .args(["/PID", &pid.to_string(), "/T"])
                            .status();
                    }
                    #[allow(clippy::print_stdout)]
                    {
                        println!("Sent SIGTERM to daemon (PID {pid}).");
                    }
                    return Ok(());
                }
            }
        }
        #[allow(clippy::print_stdout)]
        {
            println!("Daemon stopped.");
        }
    }

    Ok(())
}
