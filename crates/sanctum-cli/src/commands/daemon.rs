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
            // Wait briefly for shutdown
            std::thread::sleep(std::time::Duration::from_millis(500));
            start_daemon()
        }
    }
}

fn start_daemon() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    // Check if already running
    if paths.socket_path.exists() {
        if let Ok(IpcResponse::Status { .. }) = ipc_client::send_command(&IpcCommand::Status) {
            #[allow(clippy::print_stdout)]
            {
                println!("Daemon is already running.");
            }
            return Ok(());
        }
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

            if paths.socket_path.exists() {
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
        Err(e) => Err(CliError::InvalidArgs(format!(
            "failed to start daemon: {e}. Is sanctum-daemon in your PATH?"
        ))),
    }
}

fn stop_daemon() -> Result<(), CliError> {
    let paths = WellKnownPaths::default();

    if !paths.socket_path.exists() {
        // Try to find and kill via PID file
        if paths.pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&paths.pid_file) {
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    let raw_pid = i32::try_from(pid).map_err(|_| {
                        CliError::InvalidArgs(format!("PID {pid} exceeds i32::MAX"))
                    })?;
                    #[cfg(unix)]
                    {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(raw_pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
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
                    let raw_pid = i32::try_from(pid).map_err(|_| {
                        CliError::InvalidArgs(format!("PID {pid} exceeds i32::MAX"))
                    })?;
                    #[cfg(unix)]
                    {
                        let _ = nix::sys::signal::kill(
                            nix::unistd::Pid::from_raw(raw_pid),
                            nix::sys::signal::Signal::SIGTERM,
                        );
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
