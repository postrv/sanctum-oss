//! `sanctum run` — Run a command with Sanctum protections.

use sanctum_types::errors::CliError;

/// Run the run command.
///
/// Wraps a command with Sanctum protections:
/// - Ensures daemon is running
/// - Optionally invokes nono for sandbox (if --sandbox and nono is installed)
/// - Executes the target command
pub fn run(sandbox: bool, command: &[String]) -> Result<(), CliError> {
    if command.is_empty() {
        return Err(CliError::InvalidArgs("no command specified".to_string()));
    }

    // Check if daemon is running; if not, try to start it
    let paths = sanctum_types::paths::WellKnownPaths::default();
    if !paths.socket_path.exists() {
        #[allow(clippy::print_stdout)]
        {
            println!("Starting Sanctum daemon...");
        }
        let _ = std::process::Command::new("sanctum-daemon")
            .arg("start")
            .spawn();
        // Give it a moment to start
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let (program, args) = if sandbox {
        // Check if nono is installed
        let nono_available = std::process::Command::new("which")
            .arg("nono")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);

        if nono_available {
            #[allow(clippy::print_stdout)]
            {
                println!("Running with nono sandbox...");
            }
            let mut nono_args = vec!["--".to_string()];
            nono_args.extend_from_slice(command);
            ("nono".to_string(), nono_args)
        } else {
            #[allow(clippy::print_stdout)]
            {
                println!("Warning: --sandbox specified but nono is not installed. Running without sandbox.");
            }
            (command[0].clone(), command[1..].to_vec())
        }
    } else {
        (command[0].clone(), command[1..].to_vec())
    };

    // Set SANCTUM_ACTIVE environment variable
    let status = std::process::Command::new(&program)
        .args(&args)
        .env("SANCTUM_ACTIVE", "1")
        .status()
        .map_err(|e| CliError::InvalidArgs(format!("failed to execute '{program}': {e}")))?;

    if !status.success() {
        let code = status.code().unwrap_or(1);
        std::process::exit(code);
    }

    Ok(())
}
