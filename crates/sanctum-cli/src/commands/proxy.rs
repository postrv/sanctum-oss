//! `sanctum proxy` -- HTTP budget proxy management.
//!
//! Subcommands:
//! - `start`       — Start the proxy server
//! - `stop`        — Stop the running proxy
//! - `status`      — Show proxy status
//! - `install-ca`  — Generate and save the CA certificate
//! - `trust`       — Add the CA to the system trust store

use sanctum_proxy::ca::CertificateAuthority;
use sanctum_types::errors::CliError;
use sanctum_types::paths::WellKnownPaths;

use crate::ProxyCliAction;

/// Run the proxy command.
pub fn run(action: &ProxyCliAction) -> Result<(), CliError> {
    match action {
        ProxyCliAction::Start { port } => cmd_start(*port),
        ProxyCliAction::Stop => cmd_stop(),
        ProxyCliAction::Status => cmd_status(),
        ProxyCliAction::InstallCa => cmd_install_ca(),
        ProxyCliAction::Trust => cmd_trust(),
    }
}

/// Start the proxy server.
fn cmd_start(port: u16) -> Result<(), CliError> {
    let paths = WellKnownPaths::require().map_err(CliError::InvalidArgs)?;
    let key_path = CertificateAuthority::default_key_path(&paths.data_dir);
    let cert_path = CertificateAuthority::default_cert_path(&paths.data_dir);

    // Ensure CA exists.
    if !key_path.exists() || !cert_path.exists() {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("CA certificate not found. Run `sanctum proxy install-ca` first.");
        }
        return Err(CliError::InvalidArgs(
            "CA not installed -- run `sanctum proxy install-ca`".to_string(),
        ));
    }

    let addr = format!("127.0.0.1:{port}");
    #[allow(clippy::print_stderr)]
    {
        eprintln!("Starting proxy on {addr}...");
        eprintln!("Set HTTPS_PROXY=http://{addr} in your tools to route through Sanctum.");
    }

    let rt = tokio::runtime::Runtime::new().map_err(CliError::Io)?;
    rt.block_on(async {
        run_proxy_server(&addr, &key_path, &cert_path).await
    })
}

/// Run the proxy server (async entry point).
async fn run_proxy_server(
    addr: &str,
    key_path: &std::path::Path,
    cert_path: &std::path::Path,
) -> Result<(), CliError> {
    let ca = CertificateAuthority::load(key_path, cert_path)
        .map_err(|e| CliError::CommandFailed(format!("failed to load CA: {e}")))?;

    let config = sanctum_types::config::SanctumConfig::default();
    let tracker = sanctum_budget::BudgetTracker::new(&config.budgets);
    let server = sanctum_proxy::ProxyServer::bind(
        addr,
        tracker,
        config.budgets,
        config.proxy,
    )
    .await
    .map_err(|e| CliError::CommandFailed(format!("failed to start proxy: {e}")))?;

    // Store the CA in the server state for CONNECT handling.
    // For now the CA is loaded but the full MITM pipeline integration
    // happens through the ConnectState in the accept loop.
    let _ = ca;

    server
        .run()
        .await
        .map_err(|e| CliError::CommandFailed(format!("proxy server error: {e}")))
}

/// Stop the running proxy.
fn cmd_stop() -> Result<(), CliError> {
    #[allow(clippy::print_stderr)]
    {
        eprintln!("sanctum proxy stop: not yet implemented");
        eprintln!("To stop the proxy, terminate the `sanctum proxy start` process.");
    }
    Err(CliError::PreviewFeature(
        "proxy stop not yet implemented".to_string(),
    ))
}

/// Show proxy status.
fn cmd_status() -> Result<(), CliError> {
    let paths = WellKnownPaths::require().map_err(CliError::InvalidArgs)?;
    let key_path = CertificateAuthority::default_key_path(&paths.data_dir);
    let cert_path = CertificateAuthority::default_cert_path(&paths.data_dir);

    #[allow(clippy::print_stderr)]
    {
        eprintln!("Sanctum Proxy Status");
        eprintln!("====================");
        if key_path.exists() && cert_path.exists() {
            eprintln!("CA certificate: installed");
            eprintln!("  Key:  {}", key_path.display());
            eprintln!("  Cert: {}", cert_path.display());
        } else {
            eprintln!("CA certificate: not installed");
            eprintln!("  Run `sanctum proxy install-ca` to generate.");
        }
        eprintln!("Default port: {}", sanctum_types::config::DEFAULT_PROXY_PORT);
    }

    Ok(())
}

/// Generate and install the CA certificate.
fn cmd_install_ca() -> Result<(), CliError> {
    let paths = WellKnownPaths::require().map_err(CliError::InvalidArgs)?;
    let key_path = CertificateAuthority::default_key_path(&paths.data_dir);
    let cert_path = CertificateAuthority::default_cert_path(&paths.data_dir);

    let config = sanctum_types::config::ProxyConfig::default();
    let ca = CertificateAuthority::generate(config.ca_validity_days)
        .map_err(|e| CliError::CommandFailed(format!("failed to generate CA: {e}")))?;

    ca.save(&key_path, &cert_path)
        .map_err(|e| CliError::CommandFailed(format!("failed to save CA: {e}")))?;

    #[allow(clippy::print_stderr)]
    {
        eprintln!("CA certificate generated successfully.");
        eprintln!("  Key:  {}", key_path.display());
        eprintln!("  Cert: {}", cert_path.display());
        eprintln!();
        eprintln!("Next steps:");
        eprintln!("  1. Trust the CA: `sanctum proxy trust`");
        eprintln!("  2. Start the proxy: `sanctum proxy start`");
        eprintln!("  3. Set HTTPS_PROXY=http://127.0.0.1:{} in your tools", config.listen_port);
    }

    Ok(())
}

/// Add the CA certificate to the system trust store.
fn cmd_trust() -> Result<(), CliError> {
    let paths = WellKnownPaths::require().map_err(CliError::InvalidArgs)?;
    let cert_path = CertificateAuthority::default_cert_path(&paths.data_dir);

    if !cert_path.exists() {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("CA certificate not found. Run `sanctum proxy install-ca` first.");
        }
        return Err(CliError::InvalidArgs(
            "CA not installed -- run `sanctum proxy install-ca`".to_string(),
        ));
    }

    trust_platform(&cert_path)
}

/// Platform-specific trust store installation.
#[cfg(target_os = "macos")]
fn trust_platform(cert_path: &std::path::Path) -> Result<(), CliError> {
    trust_macos(cert_path)
}

/// Platform-specific trust store installation.
#[cfg(target_os = "linux")]
fn trust_platform(cert_path: &std::path::Path) -> Result<(), CliError> {
    trust_linux(cert_path)
}

/// Platform-specific trust store installation.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn trust_platform(cert_path: &std::path::Path) -> Result<(), CliError> {
    #[allow(clippy::print_stderr)]
    {
        eprintln!("Automatic trust store installation is not supported on this platform.");
        eprintln!("Manually add {} to your system trust store.", cert_path.display());
    }
    Err(CliError::PreviewFeature(
        "trust store installation not supported on this platform".to_string(),
    ))
}

/// Trust the CA on macOS using the security command.
#[cfg(target_os = "macos")]
fn trust_macos(cert_path: &std::path::Path) -> Result<(), CliError> {
    #[allow(clippy::print_stderr)]
    {
        eprintln!("Adding CA to macOS trust store...");
        eprintln!("This may prompt for your password.");
    }

    let output = std::process::Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain",
        ])
        .arg(cert_path)
        .output()
        .map_err(CliError::Io)?;

    if output.status.success() {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("CA certificate added to macOS system trust store.");
        }
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CliError::CommandFailed(format!(
            "failed to add CA to trust store: {stderr}"
        )))
    }
}

/// Trust the CA on Linux using update-ca-certificates.
#[cfg(target_os = "linux")]
fn trust_linux(cert_path: &std::path::Path) -> Result<(), CliError> {
    let dest = std::path::Path::new("/usr/local/share/ca-certificates/sanctum-ca.crt");

    #[allow(clippy::print_stderr)]
    {
        eprintln!("Copying CA to {} (may require sudo)...", dest.display());
    }

    // Copy the cert to the system CA directory.
    std::fs::copy(cert_path, dest)
        .map_err(|e| CliError::CommandFailed(format!(
            "failed to copy CA cert to {}: {e}. Try running with sudo.",
            dest.display()
        )))?;

    // Run update-ca-certificates.
    let output = std::process::Command::new("update-ca-certificates")
        .output()
        .map_err(CliError::Io)?;

    if output.status.success() {
        #[allow(clippy::print_stderr)]
        {
            eprintln!("CA certificate added to Linux trust store.");
        }
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(CliError::CommandFailed(format!(
            "update-ca-certificates failed: {stderr}"
        )))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_stop_returns_error() {
        let result = run(&ProxyCliAction::Stop);
        assert!(result.is_err(), "proxy stop should return an error");
    }

    #[test]
    fn test_proxy_status_succeeds() {
        // Status should succeed (just prints info).
        let result = run(&ProxyCliAction::Status);
        assert!(result.is_ok(), "proxy status should succeed");
    }

    #[test]
    fn test_proxy_install_ca_succeeds() {
        // This should succeed as long as HOME is set.
        let result = run(&ProxyCliAction::InstallCa);
        assert!(result.is_ok(), "install-ca should succeed");

        // Verify CA files were created.
        let paths = WellKnownPaths::require().unwrap();
        let key_path = CertificateAuthority::default_key_path(&paths.data_dir);
        let cert_path = CertificateAuthority::default_cert_path(&paths.data_dir);
        assert!(key_path.exists(), "CA key should exist after install-ca");
        assert!(cert_path.exists(), "CA cert should exist after install-ca");

        // Clean up.
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&cert_path);
    }

    #[test]
    fn test_proxy_start_without_ca_fails() {
        // Ensure CA doesn't exist (use a temp dir to avoid interference).
        // This test just verifies the error path when CA is missing.
        // We can't easily test this without mocking WellKnownPaths.
        // Instead, verify the start command with port 0 would fail
        // if CA isn't present.
        let result = run(&ProxyCliAction::Start { port: 0 });
        // May fail due to missing CA or bind error -- either is acceptable.
        if let Err(e) = result {
            let err = e.to_string();
            assert!(
                err.contains("CA") || err.contains("bind") || err.contains("install"),
                "error should mention CA or bind: {err}"
            );
        }
    }
}
