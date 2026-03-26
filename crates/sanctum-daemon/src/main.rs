//! Sanctum daemon entry point.
//!
//! The daemon runs as a background process, handling:
//! - Filesystem watching for `.pth` files
//! - IPC server for CLI communication
//! - Signal handling (SIGTERM, SIGHUP)
//! - PID file management

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Instant;

use sanctum_budget::BudgetTracker;
use sanctum_sentinel::credentials::{CredentialEvent, CredentialWatcher};
use sanctum_sentinel::pth::lineage::{LineageAssessment, ProcessLineage, SystemProcSource};
use sanctum_sentinel::pth::quarantine::{Quarantine, QuarantineMetadata};
use sanctum_sentinel::watcher::{PthWatcher, WatchEvent, WatchEventKind};
use sanctum_types::config::SanctumConfig;
use sanctum_types::paths::WellKnownPaths;
use tokio::sync::{Mutex, RwLock};

mod config;
mod daemon;
mod ipc;

use ipc::{IpcCommand, IpcResponse, IpcServer, ProviderBudgetInfo, QuarantineListItem};

fn main() -> ExitCode {
    // Initialise tracing subscriber
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .json()
        .init();

    // Parse CLI args: sanctum-daemon [start|stop|reload]
    let args: Vec<String> = std::env::args().collect();
    let subcommand = args.get(1).map_or("start", String::as_str);

    let paths = WellKnownPaths::default();

    match subcommand {
        "stop" => return handle_stop(&paths),
        "reload" => return handle_reload(&paths),
        "start" => {}
        other => {
            tracing::error!(subcommand = other, "unknown subcommand");
            return ExitCode::FAILURE;
        }
    }

    // === START subcommand ===
    tracing::info!("sanctum-daemon starting");

    let manager = daemon::DaemonManager::new(paths.pid_file.clone());

    // Check for existing daemon
    match manager.check_existing() {
        Ok(Some(pid)) => {
            tracing::error!(pid, "daemon is already running");
            return ExitCode::FAILURE;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(%e, "failed to check existing daemon");
            return ExitCode::FAILURE;
        }
    }

    // Write PID file
    if let Err(e) = manager.write_pid_file() {
        tracing::error!(%e, "failed to write PID file");
        return ExitCode::FAILURE;
    }

    // Load configuration
    let config = match config::find_config_path() {
        Some(path) => match config::load_config(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(%e, "failed to load config");
                return ExitCode::FAILURE;
            }
        },
        None => SanctumConfig::default(),
    };
    let shared_config = Arc::new(RwLock::new(config));

    // Build and run the tokio runtime
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(%e, "failed to create tokio runtime");
            return ExitCode::FAILURE;
        }
    };

    let exit = runtime.block_on(async move {
        run_daemon(shared_config, paths, manager).await
    });

    tracing::info!("sanctum-daemon exiting");
    exit
}

async fn run_daemon(
    shared_config: Arc<RwLock<SanctumConfig>>,
    paths: WellKnownPaths,
    _manager: daemon::DaemonManager,
) -> ExitCode {
    let start_time = Instant::now();

    // Initialise budget tracker from config, loading persisted state if available
    let budget_state_path = paths.data_dir.join("budget_state.json");
    let budget_tracker = {
        let config_snapshot = shared_config.read().await;
        BudgetTracker::load_from_file(&budget_state_path, &config_snapshot.budgets).map_or_else(
            |_| {
                tracing::debug!("no persisted budget state found, starting fresh");
                BudgetTracker::new(&config_snapshot.budgets)
            },
            |tracker| {
                tracing::info!("loaded persisted budget state");
                tracker
            },
        )
    };
    let shared_budget = Arc::new(Mutex::new(budget_tracker));

    // Start IPC server
    let ipc_server = match IpcServer::bind(&paths.socket_path) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to start IPC server");
            return ExitCode::FAILURE;
        }
    };

    // Shutdown channel for IPC-initiated shutdown (C1)
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    let (watcher, mut watch_rx) = start_pth_watcher(&shared_config).await;
    let quarantine = Quarantine::new(paths.quarantine_dir.clone());
    let (_cred_watcher, mut cred_rx) = start_credential_watcher(&shared_config).await;

    // Register signal handlers
    let mut sigterm = match tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to register SIGTERM handler");
            return ExitCode::FAILURE;
        }
    };
    let mut sighup = match tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::hangup(),
    ) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to register SIGHUP handler");
            return ExitCode::FAILURE;
        }
    };

    tracing::info!("daemon ready, entering main event loop");

    run_event_loop(
        &start_time, &shared_config, &shared_budget, &ipc_server,
        &shutdown_tx, &mut shutdown_rx, watcher.as_ref(), &mut watch_rx,
        &quarantine, &mut cred_rx, &mut sigterm, &mut sighup,
    ).await;

    // Save budget tracker state to disk on shutdown
    save_budget_state(&shared_budget, &paths.data_dir, &budget_state_path).await;

    ExitCode::SUCCESS
}

/// Discover site-packages directories and start the .pth file watcher.
async fn start_pth_watcher(
    shared_config: &Arc<RwLock<SanctumConfig>>,
) -> (Option<PthWatcher>, tokio::sync::mpsc::Receiver<WatchEvent>) {
    let watch_paths = if shared_config.read().await.sentinel.watch_pth {
        let discovered = sanctum_sentinel::watcher::discover_site_packages().await;
        if discovered.is_empty() {
            tracing::warn!("no Python site-packages directories found");
        } else {
            tracing::info!(count = discovered.len(), "discovered site-packages directories");
        }
        discovered
    } else {
        Vec::new()
    };

    let (watch_tx, watch_rx) = tokio::sync::mpsc::channel::<WatchEvent>(256);

    let watcher = if watch_paths.is_empty() {
        None
    } else {
        match PthWatcher::start(&watch_paths, watch_tx) {
            Ok(w) => {
                tracing::info!("filesystem watcher started");
                Some(w)
            }
            Err(e) => {
                tracing::error!(%e, "failed to start filesystem watcher");
                None
            }
        }
    };

    (watcher, watch_rx)
}

/// Start the credential file watcher if configured.
async fn start_credential_watcher(
    shared_config: &Arc<RwLock<SanctumConfig>>,
) -> (Option<CredentialWatcher>, tokio::sync::mpsc::Receiver<CredentialEvent>) {
    let (cred_tx, cred_rx) = tokio::sync::mpsc::channel::<CredentialEvent>(256);

    let cred_watcher = if shared_config.read().await.sentinel.watch_credentials {
        let cred_paths = sanctum_types::paths::credential_paths();
        if cred_paths.is_empty() {
            tracing::warn!("no credential paths found to watch");
            None
        } else {
            tracing::info!(count = cred_paths.len(), "watching credential paths");
            match CredentialWatcher::start(&cred_paths, cred_tx) {
                Ok(w) => {
                    tracing::info!("credential watcher started");
                    Some(w)
                }
                Err(e) => {
                    tracing::error!(%e, "failed to start credential watcher");
                    None
                }
            }
        }
    } else {
        None
    };

    (cred_watcher, cred_rx)
}

/// Main event loop: handle IPC, filesystem, credential, and signal events.
#[allow(clippy::too_many_arguments)]
async fn run_event_loop(
    start_time: &Instant,
    shared_config: &Arc<RwLock<SanctumConfig>>,
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    ipc_server: &IpcServer,
    shutdown_tx: &tokio::sync::mpsc::Sender<()>,
    shutdown_rx: &mut tokio::sync::mpsc::Receiver<()>,
    watcher: Option<&PthWatcher>,
    watch_rx: &mut tokio::sync::mpsc::Receiver<WatchEvent>,
    quarantine: &Quarantine,
    cred_rx: &mut tokio::sync::mpsc::Receiver<CredentialEvent>,
    sigterm: &mut tokio::signal::unix::Signal,
    sighup: &mut tokio::signal::unix::Signal,
) {
    loop {
        // Check for day-boundary daily budget resets on each iteration
        shared_budget.lock().await.maybe_reset_daily();

        tokio::select! {
            // Handle IPC connections
            accept_result = ipc_server.accept() => {
                match accept_result {
                    Ok(mut conn) => {
                        let uptime = start_time.elapsed().as_secs();
                        let watchers_active = watcher.map_or(0, |w| u32::from(w.is_alive()));
                        #[allow(clippy::cast_possible_truncation)] // quarantine entries are bounded well below u32::MAX
                        let quarantine_count = quarantine.list().map_or(0, |l| l.len() as u32);
                        let shutdown_tx = shutdown_tx.clone();
                        let ipc_config = Arc::clone(shared_config);
                        let ipc_budget = Arc::clone(shared_budget);

                        tokio::spawn(async move {
                            if let Err(e) = handle_ipc_command(
                                &mut conn,
                                uptime,
                                watchers_active,
                                quarantine_count,
                                shutdown_tx,
                                ipc_config,
                                ipc_budget,
                            ).await {
                                tracing::warn!(%e, "IPC handler error");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%e, "failed to accept IPC connection");
                    }
                }
            }

            // Handle filesystem events
            Some(event) = watch_rx.recv() => {
                let config_snapshot = shared_config.read().await.clone();
                handle_watch_event(&event, quarantine, &config_snapshot);
            }

            // Handle credential file events
            Some(cred_event) = cred_rx.recv() => {
                handle_credential_event(&cred_event);
            }

            // Handle SIGTERM (graceful shutdown)
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
                break;
            }

            // Handle SIGHUP (reload config)
            _ = sighup.recv() => {
                tracing::info!("received SIGHUP, reloading configuration");
                reload_shared_config(shared_config).await;
            }

            // Handle IPC-initiated shutdown (C1)
            _ = shutdown_rx.recv() => {
                tracing::info!("received shutdown command via IPC, shutting down");
                break;
            }
        }
    }
}

/// Save budget tracker state to disk on shutdown.
async fn save_budget_state(
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    data_dir: &Path,
    budget_state_path: &Path,
) {
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        tracing::error!(%e, "failed to create data directory for budget state");
    } else {
        let save_result = shared_budget.lock().await.save_to_file(budget_state_path);
        if let Err(e) = save_result {
            tracing::error!(%e, "failed to save budget state on shutdown");
        } else {
            tracing::info!("budget state saved");
        }
    }
}

async fn handle_ipc_command(
    conn: &mut ipc::IpcConnection,
    uptime: u64,
    watchers_active: u32,
    quarantine_count: u32,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
    shared_config: Arc<RwLock<SanctumConfig>>,
    shared_budget: Arc<Mutex<BudgetTracker>>,
) -> Result<(), sanctum_types::errors::DaemonError> {
    let command = conn.read_command().await?;

    let paths = WellKnownPaths::default();
    let quarantine = Quarantine::new(paths.quarantine_dir);

    let mut should_shutdown = false;
    let mut should_reload = false;

    let response = match command {
        IpcCommand::Status => IpcResponse::Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: uptime,
            watchers_active,
            quarantine_count,
        },
        IpcCommand::ListQuarantine => handle_quarantine_list(&quarantine),
        IpcCommand::RestoreQuarantine { id } => handle_quarantine_restore(&quarantine, &id),
        IpcCommand::DeleteQuarantine { id } => handle_quarantine_delete(&quarantine, &id),
        IpcCommand::ReloadConfig => {
            should_reload = true;
            IpcResponse::Ok {
                message: "config reload requested".to_string(),
            }
        }
        IpcCommand::Shutdown => {
            should_shutdown = true;
            IpcResponse::Ok {
                message: "shutdown initiated".to_string(),
            }
        }
        IpcCommand::BudgetStatus => handle_budget_status(&shared_budget).await,
        IpcCommand::BudgetSet { session_cents, daily_cents } => {
            handle_budget_set(&shared_budget, session_cents, daily_cents).await
        }
        IpcCommand::BudgetExtend { additional_cents } => {
            handle_budget_extend(&shared_budget, additional_cents).await
        }
        IpcCommand::BudgetReset => {
            shared_budget.lock().await.reset_session();
            IpcResponse::Ok {
                message: "session budget counters reset".to_string(),
            }
        }
    };

    conn.send_response(&response).await?;

    // Perform post-response actions so the client gets the response first
    if should_reload {
        reload_shared_config(&shared_config).await;
    }
    if should_shutdown {
        // Signal the main loop to break; ignore send error (receiver dropped = already shutting down)
        let _ = shutdown_tx.send(()).await;
    }

    Ok(())
}

/// List quarantine entries and return the IPC response.
fn handle_quarantine_list(quarantine: &Quarantine) -> IpcResponse {
    match quarantine.list() {
        Ok(entries) => {
            let items = entries
                .iter()
                .map(|e| QuarantineListItem {
                    id: e.id.clone(),
                    original_path: e.metadata.original_path.display().to_string(),
                    reason: e.metadata.reason.clone(),
                    quarantined_at: e.quarantined_at.to_rfc3339(),
                })
                .collect();
            IpcResponse::QuarantineList { items }
        }
        Err(e) => IpcResponse::Error {
            message: format!("failed to list quarantine: {e}"),
        },
    }
}

/// Restore a quarantine entry and return the IPC response.
fn handle_quarantine_restore(quarantine: &Quarantine, id: &str) -> IpcResponse {
    match quarantine.restore(id) {
        Ok(()) => IpcResponse::Ok {
            message: format!("restored quarantine entry {id}"),
        },
        Err(e) => IpcResponse::Error {
            message: format!("failed to restore {id}: {e}"),
        },
    }
}

/// Delete a quarantine entry and return the IPC response.
fn handle_quarantine_delete(quarantine: &Quarantine, id: &str) -> IpcResponse {
    match quarantine.delete(id) {
        Ok(()) => IpcResponse::Ok {
            message: format!("deleted quarantine entry {id}"),
        },
        Err(e) => IpcResponse::Error {
            message: format!("failed to delete {id}: {e}"),
        },
    }
}

/// Retrieve budget status from the tracker and return the IPC response.
async fn handle_budget_status(shared_budget: &Arc<Mutex<BudgetTracker>>) -> IpcResponse {
    let statuses = shared_budget.lock().await.all_statuses();
    let providers = statuses
        .into_iter()
        .map(|s| ProviderBudgetInfo {
            name: s.provider.to_string(),
            session_spent_cents: s.session_spent_cents,
            session_limit_cents: s.session_limit_cents,
            daily_spent_cents: s.daily_spent_cents,
            daily_limit_cents: s.daily_limit_cents,
            alert_triggered: s.alert_triggered,
            session_exceeded: s.session_exceeded,
        })
        .collect();
    IpcResponse::BudgetStatus { providers }
}

/// Update budget limits and return the IPC response.
async fn handle_budget_set(
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    session_cents: Option<u64>,
    daily_cents: Option<u64>,
) -> IpcResponse {
    let mut tracker = shared_budget.lock().await;
    tracker.set_default_session_limit(session_cents);
    tracker.set_default_daily_limit(daily_cents);
    drop(tracker);
    IpcResponse::Ok {
        message: "budget limits updated".to_string(),
    }
}

/// Extend session budget for all providers and return the IPC response.
async fn handle_budget_extend(
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    additional_cents: u64,
) -> IpcResponse {
    let mut tracker = shared_budget.lock().await;
    tracker.extend_session(sanctum_budget::Provider::OpenAI, additional_cents);
    tracker.extend_session(sanctum_budget::Provider::Anthropic, additional_cents);
    tracker.extend_session(sanctum_budget::Provider::Google, additional_cents);
    drop(tracker);
    IpcResponse::Ok {
        message: format!("session budget extended by {additional_cents} cents for all providers"),
    }
}

/// Reload configuration from disk into the shared config.
/// Best-effort: logs errors but does not propagate them.
async fn reload_shared_config(shared_config: &Arc<RwLock<SanctumConfig>>) {
    match config::find_config_path() {
        Some(path) => {
            match config::load_config(&path) {
                Ok(new_config) => {
                    *shared_config.write().await = new_config;
                    tracing::info!("configuration reloaded");
                }
                Err(e) => {
                    tracing::error!(%e, "failed to reload config");
                }
            }
        }
        None => {
            tracing::info!("no config file found, keeping current config");
        }
    }
}

/// Best-effort attempt to find the PID of the process that created or modified a file.
///
/// On Linux, scans `/proc/*/fd/` for open file descriptors pointing to the given path.
/// On macOS, this is extremely difficult without elevated privileges, so we skip it.
///
/// This is inherently racy: the creating process may have already closed the file
/// descriptor by the time we scan. The result is best-effort and may return `None`.
const fn try_find_creator_pid(_path: &Path) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        linux_find_creator_pid(_path)
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Linux-specific: scan `/proc/*/fd/` to find a process with the given file open.
#[cfg(target_os = "linux")]
fn linux_find_creator_pid(path: &Path) -> Option<u32> {
    use std::fs;

    let proc_entries = fs::read_dir("/proc").ok()?;

    for entry in proc_entries.flatten() {
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_str()?;
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                if link_target == path {
                    return Some(pid);
                }
            }
        }
    }

    None
}

/// Trace process lineage for a given PID and return the assessment,
/// creator PID, and creator executable path.
///
/// Returns `(creator_pid, creator_exe, assessment)`. If lineage tracing
/// fails (process already exited, etc.), returns the PID with `None` exe
/// and `Undetermined` assessment.
fn trace_creator_lineage(
    pid: u32,
) -> (Option<u32>, Option<std::path::PathBuf>, LineageAssessment) {
    match ProcessLineage::trace(pid, &SystemProcSource) {
        Ok(lineage) => {
            let assessment = lineage.assess_pth_creation();
            let creator_exe = lineage
                .root_ancestor()
                .exe
                .clone();
            tracing::info!(
                pid,
                assessment = ?assessment,
                "process lineage traced"
            );
            (Some(pid), creator_exe, assessment)
        }
        Err(e) => {
            tracing::debug!(
                pid,
                %e,
                "failed to trace process lineage (process may have exited)"
            );
            (Some(pid), None, LineageAssessment::Undetermined)
        }
    }
}

/// Handle a credential file event by creating a threat event and sending notification.
fn handle_credential_event(event: &CredentialEvent) {
    match event {
        CredentialEvent::AccessDetected {
            path,
            accessor_pid,
            accessor_name,
            allowed,
        } => {
            if *allowed {
                tracing::debug!(
                    path = %path.display(),
                    accessor = accessor_name.as_deref().unwrap_or("unknown"),
                    "credential file accessed by allowed process"
                );
                return;
            }

            let accessor_desc = match (accessor_pid, accessor_name.as_deref()) {
                (Some(pid), Some(name)) => format!("{name} (PID {pid})"),
                (Some(pid), None) => format!("unknown (PID {pid})"),
                (None, Some(name)) => name.to_string(),
                (None, None) => "unknown process".to_string(),
            };

            tracing::warn!(
                path = %path.display(),
                accessor = %accessor_desc,
                "credential file accessed by unexpected process"
            );

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Warning,
                category: sanctum_types::threat::ThreatCategory::CredentialAccess,
                description: format!(
                    "Credential file {} accessed by {}",
                    path.display(),
                    accessor_desc,
                ),
                source_path: path.clone(),
                creator_pid: *accessor_pid,
                creator_exe: None,
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
        }
        CredentialEvent::Modified { path } => {
            tracing::info!(
                path = %path.display(),
                "credential file modified"
            );
        }
    }
}

fn handle_watch_event(
    event: &WatchEvent,
    quarantine: &Quarantine,
    config: &SanctumConfig,
) {
    use sanctum_sentinel::pth::analyser::{analyse_pth_file_with_context, content_hash, FileVerdict};

    match event.kind {
        WatchEventKind::Created | WatchEventKind::Modified => {
            tracing::info!(path = %event.path.display(), "detected .pth file change");

            // Read the file content
            let content = match std::fs::read_to_string(&event.path) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(path = %event.path.display(), %e, "failed to read file");
                    return;
                }
            };

            // Extract package name from the .pth file stem (e.g. "setuptools.pth" -> "setuptools")
            let package_name = event
                .path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown");

            let hash = content_hash(content.as_bytes());
            let analysis = analyse_pth_file_with_context(&content, package_name, &hash);

            // Attempt to determine the creator process (best-effort)
            let (creator_pid, creator_exe, lineage_assessment) =
                try_find_creator_pid(&event.path).map_or(
                    (None, None, LineageAssessment::Undetermined),
                    trace_creator_lineage,
                );

            // Determine the effective threat level, escalating if lineage is suspicious
            let escalate_for_lineage =
                lineage_assessment == LineageAssessment::SuspiciousPythonStartup;

            match analysis.verdict {
                FileVerdict::Safe | FileVerdict::AllowlistedKnownPackage => {
                    handle_safe_verdict(event, escalate_for_lineage, creator_pid, creator_exe);
                }
                FileVerdict::Warning => {
                    handle_warning_verdict(event, &analysis, escalate_for_lineage, creator_pid, creator_exe);
                }
                FileVerdict::Critical => {
                    handle_critical_verdict(event, &analysis, &hash, config, quarantine, creator_pid, creator_exe);
                }
            }
        }
        WatchEventKind::Deleted => {
            tracing::info!(path = %event.path.display(), "watched file deleted");
        }
    }
}

/// Handle a safe or allowlisted .pth file verdict, escalating if lineage is suspicious.
fn handle_safe_verdict(
    event: &WatchEvent,
    escalate_for_lineage: bool,
    creator_pid: Option<u32>,
    creator_exe: Option<std::path::PathBuf>,
) {
    if escalate_for_lineage {
        // File content looks safe but was created by Python startup --
        // this is unusual and worth alerting on.
        tracing::warn!(
            path = %event.path.display(),
            creator_pid = ?creator_pid,
            "safe .pth file created during suspicious Python startup"
        );
        let threat_event = sanctum_types::threat::ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: sanctum_types::threat::ThreatLevel::Warning,
            category: sanctum_types::threat::ThreatCategory::PthInjection,
            description: format!(
                "Safe .pth file created during suspicious Python startup: {}",
                event.path.display()
            ),
            source_path: event.path.clone(),
            creator_pid,
            creator_exe,
            action_taken: sanctum_types::threat::Action::Alerted,
        };
        sanctum_notify::notify_threat(&threat_event);
    } else {
        tracing::debug!(path = %event.path.display(), "file is safe");
    }
}

/// Handle a warning-level .pth file verdict, escalating if lineage is suspicious.
fn handle_warning_verdict(
    event: &WatchEvent,
    analysis: &sanctum_sentinel::pth::analyser::FileAnalysis,
    escalate_for_lineage: bool,
    creator_pid: Option<u32>,
    creator_exe: Option<std::path::PathBuf>,
) {
    // Escalate to Critical if the lineage is suspicious
    let level = if escalate_for_lineage {
        sanctum_types::threat::ThreatLevel::Critical
    } else {
        sanctum_types::threat::ThreatLevel::Warning
    };

    tracing::warn!(
        path = %event.path.display(),
        warnings = analysis.warning_lines.len(),
        ?level,
        "file contains suspicious imports"
    );
    // For warning-level findings, notify but don't quarantine
    let threat_event = sanctum_types::threat::ThreatEvent {
        timestamp: chrono::Utc::now(),
        level,
        category: sanctum_types::threat::ThreatCategory::PthInjection,
        description: format!(
            "Suspicious import found in {}",
            event.path.display()
        ),
        source_path: event.path.clone(),
        creator_pid,
        creator_exe,
        action_taken: sanctum_types::threat::Action::Alerted,
    };
    sanctum_notify::notify_threat(&threat_event);
}

/// Handle a critical .pth file verdict by quarantining, alerting, or logging based on config.
fn handle_critical_verdict(
    event: &WatchEvent,
    analysis: &sanctum_sentinel::pth::analyser::FileAnalysis,
    hash: &str,
    config: &SanctumConfig,
    quarantine: &Quarantine,
    creator_pid: Option<u32>,
    creator_exe: Option<std::path::PathBuf>,
) {
    tracing::error!(
        path = %event.path.display(),
        critical_lines = analysis.critical_lines.len(),
        creator_pid = ?creator_pid,
        "CRITICAL: malicious .pth file detected"
    );

    match config.sentinel.pth_response {
        sanctum_types::config::PthResponse::Quarantine => {
            let metadata = QuarantineMetadata {
                original_path: event.path.clone(),
                content_hash: hash.to_string(),
                creator_pid,
                reason: analysis
                    .critical_lines
                    .iter()
                    .flat_map(|l| l.reasons.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                quarantined_at: chrono::Utc::now(),
            };

            match quarantine.quarantine_file(&event.path, &metadata) {
                Ok(entry) => {
                    tracing::info!(
                        id = entry.id,
                        path = %event.path.display(),
                        "file quarantined"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        path = %event.path.display(),
                        %e,
                        "failed to quarantine file"
                    );
                }
            }

            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!(
                    "Malicious .pth file quarantined: {}",
                    event.path.display()
                ),
                source_path: event.path.clone(),
                creator_pid,
                creator_exe,
                action_taken: sanctum_types::threat::Action::Quarantined,
            };
            sanctum_notify::notify_threat(&threat_event);
        }
        sanctum_types::config::PthResponse::Alert => {
            let threat_event = sanctum_types::threat::ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: sanctum_types::threat::ThreatLevel::Critical,
                category: sanctum_types::threat::ThreatCategory::PthInjection,
                description: format!(
                    "Malicious .pth file detected: {}",
                    event.path.display()
                ),
                source_path: event.path.clone(),
                creator_pid,
                creator_exe,
                action_taken: sanctum_types::threat::Action::Alerted,
            };
            sanctum_notify::notify_threat(&threat_event);
        }
        sanctum_types::config::PthResponse::Log => {
            tracing::error!(
                path = %event.path.display(),
                creator_pid = ?creator_pid,
                "malicious .pth detected (log-only mode)"
            );
        }
    }
}

fn handle_stop(paths: &WellKnownPaths) -> ExitCode {
    let manager = daemon::DaemonManager::new(paths.pid_file.clone());
    match manager.check_existing() {
        Ok(Some(pid)) => {
            let Ok(raw_pid) = i32::try_from(pid) else {
                tracing::error!(pid, "PID exceeds i32::MAX, cannot send signal");
                return ExitCode::FAILURE;
            };
            tracing::info!(pid, "sending SIGTERM to daemon");
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(raw_pid),
                    nix::sys::signal::Signal::SIGTERM,
                );
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            tracing::info!("no daemon is running");
            ExitCode::SUCCESS
        }
        Err(e) => {
            tracing::error!(%e, "failed to check daemon status");
            ExitCode::FAILURE
        }
    }
}

fn handle_reload(paths: &WellKnownPaths) -> ExitCode {
    let manager = daemon::DaemonManager::new(paths.pid_file.clone());
    match manager.check_existing() {
        Ok(Some(pid)) => {
            let Ok(raw_pid) = i32::try_from(pid) else {
                tracing::error!(pid, "PID exceeds i32::MAX, cannot send signal");
                return ExitCode::FAILURE;
            };
            tracing::info!(pid, "sending SIGHUP to daemon");
            #[cfg(unix)]
            {
                let _ = nix::sys::signal::kill(
                    nix::unistd::Pid::from_raw(raw_pid),
                    nix::sys::signal::Signal::SIGHUP,
                );
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            tracing::error!("no daemon is running");
            ExitCode::FAILURE
        }
        Err(e) => {
            tracing::error!(%e, "failed to check daemon status");
            ExitCode::FAILURE
        }
    }
}
