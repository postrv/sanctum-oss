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
use std::time::{Duration, Instant};

use sanctum_budget::{BudgetTracker, Provider, UsageData};
use sanctum_sentinel::credentials::{CredentialEvent, CredentialWatcher};
use sanctum_sentinel::network::{NetworkEvent, NetworkWatcher};
use sanctum_sentinel::pth::quarantine::Quarantine;
use sanctum_sentinel::watcher::{PthWatcher, WatchEvent};
use sanctum_types::config::SanctumConfig;
use sanctum_types::paths::WellKnownPaths;
use tokio::sync::{Mutex, RwLock, Semaphore};

mod audit;
mod config;
mod context;
mod daemon;
mod event_handler;
mod ipc;

use context::EventLoopContext;
use ipc::{
    IpcCommand, IpcResponse, IpcServer, ProviderBudgetInfo, QuarantineListItem, ThreatListItem,
};

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

    // Load configuration with security floor enforcement
    let config = match config::load_and_resolve() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(%e, "failed to load config");
            return ExitCode::FAILURE;
        }
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

    let exit = runtime.block_on(async move { run_daemon(shared_config, paths, manager).await });

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

    let audit_path = paths.data_dir.join("audit.log");

    let (watcher, mut watch_rx) = start_pth_watcher(&shared_config).await;
    let shared_quarantine = Arc::new(Mutex::new(Quarantine::new(paths.quarantine_dir.clone())));
    let (_cred_watcher, mut cred_rx) = start_credential_watcher(&shared_config).await;

    // Start network watcher if configured
    let (net_tx, mut net_rx) = tokio::sync::mpsc::channel::<NetworkEvent>(256);
    let _net_watcher = {
        let net_config_snap = shared_config.read().await.clone();
        if net_config_snap.sentinel.watch_network {
            tracing::info!("starting network watcher");
            Some(NetworkWatcher::start(
                net_config_snap.sentinel.network,
                net_tx,
            ))
        } else {
            tracing::info!("network monitoring disabled (watch_network = false)");
            drop(net_tx);
            None
        }
    };

    // Register signal handlers
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to register SIGTERM handler");
            return ExitCode::FAILURE;
        }
    };
    let mut sigint = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to register SIGINT handler");
            return ExitCode::FAILURE;
        }
    };
    let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(%e, "failed to register SIGHUP handler");
            return ExitCode::FAILURE;
        }
    };

    let ipc_semaphore = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));

    // Periodic budget state persistence (every 5 minutes) to limit data loss on crash
    let mut budget_save_interval = tokio::time::interval(Duration::from_secs(300));
    // The first tick completes immediately; consume it so we don't save right at startup.
    budget_save_interval.tick().await;

    tracing::info!("daemon ready, entering main event loop");

    let mut ctx = EventLoopContext {
        start_time: &start_time,
        shared_config: &shared_config,
        shared_budget: &shared_budget,
        ipc_server: &ipc_server,
        shutdown_tx: &shutdown_tx,
        shutdown_rx: &mut shutdown_rx,
        watcher: watcher.as_ref(),
        watch_rx: &mut watch_rx,
        shared_quarantine: &shared_quarantine,
        cred_rx: &mut cred_rx,
        net_rx: &mut net_rx,
        sigterm: &mut sigterm,
        sigint: &mut sigint,
        sighup: &mut sighup,
        audit_path: &audit_path,
        ipc_semaphore: &ipc_semaphore,
        budget_save_interval: &mut budget_save_interval,
        data_dir: &paths.data_dir,
        budget_state_path: &budget_state_path,
    };

    run_event_loop(&mut ctx).await;

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
            tracing::info!(
                count = discovered.len(),
                "discovered site-packages directories"
            );
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
) -> (
    Option<CredentialWatcher>,
    tokio::sync::mpsc::Receiver<CredentialEvent>,
) {
    let (cred_tx, cred_rx) = tokio::sync::mpsc::channel::<CredentialEvent>(256);

    let cred_watcher = if shared_config.read().await.sentinel.watch_credentials {
        let cred_paths = sanctum_types::paths::credential_paths();
        let custom_cred_allowlist = shared_config
            .read()
            .await
            .sentinel
            .credential_allowlist
            .clone();
        if cred_paths.is_empty() {
            tracing::warn!("no credential paths found to watch");
            None
        } else {
            tracing::info!(count = cred_paths.len(), "watching credential paths");
            match CredentialWatcher::start(&cred_paths, cred_tx, custom_cred_allowlist) {
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
async fn run_event_loop(ctx: &mut EventLoopContext<'_>) {
    loop {
        // Check for day-boundary daily budget resets on each iteration
        ctx.shared_budget.lock().await.maybe_reset_daily();

        tokio::select! {
            // Handle IPC connections
            accept_result = ctx.ipc_server.accept() => {
                match accept_result {
                    Ok(mut conn) => {
                        let Ok(permit) = ctx.ipc_semaphore.clone().try_acquire_owned() else {
                            tracing::warn!("IPC connection limit reached, rejecting");
                            continue;
                        };
                        let uptime = ctx.start_time.elapsed().as_secs();
                        let watchers_active = ctx.watcher.map_or(0, |w| u32::from(w.is_alive()));
                        #[allow(clippy::cast_possible_truncation)] // quarantine entries are bounded well below u32::MAX
                        let quarantine_count = ctx.shared_quarantine.lock().await.list().map_or(0, |l| l.len() as u32);
                        let shutdown_tx = ctx.shutdown_tx.clone();
                        let ipc_config = Arc::clone(ctx.shared_config);
                        let ipc_budget = Arc::clone(ctx.shared_budget);
                        let ipc_quarantine = Arc::clone(ctx.shared_quarantine);

                        tokio::spawn(async move {
                            let _permit = permit;
                            match tokio::time::timeout(
                                Duration::from_secs(30),
                                handle_ipc_command(
                                    &mut conn,
                                    uptime,
                                    watchers_active,
                                    quarantine_count,
                                    shutdown_tx,
                                    ipc_config,
                                    ipc_budget,
                                    ipc_quarantine,
                                ),
                            ).await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    tracing::warn!(%e, "IPC handler error");
                                }
                                Err(_) => {
                                    tracing::warn!("IPC connection timed out after 30s");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!(%e, "failed to accept IPC connection");
                    }
                }
            }

            // Handle filesystem events (dispatched to blocking thread to avoid stalling the loop)
            Some(event) = ctx.watch_rx.recv() => {
                let config_snapshot = ctx.shared_config.read().await.clone();
                let quarantine = Arc::clone(ctx.shared_quarantine);
                let audit_path = ctx.audit_path.to_path_buf();
                tokio::task::spawn_blocking(move || {
                    let quarantine_guard = quarantine.blocking_lock();
                    event_handler::handle_watch_event(&event, &quarantine_guard, &config_snapshot, &audit_path);
                });
            }

            // Handle credential file events (dispatched to blocking thread for audit I/O)
            Some(cred_event) = ctx.cred_rx.recv() => {
                let audit_path = ctx.audit_path.to_path_buf();
                tokio::task::spawn_blocking(move || {
                    event_handler::handle_credential_event(&cred_event, &audit_path);
                });
            }

            // Handle network anomaly events (dispatched to blocking thread for audit I/O)
            Some(net_event) = ctx.net_rx.recv() => {
                let audit_path = ctx.audit_path.to_path_buf();
                tokio::task::spawn_blocking(move || {
                    event_handler::handle_network_event(&net_event, &audit_path);
                });
            }

            // Handle SIGTERM (graceful shutdown)
            _ = ctx.sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
                break;
            }

            // Handle SIGINT (graceful shutdown)
            _ = ctx.sigint.recv() => {
                tracing::info!("received SIGINT, shutting down");
                break;
            }

            // Handle SIGHUP (reload config)
            _ = ctx.sighup.recv() => {
                tracing::info!("received SIGHUP, reloading configuration");
                reload_shared_config(ctx.shared_config).await;
            }

            // Handle IPC-initiated shutdown (C1)
            _ = ctx.shutdown_rx.recv() => {
                tracing::info!("received shutdown command via IPC, shutting down");
                break;
            }

            // Periodic budget state persistence (every 5 minutes)
            _ = ctx.budget_save_interval.tick() => {
                let budget = Arc::clone(ctx.shared_budget);
                let data_dir = ctx.data_dir.to_path_buf();
                let state_path = ctx.budget_state_path.to_path_buf();
                tokio::task::spawn_blocking(move || {
                    save_budget_state_blocking(&budget, &data_dir, &state_path);
                });
            }
        }
    }
}

/// Save budget tracker state to disk on shutdown (async context, called once at exit).
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

/// Save budget tracker state to disk from a blocking (non-async) context.
///
/// Uses `blocking_lock()` instead of `.lock().await` so it can run inside
/// `spawn_blocking` without an async runtime on the current thread.
fn save_budget_state_blocking(
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    data_dir: &Path,
    budget_state_path: &Path,
) {
    if let Err(e) = std::fs::create_dir_all(data_dir) {
        tracing::error!(%e, "failed to create data directory for budget state");
    } else {
        let save_result = shared_budget
            .blocking_lock()
            .save_to_file(budget_state_path);
        if let Err(e) = save_result {
            tracing::error!(%e, "failed to save budget state");
        } else {
            tracing::info!("budget state saved");
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // handler needs all shared state references
async fn handle_ipc_command(
    conn: &mut ipc::IpcConnection,
    uptime: u64,
    watchers_active: u32,
    quarantine_count: u32,
    shutdown_tx: tokio::sync::mpsc::Sender<()>,
    shared_config: Arc<RwLock<SanctumConfig>>,
    shared_budget: Arc<Mutex<BudgetTracker>>,
    shared_quarantine: Arc<Mutex<Quarantine>>,
) -> Result<(), sanctum_types::errors::DaemonError> {
    let command = conn.read_command().await?;

    let paths = WellKnownPaths::default();

    let mut should_shutdown = false;
    let mut should_reload = false;

    let response = match command {
        IpcCommand::Status => IpcResponse::Status {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_secs: uptime,
            watchers_active,
            quarantine_count,
        },
        IpcCommand::ListQuarantine => {
            let quarantine = shared_quarantine.lock().await;
            handle_quarantine_list(&quarantine)
        }
        IpcCommand::RestoreQuarantine { id } => {
            let quarantine = shared_quarantine.lock().await;
            handle_quarantine_restore(&quarantine, &id)
        }
        IpcCommand::DeleteQuarantine { id } => {
            let quarantine = shared_quarantine.lock().await;
            handle_quarantine_delete(&quarantine, &id)
        }
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
        IpcCommand::BudgetSet {
            session_cents,
            daily_cents,
        } => handle_budget_set(&shared_budget, session_cents, daily_cents).await,
        IpcCommand::BudgetExtend { additional_cents } => {
            handle_budget_extend(&shared_budget, additional_cents).await
        }
        IpcCommand::BudgetReset => {
            shared_budget.lock().await.reset_session();
            IpcResponse::Ok {
                message: "session budget counters reset".to_string(),
            }
        }
        IpcCommand::RecordUsage {
            provider,
            model,
            input_tokens,
            output_tokens,
        } => {
            let audit_path = paths.log_dir.join("audit.log");
            handle_record_usage(
                &shared_budget,
                &provider,
                &model,
                input_tokens,
                output_tokens,
                &audit_path,
            )
            .await
        }
        IpcCommand::ListThreats { category, level } => {
            let paths_clone = paths.clone();
            let cat = category.clone();
            let lvl = level.clone();
            match tokio::task::spawn_blocking(move || {
                handle_list_threats(&paths_clone, cat.as_deref(), lvl.as_deref())
            })
            .await
            {
                Ok(resp) => resp,
                Err(e) => IpcResponse::Error {
                    message: format!("task failed: {e}"),
                },
            }
        }
        IpcCommand::GetThreatDetails { id } => {
            let paths_clone = paths.clone();
            let quarantine_arc = Arc::clone(&shared_quarantine);
            match tokio::task::spawn_blocking(move || {
                let quarantine = quarantine_arc.blocking_lock();
                handle_get_threat_details(&paths_clone, &quarantine, &id)
            })
            .await
            {
                Ok(resp) => resp,
                Err(e) => IpcResponse::Error {
                    message: format!("task failed: {e}"),
                },
            }
        }
        IpcCommand::ResolveThreat { id, action, note } => {
            let paths_clone = paths.clone();
            let quarantine_arc = Arc::clone(&shared_quarantine);
            match tokio::task::spawn_blocking(move || {
                let quarantine = quarantine_arc.blocking_lock();
                handle_resolve_threat(&paths_clone, &quarantine, &id, &action, &note)
            })
            .await
            {
                Ok(resp) => resp,
                Err(e) => IpcResponse::Error {
                    message: format!("task failed: {e}"),
                },
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

/// Parse a provider string and record token usage, returning the budget status.
///
/// When recording pushes spend over a session or daily limit, emits a
/// `BudgetOverrun` `ThreatEvent` to the audit log.
async fn handle_record_usage(
    shared_budget: &Arc<Mutex<BudgetTracker>>,
    provider_str: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    audit_path: &Path,
) -> IpcResponse {
    let provider = match provider_str.to_lowercase().as_str() {
        "openai" => Provider::OpenAI,
        "anthropic" => Provider::Anthropic,
        "google" => Provider::Google,
        _ => {
            return IpcResponse::Error {
                message: format!("unknown provider: {provider_str}"),
            };
        }
    };

    let usage = UsageData {
        provider,
        model: model.to_string(),
        input_tokens,
        output_tokens,
    };

    let status = shared_budget.lock().await.record_usage(&usage);

    // Emit BudgetOverrun threat event when a limit is exceeded
    if status.session_exceeded || status.daily_exceeded {
        let exceeded_type = if status.session_exceeded {
            "session"
        } else {
            "daily"
        };
        let limit = if status.session_exceeded {
            status.session_limit_cents.unwrap_or(0)
        } else {
            status.daily_limit_cents.unwrap_or(0)
        };
        let spent = if status.session_exceeded {
            status.session_spent_cents
        } else {
            status.daily_spent_cents
        };

        let event = sanctum_types::threat::ThreatEvent {
            timestamp: chrono::Utc::now(),
            level: sanctum_types::threat::ThreatLevel::Critical,
            category: sanctum_types::threat::ThreatCategory::BudgetOverrun,
            description: format!(
                "{provider} {exceeded_type} budget exceeded: {spent}c spent, {limit}c limit (model: {model})"
            ),
            source_path: std::path::PathBuf::from(format!("budget:{provider}")),
            creator_pid: None,
            creator_exe: None,
            action_taken: sanctum_types::threat::Action::Blocked,
        };

        audit::append_audit_event(&event, audit_path);
    }

    IpcResponse::Ok {
        message: format!(
            "{provider}: session {session}c/{session_limit}, daily {daily}c/{daily_limit}",
            session = status.session_spent_cents,
            session_limit = status
                .session_limit_cents
                .map_or_else(|| "unlimited".to_string(), |c| format!("{c}c")),
            daily = status.daily_spent_cents,
            daily_limit = status
                .daily_limit_cents
                .map_or_else(|| "unlimited".to_string(), |c| format!("{c}c")),
        ),
    }
}

// ============================================================
// Threat / fix helpers
// ============================================================

/// Read threat events from the audit log, returning at most `max_events` most recent entries.
///
/// Uses `BufReader::lines()` to avoid loading the entire file into memory,
/// preventing OOM on large audit logs.
fn read_audit_events(
    paths: &WellKnownPaths,
    max_events: usize,
) -> Vec<sanctum_types::threat::ThreatEvent> {
    use std::io::BufRead;

    let audit_path = paths.data_dir.join("audit.log");
    let Ok(file) = std::fs::File::open(&audit_path) else {
        return Vec::new();
    };
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%e, "error reading audit log line");
                continue;
            }
        };
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<sanctum_types::threat::ThreatEvent>(&trimmed) {
            Ok(event) => events.push(event),
            Err(e) => {
                tracing::warn!(%e, "skipping malformed audit log line");
            }
        }
    }
    if events.len() > max_events {
        events.split_off(events.len() - max_events)
    } else {
        events
    }
}

/// Read resolved threat IDs from the resolution log, bounded to `max_entries` most recent.
///
/// Uses `BufReader::lines()` to avoid loading the entire file into memory,
/// preventing OOM on large resolution logs.
fn read_resolved_ids(
    paths: &WellKnownPaths,
    max_entries: usize,
) -> std::collections::HashSet<String> {
    use std::io::BufRead;

    let resolution_path = paths.data_dir.join("resolutions.log");
    let Ok(file) = std::fs::File::open(&resolution_path) else {
        return std::collections::HashSet::new();
    };
    let reader = std::io::BufReader::new(file);
    let mut resolutions = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(%e, "error reading resolution log line");
                continue;
            }
        };
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<sanctum_types::threat::ThreatResolution>(&trimmed) {
            Ok(r) => resolutions.push(r.threat_id),
            Err(e) => {
                tracing::warn!(%e, "skipping malformed resolution log line");
            }
        }
    }
    if resolutions.len() > max_entries {
        resolutions
            .split_off(resolutions.len() - max_entries)
            .into_iter()
            .collect()
    } else {
        resolutions.into_iter().collect()
    }
}

/// Append a resolution entry to the resolution log.
///
/// Returns an error description if the write fails so the caller can
/// propagate it to the IPC client.
fn append_resolution(
    paths: &WellKnownPaths,
    resolution: &sanctum_types::threat::ThreatResolution,
) -> Result<(), String> {
    append_resolution_inner(paths, resolution)
        .map_err(|e| format!("failed to write resolution log entry: {e}"))
}

/// Maximum resolution log file size before rotation (10 MB).
const MAX_RESOLUTION_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Rotate the resolution log if it exceeds the size threshold.
///
/// Renames the current log to `resolutions.log.1` (replacing any existing `.1`
/// file), so that subsequent writes go to a fresh `resolutions.log`.
fn maybe_rotate_resolution_log(path: &std::path::Path) {
    if let Ok(metadata) = std::fs::metadata(path) {
        if metadata.len() >= MAX_RESOLUTION_LOG_BYTES {
            let rotated = path.with_extension("log.1");
            let _ = std::fs::rename(path, rotated);
            tracing::info!(
                "rotated resolution log (exceeded {} bytes)",
                MAX_RESOLUTION_LOG_BYTES
            );
        }
    }
}

fn append_resolution_inner(
    paths: &WellKnownPaths,
    resolution: &sanctum_types::threat::ThreatResolution,
) -> Result<(), std::io::Error> {
    use std::io::Write;

    let resolution_path = paths.data_dir.join("resolutions.log");

    // Rotate if the log exceeds the size threshold
    maybe_rotate_resolution_log(&resolution_path);

    // Ensure parent directory exists
    if let Some(parent) = resolution_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&resolution_path)?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&resolution_path, perms)?;
    }

    let json = serde_json::to_string(resolution).map_err(std::io::Error::other)?;
    writeln!(file, "{json}")?;
    file.sync_all()?;
    Ok(())
}

/// Maximum number of threat items returned in a single `ListThreats` response.
///
/// Prevents exceeding the 64 KB IPC frame limit when the audit log is large.
const MAX_THREAT_LIST_ITEMS: usize = 500;

/// List unresolved threats, optionally filtered by category and level.
fn handle_list_threats(
    paths: &WellKnownPaths,
    category: Option<&str>,
    level: Option<&str>,
) -> IpcResponse {
    let events = read_audit_events(paths, MAX_AUDIT_EVENTS);
    let resolved = read_resolved_ids(paths, MAX_AUDIT_EVENTS);

    let threats: Vec<ThreatListItem> = events
        .iter()
        .filter_map(|event| {
            let id = event.threat_id();

            // Skip resolved threats
            if resolved.contains(&id) {
                return None;
            }

            // Apply category filter
            if let Some(cat) = category {
                let event_cat = format!("{:?}", event.category);
                if !event_cat.eq_ignore_ascii_case(cat) {
                    return None;
                }
            }

            // Apply level filter
            if let Some(lvl) = level {
                let event_lvl = format!("{:?}", event.level);
                if !event_lvl.eq_ignore_ascii_case(lvl) {
                    return None;
                }
            }

            Some(ThreatListItem {
                id,
                timestamp: event.timestamp.to_rfc3339(),
                level: format!("{:?}", event.level),
                category: format!("{:?}", event.category),
                description: event.description.clone(),
                source_path: event.source_path.display().to_string(),
                action_taken: format!("{:?}", event.action_taken),
            })
        })
        .collect();

    let truncated = threats.len() > MAX_THREAT_LIST_ITEMS;
    let threats = if truncated {
        threats.into_iter().take(MAX_THREAT_LIST_ITEMS).collect()
    } else {
        threats
    };

    IpcResponse::ThreatList { threats, truncated }
}

/// Get detailed information about a specific threat.
fn handle_get_threat_details(
    paths: &WellKnownPaths,
    quarantine: &sanctum_sentinel::pth::quarantine::Quarantine,
    id: &str,
) -> IpcResponse {
    let events = read_audit_events(paths, MAX_AUDIT_EVENTS);

    let Some(event) = events.iter().find(|e| e.threat_id() == id) else {
        return IpcResponse::Error {
            message: format!("threat not found: {id}"),
        };
    };

    // Check for a matching quarantine entry by comparing source_path
    let quarantine_id = quarantine.list().ok().and_then(|entries| {
        entries
            .into_iter()
            .find(|entry| entry.metadata.original_path == event.source_path)
            .map(|entry| entry.id)
    });

    IpcResponse::ThreatDetails {
        id: id.to_string(),
        timestamp: event.timestamp.to_rfc3339(),
        level: format!("{:?}", event.level),
        category: format!("{:?}", event.category),
        description: event.description.clone(),
        source_path: event.source_path.display().to_string(),
        creator_pid: event.creator_pid,
        creator_exe: event.creator_exe.as_ref().map(|p| p.display().to_string()),
        action_taken: format!("{:?}", event.action_taken),
        quarantine_id,
    }
}

/// Resolve a threat by performing the specified action.
fn handle_resolve_threat(
    paths: &WellKnownPaths,
    quarantine: &sanctum_sentinel::pth::quarantine::Quarantine,
    id: &str,
    action: &str,
    note: &str,
) -> IpcResponse {
    use sanctum_types::threat::{ResolutionAction, ThreatResolution};

    let events = read_audit_events(paths, MAX_AUDIT_EVENTS);

    let Some(event) = events.iter().find(|e| e.threat_id() == id) else {
        return IpcResponse::Error {
            message: format!("threat not found: {id}"),
        };
    };

    // Find matching quarantine entry by source_path
    let quarantine_entry = quarantine.list().ok().and_then(|entries| {
        entries
            .into_iter()
            .find(|entry| entry.metadata.original_path == event.source_path)
    });

    let resolution_action = match action {
        "restore" => {
            if let Some(ref entry) = quarantine_entry {
                if let Err(e) = quarantine.restore(&entry.id) {
                    return IpcResponse::Error {
                        message: format!("failed to restore quarantined file: {e}"),
                    };
                }
            }
            ResolutionAction::Restored
        }
        "delete" => {
            if let Some(ref entry) = quarantine_entry {
                if let Err(e) = quarantine.delete(&entry.id) {
                    return IpcResponse::Error {
                        message: format!("failed to delete quarantined file: {e}"),
                    };
                }
            }
            ResolutionAction::Deleted
        }
        "dismiss" => ResolutionAction::Dismissed,
        other => {
            return IpcResponse::Error {
                message: format!("unknown resolution action: {other}"),
            };
        }
    };

    // Sanitise note: strip control characters (except newline) and cap length
    let sanitised_note: String = note
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(1024)
        .collect();

    let resolution = ThreatResolution {
        threat_id: id.to_string(),
        resolved_at: chrono::Utc::now(),
        resolution: resolution_action,
        note: sanitised_note,
    };

    if let Err(e) = append_resolution(paths, &resolution) {
        return IpcResponse::Error { message: e };
    }

    IpcResponse::Ok {
        message: format!("threat {id} resolved with action: {action}"),
    }
}

/// Reload configuration from disk into the shared config.
/// Best-effort: logs errors but does not propagate them.
async fn reload_shared_config(shared_config: &Arc<RwLock<SanctumConfig>>) {
    match config::load_and_resolve() {
        Ok(new_config) => {
            *shared_config.write().await = new_config;
            tracing::info!("configuration reloaded");
            tracing::info!("note: watcher configuration changes (watch_pth, watch_credentials, watch_network) require a daemon restart to take effect");
        }
        Err(e) => {
            tracing::error!(%e, "failed to reload config");
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

/// Maximum number of audit events to load into memory from the audit log.
const MAX_AUDIT_EVENTS: usize = 10_000;

/// Maximum number of concurrent IPC connections.
const MAX_IPC_CONNECTIONS: usize = 64;

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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use sanctum_types::threat::{Action, ThreatCategory, ThreatEvent, ThreatLevel};
    use std::io::Write;
    use std::path::PathBuf;

    fn write_events_to_audit_log(dir: &std::path::Path, count: usize) -> WellKnownPaths {
        let data_dir = dir.join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let audit_path = data_dir.join("audit.log");
        let mut file = std::fs::File::create(&audit_path).expect("create audit.log");
        for i in 0..count {
            let event = ThreatEvent {
                timestamp: chrono::Utc::now(),
                level: ThreatLevel::Critical,
                category: ThreatCategory::PthInjection,
                description: format!("event-{i}"),
                source_path: PathBuf::from(format!("/test/file-{i}.pth")),
                creator_pid: Some(1234),
                creator_exe: None,
                action_taken: Action::Quarantined,
            };
            let json = serde_json::to_string(&event).expect("serialize");
            writeln!(file, "{json}").expect("write");
        }
        WellKnownPaths {
            ssh_dir: dir.join(".ssh"),
            data_dir,
            config_dir: dir.join("config"),
            quarantine_dir: dir.join("quarantine"),
            log_dir: dir.join("logs"),
            pid_file: dir.join("sanctum.pid"),
            socket_path: dir.join("sanctum.sock"),
        }
    }

    #[test]
    fn read_audit_events_returns_all_when_under_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = write_events_to_audit_log(dir.path(), 5);
        let events = read_audit_events(&paths, 100);
        assert_eq!(events.len(), 5);
    }

    #[test]
    fn read_audit_events_truncates_to_max() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = write_events_to_audit_log(dir.path(), 20);
        let events = read_audit_events(&paths, 10);
        assert_eq!(events.len(), 10);
        // Should keep the most recent (last) events
        assert_eq!(events[0].description, "event-10");
        assert_eq!(events[9].description, "event-19");
    }

    #[test]
    fn read_audit_events_returns_empty_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = WellKnownPaths {
            ssh_dir: dir.path().join(".ssh"),
            data_dir: dir.path().join("nonexistent"),
            config_dir: dir.path().join("config"),
            quarantine_dir: dir.path().join("quarantine"),
            log_dir: dir.path().join("logs"),
            pid_file: dir.path().join("sanctum.pid"),
            socket_path: dir.path().join("sanctum.sock"),
        };
        let events = read_audit_events(&paths, 100);
        assert!(events.is_empty());
    }

    #[test]
    fn read_audit_events_with_zero_max_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = write_events_to_audit_log(dir.path(), 5);
        let events = read_audit_events(&paths, 0);
        assert!(events.is_empty());
    }

    #[test]
    fn read_resolved_ids_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path().join("data");
        std::fs::create_dir_all(&data_dir).expect("create data dir");
        let resolution_path = data_dir.join("resolutions.log");
        let mut file = std::fs::File::create(&resolution_path).expect("create resolutions.log");
        for i in 0..20 {
            let resolution = sanctum_types::threat::ThreatResolution {
                threat_id: format!("threat-{i}"),
                resolved_at: chrono::Utc::now(),
                resolution: sanctum_types::threat::ResolutionAction::Dismissed,
                note: "test".to_string(),
            };
            let json = serde_json::to_string(&resolution).expect("serialize");
            writeln!(file, "{json}").expect("write");
        }
        let paths = WellKnownPaths {
            ssh_dir: dir.path().join(".ssh"),
            data_dir,
            config_dir: dir.path().join("config"),
            quarantine_dir: dir.path().join("quarantine"),
            log_dir: dir.path().join("logs"),
            pid_file: dir.path().join("sanctum.pid"),
            socket_path: dir.path().join("sanctum.sock"),
        };
        let ids = read_resolved_ids(&paths, 10);
        assert_eq!(ids.len(), 10);
        // Should contain the most recent IDs (10-19)
        for i in 10..20 {
            assert!(ids.contains(&format!("threat-{i}")));
        }
    }

    #[test]
    #[allow(clippy::significant_drop_tightening)]
    fn ipc_semaphore_limits_permits() {
        let sem = Arc::new(Semaphore::new(2));
        let p1 = sem.clone().try_acquire_owned();
        assert!(p1.is_ok());
        let p2 = sem.clone().try_acquire_owned();
        assert!(p2.is_ok());
        let p3 = sem.clone().try_acquire_owned();
        assert!(p3.is_err(), "third permit should be rejected");
        drop(p1);
        let p4 = sem.try_acquire_owned();
        assert!(p4.is_ok(), "permit should be available after drop");
    }

    // ============================================================
    // H4: ListThreats truncation
    // ============================================================

    #[test]
    fn list_threats_truncates_at_max() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write more events than MAX_THREAT_LIST_ITEMS (500)
        let paths = write_events_to_audit_log(dir.path(), 600);
        let response = handle_list_threats(&paths, None, None);
        match response {
            IpcResponse::ThreatList { threats, truncated } => {
                assert_eq!(threats.len(), MAX_THREAT_LIST_ITEMS);
                assert!(
                    truncated,
                    "truncated should be true when items exceed the limit"
                );
            }
            other => panic!("expected ThreatList, got {other:?}"),
        }
    }

    // ============================================================
    // BudgetOverrun ThreatEvent emission
    // ============================================================

    #[tokio::test]
    async fn record_usage_emits_budget_overrun_when_session_exceeded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("create log dir");
        let audit_path = log_dir.join("audit.log");

        // Create a tracker with a very low session limit (100 cents = $1)
        let config = sanctum_types::config::BudgetConfig {
            default_session: Some(sanctum_types::config::BudgetAmount { cents: 100 }),
            default_daily: None,
            alert_at_percent: 75,
            providers: std::collections::HashMap::new(),
        };
        let tracker = BudgetTracker::new(&config);
        let shared = Arc::new(Mutex::new(tracker));

        // Record massive usage that exceeds the session limit
        let response = handle_record_usage(
            &shared,
            "openai",
            "gpt-4o",
            10_000_000, // enough to exceed $1
            0,
            &audit_path,
        )
        .await;

        // Should succeed (not an error response)
        match &response {
            IpcResponse::Ok { message } => {
                assert!(
                    message.contains("OpenAI"),
                    "response should mention provider: {message}"
                );
            }
            other => panic!("expected Ok, got {other:?}"),
        }

        // Verify BudgetOverrun event was written to audit log
        assert!(audit_path.exists(), "audit log should be created");
        let content = std::fs::read_to_string(&audit_path).expect("read audit");
        let parsed: ThreatEvent = serde_json::from_str(content.trim()).expect("parse event");
        assert_eq!(parsed.category, ThreatCategory::BudgetOverrun);
        assert_eq!(parsed.level, ThreatLevel::Critical);
        assert_eq!(parsed.action_taken, Action::Blocked);
        assert!(
            parsed.description.contains("session"),
            "description should mention session: {}",
            parsed.description
        );
        assert!(
            parsed.source_path.to_string_lossy().starts_with("budget:"),
            "source_path should start with budget:"
        );
    }

    #[tokio::test]
    async fn record_usage_no_audit_when_within_budget() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log_dir = dir.path().join("logs");
        std::fs::create_dir_all(&log_dir).expect("create log dir");
        let audit_path = log_dir.join("audit.log");

        // No limits set — unlimited budget
        let config = sanctum_types::config::BudgetConfig {
            default_session: None,
            default_daily: None,
            alert_at_percent: 75,
            providers: std::collections::HashMap::new(),
        };
        let tracker = BudgetTracker::new(&config);
        let shared = Arc::new(Mutex::new(tracker));

        let _ = handle_record_usage(&shared, "openai", "gpt-4o", 1000, 500, &audit_path).await;

        // No audit log should be created
        assert!(
            !audit_path.exists(),
            "no audit log should be created when within budget"
        );
    }

    #[test]
    fn list_threats_not_truncated_when_under_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = write_events_to_audit_log(dir.path(), 10);
        let response = handle_list_threats(&paths, None, None);
        match response {
            IpcResponse::ThreatList { threats, truncated } => {
                assert_eq!(threats.len(), 10);
                assert!(
                    !truncated,
                    "truncated should be false when items are under the limit"
                );
            }
            other => panic!("expected ThreatList, got {other:?}"),
        }
    }
}
