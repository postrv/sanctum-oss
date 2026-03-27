//! Context types that bundle related parameters for the daemon event loop.

use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use sanctum_budget::BudgetTracker;
use sanctum_sentinel::credentials::CredentialEvent;
use sanctum_sentinel::network::NetworkEvent;
use sanctum_sentinel::pth::quarantine::Quarantine;
use sanctum_sentinel::watcher::{PthWatcher, WatchEvent};
use sanctum_types::config::SanctumConfig;
use tokio::sync::{Mutex, RwLock};

/// Bundles all state and channels needed by the main event loop.
///
/// This replaces the 13-parameter `run_event_loop` function signature with
/// a single context struct, improving readability and making it easier to
/// pass subsets of state to handler functions.
pub struct EventLoopContext<'a> {
    pub start_time: &'a Instant,
    pub shared_config: &'a Arc<RwLock<SanctumConfig>>,
    pub shared_budget: &'a Arc<Mutex<BudgetTracker>>,
    pub ipc_server: &'a crate::ipc::IpcServer,
    pub shutdown_tx: &'a tokio::sync::mpsc::Sender<()>,
    pub shutdown_rx: &'a mut tokio::sync::mpsc::Receiver<()>,
    pub watcher: Option<&'a PthWatcher>,
    pub watch_rx: &'a mut tokio::sync::mpsc::Receiver<WatchEvent>,
    pub quarantine: &'a Quarantine,
    pub cred_rx: &'a mut tokio::sync::mpsc::Receiver<CredentialEvent>,
    pub net_rx: &'a mut tokio::sync::mpsc::Receiver<NetworkEvent>,
    pub sigterm: &'a mut tokio::signal::unix::Signal,
    pub sighup: &'a mut tokio::signal::unix::Signal,
    pub audit_path: &'a Path,
}

/// Bundles the common parameters shared across verdict handlers.
///
/// Replaces the 5-8 parameter signatures of `handle_safe_verdict`,
/// `handle_warning_verdict`, and `handle_critical_verdict`.
pub struct VerdictContext<'a> {
    pub event: &'a WatchEvent,
    pub creator_pid: Option<u32>,
    pub creator_exe: Option<std::path::PathBuf>,
    pub audit_path: &'a Path,
}
