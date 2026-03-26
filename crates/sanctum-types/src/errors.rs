//! Error types for Sanctum.
//!
//! All errors use `thiserror` for derive macros. No panics, no unwraps —
//! every fallible operation returns a `Result`.

use std::path::PathBuf;

/// Errors from the Sentinel module.
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    /// Failed to set up filesystem watcher.
    #[error("failed to initialise filesystem watcher: {0}")]
    WatcherInit(String),

    /// Failed to read or parse a `.pth` file.
    #[error("failed to read .pth file at {path}: {source}")]
    PthRead {
        path: PathBuf,
        source: std::io::Error,
    },

    /// Failed to trace process lineage.
    #[error("failed to trace process lineage for PID {pid}: {reason}")]
    LineageTrace { pid: u32, reason: String },

    /// Process not found (may have already exited).
    #[error("process {pid} not found (may have exited)")]
    ProcessNotFound { pid: u32 },

    /// Quarantine operation failed.
    #[error("quarantine operation failed for {path}: {source}")]
    Quarantine {
        path: PathBuf,
        source: std::io::Error,
    },

    /// File is already quarantined.
    #[error("file already quarantined: {path}")]
    AlreadyQuarantined { path: PathBuf },

    /// Quarantine entry not found.
    #[error("quarantine entry not found: {id}")]
    QuarantineEntryNotFound { id: String },

    /// Invalid quarantine ID (path traversal or malformed).
    #[error("invalid quarantine ID: {id}: {reason}")]
    InvalidQuarantineId { id: String, reason: String },
}

/// Errors from the daemon.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    /// Another instance is already running.
    #[error("daemon is already running (PID {0})")]
    AlreadyRunning(u32),

    /// Failed to create PID file.
    #[error("failed to create PID file at {path}: {source}")]
    PidFile {
        path: PathBuf,
        source: std::io::Error,
    },

    /// IPC socket error.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// General I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors from the CLI.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Daemon is not running.
    #[error("daemon is not running — start it with `sanctum daemon start`")]
    DaemonNotRunning,

    /// Failed to connect to daemon.
    #[error("failed to connect to daemon: {0}")]
    ConnectionFailed(String),

    /// Invalid command arguments.
    #[error("invalid arguments: {0}")]
    InvalidArgs(String),

    /// General I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
