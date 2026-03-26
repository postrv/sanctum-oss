//! Sanctum Sentinel — runtime integrity monitoring for developer environments.
//!
//! This crate provides the core security monitoring capabilities:
//!
//! - **`.pth` content analysis**: Classifies `.pth` file lines as benign path
//!   entries, suspicious imports, or critical obfuscated execution payloads.
//! - **Process lineage tracing**: Traces the parent process chain to determine
//!   whether a file modification originated from a legitimate package manager.
//! - **Quarantine protocol**: Safely isolates suspicious files while preserving
//!   the ability to review and restore them.
//! - **Filesystem watcher**: Monitors `site-packages` directories for new or
//!   modified `.pth` and `sitecustomize.py` files in real time.
//! - **Credential file monitoring**: Watches for unexpected access to SSH keys,
//!   cloud credentials, and other sensitive files.
//! - **Allowlist management**: Maintains a list of known-safe packages and their
//!   `.pth` content hashes.

pub mod allowlist;
pub mod credentials;
pub mod pth;
pub mod watcher;
