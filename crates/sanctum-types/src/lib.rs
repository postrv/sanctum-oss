//! Shared types, error types, and constants for Sanctum.
//!
//! This crate defines the foundational types used across all Sanctum crates:
//! threat classifications, configuration structures, error types, and
//! well-known filesystem paths.

pub mod audit;
pub mod config;
pub mod errors;
pub mod ipc;
pub mod paths;
pub mod threat;
