//! Claude Code hook handlers.
//!
//! Implements pre- and post-tool-call hooks that enforce security policy for
//! AI coding agents. Hooks inspect tool names and arguments to detect and
//! block dangerous operations such as credential exfiltration, supply chain
//! writes, and reading sensitive files.

pub mod claude;
pub mod protocol;
