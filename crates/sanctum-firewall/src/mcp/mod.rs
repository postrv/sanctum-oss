//! MCP (Model Context Protocol) auditing and policy enforcement.
//!
//! Provides audit logging of MCP tool invocations and configurable policy
//! rules that restrict which tools can access which paths.

pub mod audit;
pub mod cel;
pub mod policy;
