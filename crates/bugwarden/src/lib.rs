//! bugwarden — MCP server for Bugzilla with operator-controlled security
//! guards.
//!
//! This library target exists so the MCP tool surface can be driven end to
//! end by integration tests (`tests/`): the binary (`main.rs`) is a thin
//! transport wrapper around [`server::BugWarden`], and a binary-only crate
//! would leave the tool gates — the code that calls the guard — untestable
//! as a unit. The supported product remains the `bugwarden` binary; this
//! API carries no stability promise of its own.

/// Operator-facing audit event stream: record schema and JSONL file sink.
pub mod audit;
pub mod config;
/// Bearer authentication for the streamable-HTTP transport.
pub mod http_auth;
pub mod server;

#[cfg(test)]
mod testlog;
