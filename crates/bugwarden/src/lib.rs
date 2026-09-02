//! bugwarden — MCP server for Bugzilla with operator-controlled security
//! guards.
//!
//! This library target exists so the MCP tool surface can be driven end to
//! end by integration tests (`tests/`): the binary (`main.rs`) is a thin
//! transport wrapper around [`server::BugWarden`], and a binary-only crate
//! would leave the tool gates — the code that calls the guard — untestable
//! as a unit. The supported product remains the `bugwarden` binary; this
//! API carries no stability promise of its own.

pub mod audit;
pub mod config;
pub mod http_auth;
pub mod http_session;
pub mod otel;
pub mod server;
pub mod stdio;

#[cfg(test)]
mod testlog;

// The environment pin the integration tests share, so the crate's own unit
// tests parse a `Cli` the same way (#214). `#[path]` rather than a module
// of `tests/common/mod.rs`: that one compiles into every binary saying `mod
// common;`, where a helper only some of them use is `dead_code` (#167).
#[cfg(test)]
#[path = "../tests/common/pinned_cli.rs"]
mod pinned_cli;
