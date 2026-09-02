//! Shared helpers for bugwarden integration tests.
//!
//! Only what every `mod common;` binary uses belongs here; anything
//! narrower goes in a sibling file included by `#[path]`, or it is
//! `dead_code` in the binaries that skip it (#167, #214). The refused
//! address moved to `common/refused.rs` for that reason (#229).

/// Bound on the I12 client calls. Loopback refuse is immediate; a hang
/// here is a proxy or routing defect, not a 30s client timeout.
pub const REFUSED_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
