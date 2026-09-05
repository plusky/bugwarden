//! The deadline these harnesses hold every request to, and the helper that
//! applies it to a future (#254). A hand-built POST has no single future
//! to wrap and takes the same number from `common/raw_client.rs` instead.
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only some of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects (#167, #214). Only
//! two binaries say it, and most of the client-driving harnesses are not
//! among them.

use std::future::Future;
use std::time::Duration;

/// Bound on every request one of these harnesses awaits an answer to.
///
/// rmcp 3.1.4 sends with `PeerRequestOptions::default()`, whose `timeout`
/// is `None` (`service.rs`), and the `initialize` handshake reads its
/// response off the transport with no deadline either. So a request the
/// server never answers waits forever: it hangs its test, its whole test
/// binary, and — cargo runs the `bugwarden` crate's binaries before
/// `bugwarden-core`'s — every binary queued behind it. A defect must fail
/// ONE test, not decide how long the run takes; under cargo-mutants it must
/// come back CAUGHT rather than TIMEOUT with the verdict unknown.
///
/// 30s is far above anything legitimate here. None of the harnesses that
/// include this file delays a mock reply — the workspace's one
/// `set_delay` sits in bugwarden-core's `guard_wiremock`, which drives no
/// rmcp client — and every mock listens on loopback, so what this bounds
/// is milliseconds: across the green suite the slowest of 480 bounded
/// executions took 49ms. What it bounds is one REQUEST, which is why a
/// binary's wall time is the wrong quantity to compare against — that
/// moves with `--test-threads` (the slowest of these binaries is 2.0s at
/// 32 and 5.8s at 2) while a single request does not.
///
/// The addresses aimed at a dead port refuse at connect instead of
/// hanging: `common/refused.rs` panics rather than hand out one that timed
/// out, and the single tool call routed through one carries a tighter
/// bound of its own (`REFUSED_CONNECT_BUDGET`, 2s) that fires first and
/// keeps its own message. A blackholed upstream is the case this value
/// could not absorb, and it would not cost one leg: `BugzillaClient`'s own
/// 30s timeout is per HTTP request, and one tool call can issue several in
/// sequence — up to `SEARCH_SCAN_REQUESTS` (10) behind a guarded search,
/// one per named field for `bug_fields`. Such a test would need minutes
/// here, not a nudge; none exists, and writing one means revisiting this
/// constant rather than assuming it already covers the case.
///
/// `server.rs`'s test module declares this number a second time, because a
/// `#[cfg(test)]` module in the library cannot reach `tests/`. The two are
/// equal by hand and nothing checks it, so a change here is a change
/// there.
pub const CALL_DEADLINE: Duration = Duration::from_secs(30);

/// Await `fut` under [`CALL_DEADLINE`], panicking if it does not resolve.
///
/// `what` names the request, because the panic is all a reader of a CI log
/// gets: "a deadline fired" is not a diagnosis. The value is passed
/// through untouched, so a caller keeps its own `expect`/`expect_err` on
/// the request's own `Result`.
pub async fn bounded<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(CALL_DEADLINE, fut)
        .await
        .unwrap_or_else(|_| panic!("{what} was not answered within {CALL_DEADLINE:?}"))
}
