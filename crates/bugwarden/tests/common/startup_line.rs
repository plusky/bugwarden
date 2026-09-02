//! The shipped binary's own startup line, the readiness barrier for the
//! tests that need the child bound before they act (#173, #222, #230), plus
//! the stderr line reader every spawning test shares.
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that says
//! `mod common;`, so a helper only some of them use would be `dead_code` in
//! the rest, which `-D warnings` rejects.
//!
//! Nothing here owns the reader or picks the timeout, because the three
//! includers need different policies past the barrier and no one of them can
//! be the shared default. `binary_shutdown::Server` keeps one reader for the
//! process's life — a `BufReader` built per wait throws away whatever it
//! buffered past the match, which can swallow the line a later assertion
//! needs — while `http_auth_wiremock` hands its reader to a drain, because
//! its child keeps serving past the barrier and an unread pipe becomes
//! backpressure, and `binary_tracing_caps` throws child and reader away
//! after one line. So the shared part is the needle plus wait-and-parse;
//! ownership and budget stay with the caller.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::AsyncBufReadExt as _;
use tokio::io::BufReader;
use tokio::io::Lines;
use tokio::process::Child;
use tokio::process::ChildStderr;

/// The line the http transport logs once it is bound *and* its signal
/// handlers are armed; the address that follows is the one the kernel
/// assigned, which under `--port 0` is the only way to learn it.
#[allow(dead_code, reason = "only the http includers wait on this barrier")]
pub const HTTP_READY: &str = "Starting Bugzilla MCP server on ";

/// A spawned child's stderr, read a line at a time.
pub type StderrLines = Lines<BufReader<ChildStderr>>;

/// Take the child's piped stderr as a line reader.
pub fn stderr_lines(child: &mut Child) -> StderrLines {
    BufReader::new(child.stderr.take().expect("stderr is piped")).lines()
}

/// Next stderr line, recorded in `log`; `None` at EOF.
pub async fn next_logged_line(lines: &mut StderrLines, log: &mut String) -> Option<String> {
    let line = lines
        .next_line()
        .await
        .expect("the child's stderr must be readable")?;
    log.push_str(&line);
    log.push('\n');
    Some(line)
}

/// Read stderr until a line contains `needle`, and return that line.
///
/// Both failures dump everything read so far, so a renamed startup line
/// fails with the log that names it rather than a bare timeout.
pub async fn wait_for_line(
    lines: &mut StderrLines,
    log: &mut String,
    needle: &str,
    budget: Duration,
) -> String {
    let found = tokio::time::timeout(budget, async {
        while let Some(line) = next_logged_line(lines, log).await {
            if line.contains(needle) {
                return Some(line);
            }
        }
        None
    })
    .await;
    match found {
        Ok(Some(line)) => line,
        Ok(None) => panic!("the child's stderr ended before {needle:?}: {log}"),
        Err(_) => panic!("timed out waiting for {needle:?} on the child's stderr: {log}"),
    }
}

/// The address an [`HTTP_READY`] `line` names.
///
/// The kernel picked it under `--port 0`, so a line still carrying the
/// requested `0` — or an address off loopback — means the barrier matched
/// something that is not the child's real listener.
#[allow(dead_code, reason = "only the http includers have an address to parse")]
pub fn parse_bound_addr(line: &str) -> SocketAddr {
    let addr: SocketAddr = line
        .split_once(HTTP_READY)
        .expect("the wait matched the needle")
        .1
        .trim()
        .parse()
        .unwrap_or_else(|e| panic!("the startup line must name the bound address: {line}: {e}"));
    assert!(
        addr.ip().is_loopback() && addr.port() != 0,
        "the startup line must carry the loopback address the kernel \
         assigned, not the requested port 0: {line}"
    );
    addr
}
