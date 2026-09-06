//! An address that refuses every connection and no test in this suite can
//! occupy, for the harnesses that need a connect-time failure (#115, #229).
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only some of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects (#167, #214).
//! `REFUSED_CONNECT_BUDGET` stayed behind because only the guard-client
//! harnesses bound a call with it.
//!
//! The library's `#[cfg(test)]` tree includes this file the same way
//! (`lib.rs`): an integration-test file is out of reach for `use`, not
//! for `#[path]`, so a unit test that DIALS an unreachable upstream
//! checks the address instead of assuming it (#280).
//!
//! Where it belongs, one rule: take the probe wherever a test's client
//! actually connects to the address, because that is where a box that
//! filters port 1 instead of closing it costs a wait on the caller's
//! client timeout, and the probe spends 500 ms to name the cause here
//! rather than fail obscurely there. An address handed to a client that
//! never opens a connection has no such wait to buy out and stays a
//! bare literal; `server::tests::NO_BUGZILLA` and
//! `otel::tests::NO_COLLECTOR` are those, and point back here.
//!
//! `bugwarden-core` keeps its own copy — the private `refused_base_url`
//! in `crates/bugwarden-core/tests/guard_wiremock.rs` — because a
//! `#[path]` out of that package into this one's `tests/` reaches
//! outside the package directory and would not survive packaging.
//! `the_core_copy_matches` is the pin: the two function bodies, modulo
//! the timeout-panic sentence #280 reworded.

/// Connect-time failure nothing in this process can answer (#115, #229).
///
/// The address is `127.0.0.1:1`. Port 1 is privileged: a non-root test
/// process cannot bind it, so neither wiremock's `127.0.0.1:0` pool nor a
/// stranger racing an ephemeral port can answer this request. The
/// load-bearing assertion is `port() < 1024` — a bind-then-drop of an
/// ephemeral port fails the helper. A 500 ms TCP probe refuses to
/// return an address that timed out; the URL is built from the probed
/// socket so the two cannot drift.
///
/// Scheme and authority only: a caller needing a path (`/v1/logs` for
/// the OTLP export) appends its own.
pub fn refused_base_url() -> String {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(
        addr.port() < 1024,
        "these tests must use a privileged port; wiremock binds 127.0.0.1:0 (#115, #229)"
    );
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)) {
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => panic!(
            "{addr} timed out; refusing to hand out an address whose failure \
             would arrive on the caller's client timeout instead of at \
             connect (#115, #280)"
        ),
        _ => format!("http://{addr}"),
    }
}

/// Core cannot `#[path]` into this package's `tests/`; the bodies stay
/// identical except the timeout-panic sentence #280 reworded.
#[test]
fn the_core_copy_matches() {
    fn body(src: &str) -> &str {
        const SIG: &str = "fn refused_base_url() -> String {";
        let start = src.find(SIG).unwrap_or_else(|| panic!("{SIG} must exist")) + SIG.len();
        let rest = &src[start..];
        let end = rest
            .find("\n}")
            .unwrap_or_else(|| panic!("{SIG} body must close"));
        &rest[..end]
    }

    // The one allowed difference: the string inside this panic!(...).
    fn without_timeout_sentence(body: &str) -> String {
        const ARM: &str = "Err(e) if e.kind() == std::io::ErrorKind::TimedOut => panic!(";
        let start = body
            .find(ARM)
            .unwrap_or_else(|| panic!("the timeout-panic arm must exist"));
        let rest = &body[start + ARM.len()..];
        let close = rest
            .find("),")
            .unwrap_or_else(|| panic!("the timeout panic must close"));
        let mut out = String::with_capacity(body.len());
        out.push_str(&body[..start + ARM.len()]);
        out.push_str(" SENTENCE ");
        out.push_str(&rest[close..]);
        out
    }

    let here = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let ours = std::fs::read_to_string(here.join("tests/common/refused.rs")).expect("this file");
    let core = std::fs::read_to_string(here.join("../bugwarden-core/tests/guard_wiremock.rs"))
        .expect("core's packaging-bound copy");
    assert_eq!(
        without_timeout_sentence(body(&ours)),
        without_timeout_sentence(body(&core)),
        "the two refused_base_url bodies must match modulo the timeout-panic sentence (#287)"
    );
}
