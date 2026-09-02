//! An address that refuses every connection and no test in this suite can
//! occupy, for the harnesses that need a connect-time failure (#115, #229).
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only some of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects (#167, #214).
//! `REFUSED_CONNECT_BUDGET` stayed behind because only the guard-client
//! harnesses bound a call with it.

/// Connect-time failure nothing in this process can answer (#115, #229).
///
/// The address is `127.0.0.1:1`. Port 1 is privileged: a non-root test
/// process cannot bind it, so neither wiremock's `127.0.0.1:0` pool nor a
/// stranger racing an ephemeral port can answer this request. The
/// load-bearing assertion is `port() < 1024` — a bind-then-drop of an
/// ephemeral port fails the helper. A 500 ms TCP probe refuses to
/// return an address that accepted or timed out; the URL is built from
/// the probed socket so the two cannot drift.
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
        Ok(_) => panic!(
            "{addr} accepted a connection; these tests need a refused address \
             that wiremock's 127.0.0.1:0 pool cannot occupy (#115)"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => panic!(
            "{addr} timed out; refusing to point a 30s client at an address \
             that would hang the test (#115)"
        ),
        Err(_) => format!("http://{addr}"),
    }
}
