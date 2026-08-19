//! Shared helpers for bugwarden integration tests.

/// Connect-time failure that wiremock's 127.0.0.1 pool cannot serve (#115).
///
/// The address is `127.0.0.1:1`. Port 1 is privileged: a non-root
/// wiremock listener binds `127.0.0.1:0` and cannot occupy it, so a
/// pooled listener from another test cannot answer this request. The
/// load-bearing assertion is `port() < 1024` — a bind-then-drop of an
/// ephemeral port fails the helper. A 500 ms TCP probe refuses to
/// return an address that accepted or timed out; the URL is built from
/// the probed socket so the two cannot drift.
pub fn refused_base_url() -> String {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    assert!(
        addr.port() < 1024,
        "I12 transport tests must use a privileged port; wiremock binds 127.0.0.1:0 (#115)"
    );
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)) {
        Ok(_) => panic!(
            "{addr} accepted a connection; I12 tests need a refused address \
             that wiremock's 127.0.0.1:0 pool cannot occupy (#115)"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => panic!(
            "{addr} timed out; refusing to point the 30s client at an address \
             that would hang the test (#115)"
        ),
        Err(_) => format!("http://{addr}"),
    }
}

/// Bound on the I12 client calls. Loopback refuse is immediate; a hang
/// here is a proxy or routing defect, not a 30s client timeout.
pub const REFUSED_CONNECT_BUDGET: std::time::Duration = std::time::Duration::from_secs(2);
