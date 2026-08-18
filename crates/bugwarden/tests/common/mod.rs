//! Shared helpers for bugwarden integration tests.

/// Connect-time failure that wiremock's 127.0.0.1 pool cannot serve (#115).
///
/// `127.0.0.1:1` is a privileged port: a non-root wiremock listener binds
/// `127.0.0.1:0` and cannot occupy it. Both Linux and macOS refuse
/// immediately if nothing is listening (unlike `127.0.0.2`, which is not
/// aliased on macOS and hangs). A bounded probe refuses to return an
/// address that accepted or timed out. The URL is built from the probed
/// socket so the two cannot drift, and the port must stay privileged so
/// a bind-then-drop of an ephemeral port fails this helper.
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
