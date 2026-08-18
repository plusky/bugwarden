//! Shared helpers for bugwarden integration tests.

/// Connect-time failure that wiremock's 127.0.0.1 pool cannot serve (#115).
///
/// 127.0.0.2 is still loopback (`127.0.0.0/8`); port 1 is a system port.
/// A bounded probe refuses to return an address that accepted or timed out,
/// so the 30s client cannot hang on an unroutable extra-loopback. The URL
/// is built from the probed socket so the two cannot drift, and 127.0.0.1
/// is rejected so a bind-then-drop mutation fails this helper.
pub fn refused_base_url() -> String {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 2], 1));
    assert_ne!(
        addr.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "I12 transport tests must not target 127.0.0.1; wiremock's pool binds there (#115)"
    );
    match std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(500)) {
        Ok(_) => panic!(
            "{addr} accepted a connection; I12 tests need a refused address \
             that wiremock's 127.0.0.1 pool cannot occupy (#115)"
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
