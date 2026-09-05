//! A reqwest client for the harnesses that POST to `/mcp` by hand, under
//! the same deadline every other request in the suite carries (#254).
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only two of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects (#167, #214). A
//! sibling of `common/deadline.rs` rather than an item inside it for that
//! same reason: six binaries need `bounded`, only two need this.

/// A reqwest client carrying `CALL_DEADLINE` as a total request deadline.
///
/// These harnesses hand-build POSTs that no rmcp client would send, and
/// they reach the same `dispatch` a session request does — so they need
/// the same bound. `bounded` cannot give it to them: `send()` resolves
/// when the response HEADERS arrive and the body, which for the
/// per-request path is an SSE stream, is read afterwards, so a server that
/// answered a header and then stopped would still park the test.
/// `ClientBuilder::timeout` spans both halves — reqwest documents it as
/// running from the start of the connect until the body has finished — and
/// every request built from the client inherits it, so the deadline is set
/// once here instead of at each call. `Client::new()` sets none at all.
///
/// The number is read out of `common/deadline.rs` rather than repeated
/// here: two constants that must agree and are written down twice are two
/// constants that drift apart. A binary including this file must therefore
/// include that one as well, and the compiler says so if it does not.
pub fn raw_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(crate::deadline::CALL_DEADLINE)
        .build()
        .expect("reqwest client")
}
