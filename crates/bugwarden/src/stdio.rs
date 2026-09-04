//! What wraps rmcp's stdio transport: a frame bound ([`BoundedLines`])
//! and a `server/discover` answer ([`DiscoverAnswering`]).
//!
//! rmcp's `AsyncRwTransport` reads a newline-delimited frame with
//! `read_until(b'\n', &mut self.line_buf)` into a `Vec<u8>` it never
//! bounds, so a peer that writes bytes and no `\n` grows that buffer until
//! the allocator gives up (#234). HTTP has the derived POST cap and a
//! `413`; stdio had nothing.
//!
//! [`BoundedLines`] is that missing half: an [`AsyncRead`] wrapper that
//! counts the bytes since the last `\n` and fails the read past the cap.
//! The obvious alternatives do not work — `JsonRpcMessageCodec`'s
//! `new_with_max_length` bounds only the `FramedWrite` half, which is
//! bugwarden's own output, and `AsyncReadExt::take` truncates the whole
//! stream rather than one frame.
//!
//! An over-cap frame is fatal, not skippable: the request id lives inside
//! the unparsed frame, so no response can name it, and rmcp clients set no
//! default request timeout — a peer that resumed would hang forever, which
//! is worse than a closed transport. rmcp maps the read error to
//! `receive() -> None`, i.e. a silent close indistinguishable from a clean
//! peer hangup, so the trip is also published through [`BoundedLines::over_cap`]
//! for `main` to turn into a non-zero exit.
//!
//! [`DiscoverAnswering`] is the other half: rmcp reads the stdio lifecycle
//! off the first frame, so a `server/discover` probe committed the session
//! to the handshake-free lifecycle before it was answered (#267). Both are
//! transport-level because both are: the frame never reaches a handler.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use rmcp::model::{
    ClientJsonRpcMessage, ClientRequest, DiscoverResult, ErrorData as McpError, GetMeta as _,
    ProtocolVersion, RequestId, ServerJsonRpcMessage, ServerResult,
};
use rmcp::transport::async_rw::AsyncRwTransport;
use rmcp::transport::Transport;
use rmcp::{RoleServer, ServerHandler as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::server::{BugWarden, SUPPORTED_PROTOCOL_VERSIONS};

/// An [`AsyncRead`] that fails once a newline-delimited frame exceeds
/// `cap` bytes.
///
/// Wraps stdin under rmcp's own `BufReader`, so the counter sees the
/// delivered chunks and not the frames: the cap is enforced as soon as the
/// running frame passes it, without waiting for the `\n` that may never
/// come. A frame of exactly `cap` bytes is accepted, mirroring the http
/// side's `<= max_bytes`.
///
/// The count lives here rather than in a per-`receive` future because rmcp
/// keeps partial bytes across cancelled polls: `receive` is polled inside a
/// `select!` and an in-progress line read is dropped whenever an outgoing
/// response wins, so a per-call counter would restart mid-frame and the cap
/// would bound nothing.
#[derive(Debug)]
pub struct BoundedLines<R> {
    inner: R,
    /// Largest frame accepted, in bytes before the delimiter.
    cap: usize,
    /// Bytes delivered since the last `\n` — the length of the frame in
    /// progress.
    since_newline: usize,
    /// Set once, never cleared: the read stays failed, and `main` reads it
    /// after `waiting()` to tell an over-cap close from a clean one.
    over_cap: Arc<AtomicBool>,
}

impl<R> BoundedLines<R> {
    /// Bound `inner` to frames of at most `cap` bytes before the `\n`.
    pub fn new(inner: R, cap: usize) -> Self {
        Self {
            inner,
            cap,
            since_newline: 0,
            over_cap: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The frame cap this reader enforces, in bytes before the delimiter.
    ///
    /// Exposed so a test can assert that the stdio and http transports were
    /// sized from the same derivation rather than from two numbers that
    /// happen to agree today.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// The trip flag, shared with whoever outlives the transport.
    ///
    /// rmcp turns the read error into `receive() -> None`, which the
    /// service reports as an ordinary close (`QuitReason::Closed`) — so
    /// without this flag a refused frame and a peer hangup are the same
    /// `Ok` exit. `main` bails on it after `waiting()` so both stages exit
    /// non-zero.
    pub fn over_cap(&self) -> Arc<AtomicBool> {
        self.over_cap.clone()
    }

    /// The error a tripped reader returns, on the trip and on every read
    /// after it. `InvalidData` matches rmcp's own mapping of its codec's
    /// `MaxLineLengthExceeded`.
    fn refusal(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stdio frame exceeds the {}-byte request cap", self.cap),
        )
    }

    /// Trip the flag, log once from bugwarden's side, and return the error.
    ///
    /// The log matters: rmcp's own `Error reading from stream` is the only
    /// other trace of this, and it names neither the cap nor the transport.
    fn trip(&mut self) -> io::Error {
        self.over_cap.store(true, Ordering::Release);
        tracing::error!(
            "stdio frame exceeds the {}-byte request cap; closing the transport",
            self.cap
        );
        self.refusal()
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedLines<R> {
    /// Delegates the read, then measures what arrived.
    ///
    /// Every frame in the chunk is checked at its delimiter, not only the
    /// bytes after the chunk's last newline: a frame that both passes the
    /// cap and *ends* inside the tripping chunk would otherwise be seen as a
    /// short tail and let through. (Chunk length is not the measure either —
    /// many short frames may share one chunk.) Overshoot is bounded by one chunk
    /// (8 KiB under rmcp's `BufReader`), since the cap can only be observed
    /// on bytes already delivered.
    ///
    /// Bytes the tripping read delivered stay in `buf`; the caller drops
    /// them with the error, and the transport is closed either way.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.over_cap.load(Ordering::Acquire) {
            return Poll::Ready(Err(this.refusal()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut this.inner).poll_read(cx, buf))?;
        let mut rest = &buf.filled()[before..];
        while let Some(newline) = rest.iter().position(|&byte| byte == b'\n') {
            if this.since_newline.saturating_add(newline) > this.cap {
                return Poll::Ready(Err(this.trip()));
            }
            this.since_newline = 0;
            rest = &rest[newline + 1..];
        }
        this.since_newline = this.since_newline.saturating_add(rest.len());
        if this.since_newline > this.cap {
            return Poll::Ready(Err(this.trip()));
        }
        Poll::Ready(Ok(()))
    }
}

/// One reply's write, boxed so it can outlive the `receive` that queued
/// it. See [`DiscoverAnswering::receive`].
type QueuedSend<E> = Pin<Box<dyn Future<Output = Result<(), E>> + Send>>;

/// A [`Transport`] that answers `server/discover` itself and hands rmcp
/// every other frame untouched.
///
/// `server/discover` is a probe, but over stdio rmcp lets it CHOOSE the
/// session lifecycle before anyone answers it: `serve_server_with_ct_inner`
/// (rmcp 3.1.4 `service/server.rs:510-577`) takes any first non-`ping`
/// frame that is not `initialize` as a commitment to the handshake-free
/// lifecycle and calls `Peer::require_request_metadata()` (`:562`) — a
/// sticky `AtomicBool` that no later `initialize` clears and no public API
/// can reset, both methods being `pub(crate)`. Every subsequent request
/// but `initialize` that carries no `_meta` is then refused -32602
/// (`handler/server.rs:78-100`), so a client that probes and then opens a
/// session is dead (#267). A probe rmcp refuses is worse: it answers and
/// then ENDS the process with `ExpectedInitializeRequest`.
///
/// Answering here keeps discover off that path entirely. rmcp's first frame
/// is then the first one that IS a commitment — `initialize` for a session,
/// or a `_meta`-carrying request that sets the flag exactly as before. The
/// per-request gate stays rmcp's and no other frame is intercepted — but a
/// probe no longer moves rmcp past its pre-`initialize` loop, so a `ping`
/// after one is answered `{}` there rather than refused -32601 by the
/// per-request handler (`handler/server.rs:112-118`), which is where a
/// probe used to leave it.
///
/// http needs none of this: there `serve_negotiated_request_directly`
/// answers a discover per POST and sets no flag.
pub struct DiscoverAnswering<T: Transport<RoleServer>> {
    inner: T,
    /// Cloned, not snapshotted: `get_info()` is read per discover, as
    /// rmcp's default handler reads it.
    server: BugWarden,
    /// A discover reply whose write has not finished, parked across
    /// `receive` calls because `receive` is one arm of rmcp's `select!`
    /// (`service.rs:1395`) and is dropped whenever another arm wins. A
    /// reply awaited on that stack dies with the frame that asked for it —
    /// consumed, never answered, the client hung on that id — while the
    /// inner transport survives the same cancellation by keeping its
    /// partial line in `line_buf` (`transport/async_rw.rs:126-131`).
    pending: Option<QueuedSend<T::Error>>,
    /// Set once a probe's reply has reached the peer, served or refused.
    /// See [`DiscoverAnswering::answered`].
    probed: Arc<AtomicBool>,
}

impl<T: Transport<RoleServer>> DiscoverAnswering<T> {
    /// Answer `server/discover` on `inner` from `server`.
    pub fn new(inner: T, server: BugWarden) -> Self {
        Self {
            inner,
            server,
            pending: None,
            probed: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Whether a probe has been answered, shared with whoever outlives the
    /// transport.
    ///
    /// A probe answered here leaves rmcp still waiting for its first
    /// committing frame, so a probe-only client's hangup surfaces as
    /// `ServerInitializeError::ConnectionClosed` rather than as the clean
    /// close it is. `main` reads this to tell the two apart (#267).
    pub fn answered(&self) -> Arc<AtomicBool> {
        self.probed.clone()
    }

    /// rmcp's own answer for one discover request, in rmcp's own order:
    /// the pre-`initialize` metadata check (`service/server.rs:541-551`,
    /// its text at `:486`), then the declared-revision check
    /// (`handler/server.rs:64-72`), then that file's default result (`:347`).
    ///
    /// That order is the pre-`initialize` path's, which is the one this
    /// replaces; rmcp's in-session handler runs the two the other way
    /// round, so a `_meta` malformed BOTH ways — an unserved revision and
    /// no `clientCapabilities` — now draws -32602 where a mid-session
    /// probe drew -32022. Refused either way, and a `_meta` missing a
    /// required key declares no lifecycle worth reading a version out of.
    ///
    /// Not stripped for a legacy peer: `strip_result_type_for_legacy_peer`
    /// (`model.rs:4596`) has no `DiscoverResult` arm, so `resultType`
    /// stays on the wire whatever revision the probe declares.
    fn discover_reply(&self, request: &ClientRequest, id: RequestId) -> ServerJsonRpcMessage {
        let meta = request.get_meta();
        let missing = meta.missing_required_keys(&ProtocolVersion::V_2026_07_28);
        if !missing.is_empty() {
            return ServerJsonRpcMessage::error(
                McpError::invalid_params(
                    format!(
                        "request _meta is missing or has malformed required fields: {}",
                        missing.join(", ")
                    ),
                    None,
                ),
                Some(id),
            );
        }
        if let Some(requested) = meta
            .protocol_version()
            .filter(|version| !SUPPORTED_PROTOCOL_VERSIONS.contains(version))
        {
            return ServerJsonRpcMessage::error(
                McpError::unsupported_protocol_version(requested, SUPPORTED_PROTOCOL_VERSIONS),
                Some(id),
            );
        }
        ServerJsonRpcMessage::response(
            ServerResult::DiscoverResult(DiscoverResult::from_server_info(
                SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
                self.server.get_info(),
            )),
            id,
        )
    }
}

impl<R, W> DiscoverAnswering<AsyncRwTransport<RoleServer, R, W>>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin + 'static,
{
    /// The same wrapper over a newline-framed pair, so `main` frames stdio
    /// through rmcp rather than naming rmcp's transport itself.
    pub fn framed(read: R, write: W, server: BugWarden) -> Self {
        Self::new(AsyncRwTransport::new_server(read, write), server)
    }
}

impl<T: Transport<RoleServer>> Transport<RoleServer> for DiscoverAnswering<T> {
    type Error = T::Error;

    fn send(
        &mut self,
        item: ServerJsonRpcMessage,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'static {
        self.inner.send(item)
    }

    /// Loops instead of returning: an answered discover is consumed here
    /// and the next frame awaited, so rmcp never learns a lifecycle from
    /// one. A failed send closes the transport, like every other write
    /// failure on this path.
    ///
    /// The reply is queued in `pending` and driven at the top of the loop,
    /// never awaited on this stack: this future is cancelled whenever
    /// another arm of rmcp's `select!` wins, which under any pipelining is
    /// most of the time.
    async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
        loop {
            if let Some(pending) = self.pending.as_mut() {
                let sent = pending.await;
                self.pending = None;
                sent.ok()?;
                self.probed.store(true, Ordering::Release);
            }
            match self.inner.receive().await? {
                ClientJsonRpcMessage::Request(request)
                    if matches!(request.request, ClientRequest::DiscoverRequest(_)) =>
                {
                    let reply = self.discover_reply(&request.request, request.id);
                    self.pending = Some(Box::pin(self.inner.send(reply)));
                }
                other => return Some(other),
            }
        }
    }

    /// Drains `pending` first: rmcp closes the transport on its way out of
    /// the serve loop, and the last `receive` may have been cancelled with
    /// a probe's answer still queued.
    async fn close(&mut self) -> Result<(), Self::Error> {
        if let Some(pending) = self.pending.take() {
            let _ = pending.await;
        }
        self.inner.close().await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmcp::transport::async_rw::AsyncRwTransport;
    use rmcp::transport::Transport as _;
    use rmcp::RoleServer;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

    use super::BoundedLines;

    /// Read everything `bytes` yields through a reader capped at `cap`,
    /// returning the first error if there was one.
    async fn drain(bytes: &[u8], cap: usize) -> std::io::Result<()> {
        let mut reader = BoundedLines::new(bytes, cap);
        let mut sink = [0u8; 512];
        while reader.read(&mut sink).await? != 0 {}
        Ok(())
    }

    fn duplex(cap: usize) -> (DuplexStream, BoundedLines<DuplexStream>) {
        let (peer, ours) = tokio::io::duplex(64 * 1024);
        (peer, BoundedLines::new(ours, cap))
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_cap_is_accepted() {
        // `<= cap`, mirroring http's `<= max_bytes`. A `>=` here would
        // refuse the largest frame the cap names.
        drain(b"0123456789abcdef\n", 16)
            .await
            .expect("16 bytes is the cap, not past it");
    }

    #[tokio::test]
    async fn a_frame_of_exactly_the_cap_waits_for_its_delimiter() {
        // The chunked half of the same `<=`: a 4 MiB frame arrives in 8 KiB
        // pieces, so the cap is reached with the `\n` still in flight. A
        // `>=` in the no-delimiter-yet branch refuses the largest legal
        // frame on every real stream while the whole-chunk test above still
        // passes.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789abcdef")
            .await
            .expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("exactly the cap"), 16);
        peer.write_all(b"\n").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("the delimiter"), 1);
    }

    #[tokio::test]
    async fn one_byte_past_the_cap_is_refused() {
        let err = drain(b"0123456789abcdefg\n", 16)
            .await
            .expect_err("17 bytes is past a 16-byte cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("16-byte request cap"),
            "the refusal must name the cap: {err}"
        );
    }

    #[tokio::test]
    async fn the_count_is_per_frame_and_not_a_running_total() {
        // Chunked on purpose: within a single chunk the loop starts from
        // zero whether or not it resets, so a whole-frames-in-one-read test
        // passes even with the reset deleted. Only a frame that STRADDLES a
        // chunk boundary leaves a stale count for the next one to inherit —
        // and then an ordinary session is refused after a few requests.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("10 bytes"), 10);
        // Closes that frame at 12 bytes and opens the next one.
        peer.write_all(b"ab\ncdef").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("12 then 4"), 7);
        // 10 bytes into the second frame, but 20 into the session.
        peer.write_all(b"ghijkl\n").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("10 bytes, not 20"), 7);
    }

    #[tokio::test]
    async fn a_frame_that_ends_inside_the_tripping_chunk_is_still_refused() {
        // One chunk carrying an over-cap frame AND its delimiter. Checking
        // only the bytes after the chunk's last newline lets this through
        // as a short tail.
        let err = drain(b"0123456789abcdefg\nshort\n", 16)
            .await
            .expect_err("the delimiter does not excuse the frame before it");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_over_cap_second_frame_inside_one_chunk_is_refused() {
        // The under-cap first frame must not reset the scan so far that the
        // second one, entirely inside the same chunk, escapes its check.
        let err = drain(b"short\n0123456789abcdefg\n", 16)
            .await
            .expect_err("the second frame of the chunk is over the cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn several_under_cap_frames_in_one_chunk_are_accepted() {
        // Four 8-byte frames in a 32-byte chunk at cap 16: a check that
        // measured the chunk, or forgot to reset at each delimiter, would
        // refuse a stream of frames that individually fit.
        drain(b"aaaaaaa\nbbbbbbb\nccccccc\nddddddd\n", 16)
            .await
            .expect("every frame is half the cap");
    }

    #[tokio::test]
    async fn the_count_survives_a_cancelled_read() {
        // rmcp polls `receive` inside a `select!` and keeps the partial
        // bytes when another branch wins, so the counter has to live in the
        // reader. A per-future count would restart here and accept 20 bytes
        // under a 16-byte cap.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789").await.expect("duplex write");
        assert_eq!(reader.read(&mut buf).await.expect("first chunk"), 10);
        // A read with nothing to deliver, dropped mid-flight.
        assert!(
            tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buf))
                .await
                .is_err(),
            "an empty duplex must leave the read pending"
        );
        peer.write_all(b"0123456789").await.expect("duplex write");
        let err = reader
            .read(&mut buf)
            .await
            .expect_err("20 bytes of one frame is past a 16-byte cap");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn the_refusal_is_sticky() {
        // rmcp stops reading after the first error, but nothing in the
        // `AsyncRead` contract makes it: a reader that recovered would hand
        // the tail of a refused frame to the parser as a fresh one.
        //
        // The refused frame carries its own delimiter, so the count is back
        // at zero and the next frame is legal on its face — without the
        // sticky check the second read succeeds. A refusal with no
        // delimiter would leave the count over the cap and trip again
        // whether or not the reader remembered anything.
        let (mut peer, mut reader) = duplex(16);
        let mut buf = [0u8; 512];
        peer.write_all(b"0123456789abcdefg\n")
            .await
            .expect("duplex write");
        reader.read(&mut buf).await.expect_err("over the cap");
        peer.write_all(b"{}\n").await.expect("duplex write");
        let err = reader
            .read(&mut buf)
            .await
            .expect_err("a tripped reader stays failed");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn an_under_cap_stream_reaches_the_reader_unchanged() {
        // The wrapper is transparent below the cap: a `\r\n` frame, an
        // empty frame and a trailing fragment all pass through byte for
        // byte, so nothing it does can corrupt the framing rmcp parses.
        let payload = b"{\"a\":1}\r\n\n{\"b\":2}\ntrailing";
        let mut reader = BoundedLines::new(&payload[..], 16);
        let mut read = Vec::new();
        reader.read_to_end(&mut read).await.expect("under the cap");
        assert_eq!(read, payload);
    }

    #[tokio::test]
    async fn rmcp_turns_the_refusal_into_a_closed_transport() {
        // The contract this whole design rests on, and the one thing an
        // rmcp bump can silently change: `receive` maps a read error to
        // `None`, so the service quits instead of retrying. If a future
        // rmcp propagated the error or resumed the read, this fails and the
        // exit-code path in `main` needs rethinking.
        //
        // Bounded: a reader that does not refuse leaves rmcp blocked in
        // `read_until` on a duplex nothing else will write to, and this
        // would hang the suite instead of failing.
        let (mut peer, reader) = duplex(16);
        let mut transport =
            AsyncRwTransport::<RoleServer, _, _>::new_server(reader, tokio::io::sink());
        peer.write_all(b"0123456789abcdefghij\n")
            .await
            .expect("duplex write");
        let received = tokio::time::timeout(Duration::from_secs(5), transport.receive())
            .await
            .expect("the transport must not block on a frame it will never accept");
        assert!(
            received.is_none(),
            "an over-cap frame must close the transport, not yield a message"
        );
    }
}

/// [`DiscoverAnswering`]: what the wrapper answers, what it lets past, and
/// that the lifecycle rmcp ends up on is the one the client's FIRST
/// committing request chose (#267).
#[cfg(test)]
mod discover {
    use std::sync::Arc;
    use std::time::Duration;

    use bugwarden_core::guard::Guard;
    use bugwarden_core::policy::Policy;
    use rmcp::model::{
        ClientJsonRpcMessage, ClientRequest, DiscoverResult, ProtocolVersion, ServerJsonRpcMessage,
    };
    use rmcp::transport::Transport as _;
    use rmcp::{RoleServer, ServerHandler as _, ServiceExt as _};
    use serde_json::{json, Value};
    use tokio::io::{
        AsyncBufReadExt as _, AsyncWriteExt as _, BufReader, DuplexStream, ReadHalf, WriteHalf,
    };

    use super::DiscoverAnswering;
    use crate::pinned_cli::pinned;
    use crate::server::{bugzilla_client, BugWarden, SUPPORTED_PROTOCOL_VERSIONS};

    /// Bounded so a wrapper that swallows a frame fails rather than hanging
    /// the suite until CI's own timeout kills it.
    const REPLY_BUDGET: Duration = Duration::from_secs(10);

    /// A revision this build serves, so a probe carrying it is answered.
    const SERVED: &str = "2026-07-28";

    /// A revision no build serves, standing in for the next one a client
    /// adopts before bugwarden does — the reporter's case.
    const UNSERVED: &str = "2027-01-01";

    /// The narrow pipe [`Session::open_narrow`] serves over: wide enough
    /// for a whole burst of requests, far too narrow for the answers.
    const PIPE: usize = 8 * 1024;

    fn test_server() -> BugWarden {
        let cfg = Arc::new(pinned(&[
            "bugwarden",
            "--bugzilla-server",
            "https://bugzilla.example.invalid",
            "--transport",
            "stdio",
            "--api-key",
            "test-key",
        ]));
        let guard = Arc::new(Guard {
            policy: Policy::from_toml_str("").expect("the empty policy must parse"),
        });
        let bz = Arc::new(bugzilla_client(&cfg).expect("client must build"));
        BugWarden::new(cfg, guard, bz).expect("server must build")
    }

    /// The `_meta` a 2026-07-28 client sends, with the two required keys.
    fn meta(version: &str) -> Value {
        json!({
            "io.modelcontextprotocol/protocolVersion": version,
            "io.modelcontextprotocol/clientCapabilities": {},
        })
    }

    fn discover(id: u32, meta: Value) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": "server/discover",
                "params": { "_meta": meta } })
    }

    /// The one frame rmcp answers before `initialize`, and this file's
    /// filler for pipelining probes against.
    fn ping(id: u32) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "method": "ping" })
    }

    /// The client end of a served stdio session: raw JSON lines in, raw
    /// JSON lines out, exactly what a subprocess client writes.
    struct Session {
        write: WriteHalf<DuplexStream>,
        lines: tokio::io::Lines<BufReader<ReadHalf<DuplexStream>>>,
    }

    impl Session {
        /// Serve `test_server()` over a duplex pair, wrapped the way `main`
        /// wraps stdio.
        fn open() -> Self {
            Self::serving(true, 256 * 1024)
        }

        /// The same server with rmcp answering the probe itself: the
        /// oracle the wrapper is diffed against.
        fn open_bare() -> Self {
            Self::serving(false, 256 * 1024)
        }

        /// A pipe too small for the replies a burst produces, so the
        /// writes really do park — which is what makes rmcp's `select!`
        /// cancel a `receive` mid-send.
        fn open_narrow() -> Self {
            Self::serving(true, PIPE)
        }

        fn serving(wrapped: bool, capacity: usize) -> Self {
            let (theirs, ours) = tokio::io::duplex(capacity);
            let (read, write) = tokio::io::split(ours);
            let server = test_server();
            tokio::spawn(async move {
                let service = if wrapped {
                    let transport = DiscoverAnswering::framed(read, write, server.clone());
                    server.serve(transport).await?
                } else {
                    server.serve((read, write)).await?
                };
                service.waiting().await?;
                Ok::<(), anyhow::Error>(())
            });
            let (read, write) = tokio::io::split(theirs);
            Session {
                write,
                lines: BufReader::new(read).lines(),
            }
        }

        async fn send(&mut self, message: Value) {
            self.write
                .write_all(format!("{message}\n").as_bytes())
                .await
                .expect("the session must accept input");
        }

        /// Write every frame in one go, so replies are still being written
        /// when the next frames land — the contention that makes rmcp's
        /// `select!` cancel `receive`.
        async fn burst(&mut self, frames: &[Value]) {
            let mut buffer = String::new();
            for frame in frames {
                buffer.push_str(&format!("{frame}\n"));
            }
            self.write
                .write_all(buffer.as_bytes())
                .await
                .expect("the session must accept input");
        }

        /// The next frame the server wrote, parsed.
        async fn recv(&mut self) -> Value {
            let line = tokio::time::timeout(REPLY_BUDGET, self.lines.next_line())
                .await
                .expect("the server must answer within the budget")
                .expect("the session must be readable")
                .expect("the server must not close before answering");
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("{line:?}: {e}"))
        }

        /// Send `message` and read its reply.
        async fn call(&mut self, message: Value) -> Value {
            self.send(message).await;
            self.recv().await
        }

        /// Handshake at 2025-11-25 and announce it, the legacy lifecycle.
        async fn initialize(&mut self, id: u32) -> Value {
            let reply = self
                .call(json!({
                    "jsonrpc": "2.0", "id": id, "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": { "name": "discover-test", "version": "0" },
                    }
                }))
                .await;
            self.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
                .await;
            reply
        }
    }

    /// The `tools` array of a served listing.
    fn tools_of(reply: &Value) -> &Vec<Value> {
        reply["result"]["tools"]
            .as_array()
            .unwrap_or_else(|| panic!("a served listing carries a tools array: {reply}"))
    }

    /// The JSON-RPC error code of a refusal.
    fn error_code(reply: &Value) -> i64 {
        reply["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("a refusal carries an error code: {reply}"))
    }

    /// rmcp's per-request metadata refusal, spelled out rather than read
    /// off the code under test.
    const MISSING_META: &str = "request _meta is missing or has malformed required fields: ";

    #[tokio::test]
    async fn the_reporter_chain_reaches_the_tool_list() {
        // Issue #267 exactly: a Go SDK client probes with a revision this
        // build does not serve, is told so, falls back to the legacy
        // handshake — and used to find every later request refused -32602,
        // because rmcp had already committed the session to the
        // handshake-free lifecycle on the probe alone.
        let mut session = Session::open();
        let probe = session.call(discover(1, meta(UNSERVED))).await;
        assert_eq!(error_code(&probe), -32022, "{probe}");
        let init = session.initialize(2).await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
        let listed = session
            .call(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }))
            .await;
        assert!(!tools_of(&listed).is_empty(), "{listed}");
    }

    #[tokio::test]
    async fn a_served_probe_then_a_session_reaches_the_tool_list() {
        // The other half of the same defect, and the commoner one: the
        // probe SUCCEEDS and the client opens a session anyway. Nothing
        // about the answer differs; the lifecycle must still be the
        // session's.
        let mut session = Session::open();
        let probe = session.call(discover(1, meta(SERVED))).await;
        assert!(probe["result"]["supportedVersions"].is_array(), "{probe}");
        session.initialize(2).await;
        let listed = session
            .call(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }))
            .await;
        assert!(!tools_of(&listed).is_empty(), "{listed}");
    }

    #[tokio::test]
    async fn a_probe_with_no_meta_is_refused_and_the_session_survives() {
        // On main this frame was answered and then ENDED the process
        // (`ExpectedInitializeRequest`), so the client's `initialize`
        // reached a closed pipe. The refusal is unchanged; what changes is
        // that the session outlives it.
        let mut session = Session::open();
        let probe = session
            .call(
                json!({ "jsonrpc": "2.0", "id": 1, "method": "server/discover",
                          "params": {} }),
            )
            .await;
        assert_eq!(error_code(&probe), -32602, "{probe}");
        assert_eq!(
            probe["error"]["message"],
            json!(format!(
                "{MISSING_META}io.modelcontextprotocol/protocolVersion, \
                 io.modelcontextprotocol/clientCapabilities"
            )),
            "{probe}"
        );
        let init = session.initialize(2).await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
        let listed = session
            .call(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }))
            .await;
        assert!(!tools_of(&listed).is_empty(), "{listed}");
    }

    #[tokio::test]
    async fn a_probe_mid_session_is_answered_and_changes_nothing() {
        // A probe is not only an opener: a client may re-probe a live
        // session. The wrapper intercepts that one too, so the answer must
        // still be the full result and the session must keep serving
        // `_meta`-free requests afterwards.
        let mut session = Session::open();
        session.initialize(1).await;
        let probe = session.call(discover(2, meta(SERVED))).await;
        assert_eq!(probe["result"]["resultType"], "complete", "{probe}");
        let listed = session
            .call(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }))
            .await;
        assert!(!tools_of(&listed).is_empty(), "{listed}");
    }

    #[tokio::test]
    async fn a_pipelined_probe_is_answered_under_write_contention() {
        // The one thing this wrapper does that the inner transport does
        // not: hold a reply. rmcp polls `receive` as one arm of a
        // `select!` (rmcp 3.1.4 `service.rs:1395`) and drops the future
        // whenever another arm wins, so a reply awaited on `receive`'s own
        // stack dies with the frame that asked for it — consumed, never
        // answered, the client hung on that id while every other reply
        // arrives. Every other row here is lock-step, where nothing else
        // is ever ready and the drop never happens. A session first:
        // before `initialize` rmcp awaits `receive` outside its `select!`
        // (`service/server.rs:511`), so a probe-only chain never shows
        // this either. The whole burst fits `PIPE`, so only the SERVER's
        // writes park.
        const FRAMES: u32 = 40;
        let mut session = Session::open_narrow();
        session.initialize(1).await;
        let frames: Vec<Value> = (2..=FRAMES + 1)
            .map(|id| {
                if id % 2 == 0 {
                    discover(id, meta(SERVED))
                } else {
                    ping(id)
                }
            })
            .collect();
        session.burst(&frames).await;
        let mut answered = std::collections::HashSet::new();
        for _ in 0..FRAMES {
            let reply = session.recv().await;
            answered.insert(
                reply["id"]
                    .as_u64()
                    .unwrap_or_else(|| panic!("every reply names its request: {reply}")),
            );
        }
        let unanswered: Vec<u64> = (2..=u64::from(FRAMES) + 1)
            .filter(|id| !answered.contains(id))
            .collect();
        assert!(unanswered.is_empty(), "unanswered ids: {unanswered:?}");
    }

    #[tokio::test]
    async fn the_per_request_lifecycle_is_still_rmcps_to_choose() {
        // The invariant the fix must not weaken. A probe commits nothing,
        // so the FIRST `_meta`-carrying request is what puts rmcp on the
        // handshake-free lifecycle — and rmcp's gate then refuses a
        // request that drops the `_meta`, exactly as before. A wrapper
        // that had answered or relaxed anything past discover would serve
        // the second listing.
        let mut session = Session::open();
        let probe = session.call(discover(1, meta(SERVED))).await;
        assert!(probe["result"]["supportedVersions"].is_array(), "{probe}");
        let declared = session
            .call(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list",
                          "params": { "_meta": meta(SERVED) } }))
            .await;
        assert!(!tools_of(&declared).is_empty(), "{declared}");
        let bare = session
            .call(json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {} }))
            .await;
        assert_eq!(error_code(&bare), -32602, "{bare}");
        assert!(
            bare["error"]["message"]
                .as_str()
                .is_some_and(|message| message.starts_with(MISSING_META)),
            "{bare}"
        );
    }

    #[tokio::test]
    async fn a_ping_before_initialize_is_still_answered_by_rmcp() {
        // The one other frame rmcp accepts before `initialize`. The
        // wrapper must pass it through, not eat it, and the probe that
        // follows must still be answered here.
        let mut session = Session::open();
        let pong = session.call(ping(1)).await;
        assert_eq!(pong["result"], json!({}), "{pong}");
        let probe = session.call(discover(2, meta(SERVED))).await;
        assert_eq!(probe["result"]["resultType"], "complete", "{probe}");
        let init = session.initialize(3).await;
        assert_eq!(init["result"]["protocolVersion"], "2025-11-25", "{init}");
    }

    #[tokio::test]
    async fn a_malformed_meta_names_only_the_key_that_is_wrong() {
        // `missing_required_keys` counts a key present but undecodable as
        // missing, and the refusal names it. A number where the revision
        // belongs must not be read as a revision, nor drag the well-formed
        // capabilities key into the message.
        let mut session = Session::open();
        let probe = session
            .call(discover(
                1,
                json!({
                    "io.modelcontextprotocol/protocolVersion": 7,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }),
            ))
            .await;
        assert_eq!(error_code(&probe), -32602, "{probe}");
        assert_eq!(
            probe["error"]["message"],
            json!(format!(
                "{MISSING_META}io.modelcontextprotocol/protocolVersion"
            )),
            "{probe}"
        );
    }

    #[tokio::test]
    async fn an_in_session_probe_wrong_two_ways_is_refused_on_the_metadata() {
        // The one shape whose refusal CODE this fix changes, pinned as a
        // decision. rmcp's in-session handler checks the declared revision
        // before the required keys (-32022); its pre-`initialize` path —
        // the one the wrapper replaces, and the one a probe normally takes
        // — checks the keys first (-32602). A `_meta` missing a required
        // key declares no lifecycle worth reading a revision out of, so
        // the pre-`initialize` order is the one kept on both.
        let mut session = Session::open();
        session.initialize(1).await;
        let probe = session
            .call(discover(
                2,
                json!({ "io.modelcontextprotocol/protocolVersion": UNSERVED }),
            ))
            .await;
        assert_eq!(error_code(&probe), -32602, "{probe}");
        assert_eq!(
            probe["error"]["message"],
            json!(format!(
                "{MISSING_META}io.modelcontextprotocol/clientCapabilities"
            )),
            "{probe}"
        );
    }

    #[tokio::test]
    async fn the_answer_is_the_sdk_default_discover_result() {
        // The parity oracle: the wrapper replaces rmcp's default
        // `ServerHandler::discover`, so what reaches the wire must be that
        // default's result, built from this server's own `get_info()` —
        // serverInfo, instructions, capabilities and the SEP-2549 cache
        // hints included. Compared whole: a field this wrapper forgot, or
        // one it added, is exactly how the identity surface drifts.
        let mut session = Session::open();
        let probe = session.call(discover(1, meta(SERVED))).await;
        let expected = serde_json::to_value(DiscoverResult::from_server_info(
            SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            test_server().get_info(),
        ))
        .expect("the SDK result must serialize");
        assert_eq!(probe["result"], expected, "{probe}");
        assert_eq!(
            probe["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
            json!({ "name": "bugwarden", "version": env!("CARGO_PKG_VERSION") }),
            "the probe must name this build, and nothing else: {probe}"
        );
        // Present whatever revision the probe declares:
        // `strip_result_type_for_legacy_peer` (rmcp 3.1.4 model.rs) has no
        // `DiscoverResult` arm, so rmcp never stripped it here either.
        assert_eq!(probe["result"]["resultType"], "complete", "{probe}");
    }

    /// The `_meta` shape whose refusal CODE the wrapper moves, named once
    /// so the differential and its exception cannot drift apart.
    const UNSERVED_WITHOUT_CAPABILITIES: &str = "an unserved revision, no capabilities";

    /// Every `_meta` shape the differential drives: what a probe carries,
    /// well formed and not.
    fn probe_shapes() -> Vec<(&'static str, Value)> {
        vec![
            ("both keys, a served revision", meta(SERVED)),
            ("both keys, a legacy revision", meta("2025-11-25")),
            ("both keys, the oldest served revision", meta("2024-11-05")),
            ("both keys, an unserved revision", meta(UNSERVED)),
            (
                "the Go SDK shape, clientInfo included",
                json!({
                    "io.modelcontextprotocol/protocolVersion": SERVED,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": { "name": "agy", "version": "1.7.0" },
                }),
            ),
            ("an empty _meta", json!({})),
            (
                "a served revision, no capabilities",
                json!({ "io.modelcontextprotocol/protocolVersion": SERVED }),
            ),
            (
                "capabilities, no revision",
                json!({ "io.modelcontextprotocol/clientCapabilities": {} }),
            ),
            (
                UNSERVED_WITHOUT_CAPABILITIES,
                json!({ "io.modelcontextprotocol/protocolVersion": UNSERVED }),
            ),
            (
                "a revision that is not a string",
                json!({
                    "io.modelcontextprotocol/protocolVersion": 7,
                    "io.modelcontextprotocol/clientCapabilities": {},
                }),
            ),
            (
                "capabilities that are not an object",
                json!({
                    "io.modelcontextprotocol/protocolVersion": SERVED,
                    "io.modelcontextprotocol/clientCapabilities": "yes",
                }),
            ),
        ]
    }

    /// One probe on a session opened for it alone: rmcp ends a bare
    /// session on the shapes it refuses pre-`initialize`, so no two rows
    /// may share one.
    async fn probe_reply(mut session: Session, in_session: bool, meta: Value) -> Value {
        let id = if in_session {
            session.initialize(1).await;
            2
        } else {
            1
        };
        session.call(discover(id, meta)).await
    }

    #[tokio::test]
    async fn the_wrapper_answers_what_rmcp_answered() {
        // The oracle `the_answer_is_the_sdk_default_discover_result`
        // cannot be: that one compares the wrapper against the constructor
        // the wrapper itself calls, so it sees nothing rmcp does BETWEEN
        // handler and wire (`handler/server.rs:246-259`, the legacy-peer
        // strip). This serves the same server bare and diffs its
        // replies over every probe shape, on both paths a probe can take —
        // so an rmcp bump that changes its default `discover`, or starts
        // stripping a `DiscoverResult`, fails here.
        for (name, meta) in probe_shapes() {
            for in_session in [false, true] {
                let bare = probe_reply(Session::open_bare(), in_session, meta.clone()).await;
                let wrapped = probe_reply(Session::open(), in_session, meta.clone()).await;
                if in_session && name == UNSERVED_WITHOUT_CAPABILITIES {
                    // The only row that moves, pinned in both directions:
                    // rmcp's in-session handler checks the declared
                    // revision before the required keys, the
                    // pre-`initialize` path the wrapper replaces checks
                    // the keys first.
                    assert_eq!(error_code(&bare), -32022, "{name}: {bare}");
                    assert_eq!(error_code(&wrapped), -32602, "{name}: {wrapped}");
                    continue;
                }
                assert_eq!(bare, wrapped, "{name}, in a session: {in_session}");
            }
        }
    }

    #[tokio::test]
    async fn a_legacy_declaration_is_answered_unstripped() {
        // The other side of that no-op: a pre-2026 revision is a served
        // one, so the probe is answered — and the answer is byte-identical
        // to the 2026-07-28 one, `resultType` included.
        let mut session = Session::open();
        let legacy = session.call(discover(1, meta("2025-11-25"))).await;
        let modern = session.call(discover(2, meta(SERVED))).await;
        assert_eq!(legacy["result"], modern["result"], "{legacy}");
        assert_eq!(legacy["result"]["resultType"], "complete", "{legacy}");
    }

    #[tokio::test]
    async fn the_refusal_lists_exactly_the_revisions_this_build_serves() {
        // What the Go SDK's retry loop reads to pick its second attempt.
        // A list narrower than the served set makes a client give up on a
        // revision that works; a wider one sends it back with a revision
        // that does not.
        let mut session = Session::open();
        let probe = session.call(discover(1, meta(UNSERVED))).await;
        assert_eq!(error_code(&probe), -32022, "{probe}");
        assert_eq!(probe["error"]["data"]["requested"], UNSERVED, "{probe}");
        assert_eq!(
            probe["error"]["data"]["supported"],
            serde_json::to_value(SUPPORTED_PROTOCOL_VERSIONS).expect("versions serialize"),
            "{probe}"
        );
    }

    /// A [`Transport`] over queued frames, so the wrapper's own dispatch is
    /// testable without a service behind it.
    ///
    /// [`Transport`]: rmcp::transport::Transport
    struct Queued {
        inbound: std::collections::VecDeque<ClientJsonRpcMessage>,
        sent: Arc<std::sync::Mutex<Vec<ServerJsonRpcMessage>>>,
        /// Fails every send, standing in for a peer that closed its end.
        broken: bool,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("send refused")]
    struct SendRefused;

    impl rmcp::transport::Transport<RoleServer> for Queued {
        type Error = SendRefused;

        fn send(
            &mut self,
            item: ServerJsonRpcMessage,
        ) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send + 'static {
            let broken = self.broken;
            let sent = self.sent.clone();
            async move {
                sent.lock().expect("sent lock poisoned").push(item);
                if broken {
                    Err(SendRefused)
                } else {
                    Ok(())
                }
            }
        }

        async fn receive(&mut self) -> Option<ClientJsonRpcMessage> {
            self.inbound.pop_front()
        }

        async fn close(&mut self) -> Result<(), Self::Error> {
            self.inbound.clear();
            Ok(())
        }
    }

    /// Parse `frames` as inbound client messages and wrap them.
    fn queued(frames: &[Value], broken: bool) -> DiscoverAnswering<Queued> {
        let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
        DiscoverAnswering::new(
            Queued {
                inbound: frames
                    .iter()
                    .map(|frame| {
                        serde_json::from_value(frame.clone())
                            .unwrap_or_else(|e| panic!("{frame}: {e}"))
                    })
                    .collect(),
                sent,
                broken,
            },
            test_server(),
        )
    }

    /// What the inner transport was asked to write.
    fn written(wrapper: &DiscoverAnswering<Queued>) -> Vec<Value> {
        wrapper
            .inner
            .sent
            .lock()
            .expect("sent lock poisoned")
            .iter()
            .map(|message| serde_json::to_value(message).expect("a reply serializes"))
            .collect()
    }

    #[tokio::test]
    async fn every_frame_but_a_discover_request_reaches_rmcp() {
        // The pass-through half, at the one place it can be observed
        // directly: a notification, a response, an error and an ordinary
        // request all come back out of `receive`, and none of them makes
        // the wrapper write anything.
        let passed = [
            json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
            json!({ "jsonrpc": "2.0", "id": 1, "result": {} }),
            json!({ "jsonrpc": "2.0", "id": 2, "error": { "code": -1, "message": "no" } }),
            json!({ "jsonrpc": "2.0", "id": 3, "method": "ping" }),
            json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/list", "params": {} }),
        ];
        let mut wrapper = queued(&passed, false);
        for frame in &passed {
            let received = wrapper
                .receive()
                .await
                .unwrap_or_else(|| panic!("{frame} must reach rmcp"));
            assert_eq!(
                serde_json::to_value(&received).expect("a frame serializes"),
                *frame
            );
        }
        assert!(wrapper.receive().await.is_none(), "the queue is drained");
        assert!(written(&wrapper).is_empty(), "{:?}", written(&wrapper));
    }

    #[tokio::test]
    async fn a_discover_is_answered_and_the_next_frame_is_returned() {
        // The interception half: the probe never leaves `receive`, its
        // answer is written to the inner transport, and the frame after it
        // is what rmcp gets — so rmcp learns the lifecycle from THAT one.
        let ping = json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" });
        let mut wrapper = queued(&[discover(1, meta(SERVED)), ping.clone()], false);
        let received = wrapper.receive().await.expect("the ping must come through");
        assert_eq!(
            serde_json::to_value(&received).expect("a frame serializes"),
            ping
        );
        let written = written(&wrapper);
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0]["id"], json!(1), "{written:?}");
        assert_eq!(
            written[0]["result"]["resultType"], "complete",
            "{written:?}"
        );
    }

    #[tokio::test]
    async fn a_reply_that_cannot_be_written_closes_the_transport() {
        // A wrapper that ignored the send error would loop on to the next
        // frame and hand rmcp a session whose peer is already gone, with
        // the probe silently unanswered. `None` is rmcp's own reading of a
        // dead transport.
        let mut wrapper = queued(
            &[
                discover(1, meta(SERVED)),
                json!({ "jsonrpc": "2.0", "id": 2, "method": "ping" }),
            ],
            true,
        );
        assert!(
            wrapper.receive().await.is_none(),
            "a failed reply must close the transport, not skip to the next frame"
        );
    }

    #[tokio::test]
    async fn send_and_close_are_the_inner_transport_s() {
        // The two delegating methods: `send` must reach the inner
        // transport (and carry its error back), `close` must reach it too.
        let mut wrapper = queued(
            &[json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })],
            false,
        );
        let pong = ServerJsonRpcMessage::response(
            rmcp::model::ServerResult::EmptyResult(rmcp::model::EmptyObject {}),
            rmcp::model::RequestId::Number(1),
        );
        wrapper.send(pong).await.expect("the inner send must run");
        assert_eq!(written(&wrapper).len(), 1);
        wrapper.close().await.expect("the inner close must run");
        assert!(
            wrapper.receive().await.is_none(),
            "close must reach the inner transport"
        );
    }

    #[test]
    fn a_discover_frame_is_recognised_by_its_method() {
        // The guard the interception arm turns on, spelled out: rmcp's
        // deserializer routes `server/discover` to `DiscoverRequest` and
        // everything else elsewhere, so `matches!` on that variant is a
        // method test. If a bump renamed the method, this fails here
        // rather than by every probe silently reaching rmcp again.
        let frame: ClientJsonRpcMessage =
            serde_json::from_value(discover(1, meta(SERVED))).expect("the probe must parse");
        let ClientJsonRpcMessage::Request(request) = frame else {
            panic!("a probe is a request");
        };
        assert!(matches!(request.request, ClientRequest::DiscoverRequest(_)));
        assert_eq!(request.request.method(), "server/discover");
    }

    #[test]
    fn the_wrapper_reads_the_list_the_handler_advertises() {
        // The wrapper answers from the constant while rmcp's default
        // handler answers from `supported_protocol_versions()`. They are
        // the same list today; if they ever diverge the probe and the
        // handshake would tell a client two different things.
        assert_eq!(
            test_server().supported_protocol_versions().as_ref(),
            SUPPORTED_PROTOCOL_VERSIONS
        );
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&ProtocolVersion::V_2026_07_28));
        assert!(!SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .any(|version| version.as_str() == UNSERVED));
    }
}
