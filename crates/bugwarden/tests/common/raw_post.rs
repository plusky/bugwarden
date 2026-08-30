//! Raw-socket POST for tests that must observe an answer the server gives
//! before it has read what it was sent.
//!
//! Included by `#[path]` from each user rather than declared in
//! `common/mod.rs`: that module is compiled into every test binary that
//! says `mod common;`, so a helper only two of them use would be
//! `dead_code` in the rest, which `-D warnings` rejects.

use std::net::SocketAddr;
use std::time::Duration;

/// The status line the server answers a POST of `body` to `/mcp`,
/// presenting `authorization` when one is given.
///
/// Raw TCP rather than reqwest, because a refusal can arrive while the body
/// is still being written and is followed by a close: the remaining write
/// then fails with a connection reset, and reqwest abandons the response it
/// already holds along with it. Here the send is best-effort and the read is
/// what the caller waits on, so the answer is observed whether or not the
/// rest of the body ever landed — the only way to test a server that
/// deliberately refuses before consuming what it was sent.
///
/// Stops at the status line: an ADMITTED body is answered with a chunked
/// `text/event-stream` that ends itself, after which the connection idles in
/// keep-alive — so a read to EOF would wait on a close nothing here performs.
/// Empty means the server answered nothing at all.
pub async fn post_status_line(
    addr: SocketAddr,
    authorization: Option<&str>,
    body: &[u8],
) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let credential = authorization.map_or_else(String::new, |v| format!("Authorization: {v}\r\n"));
    let mut request = format!(
        "POST /mcp HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n{credential}\
         Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);

    let socket = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to the listener");
    let (mut reader, mut writer) = socket.into_split();
    let sender = tokio::spawn(async move {
        let _ = writer.write_all(&request).await;
        // Hold the write half past the last byte. Dropping it half-closes
        // the connection, and hyper reads that as the caller leaving: on an
        // ADMITTED body, whose answer is still being produced when the write
        // finishes, it then closes with no answer at all. `abort` below
        // releases it once the status line is in hand.
        std::future::pending::<()>().await;
    });
    let mut line = Vec::new();
    // Byte at a time so a reset mid-line keeps what already arrived; the
    // buffered readers make no such promise.
    let read = async {
        let mut byte = [0u8; 1];
        while let Ok(1) = reader.read(&mut byte).await {
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
    };
    tokio::time::timeout(Duration::from_secs(10), read)
        .await
        .expect("the server must answer");
    sender.abort();
    String::from_utf8_lossy(&line).trim_end().to_owned()
}
