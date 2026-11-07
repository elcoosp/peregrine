//! The `pgrd` server loop (M8, architecture doc §7.2): a unix-domain-socket
//! daemon holding one [`ResidentSession`], serving `pgr -resident` clients.
//!
//! Contract (§7.2 constraints, each gated by tests):
//!
//! * **optional and transparent** — the daemon never changes output bytes;
//!   a client that cannot reach it links one-shot (driver side).
//! * **crash-safe** — the daemon holds no output state: the client writes
//!   the file (fresh vnode + rename, the Pass 5 contract), so a daemon
//!   death mid-link leaves at most a dead socket, never a corrupt output.
//! * **concurrent-build safe** — links run serialized per daemon (they are
//!   compute-bound anyway); every link is a pure function of its request,
//!   so queued clients observe each other's bytes never.
//! * **idles out** — a connection (or the listener) quiet for longer than
//!   the idle timeout ends the process; the next client restarts it.
//!
//! Single-connection design: one connection is served to completion before
//! the next is accepted. Clients therefore serialize naturally and the
//! session needs no locking.

use crate::protocol::{
    LinkRequest, PROTO_VERSION, TAG_BLOB, TAG_BYE, TAG_ERROR, TAG_HELLO, TAG_HELLO_ACK, TAG_IMAGE,
    TAG_LINK, TAG_NEED, TAG_SHUTDOWN, put_str, put_u32, put_u64,
};
use crate::session::{ResidentSession, SessionError};
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

/// A server-level failure (listener setup, fatal I/O).
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// The socket path could not be bound.
    #[error("binding {path}: {source}")]
    Bind {
        /// The socket path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// A fatal I/O error outside one connection.
    #[error("daemon I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Writes one frame: `u32 LE length | tag | body`.
pub(crate) fn write_frame(w: &mut impl Write, tag: u32, body: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(8 + body.len());
    put_u32(&mut frame, (4 + body.len()) as u32);
    put_u32(&mut frame, tag);
    frame.extend_from_slice(body);
    w.write_all(&frame)
}

/// Reads one frame; `Ok(None)` on clean EOF (peer closed).
pub(crate) fn read_frame(r: &mut impl Read) -> Result<Option<(u32, Vec<u8>)>, std::io::Error> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    // Frame bound: 256 MiB is far beyond any legitimate image or manifest
    // the M8 corpus shapes produce; a hostile length cannot force the
    // allocation.
    if !(4..=(256 << 20)).contains(&len) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "protocol: frame length out of bounds",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    let tag = u32::from_le_bytes(payload[..4].try_into().unwrap());
    Ok(Some((tag, payload[4..].to_vec())))
}

fn error_body(message: &str) -> Vec<u8> {
    let mut b = Vec::new();
    put_str(&mut b, message);
    b
}

/// Serves until a `SHUTDOWN` message or the idle timeout fires (§7.2 "it idles
/// out after a timeout"): quiet time is measured from the last connection
/// or the last served request. One session for the daemon's lifetime;
/// every accepted connection is handled to completion before the next
/// accept.
///
/// # Errors
/// [`ServerError::Bind`] when the socket cannot be bound;
/// [`ServerError::Io`] on fatal listener errors.
pub fn serve(sock: &Path, idle: Duration) -> Result<(), ServerError> {
    // A stale socket file from a dead daemon would fail bind().
    let _ = std::fs::remove_file(sock);
    if let Some(parent) = sock.parent() {
        std::fs::create_dir_all(parent).map_err(|source| ServerError::Bind {
            path: sock.display().to_string(),
            source,
        })?;
    }
    let listener =
        std::os::unix::net::UnixListener::bind(sock).map_err(|source| ServerError::Bind {
            path: sock.display().to_string(),
            source,
        })?;
    listener.set_nonblocking(true)?;
    let mut session = ResidentSession::default();
    let mut last_activity = std::time::Instant::now();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).map_err(ServerError::Io)?;
                stream.set_read_timeout(Some(idle))?;
                stream.set_write_timeout(Some(idle))?;
                match handle_connection(&mut stream, &mut session) {
                    ConnectionOutcome::Shutdown => {
                        let _ = std::fs::remove_file(sock);
                        return Ok(());
                    }
                    ConnectionOutcome::Done => {
                        last_activity = std::time::Instant::now();
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Nothing waiting: idle out once the quiet time exceeds the
                // policy. A short sleep keeps the loop cheap.
                if last_activity.elapsed() >= idle {
                    let _ = std::fs::remove_file(sock);
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                let _ = std::fs::remove_file(sock);
                return Err(ServerError::Io(e));
            }
        }
    }
}

enum ConnectionOutcome {
    Done,
    Shutdown,
}

fn handle_connection(
    stream: &mut std::os::unix::net::UnixStream,
    session: &mut ResidentSession,
) -> ConnectionOutcome {
    loop {
        let (tag, body) = match read_frame(stream) {
            Ok(Some(frame)) => frame,
            Ok(None) => return ConnectionOutcome::Done,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::UnexpectedEof
                        | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                // Idle timeout or dead peer: drop the connection, keep the
                // session (the daemon itself idles out on the accept loop).
                return ConnectionOutcome::Done;
            }
            Err(_) => return ConnectionOutcome::Done,
        };
        match tag {
            TAG_HELLO => {
                let mut ok = false;
                if body.len() == 4 {
                    let peer = u32::from_le_bytes(body[..4].try_into().unwrap());
                    if peer == PROTO_VERSION {
                        ok = true;
                    }
                }
                let reply = if ok {
                    let mut b = Vec::new();
                    put_u32(&mut b, PROTO_VERSION);
                    put_str(&mut b, env!("CARGO_PKG_VERSION"));
                    (TAG_HELLO_ACK, b)
                } else {
                    (
                        TAG_ERROR,
                        error_body(&format!(
                            "protocol version mismatch (daemon {})",
                            PROTO_VERSION
                        )),
                    )
                };
                if write_frame(stream, reply.0, &reply.1).is_err() {
                    return ConnectionOutcome::Done;
                }
            }
            TAG_LINK => {
                if serve_link(stream, session, &body).is_err() {
                    return ConnectionOutcome::Done;
                }
            }
            TAG_SHUTDOWN => {
                let _ = write_frame(stream, TAG_BYE, &[]);
                return ConnectionOutcome::Shutdown;
            }
            _ => {
                let _ = write_frame(stream, TAG_ERROR, &error_body("unknown message tag"));
                return ConnectionOutcome::Done;
            }
        }
    }
}

/// The LINK exchange: decode → `NEED` → collect `BLOB`s → link → `IMAGE`
/// or `ERROR`. Any protocol failure just drops the connection.
fn serve_link(
    stream: &mut std::os::unix::net::UnixStream,
    session: &mut ResidentSession,
    body: &[u8],
) -> std::io::Result<()> {
    let req = match LinkRequest::decode(body) {
        Ok(req) => req,
        Err(e) => return write_frame(stream, TAG_ERROR, &error_body(&e.to_string())),
    };
    // Blob negotiation: only the hashes the session lacks travel.
    let needed: Vec<[u8; 32]> = req
        .blob_hashes()
        .into_iter()
        .filter(|h| !session.has_blob(h))
        .collect();
    if !needed.is_empty() {
        let mut b = Vec::with_capacity(4 + needed.len() * 32);
        put_u32(&mut b, needed.len() as u32);
        for h in &needed {
            b.extend_from_slice(h);
        }
        write_frame(stream, TAG_NEED, &b)?;
        let mut remaining = needed.len();
        while remaining > 0 {
            let (tag, body) = match read_frame(stream)? {
                Some(frame) => frame,
                None => return Ok(()),
            };
            if tag != TAG_BLOB {
                let _ = write_frame(stream, TAG_ERROR, &error_body("expected BLOB"));
                return Ok(());
            }
            if body.len() < 40 {
                let _ = write_frame(stream, TAG_ERROR, &error_body("BLOB frame too short"));
                return Ok(());
            }
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&body[..32]);
            let bytes = body[40..].to_vec();
            if let Err(e) = session.store_blob(&hash, bytes) {
                let _ = write_frame(stream, TAG_ERROR, &error_body(&e.to_string()));
                return Ok(());
            }
            remaining -= 1;
        }
    }
    match session.link(&req) {
        Ok((image, entryoff, fixup_slots)) => {
            let mut b = Vec::with_capacity(40 + image.len());
            put_u64(&mut b, entryoff);
            put_u64(&mut b, fixup_slots);
            put_u32(&mut b, session.hits as u32);
            put_u32(&mut b, session.misses as u32);
            put_u64(&mut b, image.len() as u64);
            b.extend_from_slice(&image);
            write_frame(stream, TAG_IMAGE, &b)
        }
        Err(e @ (SessionError::Link(_) | SessionError::Emit(_))) => {
            // A real link failure: deterministic, so the client's one-shot
            // fallback reproduces the same error. Report it, keep serving.
            write_frame(stream, TAG_ERROR, &error_body(&e.to_string()))
        }
        Err(e) => write_frame(stream, TAG_ERROR, &error_body(&e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::{read_frame, write_frame};
    use std::io::Cursor;

    #[test]
    fn frames_round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, 7, b"hello").unwrap();
        let mut cur = Cursor::new(buf);
        let (tag, body) = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!(tag, 7);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn empty_eof_is_clean() {
        let mut cur = Cursor::new(Vec::new());
        assert!(read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn hostile_length_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        let mut cur = Cursor::new(buf);
        assert!(read_frame(&mut cur).is_err());
    }

    #[test]
    fn short_length_is_rejected() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u32.to_le_bytes());
        let mut cur = Cursor::new(buf);
        assert!(read_frame(&mut cur).is_err());
    }
}
