//! The resident-link client (M8): what `pgr -resident` speaks to `pgrd`.
//!
//! Fail-soft by contract (§7.2 "optional and transparent"): every failure —
//! no daemon, stale socket, protocol mismatch, mid-link daemon death — is a
//! [`ClientError`], and the driver answers it by falling back to the
//! one-shot link. Nothing here can corrupt an output: the client writes the
//! image bytes through the normal Pass 5 path after the daemon returns —
//! and since the §7.2 output-residency rung (wire v5), a patched relink's
//! reply may be a hash-gated changed-tile stream the client replays against
//! its own local bytes *before* that write: a replay that misses the gate
//! is refused, never shipped.
//!
//! [`connect_or_start`] implements "started on demand by
//! `pgr`": connect to the socket; when nothing answers, spawn `pgrd` (the
//! `pgrd` binary next to the running `pgr`) and retry briefly.

use crate::protocol::{
    DecodeError, LinkRequest, PROTO_VERSION, TAG_BLOB, TAG_ERROR, TAG_HELLO, TAG_HELLO_ACK,
    TAG_IMAGE, TAG_LINK, TAG_NEED, TAG_SHUTDOWN, content_hash, put_u32, put_u64,
};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// How the reply's image crossed the wire (v5, the §7.2 rung).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The full image crossed (a full link, or tiles not asked — the v4
    /// shape).
    Full,
    /// Only the changed tiles crossed: `tiles` frames carrying `bytes`
    /// bytes in total. An untouched relink ships `tiles = 0, bytes = 0`
    /// (the client's file already is the output; nothing is rewritten).
    Tiles {
        /// Tile frames in the stream.
        tiles: u32,
        /// Payload bytes the stream carried (the wire's honest price).
        bytes: u64,
    },
}

/// One link's outcome from the daemon.
#[derive(Debug, Clone)]
pub struct ResidentImage {
    /// The complete output image bytes (the §7.3 ladder's patched image
    /// when a record rode the request, else the full link's). Populated
    /// only for [`Transport::Full`] replies — a tiles reply carries the
    /// stream in [`ResidentImage::tiles`] and the client replays it
    /// against its own previous output.
    pub image: Vec<u8>,
    /// Entry offset within `__TEXT` (executables).
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: u64,
    /// POI hits across the session so far (diagnostics/benches).
    pub poi_hits: u64,
    /// POI misses across the session so far.
    pub poi_misses: u64,
    /// The refreshed link record (v3, M9 fusion): present when the request
    /// asked for capture or carried a record the daemon renewed. The driver
    /// stores it so the incremental cycle survives resident links.
    pub record: Option<Vec<u8>>,
    /// The in-place patch report (v3): `Some` when the daemon's §7.3
    /// ladder patched, `None` on a full link (untouched relinks carry the
    /// zeroed untouched outcome).
    pub patch: Option<pgr_emit::incremental::PatchOutcome>,
    /// The served audit verdict (v4, M9 GA rung 2): `Some` when the
    /// request asked for the audit and the ladder patched — the daemon's
    /// byte-identity verdict plus its strict-verifier issues. The client
    /// refuses to ship a failing verdict (it writes nothing).
    pub audit: Option<pgr_emit::incremental::audit::AuditOutcome>,
    /// The changed-tile stream (v5, the §7.2 rung): `Some` when the reply
    /// shipped tiles instead of the image. The replay target is the
    /// client's own previous output — the bytes the request's
    /// `prev_output` hash vouches for — and
    /// [`TilePatch::image_hash`](pgr_emit::incremental::TilePatch::image_hash)
    /// gates the result before anything is written.
    pub tiles: Option<pgr_emit::incremental::TilePatch>,
    /// How the image tail crossed (v5): [`Transport::Full`] or the tile
    /// summary (what the benches and the driver's outcome line record).
    pub transport: Transport,
}

/// A client-side failure: the caller falls back to one-shot.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The socket is absent, dead, or refused the connection.
    #[error("resident daemon unavailable at {path}: {source}")]
    Connect {
        /// The socket path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
    /// The daemon answered with an error (link failure, protocol problem).
    #[error("resident daemon error: {0}")]
    Daemon(String),
    /// The connection broke or the peer spoke nonsense.
    #[error("resident protocol: {0}")]
    Protocol(#[from] DecodeError),
    /// Local I/O on the socket.
    #[error("resident protocol I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// A request plus its byte payloads: what [`DaemonClient::link`] needs.
/// The `blobs` ride along and only the missing ones cross the wire.
#[derive(Debug, Clone)]
pub struct LinkJob {
    /// The link description (config, manifests).
    pub request: LinkRequest,
    /// Content-hash → bytes for every input and archive in the request.
    pub blobs: Vec<([u8; 32], Vec<u8>)>,
}

impl LinkJob {
    /// Builds a job from the driver-side prepared link state. The manifest
    /// hashes run on the shared compute pool (one SHA-256 per input; the
    /// largest single client-side cost of a warm relink).
    #[must_use]
    pub fn build(
        config: &pgr_core::layout::LinkConfig,
        force_load: &[Vec<u8>],
        inputs: &[pgr_core::LinkInput],
        archives: &[pgr_core::LinkArchive],
    ) -> Self {
        use rayon::prelude::*;
        let owned: Vec<&[u8]> = inputs
            .iter()
            .map(|i| i.bytes.as_slice())
            .chain(archives.iter().map(|a| a.bytes.as_slice()))
            .collect();
        let hashes: Vec<[u8; 32]> = pgr_core::pool::compute_pool().install(|| {
            owned
                .par_iter()
                .map(|b| content_hash(b))
                .collect::<Vec<_>>()
        });
        let mut blobs: Vec<([u8; 32], Vec<u8>)> = inputs
            .iter()
            .enumerate()
            .map(|(i, o)| (hashes[i], o.bytes.clone()))
            .collect();
        blobs.extend(
            archives
                .iter()
                .enumerate()
                .map(|(k, a)| (hashes[inputs.len() + k], a.bytes.clone())),
        );
        let request = LinkRequest {
            config: config.clone(),
            force_load: force_load.to_vec(),
            inputs: inputs
                .iter()
                .enumerate()
                .map(|(i, o)| crate::protocol::InputEntry {
                    name: o.name.clone(),
                    hash: hashes[i],
                })
                .collect(),
            archives: archives
                .iter()
                .enumerate()
                .map(|(k, a)| crate::protocol::ArchiveEntry {
                    name: a.name.clone(),
                    all_load: a.all_load,
                    hash: hashes[inputs.len() + k],
                })
                .collect(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        Self { request, blobs }
    }

    /// Builds a job whose link **captures** a fresh record (v3, M9
    /// fusion): the fallback full link of an `-incremental` cycle — no
    /// record rides in (the relink just refused), but the reply must
    /// carry the fresh state so the cycle survives the daemon path.
    #[must_use]
    pub fn build_capturing(
        config: &pgr_core::layout::LinkConfig,
        force_load: &[Vec<u8>],
        inputs: &[pgr_core::LinkInput],
        archives: &[pgr_core::LinkArchive],
    ) -> Self {
        let mut job = Self::build(config, force_load, inputs, archives);
        job.request.record_resolution = true;
        job
    }

    /// Builds a job for the daemon-side §7.3 relink (v3, M9 fusion): the
    /// previous record rides in, the previous output's bytes join the
    /// blob negotiation, and the reply carries the refreshed record plus
    /// the patch outcome. The daemon runs the ladder (integrity gate,
    /// anchored config, warm pipeline, plan, in-memory patch) and falls
    /// back internally to its clean full link on any refusal.
    #[must_use]
    pub fn build_incremental(
        config: &pgr_core::layout::LinkConfig,
        force_load: &[Vec<u8>],
        inputs: &[pgr_core::LinkInput],
        archives: &[pgr_core::LinkArchive],
        record: Vec<u8>,
        prev_output: &[u8],
    ) -> Self {
        let mut job = Self::build(config, force_load, inputs, archives);
        let prev_hash = content_hash(prev_output);
        job.request.record = Some(record);
        job.request.record_resolution = true;
        job.request.prev_output = Some(prev_hash);
        // v5 (the §7.2 rung): the client holds the previous output bytes
        // it just hashed — it can replay a changed-tile stream.
        job.request.tiles = true;
        job.blobs.push((prev_hash, prev_output.to_vec()));
        job
    }
}

/// One open daemon connection.
pub struct DaemonClient {
    stream: UnixStream,
}

impl DaemonClient {
    /// Connects to the daemon socket.
    ///
    /// # Errors
    /// [`ClientError::Connect`] when the socket is absent or refuses.
    pub fn connect(path: &Path) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path).map_err(|source| ClientError::Connect {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self { stream })
    }

    /// Handshakes and returns the daemon's version banner.
    ///
    /// # Errors
    /// [`ClientError`] on protocol problems.
    pub fn hello(&mut self) -> Result<String, ClientError> {
        let mut body = Vec::new();
        put_u32(&mut body, PROTO_VERSION);
        write_frame(&mut self.stream, TAG_HELLO, &body)?;
        let (tag, body) = read_frame(&mut self.stream)?;
        match tag {
            TAG_HELLO_ACK => {
                let mut r = crate::protocol::Reader::new(&body);
                let proto = r.u32()?;
                if proto != PROTO_VERSION {
                    return Err(ClientError::Daemon(format!(
                        "protocol version mismatch (daemon {proto})"
                    )));
                }
                Ok(r.str()?)
            }
            TAG_ERROR => Err(ClientError::Daemon(
                String::from_utf8_lossy(&body).into_owned(),
            )),
            _ => Err(ClientError::Daemon("unexpected handshake reply".into())),
        }
    }

    /// Runs one link. Blob negotiation skips the hashes the daemon holds.
    ///
    /// # Errors
    /// [`ClientError`] on any failure (fall back to one-shot).
    pub fn link(&mut self, job: &LinkJob) -> Result<ResidentImage, ClientError> {
        write_frame(&mut self.stream, TAG_LINK, &job.request.encode())?;
        loop {
            let (tag, body) = read_frame(&mut self.stream)?;
            match tag {
                TAG_NEED => {
                    let mut r = crate::protocol::Reader::new(&body);
                    let n = r.u32()?;
                    let mut wanted: Vec<[u8; 32]> = Vec::with_capacity(n as usize);
                    for _ in 0..n {
                        wanted.push(r.hash()?);
                    }
                    r.done()?;
                    for hash in wanted {
                        let Some((_, bytes)) = job.blobs.iter().find(|(h, _)| h == &hash) else {
                            return Err(ClientError::Daemon(
                                "daemon asked for bytes the client does not hold".into(),
                            ));
                        };
                        let mut b = Vec::with_capacity(40 + bytes.len());
                        b.extend_from_slice(&hash);
                        put_u64(&mut b, bytes.len() as u64);
                        b.extend_from_slice(bytes);
                        write_frame(&mut self.stream, TAG_BLOB, &b)?;
                    }
                }
                TAG_IMAGE => {
                    // v5 body: the M8 fields, the M9 fusion tail — patch
                    // outcome (absent on a full link) and the refreshed
                    // record (absent when no capture was asked) — the
                    // audit verdict (absent unless asked and patched) —
                    // then the §7.2 rung's image tail: a tile stream when
                    // the session shaped one, else the full image bytes.
                    let mut r = crate::protocol::Reader::new(&body);
                    let entryoff = r.u64()?;
                    let fixup_slots = r.u64()?;
                    let poi_hits = u64::from(r.u32()?);
                    let poi_misses = u64::from(r.u32()?);
                    let patch = if r.u8()? == 0 {
                        None
                    } else {
                        let bytes_patched = r.u64()?;
                        let dirty_tiles = r.u32()?;
                        let total_tiles = r.u32()?;
                        let untouched = r.u8()? != 0;
                        Some(pgr_emit::incremental::PatchOutcome {
                            bytes_patched,
                            dirty_tiles,
                            total_tiles,
                            untouched,
                        })
                    };
                    let record = match r.u8()? {
                        0 => None,
                        _ => Some(r.bytes().map(<[u8]>::to_vec)?),
                    };
                    let audit = if r.u8()? == 0 {
                        None
                    } else {
                        let identity_ok = r.u8()? != 0;
                        let healed = r.u8()? != 0;
                        let n = r.u32()?;
                        let mut verify_blocking = Vec::with_capacity(n as usize);
                        for _ in 0..n {
                            verify_blocking.push(r.str()?);
                        }
                        Some(pgr_emit::incremental::audit::AuditOutcome {
                            identity_ok,
                            healed,
                            verify_blocking,
                        })
                    };
                    let (tiles, transport, image) = if r.u8()? == 0 {
                        // Full image (the v4 tail, unchanged).
                        let len = r.u64()? as usize;
                        let image = r.take(len)?.to_vec();
                        (None, Transport::Full, image)
                    } else {
                        // The changed-tile stream + the replay gate.
                        let final_size = r.u64()?;
                        let n = r.u32()?;
                        let mut stream_tiles = Vec::with_capacity(n as usize);
                        for _ in 0..n {
                            let at = r.u64()?;
                            let bytes = r.bytes().map(<[u8]>::to_vec)?;
                            stream_tiles.push((at, bytes));
                        }
                        let image_hash = r.hash()?;
                        let stream = pgr_emit::incremental::TilePatch {
                            final_size,
                            tiles: stream_tiles,
                            image_hash,
                        };
                        let bytes = stream.wire_bytes();
                        let count = stream.tiles.len() as u32;
                        (
                            Some(stream),
                            Transport::Tiles {
                                tiles: count,
                                bytes,
                            },
                            Vec::new(),
                        )
                    };
                    r.done()?;
                    return Ok(ResidentImage {
                        image,
                        entryoff,
                        fixup_slots,
                        poi_hits,
                        poi_misses,
                        record,
                        patch,
                        audit,
                        tiles,
                        transport,
                    });
                }
                TAG_ERROR => {
                    return Err(ClientError::Daemon(
                        String::from_utf8_lossy(&body).into_owned(),
                    ));
                }
                _ => return Err(ClientError::Daemon(format!("unexpected message tag {tag}"))),
            }
        }
    }

    /// Asks the daemon to exit (its session dies with it — clients always
    /// fall back, so this is a convenience, never a correctness event).
    ///
    /// # Errors
    /// [`ClientError`] when the daemon is unreachable (already fine).
    pub fn shutdown(mut self) -> Result<(), ClientError> {
        write_frame(&mut self.stream, TAG_SHUTDOWN, &[])?;
        let _ = read_frame(&mut self.stream);
        Ok(())
    }
}

/// Connects, or — when nothing listens — spawns `pgrd` (the binary next to
/// `exe_hint`) and retries for up to ~2 s. Returns `None`-worthy errors
/// verbatim: the caller falls back to one-shot on any [`ClientError`].
///
/// # Errors
/// [`ClientError::Connect`] when the daemon cannot be reached even after a
/// start attempt.
pub fn connect_or_start(
    socket: &Path,
    exe_hint: Option<&Path>,
) -> Result<DaemonClient, ClientError> {
    if let Ok(client) = DaemonClient::connect(socket) {
        return Ok(client);
    }
    let Some(hint) = exe_hint else {
        return Err(ClientError::Connect {
            path: socket.display().to_string(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no daemon is listening and no pgrd start hint was given",
            ),
        });
    };
    let pgrd = hint.with_file_name("pgrd");
    if !pgrd.is_file() {
        return Err(ClientError::Connect {
            path: format!("{} (no pgrd binary beside the driver)", socket.display()),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "pgrd not found"),
        });
    }
    let _ = std::process::Command::new(&pgrd)
        .arg("--socket")
        .arg(socket)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if Instant::now() >= deadline {
            return Err(ClientError::Connect {
                path: socket.display().to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "pgrd did not accept within 2s",
                ),
            });
        }
        if let Ok(c) = DaemonClient::connect(socket) {
            return Ok(c);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// The one-call shape the driver uses: connect (starting the daemon on
/// demand), handshake, link. Any error propagates — the driver falls back.
///
/// # Errors
/// [`ClientError`] as above.
pub fn link_via_daemon(
    socket: &Path,
    exe_hint: Option<&Path>,
    job: &LinkJob,
) -> Result<ResidentImage, ClientError> {
    let mut client = connect_or_start(socket, exe_hint)?;
    client.hello()?;
    client.link(job)
}

/// The default socket path: `$PGR_DAEMON_SOCK`, else
/// `{tmpdir}/pgr-{uid}.sock` (unix).
#[must_use]
pub fn default_socket() -> PathBuf {
    if let Ok(p) = std::env::var("PGR_DAEMON_SOCK") {
        return PathBuf::from(p);
    }
    let uid = client_uid();
    std::env::temp_dir().join(format!("pgr-{uid}.sock"))
}

// A dependency-free per-user scratch name: the uid when the environment
// carries it (sudo sets SUDO_UID), else the process id — the socket path is
// overridable via PGR_DAEMON_SOCK for shared setups.
fn client_uid() -> u64 {
    if let Ok(uid) = std::env::var("SUDO_UID") {
        if let Ok(v) = uid.trim().parse::<u64>() {
            return v;
        }
    }
    u64::from(std::process::id())
}

/// Asks the daemon at `socket` to exit (the `pgrd --shutdown` path).
///
/// # Errors
/// [`ClientError`] when the daemon is unreachable.
pub fn shutdown_daemon(socket: &Path) -> Result<(), ClientError> {
    DaemonClient::connect(socket)?.shutdown()
}

fn write_frame(w: &mut UnixStream, tag: u32, body: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(8 + body.len());
    put_u32(&mut frame, (4 + body.len()) as u32);
    put_u32(&mut frame, tag);
    frame.extend_from_slice(body);
    w.write_all(&frame)
}

fn read_frame(r: &mut UnixStream) -> Result<(u32, Vec<u8>), ClientError> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if !(4..=(256 << 20)).contains(&len) {
        return Err(ClientError::Daemon("frame length out of bounds".into()));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload)?;
    let tag = u32::from_le_bytes(payload[..4].try_into().unwrap());
    Ok((tag, payload[4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::LinkJob;
    use crate::protocol::content_hash;
    use pgr_core::layout::LinkConfig;

    #[test]
    fn job_build_hashes_all_payloads() {
        let inputs = vec![pgr_core::LinkInput {
            name: "a.o".into(),
            bytes: b"aaaa".to_vec(),
        }];
        let job = LinkJob::build(&LinkConfig::default(), &[], &inputs, &[]);
        assert_eq!(job.request.inputs.len(), 1);
        assert_eq!(job.request.inputs[0].hash, content_hash(b"aaaa"));
        assert_eq!(job.blobs.len(), 1);
        assert!(job.request.archives.is_empty(), "no archives expected");
    }
}
