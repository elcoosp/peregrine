//! The `pgrd` wire protocol (M8): length-prefixed, little-endian,
//! hand-packed — the same no-serde discipline as the cache frames.
//!
//! Frame: `u32 LE payload length | payload`, payload = `u32 LE tag | body`.
//!
//! | tag | dir | body |
//! |---|---|---|
//! | `HELLO` 1 | C→S | `u32 proto` |
//! | `HELLO_ACK` 2 | S→C | `u32 proto, str version` |
//! | `LINK` 3 | C→S | [`LinkRequest`] |
//! | `NEED` 4 | S→C | `u32 n, n × 32-byte content hashes` |
//! | `BLOB` 5 | C→S | `32-byte hash, u64 len, bytes` |
//! | `IMAGE` 6 | S→C | `u64 entryoff, u64 fixup_slots, u32 hits, u32 misses, [patch outcome], [record bytes], [audit outcome]`, then — v5 — the `tiles` flag picks the changed-tile stream (`u64 final_size, u32 tile count, per tile: u64 offset + bytes`, then the 32-byte image hash) or `u64 len, image bytes` |
//! | `ERROR` 7 | S→C | `str message` |
//! | `SHUTDOWN` 8 | C→S | — |
//! | `BYE` 9 | S→C | — |
//!
//! The [`LinkRequest`] body carries the full link description: the
//! [`pgr_core::layout::LinkConfig`] (including the parsed dylib list), the
//! `-u` force-load names, the direct input manifests `(name, sha256)` and
//! the archive manifests `(name, all_load, sha256)`. Bytes travel separately
//! (`BLOB`, only for hashes the daemon does not already hold) so a warm
//! relink transfers manifests only.
//!
//! M9 GA (fusion rung, wire v3): the request also carries the incremental
//! halves — the previous link's encoded record (`record`), whether the
//! daemon must capture a fresh record (`record_resolution`) and the
//! previous output's content hash (`prev_output`, its bytes ride the `BLOB`
//! exchange like every input). A record-bearing request runs the §7.3
//! ladder inside the daemon; the reply carries the refreshed record and
//! the patch outcome back. The wire never carries the *config* halves
//! (`stable_imports`/`sig_anchor`/`resolve_reuse`): the record is their
//! single carrier, decoded against the session's own pipeline.
//!
//! M9 GA rung 2 (wire v4): the request's `audit` flag asks the daemon to
//! serve the `-incremental-verify` audit for a patched relink —
//! byte-identity against the reference emit plus the strict verifier —
//! and the reply carries the [`pgr_emit::incremental::audit::AuditOutcome`]
//! verdict. The audit's subject is the patch: a full link or an untouched
//! relink serves no audit (the client stands down or the verdict is
//! trivially the full link's).
//!
//! M9 output-residency rung (wire v5): the request's `tiles` flag says the
//! client holds the previous output bytes locally and can replay a
//! changed-tile stream; the reply's image tail then ships the §7.2 rung's
//! [`pgr_emit::incremental::TilePatch`] (the changed 16 KiB tiles plus the
//! patched image's content hash) instead of the whole image — the session
//! keeps every served image as resident output state, so a warm cycle
//! moves only the changed tiles across the wire.
//!
//! M10 rung 4 slice 2 (wire v6): the config body carries the chain word
//! family (one byte — `FixupPointerFormat`). The driver refuses
//! `-resident` + `arm64e` this slice (the session's reuse gates ride the
//! Offset64 shapes), so every wire request still names `offset64` — the
//! byte exists so the wire can never silently drop the family a client
//! asked for, and a fusion rung can widen the surface without the
//! config's shape moving again.
//!
//! M14 (wire v7): the config body's export-filter lists carry
//! [`SymbolPattern`]s, not bare names — one kind byte per entry (`0`
//! exact, `1` glob) ahead of the pattern's own bytes, so the wire can
//! never silently flatten a glob into an exact name (the resident
//! relink's export surface would move). A malformed pattern refuses at
//! decode time, like every other shape the wire carries.
//!
//! M15 (wire v8): the config body's tail carries the image base — the
//! `__PAGEZERO` vmsize a `-pagezero_size` link plans with — as a
//! validated u64. A resident relink lays out the base the client named,
//! never the default; a body naming a zero or misaligned base is
//! malformed (the same validation the flag parse pays, so the wire can
//! never silently move the image base a client asked for).
//!
//! M16 (wire v9): the tail also carries the initializer form — one byte
//! naming the classic pointer sections (0) or the `__init_offsets`
//! transform (1). A resident relink plans the form the client asked
//! for; an unknown byte is malformed (a refusal, never a silently
//! dropped knob).

use pgr_core::export_filter::SymbolPattern;
use pgr_core::fixups::FixupPointerFormat;
use pgr_core::icf::IcfMode;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::resolve::{Dylib, UndefinedPolicy};
use sha2::{Digest, Sha256};

/// Wire-protocol revision. A mismatch is a hard [`DecodeError::Proto`]
/// (the client falls back to one-shot rather than guessing). v3 carried
/// the M9 fusion halves (record in, refreshed record + patch outcome out);
/// v4 added the audited relink — the request's `audit` flag and the
/// reply's audit verdict ([`pgr_emit::incremental::audit::AuditOutcome`]);
/// v5 added the §7.2 output-residency rung — the request's `tiles` flag
/// and the reply's tile-stream image tail
/// ([`pgr_emit::incremental::TilePatch`]); **v6** appended the chain word
/// family to the config body (M10 rung 4 slice 2 — the family a client
/// asked for crosses the wire verbatim, never silently dropped); **v7**
/// re-encodes the export-filter lists as patterns (M14 — kind byte +
/// source bytes; globs stay globs across the wire); **v8** appends the
/// image base to the config body's tail (M15 — the validated
/// `-pagezero_size` vmsize; a resident relink lays out the base the
/// client named); **v9** appends the initializer form to that tail (M16
/// — one byte naming the classic pointer sections or the
/// `__init_offsets` transform; a resident relink plans the form the
/// client asked for); **v10** appends the segment-protection decisions
/// to that tail (M17 — one length-prefixed entry per named segment
/// (`name | maxprot | initprot`); a resident relink protects the
/// segments the client named, never the house table); **v11** appends
/// the stack reserve to that tail (M18 — a present-byte + u64 naming
/// the executable's `LC_MAIN.stacksize`; a resident relink reserves
/// what the client named, never the zero default); **v12** appends the
/// dylib/bundle image base to that tail (M19 — a present-byte + u64
/// naming the `-image_base` vmaddr; a resident relink lays out the base
/// the client named, never the M3 zero default); **v13** appends the
/// umbrella region to that tail (M20 — one length-prefixed entry per
/// member (`kind byte | name`); a resident relink emits the region the
/// client named, never the pre-M20 absence); **v14** appends the
/// sub-client list to that tail (M21 — one length-prefixed entry per
/// name; a resident relink emits the clients the linking image named,
/// never the pre-M21 absence); **v15** appends the dyld-environment
/// list to that tail (M22 — one length-prefixed entry per
/// `DYLD_<var>=<value>` pair; a resident relink exports the variables
/// the client named, never the pre-M22 absence); **v16** appends the
/// symbol-alias pairs and the bundle-loader surface to that tail (M24
/// and M25 — a resident relink exports the names and binds against the
/// host the client named); **v17** appends the loader path (M26 — a
/// present byte, then the `-dylinker` path; a resident relink execs
/// the loader the client named, never the pre-M26 `/usr/lib/dyld`
/// default); **v18** appends the PIE decision (M27 — one byte naming
/// whether the executable drops `MH_PIE`; a resident relink carries
/// the flag word the client asked for, never the pre-M27 PIE-always
/// default).
pub const PROTO_VERSION: u32 = 18;

// ---- message tags -----------------------------------------------------------

pub(crate) const TAG_HELLO: u32 = 1;
pub(crate) const TAG_HELLO_ACK: u32 = 2;
pub(crate) const TAG_LINK: u32 = 3;
pub(crate) const TAG_NEED: u32 = 4;
pub(crate) const TAG_BLOB: u32 = 5;
pub(crate) const TAG_IMAGE: u32 = 6;
pub(crate) const TAG_ERROR: u32 = 7;
pub(crate) const TAG_SHUTDOWN: u32 = 8;
pub(crate) const TAG_BYE: u32 = 9;

/// A protocol decode failure: the caller's only safe move is to fall back.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The frame is truncated, has an impossible length, or carries a
    /// malformed body.
    #[error("protocol: malformed frame: {0}")]
    Malformed(#[from] std::io::Error),
    /// The peer speaks a different protocol revision.
    #[error("protocol: version mismatch (peer {peer}, ours {ours})")]
    Proto {
        /// The peer's revision.
        peer: u32,
        /// Our revision.
        ours: u32,
    },
    /// An unknown message tag (a newer peer).
    #[error("protocol: unknown message tag {0}")]
    Tag(u32),
}

// ---- scalar writers (mirror cache.rs's hand-packing) ------------------------

pub(crate) fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

pub(crate) fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

pub(crate) fn put_str(out: &mut Vec<u8>, s: &str) {
    put_bytes(out, s.as_bytes());
}

pub(crate) fn put_opt_str(out: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(v) => {
            put_u8(out, 1);
            put_str(out, v);
        }
        None => put_u8(out, 0),
    }
}

pub(crate) fn put_hash(out: &mut Vec<u8>, h: &[u8; 32]) {
    out.extend_from_slice(h);
}

/// SHA-256 over the raw bytes (the transfer identity; the daemon derives
/// its own versioned POI cache keys from the bytes it holds).
#[must_use]
pub fn content_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Hex-encodes a content hash (error messages only — never a key path).
#[must_use]
pub fn hex(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
    }
    s
}

pub(crate) struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self { b, at: 0 }
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or_else(|| DecodeError::Malformed(std::io::ErrorKind::InvalidData.into()))?;
        let s = self
            .b
            .get(self.at..end)
            .ok_or_else(|| DecodeError::Malformed(std::io::ErrorKind::UnexpectedEof.into()))?;
        self.at = end;
        Ok(s)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .expect("`take(4)` guarantees the byte count"),
        ))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .expect("`take(8)` guarantees the byte count"),
        ))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u32()? as usize;
        self.take(n)
    }

    pub(crate) fn str(&mut self) -> Result<String, DecodeError> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    pub(crate) fn opt_str(&mut self) -> Result<Option<String>, DecodeError> {
        match self.u8()? {
            0 => Ok(None),
            _ => Ok(Some(self.str()?)),
        }
    }

    pub(crate) fn hash(&mut self) -> Result<[u8; 32], DecodeError> {
        Ok(self
            .take(32)?
            .try_into()
            .expect("`take(32)` guarantees the byte count"))
    }

    pub(crate) fn done(&mut self) -> Result<(), DecodeError> {
        if self.at == self.b.len() {
            Ok(())
        } else {
            Err(DecodeError::Malformed(
                std::io::ErrorKind::InvalidData.into(),
            ))
        }
    }
}

// ---- link request -----------------------------------------------------------

/// One direct input's manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputEntry {
    /// File name (diagnostics; the driver's mapped input name).
    pub name: String,
    /// SHA-256 of the object bytes.
    pub hash: [u8; 32],
}

/// One archive's manifest entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    /// Archive name (diagnostics; `libfoo.a`).
    pub name: String,
    /// `-all_load` / `-force_load`: pull every member.
    pub all_load: bool,
    /// SHA-256 of the archive bytes.
    pub hash: [u8; 32],
}

/// The full description of one link: everything Passes 1–5 need, with input
/// *bytes* out-of-band (the `BLOB` exchange skips what the daemon holds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// The link configuration (ident, output kind, versions, dylibs, ...).
    pub config: LinkConfig,
    /// `-u` force-load names (the daemon runs the same `-u` gate).
    pub force_load: Vec<Vec<u8>>,
    /// Direct inputs in command order.
    pub inputs: Vec<InputEntry>,
    /// Archives in command order.
    pub archives: Vec<ArchiveEntry>,
    /// The previous link's encoded record (v3, M9 fusion): when present,
    /// the daemon runs the §7.3 ladder — integrity gate on the previous
    /// output, anchored relink config (slack anchors, stable imports,
    /// signature boundary, resolve-reuse seed), warm pipeline, patch plan
    /// — and falls back to its clean-slacked full link on any refusal.
    pub record: Option<Vec<u8>>,
    /// Whether the daemon must capture a fresh record for the reply (v3):
    /// the driver sets it whenever `-incremental` is on, so the sidecar
    /// stays fresh across resident links. Independent of `record` — a
    /// fallback full link captures too (that is the rung that keeps the
    /// incremental cycle alive through daemon fallbacks).
    pub record_resolution: bool,
    /// The previous output's content hash (v3): the bytes the §7.3 ladder
    /// integrity-gates and patches. The hash joins the `BLOB` negotiation
    /// ([`LinkRequest::blob_hashes`]), so a warm session transfers it once
    /// per output state.
    pub prev_output: Option<[u8; 32]>,
    /// Whether the daemon must serve the `-incremental-verify` audit for
    /// a patched relink (v4, M9 GA rung 2): byte-identity against the
    /// reference emit plus the strict verifier, verdict on the wire. The
    /// audit's subject is the patch — a full link or an untouched relink
    /// serves no audit.
    pub audit: bool,
    /// Whether the client can replay a changed-tile stream (v5, the §7.2
    /// output-residency rung): it holds the previous output bytes locally
    /// and hashes its replay before writing, so a patched relink's reply
    /// ships the changed 16 KiB tiles instead of the whole image. A daemon
    /// serves tiles only to a flag-carrying request; a full link or a
    /// v4-shaped client receives the image as before.
    pub tiles: bool,
}

impl LinkRequest {
    /// The hashes the `BLOB` exchange must deliver before this link can run.
    #[must_use]
    pub fn blob_hashes(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = self.inputs.iter().map(|i| i.hash).collect();
        out.extend(self.archives.iter().map(|a| a.hash));
        if let Some(prev) = self.prev_output {
            out.push(prev);
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Encodes the request body (the `LINK` frame payload).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(256);
        put_u32(&mut b, PROTO_VERSION);
        encode_config(&mut b, &self.config);
        put_u32(&mut b, self.force_load.len() as u32);
        for f in &self.force_load {
            put_bytes(&mut b, f);
        }
        put_u32(&mut b, self.inputs.len() as u32);
        for i in &self.inputs {
            put_str(&mut b, &i.name);
            put_hash(&mut b, &i.hash);
        }
        put_u32(&mut b, self.archives.len() as u32);
        for a in &self.archives {
            put_str(&mut b, &a.name);
            put_u8(&mut b, u8::from(a.all_load));
            put_hash(&mut b, &a.hash);
        }
        // M9 fusion halves (v3): record in, capture flag, previous output.
        match &self.record {
            Some(r) => {
                put_u8(&mut b, 1);
                put_bytes(&mut b, r);
            }
            None => put_u8(&mut b, 0),
        }
        put_u8(&mut b, u8::from(self.record_resolution));
        match self.prev_output {
            Some(h) => {
                put_u8(&mut b, 1);
                put_hash(&mut b, &h);
            }
            None => put_u8(&mut b, 0),
        }
        // M9 GA rung 2 (v4): the audited relink flag.
        put_u8(&mut b, u8::from(self.audit));
        // M9 output-residency rung (v5): the tile-replay capability.
        put_u8(&mut b, u8::from(self.tiles));
        b
    }

    /// Decodes a request body.
    ///
    /// # Errors
    /// [`DecodeError`] on truncation, trailing bytes or a version mismatch.
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let version = r.u32()?;
        if version != PROTO_VERSION {
            return Err(DecodeError::Proto {
                peer: version,
                ours: PROTO_VERSION,
            });
        }
        let config = decode_config(&mut r)?;
        let force_load = (0..r.u32()?)
            .map(|_| r.bytes().map(<[u8]>::to_vec))
            .collect::<Result<Vec<_>, _>>()?;
        let inputs = (0..r.u32()?)
            .map(|_| {
                Ok(InputEntry {
                    name: r.str()?,
                    hash: r.hash()?,
                })
            })
            .collect::<Result<Vec<InputEntry>, DecodeError>>()?;
        let archives = (0..r.u32()?)
            .map(|_| {
                Ok(ArchiveEntry {
                    name: r.str()?,
                    all_load: r.u8()? != 0,
                    hash: r.hash()?,
                })
            })
            .collect::<Result<Vec<ArchiveEntry>, DecodeError>>()?;
        // M9 fusion halves (v3; see encode).
        let record = match r.u8()? {
            0 => None,
            _ => Some(r.bytes().map(<[u8]>::to_vec)?),
        };
        let record_resolution = r.u8()? != 0;
        let prev_output = match r.u8()? {
            0 => None,
            _ => Some(r.hash()?),
        };
        let audit = r.u8()? != 0;
        let tiles = r.u8()? != 0;
        r.done()?;
        Ok(Self {
            config,
            force_load,
            inputs,
            archives,
            record,
            record_resolution,
            prev_output,
            audit,
            tiles,
        })
    }
}

/// Encodes one export-filter pattern (M14, wire v7): a kind byte (the
/// `SymbolPattern` variant) ahead of the line as written, so the daemon
/// relinks with the surface the client named — globs stay globs.
fn put_pattern(out: &mut Vec<u8>, p: &SymbolPattern) {
    put_u8(
        out,
        match p {
            SymbolPattern::Exact(_) => 0,
            SymbolPattern::Glob(_) => 1,
        },
    );
    put_bytes(out, p.source());
}

/// Decodes one export-filter pattern: the kind byte is advisory (the
/// source decides the variant at parse), a malformed pattern refuses —
/// the wire never carries a filter the pipeline would silently misread.
fn read_pattern(r: &mut Reader<'_>) -> Result<SymbolPattern, DecodeError> {
    let _kind = r.u8()?;
    let source = r.bytes()?;
    SymbolPattern::parse(source)
        .map_err(|_| DecodeError::Malformed(std::io::ErrorKind::InvalidData.into()))
}

fn encode_config(out: &mut Vec<u8>, cfg: &LinkConfig) {
    put_str(out, &cfg.ident);
    put_u8(
        out,
        match cfg.filetype {
            OutputType::Execute => 0,
            OutputType::Dylib => 1,
            OutputType::Bundle => 2,
            // Relocatable links never ride the daemon (the driver refuses
            // `-r -resident` at parse time); the wire value is reserved so
            // the encoding stays total.
            OutputType::Relocatable => 3,
        },
    );
    put_str(out, &cfg.entry_symbol);
    put_u32(out, cfg.platform);
    put_u32(out, cfg.minos);
    put_u32(out, cfg.sdk);
    put_u8(out, u8::from(cfg.dynamic_linker));
    put_u8(out, u8::from(cfg.fixup_chains));
    put_u8(out, u8::from(cfg.adhoc));
    put_u8(out, u8::from(cfg.flat_namespace));
    put_u8(
        out,
        match cfg.undefined_policy {
            UndefinedPolicy::Error => 0,
            UndefinedPolicy::DynamicLookup => 1,
        },
    );
    put_u32(out, cfg.rpaths.len() as u32);
    for r in &cfg.rpaths {
        put_str(out, r);
    }
    match cfg.source_version {
        Some(v) => {
            put_u8(out, 1);
            put_u64(out, v);
        }
        None => put_u8(out, 0),
    }
    put_opt_str(out, cfg.install_name.as_deref());
    put_u32(out, cfg.current_version);
    put_u32(out, cfg.compatibility_version);
    match &cfg.exported_only {
        Some(list) => {
            put_u8(out, 1);
            put_u32(out, list.len() as u32);
            for p in list {
                put_pattern(out, p);
            }
        }
        None => put_u8(out, 0),
    }
    put_u32(out, cfg.unexported.len() as u32);
    for p in &cfg.unexported {
        put_pattern(out, p);
    }
    put_u8(out, u8::from(cfg.dead_strippable));
    put_u8(out, u8::from(cfg.dead_strip));
    put_u32(out, cfg.load_symbols.len() as u32);
    for n in &cfg.load_symbols {
        put_bytes(out, n);
    }
    put_u8(
        out,
        match cfg.icf {
            IcfMode::None => 0,
            IcfMode::Safe => 1,
            IcfMode::All => 2,
        },
    );
    match cfg.layout_slack {
        Some(p) => {
            put_u8(out, 1);
            put_u32(out, p.text_percent);
            put_u32(out, p.data_percent);
            put_u64(out, p.min_bytes);
            put_u64(out, p.max_bytes);
        }
        None => put_u8(out, 0),
    }
    // M9 slack anchors (v2 wire): the incremental relink's cross-link
    // layout reservations ride with the config so the resident link and
    // the one-shot link shape identical layouts.
    put_u32(out, cfg.slack_anchor.len() as u32);
    for a in &cfg.slack_anchor {
        put_str(out, &a.seg);
        put_str(out, &a.name);
        put_u64(out, a.padded);
    }
    put_u32(out, cfg.dylibs.len() as u32);
    for d in &cfg.dylibs {
        put_str(out, &d.install_name);
        put_u32(out, d.current_version);
        put_u32(out, d.compatibility_version);
        put_u32(out, d.exports.len() as u32);
        for e in &d.exports {
            put_bytes(out, e);
        }
        put_u8(out, u8::from(d.weak));
        put_u8(out, u8::from(d.reexport));
        // M14 (v7): the lazy-load kind rides beside weak/re-export — the
        // wire never silently flattens an `LC_LAZY_LOAD_DYLIB` request
        // into a plain load.
        put_u8(out, u8::from(d.lazy));
    }
    // M10 rung 4 slice 2 (v6 wire): the chain word family rides the tail
    // of the config body (the append-in-place upgrade convention).
    put_u8(
        out,
        match cfg.chain_word_format {
            FixupPointerFormat::Offset64 => 0,
            FixupPointerFormat::Arm64e => 1,
        },
    );
    // M15 (v8 wire): the image base (the validated `__PAGEZERO` vmsize)
    // rides the tail — a resident relink lays out the base the client
    // named, never the default.
    put_u64(out, cfg.pagezero.vmsize());
    // M16 (v9 wire): the initializer form rides the tail after it — one
    // byte naming the classic pointer sections (0) or the
    // `__init_offsets` transform (1); a resident relink plans the form
    // the client asked for.
    put_u8(out, u8::from(cfg.init_offsets.is_offsets()));
    // M17 (v10 wire): the segment-protection decisions ride the tail —
    // a resident relink protects the segments the client named, never
    // the house table. Every entry re-pays the core validation on
    // decode (an unplanned name, an unknown bit, an init beyond its
    // ceiling or a W+X mapping is malformed, never silently defaulted).
    put_u32(out, cfg.seg_prots.len() as u32);
    for (name, prot) in cfg.seg_prots.iter() {
        put_str(out, name);
        put_u32(out, prot.maxprot());
        put_u32(out, prot.initprot());
    }
    // M18 (v11 wire): the stack reserve rides the tail after it — a
    // present-byte plus the validated byte count; a resident relink
    // reserves what the client named, never the zero default.
    match cfg.stack_size {
        Some(s) => {
            put_u8(out, 1);
            put_u64(out, s.bytes());
        }
        None => put_u8(out, 0),
    }
    // M19 (v12 wire): the dylib/bundle image base rides the tail after
    // it — a present-byte plus the validated vmaddr; a resident relink
    // lays out the base the client named, never the M3 zero default.
    match cfg.image_base {
        Some(b) => {
            put_u8(out, 1);
            put_u64(out, b.vmaddr());
        }
        None => put_u8(out, 0),
    }
    // M20 (v13 wire): the umbrella region — one entry per member in
    // flag order (kind byte + name bytes); a glob never flattens, a
    // name never reorders (the same faithful-list convention the v7
    // filter patterns ride).
    put_u32(out, cfg.umbrella.count() as u32);
    for m in &cfg.umbrella {
        put_u8(out, m.kind().wire());
        put_str(out, m.name());
    }
    // M21 (v14 wire): the sub-client list rides the tail after the
    // region — one length-prefixed entry per name in flag order (the
    // list is single-kind, so no discriminator byte); a resident relink
    // emits the clients the linking image named, never the pre-M21
    // absence.
    put_u32(out, cfg.sub_clients.count() as u32);
    for c in &cfg.sub_clients {
        put_str(out, c.name());
    }
    // M22 (v15 wire): the dyld-environment list rides the tail after
    // the client list — one length-prefixed entry per `DYLD_<var>=<value>`
    // pair in flag order (single-kind, so no discriminator byte, the
    // v14 convention); a resident relink exports the variables the
    // client named, never the pre-M22 absence.
    put_u32(out, cfg.dyld_envs.count() as u32);
    for e in &cfg.dyld_envs {
        put_str(out, e.pair());
    }
    // M24 (v16 wire): the symbol-alias list rides the tail after the
    // environment — one length-prefixed pair per `-alias` decision in
    // flag order (the new name, then the definition it points at); a
    // resident relink exports the names the client asked for, never
    // the pre-M24 absence.
    put_u32(out, cfg.aliases.count() as u32);
    for a in &cfg.aliases {
        put_str(out, a.alias());
        put_str(out, a.definition());
    }
    // M25 (v16 wire): the bundle loader rides the tail after the
    // aliases — a present byte, then the host's path and its export
    // surface (one length-prefixed name per export, scan order); a
    // resident relink binds against the host the client named, never
    // the pre-M25 absence.
    if let Some(loader) = &cfg.bundle_loader {
        put_u8(out, 1);
        put_str(out, loader.name());
        put_u32(out, loader.exports().len() as u32);
        for e in loader.exports() {
            put_str(out, &String::from_utf8_lossy(e));
        }
    } else {
        put_u8(out, 0);
    }
    // M26 (v17 wire): the loader path rides the tail after the bundle
    // loader — a present byte, then the `-dylinker` path string; a
    // resident relink execs the loader the client named, never the
    // pre-M26 `/usr/lib/dyld` default.
    if let Some(loader) = &cfg.dylinker {
        put_u8(out, 1);
        put_str(out, loader.path());
    } else {
        put_u8(out, 0);
    }
    // M27 (v18 wire): the PIE decision rides the tail after the
    // loader path — one byte; a resident relink carries the flag word
    // the client asked for, never the pre-M27 PIE-always default.
    put_u8(out, u8::from(cfg.no_pie));
}

/// Decodes a `LinkConfig` body (the mirror of [`encode_config`]; field
/// order is the wire contract).
fn decode_config(r: &mut Reader<'_>) -> Result<LinkConfig, DecodeError> {
    let malformed = || DecodeError::Malformed(std::io::ErrorKind::InvalidData.into());
    let ident = r.str()?;
    let filetype = match r.u8()? {
        0 => OutputType::Execute,
        1 => OutputType::Dylib,
        2 => OutputType::Bundle,
        _ => return Err(malformed()),
    };
    let entry_symbol = r.str()?;
    let platform = r.u32()?;
    let minos = r.u32()?;
    let sdk = r.u32()?;
    let dynamic_linker = r.u8()? != 0;
    let fixup_chains = r.u8()? != 0;
    let adhoc = r.u8()? != 0;
    let flat_namespace = r.u8()? != 0;
    let undefined_policy = match r.u8()? {
        0 => UndefinedPolicy::Error,
        1 => UndefinedPolicy::DynamicLookup,
        _ => return Err(malformed()),
    };
    let rpaths = (0..r.u32()?)
        .map(|_| r.str())
        .collect::<Result<Vec<_>, _>>()?;
    let source_version = match r.u8()? {
        0 => None,
        _ => Some(r.u64()?),
    };
    let install_name = r.opt_str()?;
    let current_version = r.u32()?;
    let compatibility_version = r.u32()?;
    let exported_only = if r.u8()? == 0 {
        None
    } else {
        let mut list = Vec::new();
        for _ in 0..r.u32()? {
            list.push(read_pattern(&mut *r)?);
        }
        Some(list)
    };
    let mut unexported = Vec::new();
    for _ in 0..r.u32()? {
        unexported.push(read_pattern(&mut *r)?);
    }
    let dead_strippable = r.u8()? != 0;
    let dead_strip = r.u8()? != 0;
    let load_symbols = (0..r.u32()?)
        .map(|_| r.bytes().map(<[u8]>::to_vec))
        .collect::<Result<Vec<Vec<u8>>, DecodeError>>()?;
    let icf = match r.u8()? {
        0 => IcfMode::None,
        1 => IcfMode::Safe,
        2 => IcfMode::All,
        _ => return Err(malformed()),
    };
    let layout_slack = match r.u8()? {
        0 => None,
        _ => Some(pgr_core::SlackPolicy {
            text_percent: r.u32()?,
            data_percent: r.u32()?,
            min_bytes: r.u64()?,
            max_bytes: r.u64()?,
        }),
    };
    // M9 slack anchors (v2 wire; see encode_config).
    let slack_anchor = (0..r.u32()?)
        .map(|_| -> Result<pgr_core::slack::SlackAnchor, DecodeError> {
            Ok(pgr_core::slack::SlackAnchor {
                seg: r.str()?,
                name: r.str()?,
                padded: r.u64()?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let dylibs = (0..r.u32()?)
        .map(|_| {
            Ok(Dylib {
                install_name: r.str()?,
                current_version: r.u32()?,
                compatibility_version: r.u32()?,
                exports: (0..r.u32()?)
                    .map(|_| r.bytes().map(<[u8]>::to_vec))
                    .collect::<Result<Vec<Vec<u8>>, DecodeError>>()?,
                weak: r.u8()? != 0,
                reexport: r.u8()? != 0,
                lazy: r.u8()? != 0,
            })
        })
        .collect::<Result<Vec<Dylib>, DecodeError>>()?;
    // M10 rung 4 slice 2 (v6 wire): the chain word family (the tail byte;
    // mirror of `encode_config`).
    let chain_word_format = match r.u8()? {
        0 => FixupPointerFormat::Offset64,
        1 => FixupPointerFormat::Arm64e,
        _ => return Err(malformed()),
    };
    // M15 (v8 wire): the image base — the same validation the flag
    // parse pays, so a misaligned or zero base is malformed, never a
    // silently defaulted decision.
    let pagezero =
        pgr_core::pagezero::PageZero::from_override(r.u64()?).map_err(|_| malformed())?;
    // M16 (v9 wire): the initializer form — an unknown byte is
    // malformed (a refusal, never a silently dropped knob).
    let init_offsets = match r.u8()? {
        0 => pgr_core::InitOffsets::Classic,
        1 => pgr_core::InitOffsets::Offsets,
        _ => return Err(malformed()),
    };
    // M17 (v10 wire): the segment-protection decisions — the same
    // validation the flag parse pays, so a foreign frame is malformed,
    // never a silently widened mapping.
    let mut seg_prots = pgr_core::segprot::SegProts::default();
    for _ in 0..r.u32()? {
        let seg = pgr_core::segprot::SegName::parse(&r.str()?).map_err(|_| malformed())?;
        let prot =
            pgr_core::segprot::SegProt::from_bits(r.u32()?, r.u32()?).map_err(|_| malformed())?;
        seg_prots.insert(seg, prot).map_err(|_| malformed())?;
    }
    // M18 (v11 wire): the stack reserve — the same validation the flag
    // parse pays, so a zero or misaligned reserve is malformed, never a
    // silently shrunk stack.
    let stack_size = match r.u8()? {
        0 => None,
        _ => Some(
            pgr_core::stack_size::StackSize::from_override(r.u64()?).map_err(|_| malformed())?,
        ),
    };
    // M19 (v12 wire): the dylib/bundle image base — the same validation
    // the flag parse pays, so a zero or misaligned base is malformed,
    // never a silently zeroed address space.
    let image_base = match r.u8()? {
        0 => None,
        _ => Some(
            pgr_core::image_base::ImageBase::from_override(r.u64()?).map_err(|_| malformed())?,
        ),
    };
    // M20 (v13 wire): the umbrella region — the same validation the
    // flag parse pays, so an unknown kind byte, an empty or NUL-bearing
    // name or a duplicate member is malformed, never a silently widened
    // region.
    let mut umbrella = pgr_core::umbrella::Umbrella::new();
    for _ in 0..r.u32()? {
        let kind = pgr_core::umbrella::UmbrellaKind::from_wire(r.u8()?).ok_or_else(malformed)?;
        let member = pgr_core::umbrella::UmbrellaMember::from_flag(kind, &r.str()?)
            .map_err(|_| malformed())?;
        umbrella.push(member).map_err(|_| malformed())?;
    }
    // M21 (v14 wire): the sub-client list — the same validation the
    // flag parse pays, so an empty or NUL-bearing name or a duplicate
    // client is malformed, never a silently widened list.
    let mut sub_clients = pgr_core::sub_client::SubClient::new();
    for _ in 0..r.u32()? {
        let client = pgr_core::SubClientEntry::from_flag(&r.str()?).map_err(|_| malformed())?;
        sub_clients.push(client).map_err(|_| malformed())?;
    }
    // M22 (v15 wire): the dyld-environment list — the same validation
    // the flag parse pays, so a pair off the DYLD_<var>=<value> grammar
    // or a duplicate variable is malformed, never a silently changed
    // runtime.
    let mut dyld_envs = pgr_core::dyld_env::DyldEnv::new();
    for _ in 0..r.u32()? {
        let env = pgr_core::DyldEnvEntry::from_flag(&r.str()?).map_err(|_| malformed())?;
        dyld_envs.push(env).map_err(|_| malformed())?;
    }
    // M24 (v16 wire): the symbol-alias list — the same validation the
    // flag parse pays, so a pair off the `-alias <alias_name>
    // <definition_name>` grammar or a duplicate name is malformed,
    // never a silently changed export surface.
    let mut aliases = pgr_core::alias::AliasTable::new();
    for _ in 0..r.u32()? {
        let alias = r.str()?;
        let definition = r.str()?;
        let a = pgr_core::Alias::from_parts(&alias, &definition).map_err(|_| malformed())?;
        aliases.push(a).map_err(|_| malformed())?;
    }
    // M25 (v16 wire): the bundle loader — the same validation the
    // driver's scan pays, so an empty name or a duplicate export is
    // malformed, never a silently changed host surface.
    let bundle_loader = if r.u8()? != 0 {
        let name = r.str()?;
        let mut exports: Vec<Vec<u8>> = Vec::new();
        for _ in 0..r.u32()? {
            exports.push(r.str()?.into_bytes());
        }
        Some(pgr_core::BundleLoader::new(&name, exports).map_err(|_| malformed())?)
    } else {
        None
    };
    // M26 (v17 wire): the loader path — the same validation the flag
    // parse pays, so an empty, NUL-bearing or relative path is
    // malformed, never a silently changed loader.
    let dylinker = if r.u8()? != 0 {
        Some(pgr_core::Dylinker::from_flag(&r.str()?).map_err(|_| malformed())?)
    } else {
        None
    };
    // M27 (v18 wire): the PIE decision — one byte, no validation
    // beyond the bool (the output-kind refusal is the link's, not the
    // wire's).
    let no_pie = r.u8()? != 0;
    Ok(LinkConfig {
        ident,
        filetype,
        entry_symbol,
        platform,
        minos,
        sdk,
        dynamic_linker,
        fixup_chains,
        adhoc,
        dylibs,
        flat_namespace,
        undefined_policy,
        rpaths,
        source_version,
        install_name,
        current_version,
        compatibility_version,
        exported_only,
        // M9 tier-2a + GA: the import/signature anchors and the resolve
        // reuse seed are the *record's* cross-link state (the sidecar
        // lives next to the output, §7.3) — the wire carries them never;
        // the v3 request's `record` field is their single carrier and the
        // session derives the anchored relink config from it. A daemon
        // link without a record links clean (every clean link); capture
        // rides the request's `record_resolution` flag, not the config.
        stable_imports: None,
        sig_anchor: None,
        record_resolution: false,
        resolve_reuse: None,
        unexported,
        dead_strippable,
        dead_strip,
        load_symbols,
        icf,
        layout_slack,
        slack_anchor,
        chain_word_format,
        // M11: the order-file rank table is a driver-side Pass-3 input
        // the v6 wire does not carry — the driver refuses
        // `-order_file` + `-resident` at parse time (the same honest
        // scope note `-fixup_chains_format` rides), so a decoded config
        // is always order-free.
        symbol_order: None,
        pagezero,
        init_offsets,
        seg_prots,
        stack_size,
        image_base,
        umbrella,
        sub_clients,
        dyld_envs,
        aliases,
        bundle_loader,
        dylinker,
        no_pie,
    })
}

// ---- frame-level round-trip gates -------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ArchiveEntry, DecodeError, InputEntry, LinkRequest, PROTO_VERSION, Reader, TAG_LINK,
        content_hash, put_u32,
    };
    use pgr_core::export_filter::SymbolPattern;
    use pgr_core::fixups::FixupPointerFormat;
    use pgr_core::layout::LinkConfig;
    use pgr_core::resolve::Dylib;

    /// A representative config: every field set, dylibs included.
    fn rich_config() -> LinkConfig {
        LinkConfig {
            ident: "build/app".into(),
            filetype: pgr_core::layout::OutputType::Dylib,
            entry_symbol: "_start".into(),
            platform: 0x1,
            minos: 0x000c_0100,
            sdk: 0x000e_0400,
            dynamic_linker: false,
            fixup_chains: false,
            adhoc: false,
            dylibs: vec![Dylib {
                install_name: "@rpath/libgreet.dylib".into(),
                current_version: 0x1_2_3,
                compatibility_version: 1,
                exports: vec![b"_greet".to_vec(), b"_greet_loud".to_vec()],
                weak: true,
                reexport: true,
                lazy: true,
            }],
            flat_namespace: true,
            undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
            rpaths: vec!["@loader_path/../lib".into(), "/opt/lib".into()],
            source_version: Some(0x5_4_3_2_1),
            install_name: Some("@rpath/libapp.dylib".into()),
            current_version: 0x1_0_0,
            compatibility_version: 0x0_1_0,
            // The v7 filter lists: both forms ride (a glob must not
            // flatten into an exact name across the wire — the export
            // surface is the surface the client named).
            exported_only: Some(vec![
                SymbolPattern::exact(b"_public"),
                SymbolPattern::parse(b"_pub_*").unwrap(),
            ]),
            unexported: vec![
                SymbolPattern::exact(b"_secret"),
                SymbolPattern::parse(b"_priv_*").unwrap(),
            ],
            dead_strippable: true,
            dead_strip: true,
            load_symbols: vec![b"_kept".to_vec()],
            icf: pgr_core::icf::IcfMode::Safe,
            layout_slack: Some(pgr_core::SlackPolicy::default()),
            // Not on the wire (see decode): the cross-link anchors ride
            // the v3 request's `record` field, never the config.
            stable_imports: None,
            sig_anchor: None,
            record_resolution: false,
            resolve_reuse: None,
            slack_anchor: vec![pgr_core::slack::SlackAnchor {
                seg: "__TEXT".into(),
                name: "__text".into(),
                padded: 0x4000,
            }],
            // The v6 tail byte: a non-default family must survive the
            // round trip verbatim (the wire never silently drops it).
            chain_word_format: FixupPointerFormat::Arm64e,
            // The v8 tail: a non-default image base must survive the
            // round trip verbatim (a resident relink lays out the base
            // the client named, never the default).
            pagezero: pgr_core::pagezero::PageZero::from_override(0x7F7F_7F7F_C000)
                .expect("the override validates"),
            // The v9 tail: the non-default initializer form must
            // survive the round trip verbatim (a resident relink plans
            // the form the client named, never the default).
            init_offsets: pgr_core::InitOffsets::Offsets,
            // The v10 tail: a non-default protection pair must survive
            // the round trip verbatim (a resident relink protects the
            // segments the client named, never the house table).
            seg_prots: {
                let mut seg_prots = pgr_core::segprot::SegProts::default();
                seg_prots
                    .insert(
                        pgr_core::segprot::SegName::DataConst,
                        pgr_core::segprot::SegProt::parse("rw", "r")
                            .expect("the decision validates"),
                    )
                    .expect("one decision per segment");
                seg_prots
            },
            // The v11 tail: the non-default reserve must survive the
            // round trip verbatim (a resident relink reserves what the
            // client named, never the zero default).
            stack_size: Some(
                pgr_core::stack_size::StackSize::from_override(0x4000_0000)
                    .expect("the reserve validates"),
            ),
            // The v12 tail: a non-default dylib/bundle base must
            // survive the round trip verbatim (a resident relink lays
            // out the base the client named, never the M3 zero).
            image_base: Some(
                pgr_core::image_base::ImageBase::from_override(0x6_0000)
                    .expect("the base validates"),
            ),
            // The v13 tail: a non-default umbrella region must survive
            // the round trip verbatim, in flag order (a resident relink
            // emits the region the client named, never the pre-M20
            // absence).
            umbrella: {
                let mut umbrella = pgr_core::umbrella::Umbrella::new();
                umbrella
                    .push(
                        pgr_core::umbrella::UmbrellaMember::from_flag(
                            pgr_core::umbrella::UmbrellaKind::SubUmbrella,
                            "libsub.dylib",
                        )
                        .expect("the member validates"),
                    )
                    .expect("one decision per member");
                umbrella
                    .push(
                        pgr_core::umbrella::UmbrellaMember::from_flag(
                            pgr_core::umbrella::UmbrellaKind::SubLibrary,
                            "liblegacy.dylib",
                        )
                        .expect("the member validates"),
                    )
                    .expect("one decision per member");
                umbrella
            },
            // The v14 tail: a non-default client list must survive the
            // round trip verbatim, in flag order (a resident relink
            // emits the clients the linking image named, never the
            // pre-M21 absence).
            sub_clients: {
                let mut sub_clients = pgr_core::sub_client::SubClient::new();
                sub_clients
                    .push(
                        pgr_core::SubClientEntry::from_flag("client.app")
                            .expect("the client validates"),
                    )
                    .expect("one decision per client");
                sub_clients
                    .push(
                        pgr_core::SubClientEntry::from_flag("/usr/bin/tool")
                            .expect("the client validates"),
                    )
                    .expect("one decision per client");
                sub_clients
            },
            // The v15 tail: a non-default environment list must survive
            // the round trip verbatim, in flag order (a resident relink
            // exports the variables the client named, never the
            // pre-M22 absence).
            dyld_envs: {
                let mut dyld_envs = pgr_core::dyld_env::DyldEnv::new();
                dyld_envs
                    .push(
                        pgr_core::DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1")
                            .expect("the pair validates"),
                    )
                    .expect("one decision per variable");
                dyld_envs
                    .push(
                        pgr_core::DyldEnvEntry::from_flag("DYLD_PRINT_RPATHS=1")
                            .expect("the pair validates"),
                    )
                    .expect("one decision per variable");
                dyld_envs
            },
            // The v16 tail: a non-default bundle loader must survive
            // the round trip verbatim (a resident relink binds against
            // the host the client named, never the pre-M25 absence).
            bundle_loader: Some(
                pgr_core::BundleLoader::new(
                    "/usr/lib/host",
                    vec![b"_host_fn".to_vec(), b"_host_data".to_vec()],
                )
                .expect("the loader validates"),
            ),
            // The v16 tail: a non-default alias list must survive the
            // round trip verbatim, in flag order (a resident relink
            // exports the names the client asked for, never the
            // pre-M24 absence).
            aliases: {
                let mut aliases = pgr_core::alias::AliasTable::new();
                aliases
                    .push(
                        pgr_core::Alias::from_parts("_shim_a", "_greet")
                            .expect("the pair validates"),
                    )
                    .expect("one decision per name");
                aliases
                    .push(
                        pgr_core::Alias::from_parts("_shim_b", "_greet_loud")
                            .expect("the pair validates"),
                    )
                    .expect("one decision per name");
                aliases
            },
            // The v17 tail: a non-default loader path must survive the
            // round trip verbatim (a resident relink execs the loader
            // the client named, never the pre-M26 default).
            dylinker: Some(
                pgr_core::Dylinker::from_flag("/usr/local/bin/mydyld").expect("the path validates"),
            ),
            // The v18 tail: a non-default PIE decision must survive the
            // round trip verbatim (a resident relink carries the flag
            // word the client asked for, never the PIE-always default).
            no_pie: true,
            symbol_order: None,
        }
    }

    #[test]
    fn request_round_trips_byte_shape() {
        let req = LinkRequest {
            config: rich_config(),
            force_load: vec![b"_kept".to_vec()],
            inputs: vec![InputEntry {
                name: "hello.o".into(),
                hash: content_hash(b"hello"),
            }],
            archives: vec![ArchiveEntry {
                name: "libutil.a".into(),
                all_load: true,
                hash: content_hash(b"archive"),
            }],
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        assert_eq!(
            back.blob_hashes(),
            vec![content_hash(b"archive"), content_hash(b"hello")]
        );
    }

    #[test]
    fn audited_request_round_trips_byte_shape() {
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: Some(vec![1, 2, 3]),
            record_resolution: true,
            prev_output: Some(content_hash(b"prev")),
            audit: true,
            tiles: true,
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        // The audit flag flips cleanly over the wire.
        req.audit = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
    }

    #[test]
    fn default_config_round_trips() {
        let req = LinkRequest {
            config: LinkConfig::default(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn version_mismatch_is_a_proto_error() {
        let mut body = Vec::new();
        put_u32(&mut body, PROTO_VERSION + 7);
        let err = LinkRequest::decode(&body).unwrap_err();
        assert!(matches!(err, DecodeError::Proto { .. }), "{err:?}");
    }

    #[test]
    fn truncated_body_is_malformed() {
        let req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let body = req.encode();
        assert!(LinkRequest::decode(&body[..body.len() / 2]).is_err());
        // Trailing garbage rejected too.
        let mut extra = body.clone();
        extra.push(0);
        assert!(LinkRequest::decode(&extra).is_err());
    }

    #[test]
    fn request_round_trips_the_record_halves() {
        // v3 (M9 fusion): the record, the capture flag and the previous
        // output hash ride the request; the previous output joins the
        // BLOB negotiation so the daemon can gate and patch it.
        let req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: Some(vec![7, 8, 9]),
            record_resolution: true,
            prev_output: Some(content_hash(b"previous output")),
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req);
        assert!(
            back.blob_hashes()
                .contains(&content_hash(b"previous output"))
        );

        // A bare request (plain M8 resident link) round-trips with all
        // halves absent and adds nothing to the negotiation.
        let bare = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: vec![InputEntry {
                name: "a.o".into(),
                hash: content_hash(b"a"),
            }],
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&bare.encode()).unwrap();
        assert_eq!(back, bare);
        assert_eq!(back.blob_hashes(), vec![content_hash(b"a")]);

        // Truncation inside the record tail is malformed, not a panic.
        let body = req.encode();
        assert!(LinkRequest::decode(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn tag_constants_stay_stable() {
        // The tags are the wire contract; pin them.
        assert_eq!(TAG_LINK, 3);
        let mut r = Reader::new(&[1, 0, 0, 0]);
        assert_eq!(r.u32().unwrap(), 1);
    }

    #[test]
    fn tiles_flag_round_trips_cleanly() {
        // v5 (the §7.2 output-residency rung): the request's `tiles` flag
        // says the client can replay a changed-tile stream (it holds the
        // previous output bytes locally). It flips independently of the
        // fusion halves.
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: Some(vec![1]),
            record_resolution: true,
            prev_output: Some(content_hash(b"prev")),
            audit: false,
            tiles: true,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert!(back.tiles, "the flag rides the wire");
        req.tiles = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
        // Truncation inside the trailing flag byte is malformed.
        let body = back.encode();
        assert!(LinkRequest::decode(&body[..body.len() - 1]).is_err());
    }

    #[test]
    fn a_wire_garbage_pagezero_is_malformed() {
        // v8: the config tail carries the pagezero vmsize as a validated
        // value — a wire body naming a zero or misaligned base is
        // malformed, not silently defaulted (the default would move the
        // image base the client asked for).
        let req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let body = req.encode();
        // The distinctive vmsize appears exactly once (every other field
        // carries different bytes); corrupt those 8 bytes to a misaligned
        // value.
        let needle = 0x7F7F_7F7F_C000u64.to_le_bytes();
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(8) {
            if body[i..i + 8] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the vmsize rides exactly once");
        let mut bad = body;
        bad[hits[0]..hits[0] + 8].copy_from_slice(&0x3000u64.to_le_bytes());
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_segprot_decisions_round_trip() {
        // v10 (M17): the per-segment protection decisions ride the
        // config tail — a resident relink plans the protections the
        // client named, never the house table.
        let mut cfg = rich_config();
        for (seg, max, init) in [
            (pgr_core::segprot::SegName::Text, "rx", "rx"),
            (pgr_core::segprot::SegName::Data, "rw", "r"),
        ] {
            cfg.seg_prots
                .insert(
                    seg,
                    pgr_core::segprot::SegProt::parse(max, init).expect("validates"),
                )
                .expect("one decision per segment");
        }
        let req = LinkRequest {
            config: cfg,
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req, "the decisions cross byte-for-byte");
        assert_eq!(back.config.seg_prots.len(), 3);
        assert_eq!(
            back.config
                .seg_prots
                .prot_for("__DATA")
                .map(|p| (p.maxprot(), p.initprot())),
            Some((0x3, 0x1)),
            "the named pair survives the wire"
        );
    }

    #[test]
    fn a_wire_garbage_segprot_is_malformed() {
        // v10: an unplanned segment name on the wire is malformed, not
        // silently defaulted (the default would protect a segment the
        // client did not name). `rich_config` already names a decision
        // (the round-trip gate's tail), so the frame carries one entry
        // to corrupt.
        let body = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The segment name rides as a length-prefixed string exactly
        // once; swap it for an unplanned name of the same length.
        let needle = b"__DATA_CONST";
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(needle.len()) {
            if body[i..i + needle.len()] == *needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the segment name rides exactly once");
        let mut bad = body;
        bad[hits[0]..hits[0] + needle.len()].copy_from_slice(b"__PAGEZERO__");
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_stack_reserve_round_trips() {
        // v11 (M18): the executable's `LC_MAIN` stack reserve rides the
        // config tail — a resident relink reserves what the client
        // named, never the zero default.
        let mut cfg = rich_config();
        cfg.stack_size = Some(
            pgr_core::stack_size::StackSize::from_override(0x100_0000)
                .expect("the reserve validates"),
        );
        let req = LinkRequest {
            config: cfg,
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req, "the reserve crosses byte-for-byte");
        assert_eq!(
            back.config
                .stack_size
                .map(pgr_core::stack_size::StackSize::bytes),
            Some(0x100_0000),
            "the named reserve survives the wire"
        );
    }

    #[test]
    fn a_wire_garbage_stack_reserve_is_malformed() {
        // v11: a misaligned or zero reserve on the wire is malformed,
        // not silently defaulted (the default would shrink the stack
        // the client asked for).
        let mut cfg = rich_config();
        cfg.stack_size = Some(
            pgr_core::stack_size::StackSize::from_override(0x100_0000)
                .expect("the reserve validates"),
        );
        let body = LinkRequest {
            config: cfg,
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The reserve rides as a present-byte + u64 exactly once (the
        // distinctive value has no other carrier); corrupt those 8
        // bytes to a misaligned value.
        let needle = 0x100_0000u64.to_le_bytes();
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(8) {
            if body[i..i + 8] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the reserve rides exactly once");
        let mut bad = body;
        bad[hits[0]..hits[0] + 8].copy_from_slice(&0x3000u64.to_le_bytes());
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_image_base_round_trips() {
        // v12 (M19): the dylib/bundle preferred load address rides the
        // config tail — a resident relink lays out the base the client
        // named, never the M3 zero default.
        let mut cfg = rich_config();
        cfg.image_base = Some(
            pgr_core::image_base::ImageBase::from_override(0x80000).expect("the base validates"),
        );
        let req = LinkRequest {
            config: cfg,
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req, "the base crosses byte-for-byte");
        assert_eq!(
            back.config
                .image_base
                .map(pgr_core::image_base::ImageBase::vmaddr),
            Some(0x80000),
            "the named base survives the wire"
        );
    }

    #[test]
    fn a_wire_garbage_image_base_is_malformed() {
        // v12: a misaligned or zero base on the wire is malformed, not
        // silently defaulted (the default would zero the address space
        // the client asked for).
        let mut cfg = rich_config();
        cfg.image_base = Some(
            pgr_core::image_base::ImageBase::from_override(0x80000).expect("the base validates"),
        );
        let body = LinkRequest {
            config: cfg,
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The base rides as a present-byte + u64 exactly once (the
        // distinctive value has no other carrier); corrupt those 8
        // bytes to a misaligned value.
        let needle = 0x80000u64.to_le_bytes();
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(8) {
            if body[i..i + 8] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the base rides exactly once");
        let mut bad = body;
        bad[hits[0]..hits[0] + 8].copy_from_slice(&0x3000u64.to_le_bytes());
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_umbrella_region_round_trips() {
        // v13 (M20): the umbrella region rides the config tail in flag
        // order — a resident relink emits the region the client named,
        // never the pre-M20 absence. The happy path rides
        // `rich_config`'s round trip; this gate pins the members
        // byte-for-byte.
        let mut cfg = rich_config();
        let mut region = pgr_core::umbrella::Umbrella::new();
        region
            .push(
                pgr_core::umbrella::UmbrellaMember::from_flag(
                    pgr_core::umbrella::UmbrellaKind::SubUmbrella,
                    "libpair.dylib",
                )
                .expect("the member validates"),
            )
            .expect("one decision per member");
        cfg.umbrella = region;
        let back = LinkRequest::decode(
            &LinkRequest {
                config: cfg,
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
            }
            .encode(),
        )
        .unwrap();
        let names: Vec<(&str, &str)> = back
            .config
            .umbrella
            .iter()
            .map(|m| (m.kind().as_str(), m.name()))
            .collect();
        assert_eq!(
            names,
            [("sub-umbrella", "libpair.dylib")],
            "the region crosses byte-for-byte, kind and name intact"
        );
    }

    #[test]
    fn a_wire_garbage_umbrella_member_is_malformed() {
        // v13: an unknown kind byte is malformed, not silently widened
        // (the default would name a member the flag grammar cannot
        // spell).
        let body = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The member rides as (kind byte, u32 len, name bytes) exactly
        // once; the kind byte sits right before the length field.
        let needle = b"libsub.dylib";
        let mut hits = Vec::new();
        for i in 5..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the member rides exactly once");
        let mut bad = body;
        bad[hits[0] - 5] = 2; // the kind byte: an unknown kind
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_sub_client_list_round_trips() {
        // v14 (M21): the client list rides the config tail in flag
        // order — a resident relink emits the clients the linking image
        // named, never the pre-M21 absence. The happy path rides
        // `rich_config`'s round trip; this gate pins the names
        // byte-for-byte.
        let mut cfg = rich_config();
        let mut clients = pgr_core::sub_client::SubClient::new();
        clients
            .push(
                pgr_core::SubClientEntry::from_flag("com.example.app")
                    .expect("the client validates"),
            )
            .expect("one decision per client");
        cfg.sub_clients = clients;
        let back = LinkRequest::decode(
            &LinkRequest {
                config: cfg,
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
            }
            .encode(),
        )
        .unwrap();
        let names: Vec<&str> = back
            .config
            .sub_clients
            .iter()
            .map(pgr_core::SubClientEntry::name)
            .collect();
        assert_eq!(
            names,
            ["com.example.app"],
            "the clients cross byte-for-byte, name intact"
        );
    }

    #[test]
    fn a_wire_garbage_sub_client_is_malformed() {
        // v14: an empty name is malformed, not silently widened (the
        // default would name a client the flag grammar cannot spell).
        let body = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The client rides as (u32 len, name bytes) exactly once; the
        // length field sits right before the name bytes.
        let needle = b"client.app";
        let mut hits = Vec::new();
        for i in 4..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the client rides exactly once");
        let mut bad = body;
        bad[hits[0] - 4..hits[0]].copy_from_slice(&0u32.to_le_bytes()); // an empty name
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_dyld_env_list_round_trips() {
        // v15 (M22): the pair list rides the config tail in flag order
        // — a resident relink exports the variables the client named,
        // never the pre-M22 absence. The happy path rides `rich_config`'s
        // round trip; this gate pins the pairs byte-for-byte.
        let mut cfg = rich_config();
        let mut envs = pgr_core::dyld_env::DyldEnv::new();
        envs.push(
            pgr_core::DyldEnvEntry::from_flag("DYLD_PRINT_PATHS=/usr/lib")
                .expect("the pair validates"),
        )
        .expect("one decision per variable");
        cfg.dyld_envs = envs;
        let back = LinkRequest::decode(
            &LinkRequest {
                config: cfg,
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
            }
            .encode(),
        )
        .unwrap();
        let pairs: Vec<&str> = back
            .config
            .dyld_envs
            .iter()
            .map(pgr_core::DyldEnvEntry::pair)
            .collect();
        assert_eq!(
            pairs,
            ["DYLD_PRINT_PATHS=/usr/lib"],
            "the pairs cross byte-for-byte, pair intact"
        );
    }

    #[test]
    fn a_wire_garbage_dyld_env_is_malformed() {
        // v15: a pair off the DYLD_<var>=<value> grammar is malformed,
        // not silently exported (the default would export a variable
        // the flag grammar cannot spell).
        let body = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The pair rides as (u32 len, pair bytes) exactly once; the
        // length field sits right before the pair bytes.
        let needle = b"DYLD_PRINT_LIBRARIES=1";
        let mut hits = Vec::new();
        for i in 4..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the pair rides exactly once");
        let mut bad = body;
        bad[hits[0] - 4..hits[0]].copy_from_slice(&0u32.to_le_bytes()); // an empty pair
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_loader_path_round_trips() {
        // v17: a non-default `-dylinker` path must survive the round
        // trip verbatim (a resident relink execs the loader the client
        // named, never the pre-M26 default).
        let cfg = rich_config();
        assert_eq!(
            cfg.dylinker
                .as_ref()
                .map(pgr_core::Dylinker::path)
                .expect("rich_config names a loader"),
            "/usr/local/bin/mydyld",
            "rich_config carries the v17 knob"
        );
        let back = LinkRequest::decode(
            &LinkRequest {
                config: cfg,
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(
            back.config
                .dylinker
                .as_ref()
                .map(pgr_core::Dylinker::path)
                .expect("the loader crosses"),
            "/usr/local/bin/mydyld",
            "the path crosses byte-for-byte"
        );
    }

    #[test]
    fn the_pie_decision_round_trips() {
        // v18: a non-default `-no_pie` must survive the round trip
        // verbatim (a resident relink carries the flag word the client
        // asked for, never the PIE-always default).
        let cfg = rich_config();
        assert!(cfg.no_pie, "rich_config carries the v18 knob");
        let back = LinkRequest::decode(
            &LinkRequest {
                config: cfg,
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
            }
            .encode(),
        )
        .unwrap();
        assert!(back.config.no_pie, "the decision crosses byte-for-byte");
    }

    #[test]
    fn a_wire_garbage_dylinker_is_malformed() {
        // v17: a path off the -dylinker grammar is malformed, not
        // silently exec'd (the kernel would refuse a relative loader at
        // exec time anyway — the wire names the grammar up front).
        let body = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        // The path rides as (u32 len, path bytes) exactly once; the
        // length field sits right before the path bytes.
        let needle = b"/usr/local/bin/mydyld";
        let mut hits = Vec::new();
        for i in 4..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the path rides exactly once");
        let mut bad = body;
        bad[hits[0] - 4..hits[0]].copy_from_slice(&0u32.to_le_bytes()); // an empty path
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
        // And a relative path is malformed the same way: rewrite the
        // length, splice a shorter relative name in, truncate nothing
        // else — decode re-validates the grammar.
        let mut rel = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        }
        .encode();
        let rel_path = b"bin/dyld";
        let tail_start = hits[0] + needle.len();
        rel[hits[0] - 4..hits[0]].copy_from_slice(&(rel_path.len() as u32).to_le_bytes());
        rel[hits[0]..hits[0] + rel_path.len()].copy_from_slice(rel_path);
        // Shift the remainder left over the consumed suffix (the path
        // bytes shorter than the original) — the string reader reads
        // exactly `len` bytes, so the leftover bytes would corrupt the
        // fields after; build instead by re-splicing: keep everything
        // before, the rewritten frame, everything after the old frame.
        let old_frame_end = tail_start;
        let mut fixed = Vec::with_capacity(rel.len());
        fixed.extend_from_slice(&rel[..tail_start]);
        fixed.extend_from_slice(&rel[old_frame_end..]);
        rel = fixed;
        let err = LinkRequest::decode(&rel).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }
}
