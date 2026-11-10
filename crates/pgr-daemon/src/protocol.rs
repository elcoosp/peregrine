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
//! | `IMAGE` 6 | S→C | v4 body: `u64 entryoff, u64 fixup_slots, u32 hits, u32 misses, [patch outcome], [record bytes], [audit outcome], u64 len, image bytes` |
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

use pgr_core::icf::IcfMode;
use pgr_core::fixups::FixupPointerFormat;
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
/// ([`pgr_emit::incremental::TilePatch`]); **v6** appends the chain word
/// family to the config body (M10 rung 4 slice 2 — the family a client
/// asked for crosses the wire verbatim, never silently dropped).
pub const PROTO_VERSION: u32 = 6;

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
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
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
        Ok(self.take(32)?.try_into().unwrap())
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
            for n in list {
                put_bytes(out, n);
            }
        }
        None => put_u8(out, 0),
    }
    put_u32(out, cfg.unexported.len() as u32);
    for n in &cfg.unexported {
        put_bytes(out, n);
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
    let exported_only = match r.u8()? {
        0 => None,
        _ => Some(
            (0..r.u32()?)
                .map(|_| r.bytes().map(<[u8]>::to_vec))
                .collect::<Result<Vec<Vec<u8>>, DecodeError>>()?,
        ),
    };
    let unexported = (0..r.u32()?)
        .map(|_| r.bytes().map(<[u8]>::to_vec))
        .collect::<Result<Vec<Vec<u8>>, DecodeError>>()?;
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
    })
}

// ---- frame-level round-trip gates -------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ArchiveEntry, DecodeError, InputEntry, LinkRequest, PROTO_VERSION, Reader, TAG_LINK,
        content_hash, put_u32,
    };
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
            }],
            flat_namespace: true,
            undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
            rpaths: vec!["@loader_path/../lib".into(), "/opt/lib".into()],
            source_version: Some(0x5_4_3_2_1),
            install_name: Some("@rpath/libapp.dylib".into()),
            current_version: 0x1_0_0,
            compatibility_version: 0x0_1_0,
            exported_only: Some(vec![b"_public".to_vec()]),
            unexported: vec![b"_secret".to_vec()],
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
}
