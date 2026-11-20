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
//! family (one byte — `FixupPointerFormat`). Until M82 the driver refused
//! `-resident` + `arm64e` (the session's reuse gates rode the Offset64
//! shapes), so every wire request named `offset64` — the byte existed so
//! the wire could never silently drop the family a client asked for.
//! M82: the family is config, the session's warm pipeline plans it, the
//! record carries it (v7), and the relink ladders admit through it —
//! the same byte now carries the family a resident arm64e link names,
//! no config shape moved.
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
/// default); **v19** appends the section-alignment floors (M28 — one
/// length-prefixed `(segment, section, exponent)` triple per
/// `-sectalign` decision, in flag order; a resident relink aligns the
/// sections the client named, never the pre-M28 input-only shape);
/// **v20** appends the header-region floor (M29 — a present byte, then
/// the `-headerpad` floor as a u64; a resident relink reserves the
/// region the client named, never the pre-M29 natural size alone);
/// **v21** appends the data-in-code suppression (M30 — one byte naming
/// whether the image drops the `LC_DATA_IN_CODE` command; a resident
/// relink carries the stream decision the client asked for, never the
/// pre-M30 carry-when-named default); **v22** appends the
/// function-starts suppression (M31 — one byte naming whether the
/// image drops the `LC_FUNCTION_STARTS` command; a resident relink
/// carries the linkedit-metadata decision the client asked for, never
/// the pre-M31 always-carried default); **v23** appends the UUID
/// suppression (M32 — one byte naming whether the image drops the
/// `LC_UUID` command; a resident relink carries the derived-UUID
/// decision the client asked for, never the pre-M32 always-carried
/// default); **v24** appends the private-extern keep (M33 — one byte
/// naming whether the image holds input `N_PEXT` definitions external;
/// a resident relink carries the private-extern decision the client
/// asked for, never the pre-M33 conversion default); **v25** appends
/// the compact-unwind suppression (M36 — one byte naming whether the
/// image drops the `__unwind_info` section; a resident relink carries
/// the suppression decision the client asked for, never the pre-M36
/// carry default); **v26** appends the install-name auto-floor (M38 —
/// one byte naming whether the reserved header region grows past its
/// natural size by every load command's room to the longest install
/// name; a resident relink carries the header-pad decision the client
/// asked for, never the pre-M38 natural default); **v27** appends the
/// make-undefined marks (M39 — the `-U` names, count-prefixed like the
/// rpaths; a resident relink strips the definitions the client marked,
/// never the pre-M39 carried definitions); **v28** appends the
/// export-trie suppression (M40 — one byte naming whether the image
/// drops the `LC_DYLD_EXPORTS_TRIE` command; a resident relink carries
/// the export-surface decision the client asked for, never the pre-M40
/// always-carried default); **v29** appends the dedup toggle (M41 — one
/// byte naming whether identical literals stop merging; a resident
/// relink carries the D4 decision the client asked for, never the
/// pre-M41 merge default); **v30** appends the unused-dylib drop (M42 —
/// one byte naming whether input dylibs nothing binds against leave the
/// header; a resident relink carries the drop decision the client asked
/// for, never the pre-M42 keep-every-dylib default); **v31** appends
/// the `ObjC` pull (M43 — one byte naming whether archive members
/// implementing an Objective-C class or category ride the archive pull;
/// a resident relink carries the pull decision the client asked for,
/// never the pre-M43 reference-driven default); **v32** appends the
/// upward-load kind (M45 — one byte per dylib naming whether it loads
/// as `LC_LOAD_UPWARD_DYLIB`; the wire never silently flattens the
/// umbrella mark into a plain load, the M14 lazy-byte convention);
/// **v33** appends the export-dynamic roots (M46 — one byte naming
/// whether every global definition roots the dead-strip mark phase; a
/// resident relink carries the `dlsym` decision the client asked for,
/// never the pre-M46 entry-root default); **v34** appends the
/// branch-island suppression (M47 — one byte naming whether the layout
/// stops planning veneers for out-of-range branches; a resident relink
/// carries the suppression decision the client asked for, never the
/// pre-M47 islands-by-default); **v35** appends the dylib initializer
/// (M48 — a present byte, then the `-init` symbol name; a resident
/// relink carries the initializer the client named, never the pre-M48
/// absence); **v36** appends the weak-import refusal (M50 — one byte
/// naming whether a weak reference dyld must look up at runtime refuses
/// the link; a resident relink carries the decision the client asked
/// for, never the pre-M50 runtime-lookup fallthrough); **v37** appends
/// the stack-execution decision (M51 — one byte naming whether the
/// executable's header word carries `MH_ALLOW_STACK_EXECUTION`; a
/// resident relink carries the flag word the client asked for, never
/// the pre-M51 bitless default); **v38** appends the dead-strip
/// init/term roots (M52 — one byte naming whether the
/// termination-pointer sections join the dead-strip roots; a resident
/// relink strips the routines the client asked to keep, never the
/// pre-M52 term-strip default); **v39** appends the section renames
/// (M53 — a count-prefixed table, four names per entry, the source pair
/// then the target pair; a resident relink renames the sections the
/// client named, never the pre-M53 unnamed pairs); **v40** appends the
/// per-pass time report (M58/M59 — the request's `time` flag asks the
/// session to observe its own pipeline through the M54 seam
/// ([`pgr_core::time_report::TimeCollector`]), and the reply's IMAGE
/// tail carries the collected [`pgr_core::time_report::TimeReport`] —
/// the phases the session's run reported, the notes the ladder named,
/// the emit and total bands the session measured; a relink's Pass-4
/// half is the in-memory patch, so its emit band rides absent);
/// **v41** appends the Chrome-trace timeline (M61/M62 — the request's
/// `trace` flag asks the session to observe its own pipeline through
/// the M54 seam ([`pgr_core::trace::TraceCollector`], paired with the
/// time collector when both faces ask), and the reply's IMAGE tail
/// carries the rendered timeline — the same one-line Trace Event
/// Format document the one-shot `--trace` writes, the strict reader
/// (`pgr_core::trace::parse_trace_json`) is its own face); **v42**
/// registers the §7.3 ladder's rung vocabulary in the time-report tail
/// (M65 — the phase tokens `relink_gate`/`relink_plan`/`relink_patch`/
/// `relink_audit` and their detail payloads ride the tail's own shape,
/// so a captured tail carrying them restores exactly; the session's own
/// ladder reports through the seam since M66 — a warm relink's report
/// carries the rungs beside the pipeline phases). M68 extends the
/// tail's vocabulary with the emit half's tokens (`emit`/`flush` and
/// their detail payloads, ordinals 12/13) **without a version bump**:
/// the served content is unchanged — the session's warm run has no
/// fused emit and the client does the writing — so a v42 daemon never
/// sends the new tokens and a v42 client never meets them; the decode
/// side accepts them so the vocabulary is the tail's, not the one-shot
/// lane's alone); **v43** appends the served verify verdict (M72 — the
/// request's `verify` flag asks the session to run the strict verifier
/// on the final bytes — the full link's and the untouched relink's
/// alike, the `-no_adhoc` carve-out applied the audit's way — and the
/// reply's IMAGE tail carries the effective report rendered in the M13
/// interchange form, the strict reader
/// (`pgr_verify::report_json::parse_report_json`) its own face);
/// **v44** appends the verify gate's check selection (M77 — the
/// request's `verify_checks` selection, present only beside the
/// `verify` flag, carries the M12 [`pgr_verify::CheckSet`] the
/// session's served pass narrows to, rendered in the selector's own
/// canonical form; a selection the parser refuses is a malformed
/// request — the wire never carries a gate the pipeline would silently
/// widen). **v45** appends the provenance queries (M79 — the request's
/// `why_export` names and `why_load` flag ask the session's own full
/// walk for the M56/M57 answers, the reply's IMAGE tail carrying the
/// rendered text verbatim; M88 retires the beside-the-`record` refusal —
/// the replay's own walk answers honestly, the same tail either lane).
/// **v46** appends the map ask (M80 — the request's `map` flag asks the
/// session's own walk for the M55 document, the reply's IMAGE tail
/// carrying the rendered text verbatim). **v47** appends the rank table
/// (M81 — the composed `-order_file`/`-sectorder` table crosses the
/// config tail; a table the core constructor refuses is a malformed
/// request), and the M91 cstring face rides the same tail (a
/// rebuild-refusing table is a malformed request, the absent-table
/// shape byte-identical to pre-M91). **v48** appends the liveness
/// queries (M93 — the request's `why_live` names ask the session's own
/// mark record for the M92 chains, the provenance tail carrying the
/// rendered text verbatim beside the M79 answers; a liveness ask beside
/// a relocatable config is a malformed request — `-r` carries no strip,
/// the M83 replay-face rule). **v49** appends the dylib terminator (M98
/// — the config tail carries the `-term` name beside the M48 `-init`
/// name; a resident relink carries the terminator the client named,
/// never the pre-M98 absence). **v50** appends the named output UUID
/// (M99 — the config tail carries the 16 bytes beside the names; a
/// resident relink carries the identity the client named, never the
/// content-derived default). **v51** names the M100 round: the singular
/// export filters (`-exported_symbol`/`-unexported_symbol`) compose into
/// the ONE filter table the config already carries — the v7 pattern
/// carriage (a present byte + count-prefixed entries for the only-list,
/// the count-prefixed hide-list), a rebuild-refusing pattern still a
/// malformed request — so a resident relink plans the composed surface
/// the client named; no shape moves, the version gate names the round.
/// **v52** names the M101 round: `-alias_list <file>` composes into the
/// ONE alias table the config already carries — the v16 pair carriage
/// (count-prefixed, the same validation the flag parse pays, a
/// rebuild-refusing table still a malformed request) — so a resident
/// relink ships the composed aliases the client named; no shape moves,
/// the version gate names the round. **v53** names the M102 round: the
/// bind-at-load decision (`-bind_at_load`/`-no_bind_at_load`) rides the
/// tail after the cstring rank table — one byte; a resident relink
/// carries the flag word the client asked for, never the pre-M102
/// bitless default. **v54** names the M103 round: the config body's
/// `-undefined` policy byte widens to the four-value alphabet
/// (`error`, `dynamic_lookup`, `warning`, `suppress`) — a value the
/// reader refuses is a malformed frame, so an old server reading a new
/// client's request refuses it (the M82 admits pattern, reversed), and
/// the reply gains the warning-policy tail (a present byte, then the
/// session's own unresolved-open render — the exit-policy face the
/// client prints, the M62 convention). **v55** names the M104 round:
/// the symtab-shaping decision (`-keep_local_symbols`/`-x`) rides the
/// tail after the bind-at-load byte — one byte; a resident relink
/// carries the symtab shape the client asked for, never the pre-M104
/// kept default. **v56** names the M105 round: the debug-section
/// suppression (`-S`) rides the tail after the symtab-shaping byte —
/// one byte; a resident relink carries the debug-free shape the client
/// asked for, never the pre-M105 debug-carrying default.
pub const PROTO_VERSION: u32 = 56;

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
    /// Whether the session must observe its own pipeline and serve the
    /// per-pass time report (v40, M58/M59): the reply's IMAGE tail then
    /// carries the collected [`pgr_core::time_report::TimeReport`] — the
    /// phases the session's run reported (a warm relink has no `Parse`
    /// row — the POIs are resident), the ladder's notes, the measured
    /// bands. An unasked report never crosses the wire.
    pub time: bool,
    /// Whether the session must observe its own pipeline and serve the
    /// Chrome-trace timeline (v41, M61/M62): the reply's IMAGE tail then
    /// carries the rendered [`pgr_core::trace::TraceReport`] — the same
    /// one-line Trace Event Format document the one-shot `--trace`
    /// writes, spans and instants on the session's own run. An unasked
    /// timeline never crosses the wire.
    pub trace: bool,
    /// Whether the session must verify its own output and serve the
    /// verdict (v43, M72): the reply's IMAGE tail then carries the
    /// strict verifier's effective report on the final bytes — the full
    /// link's and the untouched relink's alike (the audit's subject is
    /// the patch; the verdict's subject is the image, every outcome
    /// serves one) — rendered in the M13 interchange form, the
    /// `-no_adhoc` carve-out applied the audit's way. An unasked verdict
    /// never crosses the wire.
    pub verify: bool,
    /// The verify gate's check selection (v44, M77): the M12 selector
    /// ([`pgr_verify::CheckSet`]) the session's served pass narrows to —
    /// the same subtractive contract the verifier CLI's `--checks`
    /// carries (fewer families against the same parsed image, the parse
    /// pre-pass and the stats ride regardless). `None` names the full
    /// pass (the pre-M77 shape, byte-identical on the wire's decode
    /// side); a selection only rides beside the `verify` flag — a gate
    /// the selection narrows is the only gate it means.
    pub verify_checks: Option<pgr_verify::CheckSet>,
    /// The provenance queries (v45, M79): the `-why_export` names in
    /// flag order and the `-why_load` flag — the session's own walk (the
    /// warm pipeline *is* the one-shot shape: parse from resident POIs,
    /// intern, resolve, layout) renders the M56/M57 answers, and the
    /// reply's IMAGE tail carries the rendered text verbatim. The empty
    /// list (the default) queries nothing. M88: a query rides the
    /// `record` too — the §7.3 ladder's replay runs the full Passes 1–3,
    /// so its own Pass-2 product is the honest answer (never the
    /// record's stale one), the same tail carrying the renders either
    /// lane.
    pub why_export: Vec<String>,
    /// The load-report flag (v45, M79): `-why_load` — the S7 pull's
    /// per-member decision (and, under `-dead_strip_dylibs`, every input
    /// dylib's carriage) rendered from the session's own pull record.
    /// The lane contract mirrors [`LinkRequest::why_export`].
    pub why_load: bool,
    /// The link-map flag (v46, M80): `-map` — the session's own full
    /// walk renders the placed image's report (`pgr_core::map`, the
    /// segments/sections/symbols document the cold lane's `-map`
    /// writes), and the reply's IMAGE tail carries the rendered
    /// document verbatim — the client writes the file (the daemon never
    /// touches the filesystem). M87: the flag rides the `record` too —
    /// the §7.3 ladder's replay runs the full Passes 1–3, so its own
    /// Pass-3 product renders the document the replay actually planned
    /// (never the previous link's), the same tail carrying it either
    /// lane.
    pub map: bool,
    /// The liveness queries (v48, M93): the `-why_live` names in flag
    /// order — the mark phase's own first-marker record
    /// ([`pgr_core::LinkResult::liveness`], carried when the link ran
    /// `-dead_strip`) walked from the queried definition back to its
    /// root, the chains rendered by [`pgr_core::why_live`] and the
    /// reply's provenance tail carrying them verbatim beside the M79
    /// answers. The empty list (the default) queries nothing. The ask
    /// rides the `record` too (the replay's own walk carries the mark
    /// record), but never a relocatable config — `-r` preserves input
    /// sections verbatim and carries no strip, so a liveness ask beside
    /// `-r` is a malformed request (the M83 replay-face rule).
    pub why_live: Vec<String>,
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
        // M58/M59 (v40): the time-report request flag.
        put_u8(&mut b, u8::from(self.time));
        // M61/M62 (v41): the trace-timeline request flag.
        put_u8(&mut b, u8::from(self.trace));
        // M72 (v43): the verify-verdict request flag.
        put_u8(&mut b, u8::from(self.verify));
        // M77 (v44): the verify gate's check selection — present only
        // beside the `verify` flag (the driver refuses a selection
        // without a gate); the selector's canonical form is its own
        // wire shape, so the decode side restores the set exactly.
        match &self.verify_checks {
            Some(set) => {
                put_u8(&mut b, 1);
                put_str(&mut b, &set.to_string());
            }
            None => put_u8(&mut b, 0),
        }
        // M79 (v45): the provenance queries — the names in flag order,
        // the load-report flag beside them (the empty list is the
        // pre-M79 shape, byte-identical on the decode side).
        put_u32(&mut b, self.why_export.len() as u32);
        for name in &self.why_export {
            put_str(&mut b, name);
        }
        put_u8(&mut b, u8::from(self.why_load));
        // M80 (v46): the link-map request flag (M87 rides it beside the
        // record — the decode gates no longer refuse the shape).
        put_u8(&mut b, u8::from(self.map));
        // M93 (v48): the liveness queries — the names in flag order (the
        // empty list is the pre-M93 shape, byte-identical on the decode
        // side).
        put_u32(&mut b, self.why_live.len() as u32);
        for name in &self.why_live {
            put_str(&mut b, name);
        }
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
        let time = r.u8()? != 0;
        // M61/M62 (v41): the trace-timeline request flag.
        let trace = r.u8()? != 0;
        // M72 (v43): the verify-verdict request flag.
        let verify = r.u8()? != 0;
        // M77 (v44): the verify gate's check selection (see encode). A
        // selection the parser refuses is a malformed request — the wire
        // never carries a gate the pipeline would silently widen.
        let verify_checks = if r.u8()? == 0 {
            None
        } else {
            let rendered = r.str()?;
            Some(pgr_verify::CheckSet::parse(&rendered).map_err(|e| {
                DecodeError::Malformed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the request's check selection does not parse: {e}"),
                ))
            })?)
        };
        // M79 (v45): the provenance queries (see encode). An empty name
        // is a malformed request — the surface's grammar the driver
        // parses before the wire (a query names a C symbol). M88: the
        // queries ride the `record` too — the ladder's replay runs the
        // full Passes 1–3, so its own Pass-2 product answers honestly;
        // the refusal the M80-era arm carried is retired with the
        // outdated premise (an old server's `ERROR` is the reply the
        // client's stand-down already speaks — honest degradation).
        let why_export = (0..r.u32()?)
            .map(|_| r.str())
            .collect::<Result<Vec<String>, DecodeError>>()?;
        if why_export.iter().any(String::is_empty) {
            return Err(DecodeError::Malformed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request's provenance query names no symbol (the name is the \
                 C symbol, the leading underscore included)",
            )));
        }
        let why_load = r.u8()? != 0;
        // M80 (v46): the link-map request flag (see encode). M87: the
        // flag rides the `record` too — the ladder's replay runs the
        // full Passes 1–3, so its own Pass-3 product renders the
        // document the replay actually planned; the tail answers either
        // lane, and the refusal the M80 arm carried is retired with the
        // outdated premise (an old server's `ERROR` is the reply the
        // client's stand-down already speaks — honest degradation).
        let map = r.u8()? != 0;
        // M93 (v48): the liveness queries (see encode). An empty name is
        // a malformed request — the same C-symbol grammar the provenance
        // queries ride. The ask rides the `record` too (the replay's own
        // walk carries the mark record), but never a relocatable config:
        // `-r` preserves input sections verbatim and carries no strip,
        // so no mark record exists to walk (the M83 replay-face rule —
        // the surface refuses the knob, so the driver never asks).
        let why_live = (0..r.u32()?)
            .map(|_| r.str())
            .collect::<Result<Vec<String>, DecodeError>>()?;
        if why_live.iter().any(String::is_empty) {
            return Err(DecodeError::Malformed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the request's liveness query names no symbol (the name is the \
                 C symbol, the leading underscore included)",
            )));
        }
        // M83: the relocatable shape's edges at the wire. The object
        // walk serves the full link and the provenance queries (the
        // object's Pass-2 product is the same arena the query reads);
        // the replay faces have no object shape — a record, tiles, the
        // audit, `-verify` or `-map` beside a relocatable config is a
        // malformed request, never a silently widened one (the surface
        // refuses the knobs beside `-r`, so the driver never asks; no
        // wire caller can plan the shape either). M93: the liveness ask
        // joins the refused set — `-r` carries no strip, no mark record
        // exists to walk.
        if config.filetype == OutputType::Relocatable {
            let replay_face = record.is_some()
                || prev_output.is_some()
                || audit
                || tiles
                || verify
                || map
                || record_resolution
                || !why_live.is_empty();
            if replay_face {
                return Err(DecodeError::Malformed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the request carries a replay face beside a relocatable output: \
                     the object shape has no ladder — no record, no tiles, no audit, \
                     no verify, no map, no liveness ask beside -r",
                )));
            }
        }
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
            time,
            trace,
            verify,
            verify_checks,
            why_export,
            why_load,
            map,
            why_live,
        })
    }
}

// ---- the v40 time-report tail ------------------------------------------------

/// The phase's wire token (the variant's ordinal in the seam's own
/// declaration order — `Parse` … `Reloc`, the M65 ladder rungs beside
/// them, the M68 emit half after them; the new tokens append, the
/// existing ordinals never move).
fn phase_token(phase: pgr_core::observe::Phase) -> u8 {
    match phase {
        pgr_core::observe::Phase::Parse => 0,
        pgr_core::observe::Phase::ArchivePull => 1,
        pgr_core::observe::Phase::Intern => 2,
        pgr_core::observe::Phase::Resolve => 3,
        pgr_core::observe::Phase::Liveness => 4,
        pgr_core::observe::Phase::Fold => 5,
        pgr_core::observe::Phase::Layout => 6,
        pgr_core::observe::Phase::Reloc => 7,
        pgr_core::observe::Phase::RelinkGate => 8,
        pgr_core::observe::Phase::RelinkPlan => 9,
        pgr_core::observe::Phase::RelinkPatch => 10,
        pgr_core::observe::Phase::RelinkAudit => 11,
        pgr_core::observe::Phase::Emit => 12,
        pgr_core::observe::Phase::Flush => 13,
    }
}

fn phase_from_token(token: u8) -> Result<pgr_core::observe::Phase, DecodeError> {
    Ok(match token {
        0 => pgr_core::observe::Phase::Parse,
        1 => pgr_core::observe::Phase::ArchivePull,
        2 => pgr_core::observe::Phase::Intern,
        3 => pgr_core::observe::Phase::Resolve,
        4 => pgr_core::observe::Phase::Liveness,
        5 => pgr_core::observe::Phase::Fold,
        6 => pgr_core::observe::Phase::Layout,
        7 => pgr_core::observe::Phase::Reloc,
        8 => pgr_core::observe::Phase::RelinkGate,
        9 => pgr_core::observe::Phase::RelinkPlan,
        10 => pgr_core::observe::Phase::RelinkPatch,
        11 => pgr_core::observe::Phase::RelinkAudit,
        12 => pgr_core::observe::Phase::Emit,
        13 => pgr_core::observe::Phase::Flush,
        _ => {
            return Err(DecodeError::Malformed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the time report names an unknown phase",
            )));
        }
    })
}

/// Encodes the reply's time-report tail (v40): a present byte, then —
/// when the request asked and the session observed — the phase rows
/// (count-prefixed; per row the phase token, the detail kind byte with
/// its payload, the wall in whole microseconds), the notes
/// (count-prefixed, length-prefixed strings), and the emit/total bands
/// (a present byte + u64 µs each). A report the client did not ask for
/// rides absent — the tail is one byte.
pub fn encode_time_report(out: &mut Vec<u8>, report: Option<&pgr_core::time_report::TimeReport>) {
    let Some(report) = report else {
        put_u8(out, 0);
        return;
    };
    put_u8(out, 1);
    put_u32(out, report.phases.len() as u32);
    for event in &report.phases {
        put_u8(out, phase_token(event.phase));
        match &event.detail {
            pgr_core::observe::PhaseDetail::Objects { inputs } => {
                put_u8(out, 0);
                put_u64(out, u64::try_from(*inputs).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Members { pulled } => {
                put_u8(out, 1);
                put_u64(out, u64::try_from(*pulled).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Names { interned } => {
                put_u8(out, 2);
                put_u64(out, u64::try_from(*interned).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Winners { reused } => {
                put_u8(out, 3);
                put_u8(out, u8::from(*reused));
            }
            pgr_core::observe::PhaseDetail::Live { active } => {
                put_u8(out, 4);
                put_u8(out, u8::from(*active));
            }
            pgr_core::observe::PhaseDetail::Folded { folded } => {
                put_u8(out, 5);
                put_u64(out, u64::try_from(*folded).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Planned { segments, sections } => {
                put_u8(out, 6);
                put_u64(out, u64::try_from(*segments).unwrap_or(u64::MAX));
                put_u64(out, u64::try_from(*sections).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Reloc { inputs } => {
                put_u8(out, 7);
                put_u64(out, u64::try_from(*inputs).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Gate { pages } => {
                put_u8(out, 8);
                put_u64(out, u64::try_from(*pages).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Plan { tiles, dirty } => {
                put_u8(out, 9);
                put_u64(out, u64::try_from(*tiles).unwrap_or(u64::MAX));
                put_u64(out, u64::try_from(*dirty).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Patch { bytes, tiles } => {
                put_u8(out, 10);
                put_u64(out, *bytes);
                put_u64(out, u64::try_from(*tiles).unwrap_or(u64::MAX));
            }
            pgr_core::observe::PhaseDetail::Audit { healed, issues } => {
                put_u8(out, 11);
                put_u8(out, u8::from(*healed));
                put_u64(out, u64::try_from(*issues).unwrap_or(u64::MAX));
            }
            // M68: the emit half's rows ride the tail's own shape — the
            // vocabulary is the tail's (the session's warm run has no
            // fused emit and the client does the writing, so no served
            // content changes and the version gate stays v42; the decode
            // side restores a captured tail carrying the rows).
            pgr_core::observe::PhaseDetail::Emitted { tiles, bytes } => {
                put_u8(out, 12);
                put_u64(out, u64::try_from(*tiles).unwrap_or(u64::MAX));
                put_u64(out, *bytes);
            }
            pgr_core::observe::PhaseDetail::Flushed { blocks, writers } => {
                put_u8(out, 13);
                put_u64(out, u64::try_from(*blocks).unwrap_or(u64::MAX));
                put_u64(out, u64::try_from(*writers).unwrap_or(u64::MAX));
            }
        }
        put_u64(
            out,
            u64::try_from(event.elapsed.as_nanos() / 1_000).unwrap_or(u64::MAX),
        );
    }
    put_u32(out, report.notes.len() as u32);
    for note in &report.notes {
        put_str(out, note);
    }
    match report.emit {
        Some(d) => {
            put_u8(out, 1);
            put_u64(out, u64::try_from(d.as_nanos() / 1_000).unwrap_or(u64::MAX));
        }
        None => put_u8(out, 0),
    }
    match report.total {
        Some(d) => {
            put_u8(out, 1);
            put_u64(out, u64::try_from(d.as_nanos() / 1_000).unwrap_or(u64::MAX));
        }
        None => put_u8(out, 0),
    }
}

/// Decodes the reply's time-report tail (v40; see
/// [`encode_time_report`] for the shape). An unknown phase token or
/// detail kind is a malformed body — a refusal, never a silently
/// dropped row.
pub(crate) fn decode_time_report(
    r: &mut Reader<'_>,
) -> Result<Option<pgr_core::time_report::TimeReport>, DecodeError> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    let phases = (0..r.u32()?)
        .map(|_| {
            let phase = phase_from_token(r.u8()?)?;
            let detail = match r.u8()? {
                0 => pgr_core::observe::PhaseDetail::Objects {
                    inputs: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                1 => pgr_core::observe::PhaseDetail::Members {
                    pulled: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                2 => pgr_core::observe::PhaseDetail::Names {
                    interned: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                3 => pgr_core::observe::PhaseDetail::Winners {
                    reused: r.u8()? != 0,
                },
                4 => pgr_core::observe::PhaseDetail::Live {
                    active: r.u8()? != 0,
                },
                5 => pgr_core::observe::PhaseDetail::Folded {
                    folded: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                6 => pgr_core::observe::PhaseDetail::Planned {
                    segments: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                    sections: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                7 => pgr_core::observe::PhaseDetail::Reloc {
                    inputs: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                8 => pgr_core::observe::PhaseDetail::Gate {
                    pages: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                9 => pgr_core::observe::PhaseDetail::Plan {
                    tiles: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                    dirty: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                10 => pgr_core::observe::PhaseDetail::Patch {
                    bytes: r.u64()?,
                    tiles: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                11 => pgr_core::observe::PhaseDetail::Audit {
                    healed: r.u8()? != 0,
                    issues: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                12 => pgr_core::observe::PhaseDetail::Emitted {
                    tiles: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                    bytes: r.u64()?,
                },
                13 => pgr_core::observe::PhaseDetail::Flushed {
                    blocks: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                    writers: usize::try_from(r.u64()?).unwrap_or(usize::MAX),
                },
                _ => {
                    return Err(DecodeError::Malformed(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the time report carries an unknown detail kind",
                    )));
                }
            };
            let elapsed_us = r.u64()?;
            Ok(pgr_core::observe::PhaseEvent {
                phase,
                detail,
                elapsed: std::time::Duration::from_micros(elapsed_us),
            })
        })
        .collect::<Result<Vec<_>, DecodeError>>()?;
    let notes = (0..r.u32()?)
        .map(|_| r.str())
        .collect::<Result<Vec<_>, DecodeError>>()?;
    let emit = if r.u8()? == 0 {
        None
    } else {
        Some(std::time::Duration::from_micros(r.u64()?))
    };
    let total = if r.u8()? == 0 {
        None
    } else {
        Some(std::time::Duration::from_micros(r.u64()?))
    };
    Ok(Some(pgr_core::time_report::TimeReport {
        phases,
        emit,
        total,
        notes,
    }))
}

/// Decodes the reply's time-report tail from a whole body (v40) — the
/// byte-slice shape of the crate-private `decode_time_report`, for a consumer that
/// reads the tail in isolation (the wire codec's round-trip gate; the
/// client reads it inline after the image tail). Trailing bytes after
/// the tail refuse, like every body.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation, trailing bytes, an unknown
/// phase token or an unknown detail kind.
pub fn decode_time_report_bytes(
    body: &[u8],
) -> Result<Option<pgr_core::time_report::TimeReport>, DecodeError> {
    let mut r = Reader::new(body);
    let report = decode_time_report(&mut r)?;
    r.done()?;
    Ok(report)
}

// ---- the v41 trace-timeline tail ----------------------------------------------

/// Encodes the reply's trace-timeline tail (v41): a present byte, then —
/// when the request asked — the rendered timeline as one length-prefixed
/// UTF-8 string (the same one-line Trace Event Format document the
/// one-shot `--trace` writes; the strict reader is the document's own
/// face, so the wire carries the interchange bytes verbatim and never a
/// re-shape). An unasked timeline rides the absent byte.
pub fn encode_trace(out: &mut Vec<u8>, trace_json: Option<&str>) {
    match trace_json {
        Some(json) => {
            put_u8(out, 1);
            put_str(out, json);
        }
        None => put_u8(out, 0),
    }
}

/// Decodes the reply's trace-timeline tail (v41; see [`encode_trace`]
/// for the shape). The JSON rides verbatim — its own reader validates
/// the document, the wire validates the frame.
pub(crate) fn decode_trace(r: &mut Reader<'_>) -> Result<Option<String>, DecodeError> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    Ok(Some(r.str()?))
}

/// Decodes the reply's trace-timeline tail from a whole body (v41) — the
/// byte-slice shape of the crate-private `decode_trace`, for a consumer that reads the
/// tail in isolation (the wire codec's round-trip gate; the client
/// reads it inline after the time-report tail). Trailing bytes after
/// the tail refuse, like every body.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation or trailing bytes.
pub fn decode_trace_bytes(body: &[u8]) -> Result<Option<String>, DecodeError> {
    let mut r = Reader::new(body);
    let trace = decode_trace(&mut r)?;
    r.done()?;
    Ok(trace)
}

// ---- the v43 verify-verdict tail ----------------------------------------------

/// Encodes the reply's verify-verdict tail (v43): a present byte, then —
/// when the request asked — the effective report rendered in the M13
/// interchange form as one length-prefixed UTF-8 string (the same
/// one-line document the CLI's `--json` writes; the strict reader is
/// the document's own face, so the wire carries the interchange bytes
/// verbatim and never a re-shape). An unasked verdict rides the absent
/// byte.
pub fn encode_verify_report(out: &mut Vec<u8>, report: Option<&pgr_verify::Report>) {
    match report {
        Some(report) => {
            put_u8(out, 1);
            put_str(out, &pgr_verify::report_json::to_json(report));
        }
        None => put_u8(out, 0),
    }
}

/// Decodes the reply's verify-verdict tail (v43; see
/// [`encode_verify_report`] for the shape). The JSON rides verbatim —
/// a document the strict reader refuses is a malformed tail: the wire
/// never re-shapes, so it never re-excuses.
pub(crate) fn decode_verify_report(
    r: &mut Reader<'_>,
) -> Result<Option<pgr_verify::Report>, DecodeError> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    let json = r.str()?;
    pgr_verify::report_json::parse_report_json(&json).map_or_else(
        |e| {
            Err(DecodeError::Malformed(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the verify verdict's document does not parse: {e}"),
            )))
        },
        |report| Ok(Some(report)),
    )
}

/// Decodes the reply's verify-verdict tail from a whole body (v43) — the
/// byte-slice shape of the crate-private `decode_verify_report`, for a
/// consumer that reads the tail in isolation (the wire codec's
/// round-trip gate; the client reads it inline after the trace tail).
/// Trailing bytes after the tail refuse, like every body.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation, trailing bytes or a
/// document the strict reader refuses.
pub fn decode_verify_report_bytes(body: &[u8]) -> Result<Option<pgr_verify::Report>, DecodeError> {
    let mut r = Reader::new(body);
    let report = decode_verify_report(&mut r)?;
    r.done()?;
    Ok(report)
}

// ---- the v45 provenance tail -------------------------------------------------

/// One served `-why_export` answer (v45, M79): the queried name beside
/// the rendered text the cold lane prints — the wire carries the render
/// verbatim (the M62 convention: the wire never re-shapes the face the
/// client prints, so it never re-excuses it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedExport {
    /// The queried name (with the C underscore, verbatim).
    pub name: String,
    /// The answer's rendered text ([`pgr_core::provenance::RefExplanation::render`]
    /// — the definition the resolution installed and every reference
    /// site, in the index's own order).
    pub render: String,
}

/// One served `-why_live` answer (v48, M93): the queried name beside the
/// rendered chain the cold lane prints — the mark phase's own record
/// walked from the queried definition back to its root
/// ([`pgr_core::why_live::WhyLiveExplanation::render`], the verdict line,
/// one keeper per hop and the root decision). The wire carries the
/// render verbatim (the M62 convention).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedLive {
    /// The queried name (with the C underscore, verbatim).
    pub name: String,
    /// The answer's rendered text — the chain the strip kept (or the
    /// drop verdict), the same deterministic text the cold lane prints.
    pub render: String,
}

/// The served provenance answers (v45, M79): one entry per
/// `-why_export` query, in flag order, beside the `-why_load` report
/// when the request asked. `None` rides absent — an unasked query
/// crosses nothing (the tail is one byte). M93 (v48): the liveness
/// answers ride beside them — one entry per `-why_live` query, in flag
/// order (the empty list is the pre-M93 shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedProvenance {
    /// The export answers, in the request's flag order.
    pub exports: Vec<ServedExport>,
    /// The load report's rendered text (the S7 pull's per-member
    /// decision and the dylib carriage rows), when the request asked.
    pub loads: Option<String>,
    /// The liveness chains, in the request's flag order (M93, v48).
    pub lives: Vec<ServedLive>,
}

/// Encodes the reply's provenance tail (v45): a present byte, then —
/// when the request asked and the session answered — the export answers
/// (count-prefixed; per entry the name and the render, length-prefixed
/// strings) and the load report (a present byte + the render). A
/// request that asked nothing rides the absent byte. M93 (v48): the
/// liveness answers ride beside them — a count-prefixed list of
/// (name, render) pairs, the same shape (the pre-M93 replies carry the
/// empty list).
pub fn encode_provenance(out: &mut Vec<u8>, served: Option<&ServedProvenance>) {
    let Some(served) = served else {
        put_u8(out, 0);
        return;
    };
    put_u8(out, 1);
    put_u32(out, served.exports.len() as u32);
    for export in &served.exports {
        put_str(out, &export.name);
        put_str(out, &export.render);
    }
    match &served.loads {
        Some(render) => {
            put_u8(out, 1);
            put_str(out, render);
        }
        None => put_u8(out, 0),
    }
    put_u32(out, served.lives.len() as u32);
    for live in &served.lives {
        put_str(out, &live.name);
        put_str(out, &live.render);
    }
}

/// Decodes the reply's provenance tail (v45; see [`encode_provenance`]
/// for the shape). An empty answer name is a malformed tail — a query
/// names its answer, the session never renders one without.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation or a nameless answer.
pub(crate) fn decode_provenance(
    r: &mut Reader<'_>,
) -> Result<Option<ServedProvenance>, DecodeError> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    let exports = (0..r.u32()?)
        .map(|_| {
            Ok(ServedExport {
                name: r.str()?,
                render: r.str()?,
            })
        })
        .collect::<Result<Vec<ServedExport>, DecodeError>>()?;
    if exports.iter().any(|e| e.name.is_empty()) {
        return Err(DecodeError::Malformed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the provenance tail answers a query that named no symbol",
        )));
    }
    let loads = if r.u8()? == 0 { None } else { Some(r.str()?) };
    // M93 (v48): the liveness answers (see encode). The same grammar:
    // an empty name is a malformed tail.
    let lives = (0..r.u32()?)
        .map(|_| {
            Ok(ServedLive {
                name: r.str()?,
                render: r.str()?,
            })
        })
        .collect::<Result<Vec<ServedLive>, DecodeError>>()?;
    if lives.iter().any(|l| l.name.is_empty()) {
        return Err(DecodeError::Malformed(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the provenance tail's liveness answers include an entry that named \
             no symbol",
        )));
    }
    Ok(Some(ServedProvenance {
        exports,
        loads,
        lives,
    }))
}

/// Decodes the reply's provenance tail from a whole body (v45) — the
/// byte-slice shape of the crate-private `decode_provenance`, for a
/// consumer that reads the tail in isolation (the wire codec's
/// round-trip gate; the client reads it inline after the verify tail).
/// Trailing bytes after the tail refuse, like every body.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation, trailing bytes or a
/// nameless answer.
pub fn decode_provenance_bytes(body: &[u8]) -> Result<Option<ServedProvenance>, DecodeError> {
    let mut r = Reader::new(body);
    let served = decode_provenance(&mut r)?;
    r.done()?;
    Ok(served)
}

// ---- the v46 link-map tail -----------------------------------------------------

/// Encodes the reply's link-map tail (v46): a present byte, then — when
/// the request asked — the rendered map document as one length-prefixed
/// UTF-8 string (the same deterministic text the cold lane's `-map`
/// writes; the wire never re-shapes the face the client writes to the
/// `-map` path). An unasked map rides the absent byte.
pub fn encode_map(out: &mut Vec<u8>, document: Option<&str>) {
    match document {
        Some(text) => {
            put_u8(out, 1);
            put_str(out, text);
        }
        None => put_u8(out, 0),
    }
}

/// Decodes the reply's link-map tail (v46; see [`encode_map`] for the
/// shape). The document rides verbatim — the client writes the file.
pub(crate) fn decode_map(r: &mut Reader<'_>) -> Result<Option<String>, DecodeError> {
    if r.u8()? == 0 {
        return Ok(None);
    }
    Ok(Some(r.str()?))
}

/// Decodes the reply's link-map tail from a whole body (v46) — the
/// byte-slice shape of the crate-private `decode_map`, for a consumer
/// that reads the tail in isolation (the wire codec's round-trip gate;
/// the client reads it inline after the provenance tail). Trailing
/// bytes after the tail refuse, like every body.
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation or trailing bytes.
pub fn decode_map_bytes(body: &[u8]) -> Result<Option<String>, DecodeError> {
    let mut r = Reader::new(body);
    let document = decode_map(&mut r)?;
    r.done()?;
    Ok(document)
}

// ---- the v54 policy-warning tail ------------------------------------------------

/// Encodes the reply's policy-warning tail (v54, M103): a count-prefixed
/// list of the session's unresolved-open entries — the exit policy's
/// warning face, rendered from the session's own Pass-2 product. The
/// suppress face carries the empty list (the walk recorded it, the exit
/// prints none of it); a non-warning policy never fills the list. The
/// client prints each entry as the cold lane's `pgr: warning:` face —
/// the wire never re-shapes the face the client prints (the M62
/// convention).
pub fn encode_policy_warnings(out: &mut Vec<u8>, entries: &[String]) {
    put_u32(out, entries.len() as u32);
    for entry in entries {
        put_str(out, entry);
    }
}

/// Decodes the reply's policy-warning tail (v54; see
/// [`encode_policy_warnings`] for the shape).
///
/// # Errors
/// [`DecodeError::Malformed`] on truncation.
pub(crate) fn decode_policy_warnings(r: &mut Reader<'_>) -> Result<Vec<String>, DecodeError> {
    (0..r.u32()?).map(|_| r.str()).collect()
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
            // M83: the relocatable shape rides the daemon (until then the
            // driver refused `-r -resident` at parse time and the wire
            // value stayed reserved).
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
            UndefinedPolicy::Warning => 2,
            UndefinedPolicy::Suppress => 3,
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
        // M45 (v32 wire): the upward-load kind rides beside lazy — the
        // wire never silently flattens an `LC_LOAD_UPWARD_DYLIB` request
        // into a plain load.
        put_u8(out, u8::from(d.upward));
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
    // M28 (v19 wire): the section-alignment floors ride the tail after
    // the PIE decision — count, then one (segment, section, exponent)
    // triple per `-sectalign` decision, in flag order; a resident
    // relink aligns the sections the client named, never the pre-M28
    // input-only shape. The decode pays the seam's validation through
    // the raw door, so a foreign frame is malformed, never a silently
    // widened alignment.
    put_u32(out, cfg.sect_aligns.iter().count() as u32);
    for d in cfg.sect_aligns.iter() {
        put_str(out, d.segment().name());
        put_str(out, d.section());
        put_u8(out, d.align_log2() as u8);
    }
    // M29 (v20 wire): the header-region floor rides the tail after the
    // section-alignment floors — a present byte, then the `-headerpad`
    // floor as a u64; a resident relink reserves the region the client
    // named, never the pre-M29 natural size alone.
    if let Some(pad) = &cfg.header_pad {
        put_u8(out, 1);
        put_u64(out, pad.floor_bytes());
    } else {
        put_u8(out, 0);
    }
    // M30 (v21 wire): the data-in-code suppression rides the tail after
    // the header-region floor — one byte naming whether the image drops
    // the `LC_DATA_IN_CODE` command; a resident relink carries the
    // stream decision the client asked for, never the pre-M30
    // carry-when-named default.
    put_u8(out, u8::from(!cfg.data_in_code));
    // M31 (v22 wire): the function-starts suppression rides the tail
    // after the data-in-code suppression — one byte; a resident relink
    // carries the linkedit-metadata decision the client asked for,
    // never the pre-M31 always-carried default.
    put_u8(out, u8::from(!cfg.function_starts));
    // M32 (v23 wire): the UUID suppression rides the tail after the
    // function-starts suppression — one byte; a resident relink
    // carries the derived-UUID decision the client asked for, never
    // the pre-M32 always-carried default.
    put_u8(out, u8::from(!cfg.uuid));
    // M33 (v24 wire): the private-extern keep rides the tail after the
    // UUID suppression — one byte; a resident relink carries the
    // private-extern decision the client asked for, never the pre-M33
    // conversion default.
    put_u8(out, u8::from(cfg.keep_private_externs));
    // M36 (v25 wire): the compact-unwind suppression rides the tail
    // after the private-extern keep — one byte; a resident relink
    // carries the suppression decision the client asked for, never the
    // pre-M36 carry default.
    put_u8(out, u8::from(!cfg.compact_unwind));
    // M38 (v26 wire): the install-name auto-floor rides the tail after
    // the compact-unwind suppression — one byte; a resident relink
    // carries the header-pad decision the client asked for, never the
    // pre-M38 natural default.
    put_u8(out, u8::from(cfg.header_pad_max_install_names));
    // M39 (v27 wire): the make-undefined marks ride the tail after the
    // auto-floor — count-prefixed names (the rpaths shape); a resident
    // relink strips the definitions the client marked, never the
    // pre-M39 carried definitions.
    put_u32(out, cfg.make_undefined.count() as u32);
    for name in cfg.make_undefined.names() {
        put_str(out, name);
    }
    // M40 (v28 wire): the export-trie suppression rides the tail after
    // the marks — one byte; a resident relink carries the
    // export-surface decision the client asked for, never the pre-M40
    // always-carried default.
    put_u8(out, u8::from(!cfg.exported_symbols));
    // M41 (v29 wire): the dedup toggle rides the tail after the
    // export-trie suppression — one byte; a resident relink carries the
    // D4 decision the client asked for, never the pre-M41 merge
    // default.
    put_u8(out, u8::from(!cfg.deduplicate));
    // M42 (v30 wire): the unused-dylib drop rides the tail after the
    // dedup toggle — one byte; a resident relink carries the drop
    // decision the client asked for, never the pre-M42 keep-every-dylib
    // default.
    put_u8(out, u8::from(cfg.dead_strip_dylibs));
    // M43 (v31 wire): the ObjC pull rides the tail after the drop — one
    // byte; a resident relink carries the pull decision the client
    // asked for, never the pre-M43 reference-driven default.
    put_u8(out, u8::from(cfg.objc));
    // M46 (v33 wire): the export-dynamic roots ride the tail after the
    // pull — one byte; a resident relink carries the root-widening
    // decision the client asked for, never the pre-M46 entry-root
    // default.
    put_u8(out, u8::from(cfg.export_dynamic));
    // M47 (v34 wire): the branch-island suppression rides the tail after
    // the roots — one byte naming whether the layout stops planning
    // veneers (the default rides 0, the house convention the
    // default-true knobs pay: uuid, function starts, compact unwind); a
    // resident relink carries the suppression decision the client asked
    // for, never the pre-M47 islands-by-default.
    put_u8(out, u8::from(!cfg.branch_islands));
    // M48 (v35 wire): the dylib initializer rides the tail after the
    // islands — a present byte, then the `-init` symbol name; a resident
    // relink carries the initializer the client named, never the pre-M48
    // absence.
    if let Some(name) = &cfg.init_symbol {
        put_u8(out, 1);
        put_str(out, name);
    } else {
        put_u8(out, 0);
    }
    // M98 (v49 wire): the dylib terminator rides the tail after the
    // initializer — a present byte, then the `-term` symbol name; a
    // resident relink carries the terminator the client named, never
    // the pre-M98 absence (the M48 v35 shape, one field over).
    if let Some(name) = &cfg.term_symbol {
        put_u8(out, 1);
        put_str(out, name);
    } else {
        put_u8(out, 0);
    }
    // M99 (v50 wire): the named output UUID rides the tail after the
    // terminator — a present byte, then the 16 bytes; a resident relink
    // carries the identity the client named, never the content-derived
    // default.
    match cfg.named_uuid {
        Some(bytes) => {
            put_u8(out, 1);
            out.extend_from_slice(&bytes);
        }
        None => put_u8(out, 0),
    }
    // M50 (v36 wire): the weak-import refusal rides the tail after the
    // initializer — one byte; a resident relink carries the decision the
    // client asked for, never the pre-M50 runtime-lookup fallthrough.
    put_u8(out, u8::from(cfg.no_weak_imports));
    // M51 (v37 wire): the stack-execution decision rides the tail after
    // the weak-import refusal — one byte; a resident relink carries the
    // flag word the client asked for, never the pre-M51 bitless
    // default.
    put_u8(out, u8::from(cfg.allow_stack_execute));
    // M52 (v38 wire): the dead-strip init/term roots ride the tail
    // after the stack-execution decision — one byte; a resident relink
    // strips the routines the client asked to keep, never the pre-M52
    // term-strip default.
    put_u8(out, u8::from(cfg.no_dead_strip_inits_and_terms));
    // M53 (v39 wire): the section renames ride the tail after the
    // init/term roots — a count-prefixed table, four names per entry
    // (the source pair, then the target pair, each length-prefixed); a
    // resident relink renames the sections the client named, never the
    // pre-M53 unnamed pairs.
    put_u32(out, cfg.renames.len() as u32);
    for rename in cfg.renames.iter() {
        put_str(out, rename.from_seg());
        put_str(out, rename.from_sect());
        put_str(out, rename.to_seg());
        put_str(out, rename.to_sect());
    }
    // M81 (v47): the order-file rank table rides the tail after the
    // renames — a present byte, then a count-prefixed entry list (per
    // entry the optional object scope, the symbol, the diagnostics
    // line); a resident ordered link ranks the entries the client named,
    // never the default absence.
    match &cfg.symbol_order {
        Some(order) => {
            put_u8(out, 1);
            put_u32(out, order.entries().len() as u32);
            for entry in order.entries() {
                put_opt_str(out, entry.object.as_deref());
                put_str(out, &entry.symbol);
                put_u32(out, u32::try_from(entry.line).unwrap_or(u32::MAX));
            }
        }
        None => put_u8(out, 0),
    }
    // M91: the cstring rank table rides the v47 tail after the rank
    // table — a present byte, then a count-prefixed list of
    // length-prefixed decoded literal contents in rank order; a resident
    // link orders the `__cstring` literals the client named, never the
    // default absence.
    match &cfg.cstring_order {
        Some(ranks) => {
            put_u8(out, 1);
            put_u32(out, ranks.entries().len() as u32);
            for entry in ranks.entries() {
                put_u32(out, entry.len() as u32);
                out.extend_from_slice(entry);
            }
        }
        None => put_u8(out, 0),
    }
    // M102 (v53 wire): the bind-at-load decision rides the tail after
    // the cstring rank table — one byte; a resident relink carries the
    // flag word the client asked for, never the pre-M102 bitless
    // default.
    put_u8(out, u8::from(cfg.bind_at_load));
    // M104 (v55 wire): the symtab-shaping decision rides the tail after
    // the bind-at-load byte — one byte; a resident relink carries the
    // symtab shape the client asked for, never the pre-M104 kept
    // default.
    put_u8(out, u8::from(cfg.keep_local_symbols));
    // M105 (v56 wire): the debug-section suppression rides the tail
    // after the symtab-shaping byte — one byte; a resident relink
    // carries the debug-free shape the client asked for, never the
    // pre-M105 debug-carrying default.
    put_u8(out, u8::from(cfg.strip_debug));
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
        // M83: the relocatable shape rides the daemon — the session's
        // walk runs the object path over the raw blobs and the reply
        // carries the MH_OBJECT verbatim (the replay faces beside it
        // refuse at the gates below).
        3 => OutputType::Relocatable,
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
        2 => UndefinedPolicy::Warning,
        3 => UndefinedPolicy::Suppress,
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
                // M45 (v32 wire): the upward-load kind (the mirror of the
                // encode's fourth kind byte).
                upward: r.u8()? != 0,
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
    // M28 (v19 wire): the section-alignment floors — count, then one
    // (segment, section, exponent) triple per decision, in flag order.
    // The raw door pays the same validation the flag does (the
    // section-bearing segment, the 16-byte name grammar, the 0x4000
    // ceiling), and a twice-named pair is a malformed frame, never a
    // last-write-wins surprise.
    let mut sect_aligns = pgr_core::sect_align::SectAlignTable::default();
    for _ in 0..r.u32()? {
        let seg = pgr_core::segprot::SegName::parse(&r.str()?).map_err(|_| malformed())?;
        let sect = r.str()?;
        let exp = u32::from(r.u8()?);
        let decision = pgr_core::sect_align::SectAlign::from_exponent(seg, &sect, exp)
            .map_err(|_| malformed())?;
        sect_aligns.push(decision).map_err(|_| malformed())?;
    }
    // M29 (v20 wire): the header-region floor — a present byte, then
    // the floor as a u64. The decode pays the seam's validation (the
    // raw door refuses zero, an unaligned value and anything beyond
    // the first page), so a foreign frame is malformed, never a
    // silently grown reservation.
    let header_pad = if r.u8()? == 0 {
        None
    } else {
        Some(pgr_core::header_pad::HeaderPad::from_override(r.u64()?).map_err(|_| malformed())?)
    };
    // M30 (v21 wire): the data-in-code suppression — one byte, no
    // validation beyond the bool (there is no output-kind conflict;
    // the carriage simply never fires on the relocatable path).
    let no_data_in_code = r.u8()? != 0;
    // M31 (v22 wire): the function-starts suppression — one byte, no
    // validation beyond the bool (the verifier validates the payload
    // only when the command is present).
    let no_function_starts = r.u8()? != 0;
    // M32 (v23 wire): the UUID suppression — one byte, no validation
    // beyond the bool (the absence is the decision; the carried
    // payload is opaque).
    let no_uuid = r.u8()? != 0;
    // M33 (v24 wire): the private-extern keep — one byte, no
    // validation beyond the bool (the conversion is the default; the
    // input `N_PEXT` bit names where the decision fires).
    let keep_private_externs = r.u8()? != 0;
    // M36 (v25 wire): the compact-unwind suppression — one byte, no
    // validation beyond the bool (the absence is the decision; the
    // parse validates the table the carriage would have carried).
    let no_compact_unwind = r.u8()? != 0;
    // M38 (v26 wire): the install-name auto-floor — one byte, no
    // validation beyond the bool (the growth is a packing-loop floor
    // the layout computes from the dylib install names).
    let header_pad_max = r.u8()? != 0;
    // M39 (v27 wire): the make-undefined marks — count-prefixed names
    // (the rpaths shape); the names ride the core seam's validation, so
    // a malformed frame names the grammar it broke.
    let mut make_undefined = pgr_core::make_undefined::MakeUndefined::new();
    for _ in 0..r.u32()? {
        let name = pgr_core::MakeUndefinedName::from_flag(&r.str()?).map_err(|_| malformed())?;
        make_undefined.push(name).map_err(|_| malformed())?;
    }
    // M40 (v28 wire): the export-trie suppression — one byte, no
    // validation beyond the bool (the absence is the decision; the
    // output-kind conflicts the core re-checks refuse at link time).
    let no_exported_symbols = r.u8()? != 0;
    // M41 (v29 wire): the dedup toggle — one byte, no validation
    // beyond the bool (the merge follows the decision; the pass-through
    // shape the core plans is contract-free).
    let no_deduplicate = r.u8()? != 0;
    // M42 (v30 wire): the unused-dylib drop — one byte; the resolve
    // compacts the kept list at link time (the re-export exemption and
    // the dynamic-lookup reach the core re-checks refuse).
    let dead_strip_dylibs = r.u8()? != 0;
    // M43 (v31 wire): the ObjC pull — one byte, no validation beyond
    // the bool (the pull reads the decision in the S7 fixpoint; the
    // metadata members ride in member file order either way).
    let objc = r.u8()? != 0;
    // M46 (v33 wire): the export-dynamic roots — one byte, no validation
    // beyond the bool (the roots widen the mark phase at link time; the
    // output-kind conflicts the core re-checks refuse at link time).
    let export_dynamic = r.u8()? != 0;
    // M47 (v34 wire): the branch-island suppression — one byte, no
    // validation beyond the bool (the fixed point reads the decision at
    // link time; the out-of-range refusal is the layout's typed error).
    // The byte is the suppression (the default rides 0), so the
    // decision reconstructs negated.
    let no_branch_islands = r.u8()? != 0;
    // M48 (v35 wire): the dylib initializer — a present byte, then the
    // name (the v17 dylinker shape); the name resolves at link time
    // (the unresolved one is the core's Symbol refusal, the output-kind
    // conflicts its re-check's).
    let init_symbol = if r.u8()? != 0 { Some(r.str()?) } else { None };
    // M98 (v49 wire): the dylib terminator (see encode) — a present
    // byte, then the name (the v35 initializer shape); the name
    // resolves at link time (the unresolved one is the core's Symbol
    // refusal, the output-kind conflicts its re-check's).
    let term_symbol = if r.u8()? != 0 { Some(r.str()?) } else { None };
    // M99 (v50 wire): the named output UUID (see encode) — a present
    // byte, then the 16 bytes; any value the parse could produce rides
    // (the bytes are the identity, no further grammar to validate on
    // the wire).
    let named_uuid = if r.u8()? != 0 {
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(r.take(16)?);
        Some(bytes)
    } else {
        None
    };
    // M50 (v36 wire): the weak-import refusal — one byte, no validation
    // beyond the bool (the decision reads in the resolve's undefined
    // walk; the refusal is the core's typed Symbol error, a link-time
    // resolution never refuses).
    let no_weak_imports = r.u8()? != 0;
    // M51 (v37 wire): the stack-execution decision — one byte, no
    // validation beyond the bool (the flag-word assembly reads the
    // decision; the output-kind conflicts the core re-checks refuse at
    // link time).
    let allow_stack_execute = r.u8()? != 0;
    // M52 (v38 wire): the dead-strip init/term roots — one byte, no
    // validation beyond the bool (the dead-strip root set reads the
    // decision; without `-dead_strip` it never fires).
    let no_dead_strip_inits_and_terms = r.u8()? != 0;
    // M53 (v39 wire): the section renames — a count-prefixed table, four
    // names per entry (the source pair, then the target pair). The table
    // re-validates on decode (the seam's grammar — field widths, the
    // synthetic targets, the doubled source): a rename the seam refuses
    // is a malformed frame, the wire never carries a decision the core
    // would refuse at the classification.
    let rename_count = r.u32()?;
    let mut rename_entries = Vec::with_capacity(rename_count as usize);
    for _ in 0..rename_count {
        let from_seg = r.str()?;
        let from_sect = r.str()?;
        let to_seg = r.str()?;
        let to_sect = r.str()?;
        rename_entries.push((from_seg, from_sect, to_seg, to_sect));
    }
    let renames = pgr_core::rename::SectionRenames::new(
        rename_entries
            .iter()
            .map(|(a, b, c, d)| (a.as_str(), b.as_str(), c.as_str(), d.as_str()))
            .collect(),
    )
    .map_err(|_| malformed())?;
    // M81 (v47 wire): the order-file rank table (see encode). The absent
    // byte is the pre-M81 shape (every clean link); a table the
    // constructor refuses — an empty list, two ranks for one symbol — is
    // a malformed request: the wire never carries a table the pipeline
    // would silently misread (the parse's own refusals, mirrored here
    // with the lines carried so the report reads like the cold lane's).
    let symbol_order = if r.u8()? == 0 {
        None
    } else {
        let count = r.u32()?;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let object = r.opt_str()?;
            let symbol = r.str()?;
            let line = r.u32()?;
            entries.push(pgr_core::order::OrderEntry {
                symbol,
                object,
                line: usize::try_from(line).unwrap_or(usize::MAX),
            });
        }
        Some(
            pgr_core::order::SymbolOrder::from_entries(entries).map_err(|e| {
                DecodeError::Malformed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the request's order-file rank table does not parse: {e}"),
                ))
            })?,
        )
    };
    // M91: the cstring rank table (see encode), riding the v47 tail. The absent
    // byte is the pre-M91 shape; a table the rebuild refuses — two ranks
    // for one literal — is a malformed request (the parse's own
    // refusal, the rank positions named).
    let cstring_order = if r.u8()? == 0 {
        None
    } else {
        let count = r.u32()?;
        let mut entries = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let len = r.u32()? as usize;
            let bytes = r.take(len)?;
            entries.push(bytes.to_vec());
        }
        Some(
            pgr_core::order::CstringOrder::from_entries(entries).map_err(|e| {
                DecodeError::Malformed(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the request's cstring rank table does not parse: {e}"),
                ))
            })?,
        )
    };
    // M102 (v53 wire): the bind-at-load decision — one byte, no
    // validation beyond the bool (the flag-word assembly reads the
    // decision; the output-kind conflicts the core re-checks refuse at
    // link time).
    let bind_at_load = r.u8()? != 0;
    // M104 (v55 wire): the symtab-shaping decision — one byte, no
    // validation beyond the bool (the symtab builder reads the
    // decision; the relocatable-shape conflict the core re-checks
    // refuse at link time).
    let keep_local_symbols = r.u8()? != 0;
    // M105 (v56 wire): the debug-section suppression — one byte, no
    // validation beyond the bool (the Pass-1 classification reads the
    // decision; the relocatable-shape conflict the core re-checks
    // refuse at link time).
    let strip_debug = r.u8()? != 0;
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
        // M11: the order-file rank table rides the v47 tail now (M81) —
        // a resident ordered link ranks the entries the client named;
        // a table the constructor refuses refuses the request (never a
        // silently misread table).
        symbol_order,
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
        sect_aligns,
        header_pad,
        data_in_code: !no_data_in_code,
        function_starts: !no_function_starts,
        uuid: !no_uuid,
        keep_private_externs,
        compact_unwind: !no_compact_unwind,
        header_pad_max_install_names: header_pad_max,
        make_undefined,
        exported_symbols: !no_exported_symbols,
        deduplicate: !no_deduplicate,
        dead_strip_dylibs,
        objc,
        export_dynamic,
        branch_islands: !no_branch_islands,
        init_symbol,
        term_symbol,
        named_uuid,
        no_weak_imports,
        allow_stack_execute,
        bind_at_load,
        keep_local_symbols,
        strip_debug,
        no_dead_strip_inits_and_terms,
        renames,
        cstring_order,
    })
}

// ---- frame-level round-trip gates -------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        ArchiveEntry, DecodeError, InputEntry, LinkRequest, PROTO_VERSION, Reader, ServedExport,
        ServedLive, ServedProvenance, TAG_LINK, content_hash, decode_map_bytes,
        decode_policy_warnings, decode_provenance_bytes, decode_time_report, decode_trace_bytes,
        decode_verify_report_bytes, encode_map, encode_policy_warnings, encode_provenance,
        encode_time_report, encode_trace, encode_verify_report, put_str, put_u8, put_u32, put_u64,
        read_pattern,
    };
    use pgr_core::export_filter::SymbolPattern;
    use pgr_core::fixups::FixupPointerFormat;
    use pgr_core::layout::{LinkConfig, OutputType};
    use pgr_core::observe::LinkObserver;
    use pgr_core::resolve::Dylib;

    /// The M99 example value's raw bytes (the round-trip gate's named
    /// identity).
    const NAMED_BYTES: [u8; 16] = [
        0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e, 0x7f,
        0x80,
    ];

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
                upward: true,
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
            // The v53 tail: a non-default bind-at-load decision must
            // survive the round trip verbatim (a resident relink carries
            // the flag word the client asked for, never the pre-M102
            // bitless default).
            bind_at_load: true,
            // The v55 tail: a non-default symtab-shaping decision must
            // survive the round trip verbatim (a resident relink carries
            // the symtab shape the client asked for, never the pre-M104
            // kept default).
            keep_local_symbols: false,
            // The v56 tail: a non-default debug-section suppression must
            // survive the round trip verbatim (a resident relink carries
            // the debug-free shape the client asked for, never the
            // pre-M105 debug-carrying default).
            strip_debug: true,
            // The v19 tail: non-default section-alignment floors must
            // survive the round trip verbatim, in flag order (a
            // resident relink aligns the sections the client named,
            // never the pre-M28 input-only shape).
            sect_aligns: {
                let mut table = pgr_core::sect_align::SectAlignTable::default();
                table
                    .push(
                        pgr_core::sect_align::SectAlign::from_flag("__DATA", "__data", 0x4000)
                            .expect("the floor validates"),
                    )
                    .expect("one decision per pair");
                table
                    .push(
                        pgr_core::sect_align::SectAlign::from_flag("__TEXT", "__text", 0x1000)
                            .expect("the floor validates"),
                    )
                    .expect("one decision per pair");
                table
            },
            // The v20 tail: a non-default header-region floor must
            // survive the round trip verbatim (a resident relink
            // reserves the region the client named, never the pre-M29
            // natural size alone).
            header_pad: Some(
                pgr_core::header_pad::HeaderPad::from_override(0x2000)
                    .expect("the floor validates"),
            ),
            // The v21 tail: a non-default data-in-code suppression must
            // survive the round trip verbatim (a resident relink
            // carries the stream decision the client asked for, never
            // the pre-M30 carry-when-named default).
            data_in_code: false,
            // The v22 tail: a non-default function-starts suppression
            // must survive the round trip verbatim (a resident relink
            // carries the linkedit-metadata decision the client asked
            // for, never the pre-M31 always-carried default).
            function_starts: false,
            // The v23 tail: a non-default UUID suppression must survive
            // the round trip verbatim (a resident relink carries the
            // derived-UUID decision the client asked for, never the
            // pre-M32 always-carried default).
            uuid: false,
            // The v24 tail: a non-default private-extern keep must
            // survive the round trip verbatim (a resident relink
            // carries the private-extern decision the client asked
            // for, never the pre-M33 conversion default).
            keep_private_externs: true,
            // The v25 tail: the compact-unwind suppression rides the
            // default here — the rich config's non-default knobs are
            // the ones that shape bytes, and the suppression is the
            // knob the round-trip test flips.
            compact_unwind: true,
            header_pad_max_install_names: false,
            // The v27 tail: a non-default make-undefined table must
            // survive the round trip verbatim, in flag order (a
            // resident relink strips the definitions the client
            // marked, never the pre-M39 carried definitions).
            make_undefined: {
                let mut marks = pgr_core::make_undefined::MakeUndefined::new();
                marks
                    .push(pgr_core::MakeUndefinedName::from_flag("_override_me").expect("valid"))
                    .expect("one decision per name");
                marks
                    .push(pgr_core::MakeUndefinedName::from_flag("_also_gone").expect("valid"))
                    .expect("one decision per name");
                marks
            },
            // The v28 tail: the export-trie suppression rides the
            // default here — the knob the round-trip test flips.
            exported_symbols: true,
            // The v29 tail: the dedup toggle rides the default here —
            // the knob the round-trip test flips.
            deduplicate: true,
            // The v30 tail: the unused-dylib drop rides the default
            // here — the knob the round-trip test flips.
            dead_strip_dylibs: false,
            // The v31 tail: the ObjC pull rides the default here — the
            // decision the round-trip test flips.
            objc: false,
            // The v33 tail: the export-dynamic roots ride the default
            // here — the decision the round-trip test flips.
            export_dynamic: false,
            // The v34 tail: the branch-island suppression rides the
            // default here — the decision the round-trip test flips
            // (ld64's islands-by-default).
            branch_islands: true,
            // The v35 tail: the dylib initializer rides the default
            // here — the name the round-trip test names.
            init_symbol: None,
            // The v49 tail: the dylib terminator rides the default
            // here — the name the round-trip test names.
            term_symbol: None,
            // The v50 tail: the named output UUID rides the default
            // here — the bytes the round-trip test names.
            named_uuid: None,
            // The v36 tail: the weak-import refusal rides the default
            // here — the round-trip test names the set decision.
            no_weak_imports: false,
            // The v37 tail: the stack-execution decision rides the
            // default here — the decision the round-trip test flips.
            allow_stack_execute: false,
            // The v38 tail: the dead-strip init/term roots ride the
            // default here — the decision the round-trip test flips.
            no_dead_strip_inits_and_terms: false,
            // The v39 tail: a non-default rename map must survive the
            // round trip verbatim, in flag order (a resident relink
            // renames the sections the client named, never the pre-M53
            // unnamed pairs). The names stay off every other needle in
            // these tests — the splice gates corrupt exactly one field.
            renames: {
                let mut renames = pgr_core::rename::SectionRenames::default();
                renames
                    .push(
                        pgr_core::rename::SectionRename::from_flag(
                            "__DATA",
                            "__mydata",
                            "__DATA",
                            "__ro_data",
                        )
                        .expect("the rename validates"),
                    )
                    .expect("one decision per source");
                renames
                    .push(
                        pgr_core::rename::SectionRename::from_flag(
                            "__DATA",
                            "__other",
                            "__DATA",
                            "__rw_data",
                        )
                        .expect("the rename validates"),
                    )
                    .expect("one decision per source");
                renames
            },
            symbol_order: None,
            cstring_order: None,
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: true,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        // The audit flag flips cleanly over the wire.
        req.audit = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
    }

    #[test]
    fn verify_flag_round_trips_cleanly() {
        // v43 (M72): the verify-verdict request flag rides beside the
        // timing faces; the flag flips cleanly over the wire.
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: true,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        req.verify = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
    }

    #[test]
    fn verify_checks_selection_round_trips() {
        // v44 (M77): the verify gate's check selection rides the
        // selector's own canonical form — the decode side restores the
        // set exactly, and the absent byte names the full pass.
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: true,
            verify_checks: Some(
                pgr_verify::CheckSet::parse("segments,signature").expect("canonical names"),
            ),
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        // A different selection is a different request.
        req.verify_checks = Some(pgr_verify::CheckSet::parse("tlv").expect("canonical names"));
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
        // The absent byte still decodes to the full pass (None).
        req.verify_checks = None;
        let plain = LinkRequest::decode(&req.encode()).unwrap();
        assert!(plain.verify_checks.is_none());
    }

    #[test]
    fn verify_checks_refuses_an_unknown_family() {
        // The selection rides the selector's canonical form: a body a
        // parser refuses is a malformed request (the wire never carries
        // a gate the pipeline would silently widen).
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
            time: false,
            trace: false,
            verify: true,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        // Hand-splice the malformed selection past the well-formed tail:
        // encode a plain request body, drop the trailing absent byte and
        // the v45 provenance fields beside it plus the v46 map flag and
        // the v48 liveness count (the count u32, the load-report flag,
        // the map flag, the liveness count u32 — eleven bytes), append
        // the malformed one. The selection's parse refuses before the
        // decoder reads past it — the spliced tail rides no further
        // fields.
        let mut wire = req.encode();
        wire.truncate(wire.len() - 11);
        put_u8(&mut wire, 1);
        put_str(&mut wire, "segmants");
        let err = LinkRequest::decode(&wire).unwrap_err();
        match err {
            DecodeError::Malformed(e) => {
                let text = e.to_string();
                assert!(
                    text.contains("segmants"),
                    "the refusal names the offending token: {text}"
                );
            }
            other => panic!("expected a malformed body, got {other:?}"),
        }
    }

    #[test]
    fn verify_tail_round_trips_the_report() {
        // v43 (M72): the served verify verdict rides the M13 interchange
        // form — the strict reader is the document's own face, so the
        // round trip restores the report whole (issues, stats). An
        // unasked verdict rides the absent byte.
        let mut report = pgr_verify::Report::default();
        report.issues.push(pgr_verify::Issue::error(
            pgr_verify::Code::SegmentContract,
            "the vmaddr breaks the 16 KiB congruence",
            Some(4096),
        ));
        report.issues.push(pgr_verify::Issue::warning(
            pgr_verify::Code::Suspicious,
            "the symtab carries an odd n_desc",
            None,
        ));
        report.stats.segments = 3;
        report.stats.fixup_slots = 17;
        let mut body = Vec::new();
        encode_verify_report(&mut body, Some(&report));
        let back = decode_verify_report_bytes(&body)
            .unwrap()
            .expect("the verdict rides");
        assert_eq!(back, report);
        let mut absent = Vec::new();
        encode_verify_report(&mut absent, None);
        assert!(decode_verify_report_bytes(&absent).unwrap().is_none());
    }

    #[test]
    fn verify_tail_refuses_a_lying_document() {
        // The tail's payload is the M13 interchange form verbatim: a
        // body the strict reader refuses is a malformed tail (the wire
        // never re-shapes, so it never re-excuses).
        let mut body = Vec::new();
        put_u8(&mut body, 1);
        put_str(&mut body, "{\"stats\":{},\"issues\":[");
        let err = decode_verify_report_bytes(&body).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn provenance_queries_round_trip() {
        // v45 (M79): the provenance queries ride the request — the
        // `-why_export` names in flag order, the `-why_load` flag beside
        // them — and the no-query default stays the pre-M79 shape.
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: vec!["_greet".to_string(), "_msg".to_string()],
            why_load: true,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        // A different load-report answer is a different request.
        req.why_load = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
        // The empty list decodes to the no-query shape.
        req.why_export.clear();
        let plain = LinkRequest::decode(&req.encode()).unwrap();
        assert!(plain.why_export.is_empty() && !plain.why_load);
    }

    #[test]
    fn a_wire_garbage_provenance_name_is_malformed() {
        // The names ride the C-symbol grammar the surface parses: an
        // empty name is a malformed request, never a silently widened
        // query (the M77 selection's own convention).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        // Hand-splice a one-query tail with an empty name over the
        // no-query one: the encoded tail is the count u32 + the flag
        // bytes — rewrite the whole tail.
        let mut wire = req.encode();
        wire.truncate(wire.len() - 10);
        put_u32(&mut wire, 1);
        put_str(&mut wire, "");
        put_u8(&mut wire, 0);
        put_u8(&mut wire, 0);
        put_u32(&mut wire, 0);
        let err = LinkRequest::decode(&wire).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn provenance_queries_ride_the_record() {
        // M88: the queries ride the record — the §7.3 ladder's replay
        // runs the full Passes 1–3 (`link_from_objects` inside
        // `serve_relink`), so its own Pass-2 product is the honest
        // answer, and the v45 tail carries the renders either lane (the
        // M87 precedent: the decode gate's refusal arm retired with the
        // outdated premise — no wire shape moves).
        let req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: Some(vec![1, 2, 3]),
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: vec!["_greet".to_string()],
            why_load: true,
            map: false,
            why_live: Vec::new(),
        };
        let back = LinkRequest::decode(&req.encode()).expect("the query-bearing record decodes");
        assert_eq!(back.why_export, req.why_export, "the names ride in order");
        assert!(
            back.why_load,
            "the load-report flag rides beside the record"
        );
        assert!(back.record.is_some(), "the record rides beside the queries");
    }

    #[test]
    fn provenance_tail_round_trips_the_renders() {
        // v45 (M79): the served answers ride the tail verbatim (the M62
        // convention — the wire never re-shapes the rendered face); an
        // unasked query rides the absent byte.
        let served = ServedProvenance {
            exports: vec![ServedExport {
                name: "_greet".to_string(),
                render: "_greet: greet.o(__TEXT,__text) ...\n  read by main.o(...)\n".to_string(),
            }],
            loads: Some(
                "libgreet.a(greet.o):\n  pulled for _greet (the lazy fixpoint)\n".to_string(),
            ),
            lives: Vec::new(),
        };
        let mut body = Vec::new();
        encode_provenance(&mut body, Some(&served));
        let back = decode_provenance_bytes(&body)
            .unwrap()
            .expect("the answers ride");
        assert_eq!(back, served);
        let mut absent = Vec::new();
        encode_provenance(&mut absent, None);
        assert!(decode_provenance_bytes(&absent).unwrap().is_none());
    }

    #[test]
    fn liveness_ask_round_trips_in_the_request() {
        // M93 (wire v48): the liveness queries ride the request — the
        // names in flag order, beside the provenance tail's asks (the
        // empty list is the pre-M93 shape, byte-identical on the decode
        // side).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: vec!["_greet".to_string(), "_orphan".to_string()],
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back.why_live, req.why_live, "the names ride in order");
        // The empty list decodes to the no-query shape.
        let mut quiet = req;
        quiet.why_live.clear();
        let plain = LinkRequest::decode(&quiet.encode()).unwrap();
        assert!(
            plain.why_live.is_empty(),
            "the empty list decodes to the no-query shape"
        );
    }

    #[test]
    fn a_wire_garbage_liveness_name_is_malformed() {
        // The names ride the C-symbol grammar the surface parses: an
        // empty liveness name is a malformed request, never a silently
        // widened query (the M77 selection's own convention).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        // Hand-splice a one-name liveness tail with an empty name over
        // the no-query one: the encoded liveness tail is the count u32 —
        // rewrite it whole.
        let mut wire = req.encode();
        wire.truncate(wire.len() - 4);
        put_u32(&mut wire, 1);
        put_str(&mut wire, "");
        let err = LinkRequest::decode(&wire).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn provenance_tail_round_trips_the_liveness_answers() {
        // M93 (wire v48): the liveness chains ride the provenance tail
        // beside the export answers — one entry per `-why_live` query, in
        // flag order, the render verbatim (the M62 convention); an unasked
        // liveness rides the empty list.
        let served = ServedProvenance {
            exports: Vec::new(),
            loads: None,
            lives: vec![
                ServedLive {
                    name: "_greet".to_string(),
                    render: "_greet: kept by the strip\n  kept by _main (main.o,__TEXT,__text) \
                             at 0x0 (via _greet)\n  rooted at the entry point (-e)\n"
                        .to_string(),
                },
                ServedLive {
                    name: "_orphan".to_string(),
                    render: "_orphan: dropped by the strip\n".to_string(),
                },
            ],
        };
        let mut body = Vec::new();
        encode_provenance(&mut body, Some(&served));
        let back = decode_provenance_bytes(&body)
            .unwrap()
            .expect("the answers ride");
        assert_eq!(back, served, "the chains ride verbatim, in flag order");
    }

    #[test]
    fn provenance_tail_refuses_a_nameless_liveness_answer() {
        // A liveness entry whose name rode empty is a malformed tail —
        // the session never renders one (a query names its answer), so an
        // empty name means the body is not ours.
        let mut body = Vec::new();
        put_u8(&mut body, 1);
        put_u32(&mut body, 0); // no exports
        put_u8(&mut body, 0); // no loads
        put_u32(&mut body, 1); // one liveness answer
        put_str(&mut body, ""); // ... that names nothing
        put_str(&mut body, "_greet: kept by the strip\n");
        let err = decode_provenance_bytes(&body).unwrap_err();
        assert!(
            err.to_string().contains("liveness"),
            "the malformed shape is named: {err}"
        );
    }

    #[test]
    fn the_liveness_ask_refuses_beside_a_relocatable_output() {
        // M93: `-r` preserves input sections verbatim and carries no
        // strip — the query has no honest answer, and the surface refuses
        // the knob beside `-r` (the driver never asks; no wire caller can
        // plan the shape either — the M83 replay-face rule).
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: vec!["_greet".to_string()],
        };
        req.config.filetype = OutputType::Relocatable;
        let err = LinkRequest::decode(&req.encode()).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
        assert!(
            err.to_string().contains("-r"),
            "the relocatable premise is named: {err}"
        );
    }

    #[test]
    fn provenance_tail_refuses_a_nameless_answer() {
        // A tail entry whose name rode empty is a malformed tail — the
        // session never renders one (a query names its answer), so an
        // empty name means the body is not ours.
        let mut body = Vec::new();
        put_u8(&mut body, 1);
        put_u32(&mut body, 1);
        put_str(&mut body, "");
        put_str(&mut body, "a render");
        put_u8(&mut body, 0);
        let err = decode_provenance_bytes(&body).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn the_composed_filter_table_round_trips_in_composition_order() {
        // M100 (v51): the singular export filters compose into the ONE
        // table the config carries — flag entries and list-file entries
        // interleave in command-line order, and the composed table
        // crosses the v7 pattern carriage verbatim (a resident relink
        // plans the composed surface the client named, never a
        // reordered or re-interpreted one).
        let cfg = LinkConfig {
            exported_only: Some(vec![
                SymbolPattern::parse(b"_sdk_init").unwrap(),
                SymbolPattern::parse(b"_sdk_*").unwrap(),
                SymbolPattern::parse(b"_sdk_write").unwrap(),
            ]),
            unexported: vec![
                SymbolPattern::parse(b"_internal_seed").unwrap(),
                SymbolPattern::parse(b"_internal_*").unwrap(),
            ],
            ..LinkConfig::default()
        };
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let back = LinkRequest::decode(&req.encode()).unwrap();
        let only = back
            .config
            .exported_only
            .expect("the composed only-list rides");
        let sources: Vec<&[u8]> = only.iter().map(SymbolPattern::source).collect();
        assert_eq!(
            sources,
            [b"_sdk_init".as_slice(), b"_sdk_*", b"_sdk_write"],
            "the composition order survives the wire"
        );
        let hidden: Vec<&[u8]> = back
            .config
            .unexported
            .iter()
            .map(SymbolPattern::source)
            .collect();
        assert_eq!(hidden, [b"_internal_seed".as_slice(), b"_internal_*"]);
    }

    #[test]
    fn a_rebuild_refusing_pattern_is_a_malformed_request() {
        // The wire never carries a filter the pipeline would silently
        // misread: a pattern the seam's parse refuses (interior
        // whitespace is not a Mach-O symbol name) is malformed at the
        // decode, like every shape the config carries — the composed
        // table's entries all pay the same re-parse the v7 carriage
        // pinned.
        let mut body = Vec::new();
        put_u8(&mut body, 0); // the exact kind byte (advisory)
        put_str(&mut body, "_foo bar");
        let err = read_pattern(&mut Reader::new(&body)).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
        // The v21–v24 decision bytes stay the default here — the
        // needle's uniqueness is this test's precondition, not its
        // subject (a non-default suppression byte after the header-pad
        // floor's high zeros re-forms the needle against the empty
        // request tail).
        cfg.data_in_code = true;
        cfg.function_starts = true;
        cfg.uuid = true;
        cfg.keep_private_externs = false;
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(back.config.no_pie, "the decision crosses byte-for-byte");
    }

    #[test]
    fn the_sect_align_floors_round_trip() {
        // v19: non-default `-sectalign` floors must survive the round
        // trip verbatim, in flag order (a resident relink aligns the
        // sections the client named, never the pre-M28 input-only
        // shape).
        let cfg = rich_config();
        let named: Vec<(String, String, u32)> = cfg
            .sect_aligns
            .iter()
            .map(|d| {
                (
                    d.segment().name().to_string(),
                    d.section().to_string(),
                    d.align_log2(),
                )
            })
            .collect();
        assert_eq!(
            named,
            vec![
                ("__DATA".to_string(), "__data".to_string(), 14),
                ("__TEXT".to_string(), "__text".to_string(), 12),
            ],
            "rich_config carries the v19 knobs"
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        let crossed: Vec<(String, String, u32)> = back
            .config
            .sect_aligns
            .iter()
            .map(|d| {
                (
                    d.segment().name().to_string(),
                    d.section().to_string(),
                    d.align_log2(),
                )
            })
            .collect();
        assert_eq!(crossed, named, "the floors cross byte-for-byte, in order");
    }

    #[test]
    fn the_header_pad_floor_round_trips() {
        // v20: a non-default `-headerpad` floor must survive the round
        // trip verbatim (a resident relink reserves the region the
        // client named, never the pre-M29 natural size alone).
        let cfg = rich_config();
        assert_eq!(
            cfg.header_pad
                .as_ref()
                .map(pgr_core::header_pad::HeaderPad::floor_bytes),
            Some(0x2000),
            "rich_config carries the v20 knob"
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(
            back.config
                .header_pad
                .as_ref()
                .map(pgr_core::header_pad::HeaderPad::floor_bytes),
            Some(0x2000),
            "the floor crosses byte-for-byte"
        );
    }

    #[test]
    fn the_data_in_code_decision_round_trips() {
        // v21: a non-default data-in-code suppression must survive the
        // round trip verbatim (a resident relink carries the stream
        // decision the client asked for, never the pre-M30
        // carry-when-named default).
        let cfg = rich_config();
        assert!(!cfg.data_in_code, "rich_config carries the v21 knob");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(
            !back.config.data_in_code,
            "the suppression crosses byte-for-byte"
        );
    }

    #[test]
    fn the_function_starts_decision_round_trips() {
        // v22: a non-default function-starts suppression must survive
        // the round trip verbatim (a resident relink carries the
        // linkedit-metadata decision the client asked for, never the
        // pre-M31 always-carried default).
        let cfg = rich_config();
        assert!(!cfg.function_starts, "rich_config carries the v22 knob");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(
            !back.config.function_starts,
            "the suppression crosses byte-for-byte"
        );
    }

    #[test]
    fn the_uuid_decision_round_trips() {
        // v23: a non-default UUID suppression must survive the round
        // trip verbatim (a resident relink carries the derived-UUID
        // decision the client asked for, never the pre-M32
        // always-carried default).
        let cfg = rich_config();
        assert!(!cfg.uuid, "rich_config carries the v23 knob");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(!back.config.uuid, "the suppression crosses byte-for-byte");
    }

    #[test]
    fn the_keep_private_externs_decision_round_trips() {
        // v24: a non-default private-extern keep must survive the
        // round trip verbatim (a resident relink carries the
        // private-extern decision the client asked for, never the
        // pre-M33 conversion default).
        let cfg = rich_config();
        assert!(cfg.keep_private_externs, "rich_config carries the v24 knob");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(
            back.config.keep_private_externs,
            "the keep crosses byte-for-byte"
        );
    }

    #[test]
    fn the_header_pad_auto_floor_round_trips() {
        // v26: a non-default install-name auto-floor must survive the
        // round trip verbatim (a resident relink carries the header-pad
        // decision the client asked for, never the pre-M38 natural
        // default).
        let mut cfg = rich_config();
        assert!(!cfg.header_pad_max_install_names);
        cfg.header_pad_max_install_names = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.header_pad_max_install_names,
            "the auto-floor crosses byte-for-byte"
        );
    }

    #[test]
    fn the_no_compact_unwind_decision_round_trips() {
        // v25: a non-default compact-unwind suppression must survive
        // the round trip verbatim (a resident relink carries the
        // suppression decision the client asked for, never the pre-M36
        // carry default).
        let mut cfg = rich_config();
        assert!(cfg.compact_unwind, "rich_config carries the default");
        cfg.compact_unwind = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert!(
            !back.config.compact_unwind,
            "the suppression crosses byte-for-byte"
        );
    }

    #[test]
    fn the_make_undefined_marks_round_trip() {
        // v27: a non-default make-undefined table must survive the
        // round trip verbatim, in flag order (a resident relink strips
        // the definitions the client marked, never the pre-M39 carried
        // definitions).
        let back = LinkRequest::decode(
            &LinkRequest {
                config: rich_config(),
                force_load: Vec::new(),
                inputs: Vec::new(),
                archives: Vec::new(),
                record: None,
                record_resolution: false,
                prev_output: None,
                audit: false,
                tiles: false,
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .unwrap();
        assert_eq!(
            back.config.make_undefined.names(),
            ["_override_me", "_also_gone"],
            "the marks cross byte-for-byte, in flag order"
        );
    }

    #[test]
    fn the_export_trie_suppression_round_trips() {
        // v28: a non-default export-trie suppression must survive the
        // round trip verbatim (a resident relink carries the
        // export-surface decision the client asked for, never the
        // pre-M40 always-carried default).
        let mut cfg = rich_config();
        assert!(cfg.exported_symbols, "rich_config carries the default");
        cfg.exported_symbols = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            !back.config.exported_symbols,
            "the suppression crosses byte-for-byte"
        );
    }

    #[test]
    fn the_no_deduplicate_decision_round_trips() {
        // v29: a non-default dedup toggle must survive the round trip
        // verbatim (a resident relink carries the D4 decision the
        // client asked for, never the pre-M41 merge default).
        let mut cfg = rich_config();
        assert!(cfg.deduplicate, "rich_config carries the default");
        cfg.deduplicate = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(!back.config.deduplicate, "the toggle crosses byte-for-byte");
    }

    #[test]
    fn the_dead_strip_dylibs_decision_round_trips() {
        // v30: a non-default unused-dylib drop must survive the round
        // trip verbatim (a resident relink carries the drop decision
        // the client asked for, never the pre-M42 keep-every-dylib
        // default).
        let mut cfg = rich_config();
        assert!(!cfg.dead_strip_dylibs, "rich_config carries the default");
        cfg.dead_strip_dylibs = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.dead_strip_dylibs,
            "the drop decision crosses byte-for-byte"
        );
    }

    #[test]
    fn the_objc_pull_decision_round_trips() {
        // v31: a non-default ObjC pull must survive the round trip
        // verbatim (a resident relink carries the pull decision the
        // client asked for, never the pre-M43 reference-driven
        // default).
        let mut cfg = rich_config();
        assert!(!cfg.objc, "rich_config carries the default");
        cfg.objc = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(back.config.objc, "the pull decision crosses byte-for-byte");
    }

    #[test]
    fn the_weak_import_refusal_round_trips() {
        // v36: a non-default weak-import refusal must survive the round
        // trip verbatim (a resident relink carries the decision the
        // client asked for, never the pre-M50 runtime-lookup
        // fallthrough).
        let mut cfg = rich_config();
        assert!(!cfg.no_weak_imports, "rich_config carries the default");
        cfg.no_weak_imports = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.no_weak_imports,
            "the refusal decision crosses byte-for-byte"
        );
    }

    #[test]
    fn the_stack_execution_decision_round_trips() {
        // v37: a non-default stack-execution decision must survive the
        // round trip verbatim (a resident relink carries the flag word
        // the client asked for, never the pre-M51 bitless default).
        let mut cfg = rich_config();
        assert!(!cfg.allow_stack_execute, "rich_config carries the default");
        cfg.allow_stack_execute = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.allow_stack_execute,
            "the flag word crosses byte-for-byte"
        );
    }

    /// Hand-builds the config body's head up to and including the
    /// `-undefined` policy byte (the mirror of `encode_config`'s first
    /// eleven fields), with `policy` spliced as the value — the
    /// malformed-value gate's subject.
    fn encode_config_head_up_to_policy(out: &mut Vec<u8>, policy: u8) {
        put_str(out, "app");
        put_u8(out, 0); // OutputType::Execute
        put_str(out, "_main");
        put_u32(out, 0x1); // platform
        put_u32(out, 0x000c_0000); // minos
        put_u32(out, 0x000e_0400); // sdk
        put_u8(out, 0); // dynamic_linker
        put_u8(out, 0); // fixup_chains
        put_u8(out, 0); // adhoc
        put_u8(out, 0); // flat_namespace
        put_u8(out, policy);
    }

    #[test]
    fn the_bind_at_load_decision_round_trips() {
        // v53: a non-default bind-at-load decision must survive the
        // round trip verbatim (a resident relink carries the flag word
        // the client asked for, never the pre-M102 bitless default).
        let cfg = rich_config();
        assert!(cfg.bind_at_load, "rich_config carries the named face");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.bind_at_load,
            "the flag word crosses byte-for-byte"
        );
        // The dropped face rides too (the pair's `-no_bind_at_load`).
        let mut cfg = rich_config();
        cfg.bind_at_load = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            !back.config.bind_at_load,
            "the dropped face crosses byte-for-byte"
        );
    }

    #[test]
    fn the_keep_local_symbols_decision_round_trips() {
        // v55: a non-default symtab-shaping decision must survive the
        // round trip verbatim (a resident relink carries the symtab
        // shape the client asked for, never the pre-M104 kept default).
        let cfg = rich_config();
        assert!(
            !cfg.keep_local_symbols,
            "rich_config carries the named drop face"
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            !back.config.keep_local_symbols,
            "the symtab shape crosses byte-for-byte"
        );
        // The kept face rides too (the default and the pair's
        // `-keep_local_symbols`).
        let mut cfg = rich_config();
        cfg.keep_local_symbols = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.keep_local_symbols,
            "the kept face crosses byte-for-byte"
        );
    }

    #[test]
    fn the_strip_debug_decision_round_trips() {
        // v56: a non-default debug-section suppression must survive the
        // round trip verbatim (a resident relink carries the debug-free
        // shape the client asked for, never the pre-M105
        // debug-carrying default).
        let cfg = rich_config();
        assert!(cfg.strip_debug, "rich_config carries the named strip face");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.strip_debug,
            "the debug-free shape crosses byte-for-byte"
        );
        // The debug-carrying face rides too (the default).
        let mut cfg = rich_config();
        cfg.strip_debug = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            !back.config.strip_debug,
            "the debug-carrying face crosses byte-for-byte"
        );
    }

    #[test]
    fn the_widened_undefined_policies_round_trip() {
        // v54: the `-undefined` policy byte widens to the four-value
        // alphabet — warning and suppress cross byte-for-byte (a
        // resident relink exits under the policy the client named,
        // never the pre-M103 escalation).
        for (policy, name) in [
            (pgr_core::resolve::UndefinedPolicy::Warning, "warning"),
            (pgr_core::resolve::UndefinedPolicy::Suppress, "suppress"),
        ] {
            let mut cfg = rich_config();
            cfg.undefined_policy = policy;
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
                    time: false,
                    trace: false,
                    verify: false,
                    verify_checks: None,
                    why_export: Vec::new(),
                    why_load: false,
                    map: false,
                    why_live: Vec::new(),
                }
                .encode(),
            )
            .expect("the frame decodes");
            assert_eq!(
                back.config.undefined_policy, policy,
                "the {name} policy crosses byte-for-byte"
            );
        }
    }

    #[test]
    fn an_unknown_undefined_policy_value_is_malformed() {
        // v54: a policy value the reader refuses is a malformed frame —
        // the wire never silently widens (an old server reading a newer
        // client's alphabet refuses it, the M82 admits pattern
        // reversed). The config head is hand-built up to and including
        // the policy byte; the decode fails there, before the rest of
        // the body could matter.
        let mut body = Vec::new();
        put_u32(&mut body, PROTO_VERSION);
        encode_config_head_up_to_policy(&mut body, 9);
        let err = LinkRequest::decode(&body).unwrap_err();
        assert!(
            matches!(err, DecodeError::Malformed(_)),
            "an unknown policy value is a malformed frame: {err:?}"
        );
    }

    #[test]
    fn the_policy_warning_tail_round_trips() {
        // v54: the exit policy's unresolved-open entries cross verbatim
        // — the client prints the cold lane's face (the M62
        // convention); the suppress face's empty list rides as the
        // empty list.
        let entries = vec![
            "\"_hole\" (referenced from main.o)".to_string(),
            "\"_gap\" (referenced from util.o)".to_string(),
        ];
        let mut body = Vec::new();
        encode_policy_warnings(&mut body, &entries);
        let back = decode_policy_warnings(&mut Reader::new(&body)).expect("the tail decodes");
        assert_eq!(back, entries, "the entries cross verbatim, in order");
        let mut empty = Vec::new();
        encode_policy_warnings(&mut empty, &[]);
        let back = decode_policy_warnings(&mut Reader::new(&empty)).expect("the tail decodes");
        assert!(
            back.is_empty(),
            "the suppress face's empty list rides as the empty list"
        );
    }

    #[test]
    fn the_dead_strip_inits_and_terms_decision_round_trips() {
        // v38: a non-default dead-strip init/term roots decision must
        // survive the round trip verbatim (a resident relink strips the
        // routines the client asked to keep, never the pre-M52
        // term-strip default).
        let mut cfg = rich_config();
        assert!(
            !cfg.no_dead_strip_inits_and_terms,
            "rich_config carries the default"
        );
        cfg.no_dead_strip_inits_and_terms = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.no_dead_strip_inits_and_terms,
            "the root decision crosses byte-for-byte"
        );
    }

    #[test]
    fn the_section_renames_round_trip() {
        // v39: the rename map must survive the round trip verbatim, in
        // flag order (a resident relink renames the sections the client
        // named, never the pre-M53 unnamed pairs).
        let cfg = rich_config();
        assert_eq!(cfg.renames.len(), 2, "rich_config names two renames");
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        let renames: Vec<(String, String, String, String)> = back
            .config
            .renames
            .iter()
            .map(|r| {
                (
                    r.from_seg().to_string(),
                    r.from_sect().to_string(),
                    r.to_seg().to_string(),
                    r.to_sect().to_string(),
                )
            })
            .collect();
        assert_eq!(
            renames,
            vec![
                (
                    "__DATA".to_string(),
                    "__mydata".to_string(),
                    "__DATA".to_string(),
                    "__ro_data".to_string()
                ),
                (
                    "__DATA".to_string(),
                    "__other".to_string(),
                    "__DATA".to_string(),
                    "__rw_data".to_string()
                ),
            ],
            "the rename map crosses byte-for-byte, in flag order"
        );
    }

    #[test]
    fn a_rename_the_seam_refuses_is_a_malformed_frame() {
        // The decode re-validates the table (the seam's grammar): a
        // synthetic source a hostile peer names is a malformed frame —
        // the wire never carries a decision the core would refuse at
        // the classification. The splice keeps every byte count: the
        // first rename's source `__mydata` rewrites onto `__common`
        // (the same 8 bytes), a synthetic source the seam refuses.
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        }
        .encode();
        let needle = b"__mydata";
        let mut hits = Vec::new();
        for i in 4..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(
            hits.len(),
            1,
            "the first rename rides its source exactly once"
        );
        let mut bad = body;
        bad[hits[0]..hits[0] + needle.len()].copy_from_slice(b"__common");
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn the_upward_load_kind_round_trips() {
        // v32: the upward-load kind rides beside lazy/weak/re-export (the
        // M14 lazy-byte convention) — the wire never silently flattens an
        // `LC_LOAD_UPWARD_DYLIB` request into a plain load, so a resident
        // relink carries the umbrella mark the client named.
        let mut cfg = rich_config();
        // rich_config carries every kind flag set; flip it to the
        // upward-only shape the round trip must protect.
        assert!(cfg.dylibs[0].upward, "rich_config carries the kind set");
        cfg.dylibs[0].weak = false;
        cfg.dylibs[0].reexport = false;
        cfg.dylibs[0].lazy = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        let dylib = &back.config.dylibs[0];
        assert!(dylib.upward, "the upward kind crosses byte-for-byte");
        assert!(
            !dylib.lazy && !dylib.reexport && !dylib.weak,
            "the other kinds stay clear (the mark is the only one set)"
        );
    }

    #[test]
    fn the_export_dynamic_roots_round_trip() {
        // v33: a non-default export-dynamic decision must survive the
        // round trip verbatim (a resident relink carries the dlsym
        // decision the client asked for, never the pre-M46 entry-root
        // default).
        let mut cfg = rich_config();
        assert!(!cfg.export_dynamic, "rich_config carries the default");
        cfg.export_dynamic = true;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            back.config.export_dynamic,
            "the root-widening decision crosses byte-for-byte"
        );
    }

    #[test]
    fn the_branch_island_suppression_round_trips() {
        // v34: a non-default branch-island decision must survive the
        // round trip verbatim (a resident relink carries the suppression
        // decision the client asked for, never the pre-M47
        // islands-by-default).
        let mut cfg = rich_config();
        assert!(cfg.branch_islands, "rich_config carries the default");
        cfg.branch_islands = false;
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert!(
            !back.config.branch_islands,
            "the suppression crosses byte-for-byte"
        );
    }

    #[test]
    fn the_dylib_initializer_round_trips() {
        // v35: a named `-init` must survive the round trip verbatim (a
        // resident relink carries the initializer the client named,
        // never the pre-M48 absence).
        let mut cfg = rich_config();
        assert!(cfg.init_symbol.is_none(), "rich_config carries the default");
        cfg.init_symbol = Some("_my_init".into());
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert_eq!(
            back.config.init_symbol.as_deref(),
            Some("_my_init"),
            "the initializer crosses byte-for-byte"
        );
    }

    #[test]
    fn the_dylib_terminator_round_trips() {
        // v49: a named `-term` must survive the round trip verbatim (a
        // resident relink carries the terminator the client named,
        // never the pre-M98 absence).
        let mut cfg = rich_config();
        assert!(cfg.term_symbol.is_none(), "rich_config carries the default");
        cfg.term_symbol = Some("_my_term".into());
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert_eq!(
            back.config.term_symbol.as_deref(),
            Some("_my_term"),
            "the terminator crosses byte-for-byte"
        );
    }

    #[test]
    fn the_named_uuid_round_trips() {
        // v50: a named output UUID must survive the round trip verbatim
        // (a resident relink carries the identity the client named,
        // never the content-derived default).
        let mut cfg = rich_config();
        assert!(cfg.named_uuid.is_none(), "rich_config carries the default");
        cfg.named_uuid = Some(NAMED_BYTES);
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
                time: false,
                trace: false,
                verify: false,
                verify_checks: None,
                why_export: Vec::new(),
                why_load: false,
                map: false,
                why_live: Vec::new(),
            }
            .encode(),
        )
        .expect("the frame decodes");
        assert_eq!(
            back.config.named_uuid,
            Some(NAMED_BYTES),
            "the identity crosses byte-for-byte"
        );
    }

    #[test]
    fn a_wire_garbage_make_undefined_name_is_malformed() {
        // v27: a name off the core seam's grammar is malformed, not
        // silently marked (the decode pays the same validation the flag
        // does — the raw door is not a bypass).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        }
        .encode();
        // The marks are the wire tail's last section: the count rides
        // right behind the v26 auto-floor byte. Flip the count to 1 and
        // append an empty name (the grammar refuses it).
        let count_pos = body.len() - 8 - 4;
        let mut frame = body[..count_pos].to_vec();
        frame.extend_from_slice(&1u32.to_le_bytes());
        frame.extend_from_slice(&0u32.to_le_bytes()); // empty string
        assert!(
            LinkRequest::decode(&frame).is_err(),
            "the empty name refuses"
        );
    }

    #[test]
    fn a_wire_garbage_header_pad_is_malformed() {
        // v20: a floor off the -headerpad grammar is malformed, not
        // silently reserved (the decode pays the same validation the
        // flag does — the raw door is not a bypass).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        }
        .encode();
        // The floor rides the config tail as (present byte, u64); the
        // value 0x2000 appears exactly once in that slot — find it and
        // rewrite it to an unaligned floor.
        let floor = 0x2000u64.to_le_bytes();
        let needle: Vec<u8> = [1u8].into_iter().chain(floor).collect();
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(needle.len()) {
            if body[i..i + needle.len()] == needle[..] {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the floor rides exactly once");
        let mut bad = body;
        let value_at = hits[0] + 1;
        bad[value_at..value_at + 8].copy_from_slice(&0x2001u64.to_le_bytes());
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn a_wire_garbage_sect_align_is_malformed() {
        // v19: an exponent off the -sectalign grammar is malformed, not
        // silently widened (the decode pays the same validation the
        // flag does — the raw door is not a bypass).
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        }
        .encode();
        // The last floor byte is `__TEXT,__text`'s exponent (12); the
        // table rides at the frame tail, so the byte just before the
        // request's trailing fields is the exponent to corrupt — find
        // it by splicing a whole second table entry instead: rewrite
        // the count to name one more entry than the body carries.
        // Simpler and exact: decode with the exponent byte raised past
        // the ceiling by locating the 12 that closes the config body.
        let needle: &[u8] = &[b'_', b'_', b't', b'e', b'x', b't', 12];
        let mut hits = Vec::new();
        for i in 0..body.len().saturating_sub(needle.len()) {
            if &body[i..i + needle.len()] == needle {
                hits.push(i);
            }
        }
        assert_eq!(hits.len(), 1, "the last floor rides exactly once");
        let mut bad = body;
        bad[hits[0] + needle.len() - 1] = 15; // exponent 15 > 14
        let err = LinkRequest::decode(&bad).unwrap_err();
        assert!(matches!(err, DecodeError::Malformed(_)), "{err:?}");
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
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

    #[test]
    fn the_time_flag_round_trips_byte_shape() {
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: true,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req);
        // The flag flips cleanly over the wire.
        req.time = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
    }

    #[test]
    fn the_trace_flag_round_trips_byte_shape() {
        let mut req = LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: true,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        let body = req.encode();
        let back = LinkRequest::decode(&body).unwrap();
        assert_eq!(back, req, "the trace flag rides its own byte (v41)");
        req.trace = false;
        assert_ne!(LinkRequest::decode(&req.encode()).unwrap(), back);
        // Both faces ask together (the paired collectors' shape).
        req.time = true;
        req.trace = true;
        assert!(LinkRequest::decode(&req.encode()).unwrap().trace);
    }

    /// A representative served report: the warm pipeline's phases, an
    /// absent emit band (the relink's Pass-4 half is the in-memory
    /// patch), a measured total, and a note carrying the escape-worthy
    /// punctuation.
    fn served_report() -> pgr_core::time_report::TimeReport {
        use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
        use std::time::Duration;
        let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
            phase,
            detail,
            elapsed: Duration::from_micros(us),
        };
        pgr_core::time_report::TimeReport {
            phases: vec![
                row(Phase::ArchivePull, PhaseDetail::Members { pulled: 3 }, 42),
                row(Phase::Intern, PhaseDetail::Names { interned: 9 }, 17),
                row(Phase::Resolve, PhaseDetail::Winners { reused: true }, 23),
                row(
                    Phase::Layout,
                    PhaseDetail::Planned {
                        segments: 4,
                        sections: 9,
                    },
                    210,
                ),
            ],
            emit: None,
            total: Some(Duration::from_micros(1_234)),
            notes: vec![
                "the resolve-reuse replay fell back to the full resolve (a \"moved\" shape)"
                    .to_string(),
            ],
        }
    }

    #[test]
    fn the_time_report_tail_round_trips() {
        let report = served_report();
        let mut body = Vec::new();
        encode_time_report(&mut body, Some(&report));
        let mut r = Reader::new(&body);
        let back = decode_time_report(&mut r).expect("the tail decodes");
        r.done().expect("the tail carries no trailing bytes");
        assert_eq!(back.as_ref(), Some(&report), "the report restores exactly");
    }

    #[test]
    fn the_time_report_tail_round_trips_the_ladder_rungs() {
        // M65 (v42): the §7.3 rung vocabulary rides the tail's own shape —
        // a captured tail carrying the ladder's rows restores exactly (the
        // session's own ladder reports through the seam since M66 — wire
        // v42 in service).
        use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
        use std::time::Duration;
        let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
            phase,
            detail,
            elapsed: Duration::from_micros(us),
        };
        let report = pgr_core::time_report::TimeReport {
            phases: vec![
                row(Phase::RelinkGate, PhaseDetail::Gate { pages: 16 }, 120),
                row(
                    Phase::RelinkPlan,
                    PhaseDetail::Plan { tiles: 8, dirty: 2 },
                    340,
                ),
                row(
                    Phase::RelinkPatch,
                    PhaseDetail::Patch {
                        bytes: 32_768,
                        tiles: 2,
                    },
                    900,
                ),
                row(
                    Phase::RelinkAudit,
                    PhaseDetail::Audit {
                        healed: false,
                        issues: 0,
                    },
                    2_500,
                ),
            ],
            emit: None,
            total: Some(Duration::from_micros(4_000)),
            notes: vec!["no record for this output yet".to_string()],
        };
        let mut body = Vec::new();
        encode_time_report(&mut body, Some(&report));
        let mut r = Reader::new(&body);
        let back = decode_time_report(&mut r).expect("the rung rows decode");
        r.done().expect("no trailing bytes");
        assert_eq!(back, Some(report), "the ladder rungs restore exactly");
    }

    #[test]
    fn the_time_report_tail_round_trips_the_emit_rows() {
        // M68: the emit half's vocabulary rides the tail's own shape — a
        // captured report carrying the `emit`/`flush` rows restores
        // exactly. No served content changes (the session's warm run has
        // no fused emit and the client does the writing), so the version
        // gate stays v42: a v42 daemon never sends these tokens and a
        // v42 client never meets them; the decode side accepts them so
        // the vocabulary is the tail's, not the one-shot lane's alone.
        use pgr_core::observe::{Phase, PhaseDetail, PhaseEvent};
        use std::time::Duration;
        let row = |phase: Phase, detail: PhaseDetail, us: u64| PhaseEvent {
            phase,
            detail,
            elapsed: Duration::from_micros(us),
        };
        let report = pgr_core::time_report::TimeReport {
            phases: vec![
                row(
                    Phase::Layout,
                    PhaseDetail::Planned {
                        segments: 4,
                        sections: 9,
                    },
                    210,
                ),
                row(
                    Phase::Emit,
                    PhaseDetail::Emitted {
                        tiles: 256,
                        bytes: 4_194_304,
                    },
                    1_100,
                ),
                row(
                    Phase::Flush,
                    PhaseDetail::Flushed {
                        blocks: 1,
                        writers: 4,
                    },
                    400,
                ),
            ],
            emit: None,
            total: Some(Duration::from_micros(1_750)),
            notes: Vec::new(),
        };
        let mut body = Vec::new();
        encode_time_report(&mut body, Some(&report));
        let mut r = Reader::new(&body);
        let back = decode_time_report(&mut r).expect("the emit rows decode");
        r.done().expect("no trailing bytes");
        assert_eq!(back, Some(report), "the emit half restores exactly");
    }

    #[test]
    fn the_time_report_tail_rides_absent() {
        let mut body = Vec::new();
        encode_time_report(&mut body, None);
        let mut r = Reader::new(&body);
        let back = decode_time_report(&mut r).expect("the absence decodes");
        r.done().expect("no trailing bytes");
        assert_eq!(back, None, "an unasked report rides absent");
    }

    #[test]
    fn the_report_tail_refuses_an_unknown_phase_byte() {
        // A hand-built tail: present, one row, an unknown phase token —
        // a malformed body is a refusal, never a silently dropped row.
        let mut body = Vec::new();
        put_u8(&mut body, 1);
        put_u32(&mut body, 1);
        put_u8(&mut body, 99);
        let mut r = Reader::new(&body);
        assert!(decode_time_report(&mut r).is_err());
    }

    #[test]
    fn the_report_tail_refuses_an_unknown_detail_kind() {
        let mut body = Vec::new();
        put_u8(&mut body, 1);
        put_u32(&mut body, 1);
        put_u8(&mut body, 0); // parse
        put_u8(&mut body, 88); // an unknown detail kind
        put_u64(&mut body, 1);
        put_u64(&mut body, 1);
        let mut r = Reader::new(&body);
        assert!(decode_time_report(&mut r).is_err());
    }

    /// A representative served timeline: the session's rendered
    /// document, byte-for-byte what the one-shot `--trace` writes.
    fn served_trace() -> String {
        use pgr_core::observe::{Phase, PhaseDetail};
        let mut c = pgr_core::trace::TraceCollector::new();
        c.on_phase(pgr_core::observe::PhaseEvent {
            phase: Phase::ArchivePull,
            detail: PhaseDetail::Members { pulled: 3 },
            elapsed: std::time::Duration::from_micros(42),
        });
        c.on_phase(pgr_core::observe::PhaseEvent {
            phase: Phase::Resolve,
            detail: PhaseDetail::Winners { reused: true },
            elapsed: std::time::Duration::from_micros(23),
        });
        c.on_note(pgr_core::observe::LinkNote::ResolveReuseFallback {
            reason: "the seed's file list moved \"(the escape rides)\"".to_string(),
        });
        c.finish().render()
    }

    #[test]
    fn the_trace_tail_round_trips() {
        let json = served_trace();
        // The rendered document is the strict reader's own face — the
        // wire never re-shapes it.
        assert!(
            pgr_core::trace::parse_trace_json(&json).is_ok(),
            "the served timeline is a valid interchange document"
        );
        let mut body = Vec::new();
        encode_trace(&mut body, Some(&json));
        let back = decode_trace_bytes(&body).unwrap();
        assert_eq!(
            back.as_deref(),
            Some(json.as_str()),
            "the bytes ride verbatim"
        );
    }

    #[test]
    fn the_trace_tail_rides_absent() {
        let mut body = Vec::new();
        encode_trace(&mut body, None);
        assert_eq!(decode_trace_bytes(&body).unwrap(), None, "one byte");
        assert_eq!(body.len(), 1, "an unasked timeline never crosses");
    }

    #[test]
    fn the_trace_tail_refuses_truncation_and_trailing_bytes() {
        let mut body = Vec::new();
        encode_trace(&mut body, Some("{\"traceEvents\":[]}"));
        // The length prefix names more bytes than the body carries.
        let truncated = &body[..body.len() - 1];
        assert!(decode_trace_bytes(truncated).is_err());
        // A byte past the tail refuses (the strict-frame rule).
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(decode_trace_bytes(&trailing).is_err());
    }

    // ---- M80 (wire v46): the resident lane's served map ------------------

    /// A map-asking request (the flag beside an otherwise plain link).
    fn map_request() -> LinkRequest {
        LinkRequest {
            config: rich_config(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: true,
            why_live: Vec::new(),
        }
    }

    #[test]
    fn the_map_flag_round_trips_cleanly() {
        // The M80 rung: the `-map` flag rides the request; the empty
        // flag (the pre-M80 shape) is byte-identical on the decode side.
        let back = LinkRequest::decode(&map_request().encode()).unwrap();
        assert!(back.map, "the map ask rides the wire");
        let mut quiet = map_request();
        quiet.map = false;
        let back = LinkRequest::decode(&quiet.encode()).unwrap();
        assert!(!back.map, "an unasked map never crosses");
    }

    #[test]
    fn the_map_request_beside_a_record_serves_now() {
        // M87: the map renders from the ladder's own walk — the session's
        // relink runs the full Passes 1–3 (`link_from_objects`), so
        // `result.layout` is the walk's Pass-3 product and the v46 tail
        // carries the document verbatim (the M80 convention — the wire
        // never re-shapes the face the client writes). The decode side
        // admits the shape; the reply's tail answers it.
        let mut req = map_request();
        req.record = Some(vec![1, 2, 3]);
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert!(back.map, "the map ask rides the ladder's request");
        assert!(back.record.is_some(), "the record rides beside it");
    }

    /// A served-shape map document: the render the cold lane's `-map`
    /// writes (segments, sections, symbols), byte-for-byte.
    fn served_map_document() -> String {
        "# Sections\n\n__TEXT,__text (the placed image's report)\n".to_string()
    }

    #[test]
    fn the_map_tail_round_trips_the_document() {
        let document = served_map_document();
        // The rendered document rides verbatim — the wire never
        // re-shapes the bytes the client writes to the `-map` path.
        let mut body = Vec::new();
        encode_map(&mut body, Some(&document));
        let back = decode_map_bytes(&body).unwrap();
        assert_eq!(
            back.as_deref(),
            Some(document.as_str()),
            "the map document crosses verbatim"
        );
    }

    #[test]
    fn the_map_tail_rides_absent() {
        let mut body = Vec::new();
        encode_map(&mut body, None);
        assert_eq!(decode_map_bytes(&body).unwrap(), None, "one byte");
        assert_eq!(body.len(), 1, "an unasked map never crosses");
    }

    #[test]
    fn the_map_tail_refuses_truncation_and_trailing_bytes() {
        let mut body = Vec::new();
        encode_map(&mut body, Some("# Sections\n"));
        let truncated = &body[..body.len() - 1];
        assert!(decode_map_bytes(truncated).is_err());
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(decode_map_bytes(&trailing).is_err());
    }

    // ---- M81 (wire v47): the order-file rank table crosses the wire -----

    /// A representative rank table: a global entry, a scoped entry and
    /// another global — the parse's own shapes, in rank order.
    fn rich_order_entries() -> Vec<pgr_core::order::OrderEntry> {
        vec![
            pgr_core::order::OrderEntry {
                symbol: "_main".into(),
                object: None,
                line: 1,
            },
            pgr_core::order::OrderEntry {
                symbol: "_shared".into(),
                object: Some("first.o".into()),
                line: 2,
            },
            pgr_core::order::OrderEntry {
                symbol: "_late".into(),
                object: None,
                line: 3,
            },
        ]
    }

    #[test]
    fn the_order_table_round_trips() {
        // The M81 rung: the rank table rides the config tail — a
        // resident ordered link ranks the entries the client named
        // (never the default absence), and the rebuilt table's lookup
        // faces answer exactly what the client's table answers.
        let mut req = map_request();
        req.map = false;
        req.config.symbol_order = Some(
            pgr_core::order::SymbolOrder::from_entries(rich_order_entries())
                .expect("the table builds"),
        );
        let back = LinkRequest::decode(&req.encode()).unwrap();
        let order = back.config.symbol_order.expect("the table rides the wire");
        let entries = order.entries();
        assert_eq!(entries.len(), 3, "every entry rides");
        assert_eq!(entries[0].symbol, "_main");
        assert_eq!(entries[1].symbol, "_shared");
        assert_eq!(entries[1].object.as_deref(), Some("first.o"));
        assert_eq!(entries[1].line, 2, "the diagnostics line rides");
        assert_eq!(entries[2].symbol, "_late");
        assert_eq!(order.rank_of("first.o", b"_shared"), Some(1));
        // The scoped entry ranks its object only (the parse's own
        // shape — no global twin rode, so no other object answers).
        assert_eq!(order.rank_of("other.o", b"_shared"), None);
        assert_eq!(order.rank_of("other.o", b"_main"), Some(0));
        // The empty flag (the pre-M81 shape) is byte-identical on the
        // decode side.
        let mut plain = req.clone();
        plain.config.symbol_order = None;
        let back = LinkRequest::decode(&plain.encode()).unwrap();
        assert!(back.config.symbol_order.is_none(), "the absence rides");
    }

    #[test]
    fn a_wire_garbage_order_table_is_malformed() {
        // Two ranks for one symbol is a contradiction — the wire never
        // carries a table the pipeline would silently misread (the
        // parse's own refusal, mirrored at the decode). The encode side
        // cannot produce the shape (a [`SymbolOrder`] cannot hold a
        // duplicate), so the body is hand-spliced: a well-formed config
        // tail whose table carries the duplicate, then the plain
        // request fields.
        use super::encode_config;
        let mut body = Vec::new();
        put_u32(&mut body, PROTO_VERSION);
        encode_config(&mut body, &rich_config());
        // `rich_config` carries no tables: drop the five absent bytes the
        // encoder just wrote (the M91 tail's slots at the config's end —
        // the rank table, then the cstring table, then the M102
        // bind-at-load byte, then the M104 keep-local-symbols byte, then
        // the M105 strip-debug byte), the hand-spliced rank table takes
        // the first place and the cstring absence follows.
        body.truncate(body.len() - 5);
        // The v47 table tail: present, two entries, the second a
        // duplicate of the first (the lines ride, so the refusal reads
        // like the cold lane's).
        put_u8(&mut body, 1);
        put_u32(&mut body, 2);
        put_u8(&mut body, 0); // no object (global)
        put_str(&mut body, "_main");
        put_u32(&mut body, 1);
        put_u8(&mut body, 0);
        put_str(&mut body, "_main");
        put_u32(&mut body, 9);
        put_u8(&mut body, 0); // the M91 cstring rank table's absence
        put_u8(&mut body, 0); // the M102 bind-at-load absence
        put_u8(&mut body, 0); // the M104 keep-local-symbols drop face
        put_u8(&mut body, 0); // the M105 strip-debug absence
        // The plain request fields behind the config.
        put_u32(&mut body, 0); // force_load
        put_u32(&mut body, 0); // inputs
        put_u32(&mut body, 0); // archives
        put_u8(&mut body, 0); // record
        put_u8(&mut body, 0); // record_resolution
        put_u8(&mut body, 0); // prev_output
        put_u8(&mut body, 0); // audit
        put_u8(&mut body, 0); // tiles
        put_u8(&mut body, 0); // time
        put_u8(&mut body, 0); // trace
        put_u8(&mut body, 0); // verify
        put_u8(&mut body, 0); // verify_checks
        put_u32(&mut body, 0); // why_export count
        put_u8(&mut body, 0); // why_load
        put_u8(&mut body, 0); // map
        let err = LinkRequest::decode(&body).unwrap_err();
        let DecodeError::Malformed(e) = err else {
            panic!("a duplicate rank table is malformed, got {err:?}");
        };
        let text = e.to_string();
        assert!(
            text.contains("rank") && text.contains("_main"),
            "the refusal names the contradiction: {text}"
        );
    }

    // ---- M91: the cstring rank table crosses the wire (the v47 tail) -----

    #[test]
    fn the_cstring_rank_table_round_trips() {
        // The M91 rung: the decoded literal contents ride the config
        // tail — a resident link orders the `__cstring` literals the
        // client named (never the default absence), and the rebuilt
        // table's lookup answers exactly what the client's table
        // answers (the NUL-exclusive content match).
        let mut req = map_request();
        req.map = false;
        req.config.cstring_order =
            Some(pgr_core::order::CstringOrder::parse("first\ngamma\n").expect("the table parses"));
        let back = LinkRequest::decode(&req.encode()).unwrap();
        let ranks = back.config.cstring_order.expect("the table rides the wire");
        let entries = ranks.entries();
        assert_eq!(
            entries,
            [b"first".to_vec(), b"gamma".to_vec()],
            "the decoded contents ride in rank order: {entries:?}"
        );
        assert_eq!(
            ranks.rank_of(b"gamma\0"),
            Some(1),
            "the NUL strips before the lookup"
        );
        assert_eq!(ranks.rank_of(b"gamma"), Some(1));
        assert_eq!(ranks.rank_of(b"unranked"), None);
        // The empty flag (the pre-M91 shape) is byte-identical on the
        // decode side.
        let mut plain = req.clone();
        plain.config.cstring_order = None;
        let back = LinkRequest::decode(&plain.encode()).unwrap();
        assert!(back.config.cstring_order.is_none(), "the absence rides");
    }

    #[test]
    fn a_wire_garbage_cstring_table_is_malformed() {
        // Two ranks for one literal is a contradiction — the wire never
        // carries a table the pipeline would silently misread (the
        // rebuild's refusal, the rank positions named). The encode side
        // cannot produce the shape (a [`CstringOrder`] cannot hold a
        // duplicate), so the body is hand-spliced: a well-formed config
        // tail whose cstring table carries the duplicate, then the
        // plain request fields.
        use super::encode_config;
        let mut body = Vec::new();
        put_u32(&mut body, PROTO_VERSION);
        encode_config(&mut body, &rich_config());
        body.truncate(body.len() - 5);
        put_u8(&mut body, 0); // the rank table's absence
        // The M91 cstring tail: present, two entries, the second a
        // duplicate of the first.
        put_u8(&mut body, 1);
        put_u32(&mut body, 2);
        for _ in 0..2 {
            put_u32(&mut body, 5);
            body.extend_from_slice(b"gamma");
        }
        put_u8(&mut body, 0); // the M102 bind-at-load absence
        put_u8(&mut body, 0); // the M104 keep-local-symbols drop face
        put_u8(&mut body, 0); // the M105 strip-debug absence
        // The plain request fields behind the config.
        put_u32(&mut body, 0); // force_load
        put_u32(&mut body, 0); // inputs
        put_u32(&mut body, 0); // archives
        put_u8(&mut body, 0); // record
        put_u8(&mut body, 0); // record_resolution
        put_u8(&mut body, 0); // prev_output
        put_u8(&mut body, 0); // audit
        put_u8(&mut body, 0); // tiles
        put_u8(&mut body, 0); // time
        put_u8(&mut body, 0); // trace
        put_u8(&mut body, 0); // verify
        put_u8(&mut body, 0); // verify_checks
        put_u32(&mut body, 0); // why_export count
        put_u8(&mut body, 0); // why_load
        put_u8(&mut body, 0); // map
        let err = LinkRequest::decode(&body).unwrap_err();
        let DecodeError::Malformed(e) = err else {
            panic!("a duplicate cstring table is malformed, got {err:?}");
        };
        let text = e.to_string();
        assert!(
            text.contains("literal") && text.contains("rank"),
            "the refusal names the contradiction: {text}"
        );
    }

    // ---- M83: the relocatable shape rides the daemon -------------------

    #[test]
    fn the_relocatable_config_round_trips() {
        // The M83 rung: the reserved wire value decodes now — the
        // session's walk serves the object shape, and the codec is
        // lossless over the config it carries.
        let mut req = map_request();
        req.map = false;
        req.config.filetype = OutputType::Relocatable;
        let back = LinkRequest::decode(&req.encode()).unwrap();
        assert_eq!(
            back.config.filetype,
            OutputType::Relocatable,
            "the relocatable output rides the wire"
        );
        assert_eq!(back.encode(), req.encode(), "the codec is lossless");
    }

    /// The replay faces a relocatable request cannot carry (the wire
    /// gate's input, one setter per face).
    fn face_record(req: &mut LinkRequest) {
        req.record = Some(vec![1, 2, 3]);
    }
    fn face_prev_output(req: &mut LinkRequest) {
        req.prev_output = Some([0u8; 32]);
    }
    fn face_audit(req: &mut LinkRequest) {
        req.audit = true;
    }
    fn face_tiles(req: &mut LinkRequest) {
        req.tiles = true;
    }
    fn face_verify(req: &mut LinkRequest) {
        req.verify = true;
    }
    fn face_map(req: &mut LinkRequest) {
        req.map = true;
    }
    fn face_capture(req: &mut LinkRequest) {
        req.record_resolution = true;
    }

    #[test]
    fn a_replay_face_beside_the_relocatable_output_refuses() {
        // The object shape has no ladder: a record, tiles, the audit,
        // `-verify` or `-map` beside a relocatable config is a malformed
        // request, never a silently widened one (the surface refuses the
        // knobs beside `-r`; no wire caller can plan the shape either).
        let faces: [(fn(&mut LinkRequest), &str); 7] = [
            (face_record, "record"),
            (face_prev_output, "previous output"),
            (face_audit, "audit"),
            (face_tiles, "tiles"),
            (face_verify, "verify"),
            (face_map, "map"),
            (face_capture, "capture"),
        ];
        for (face, name) in faces {
            let mut req = map_request();
            req.map = false;
            req.config.filetype = OutputType::Relocatable;
            face(&mut req);
            let err = LinkRequest::decode(&req.encode()).unwrap_err();
            let DecodeError::Malformed(e) = err else {
                panic!("the {name} beside the relocatable output is malformed");
            };
            let text = e.to_string();
            assert!(
                text.contains("relocatable"),
                "the refusal names the shape ({name}): {text}"
            );
        }
    }
}
