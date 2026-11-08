//! M9 — the in-place incremental relink engine (architecture doc §10.4 row
//! M9; §7.3 Stage C, tier 1: *record → diff → patch → rehash*).
//!
//! A full relink writes and re-hashes every byte of the output. This module
//! implements the §7.3 output path instead:
//!
//! 1. **record** ([`LinkRecord::record`]) — after a full link, capture the
//!    emit plan's byte-producing *spans* (copy runs, synthetic pieces,
//!    `__LINKEDIT` chunks, patch stream, fixup words) with content
//!    digests, the output skeleton (sections, segments, `__LINKEDIT`
//!    chunk plan), the signature's final 4 KiB page-hash table, and the
//!    header digest. The record is a versioned, checksum-framed,
//!    pointer-free blob (the M7 cache framing shape) written next to the
//!    output.
//! 2. **plan** ([`plan_patch`]) — re-run the pipeline (Passes 1–3; the
//!    parse is the Stage A POI cache's job) and compare the *new* plan
//!    against the record:
//!    * the **skeleton gate** requires the frozen structure to hold —
//!      same file size, segment/section placement, `__LINKEDIT` chunk
//!      plan, identity — anything else is the §7.3 fallback ladder
//!      (classified through [`SlackPolicy::fits`] when slack is active);
//!    * the **span diff** marks every 16 KiB tile whose byte-producing
//!      spans changed; the dirty-tile set *is* the patch plan. When every
//!      content tile is dirty the full emit is cheaper and the planner
//!      falls back (the patch path exists to avoid work, not to hoist it).
//! 3. **patch** ([`apply_patch`]) — clone the previous output (on macOS
//!    `std::fs::copy` resolves to `fclonefileat`: an instant APFS
//!    copy-on-write clone; on Linux to `copy_file_range`), `pwrite` only
//!    the dirty tiles into the clone, rebuild page 0 with the freshly
//!    derived `LC_UUID`, and rebuild the CodeDirectory from the *merged*
//!    hash table — recorded hashes for clean tiles, recomputed hashes for
//!    dirty ones — then rename over the output. Bytes written scale with
//!    the change, not the image.
//!
//! Correctness contract (stronger than the §7.3 GA bar): the emit is a
//! pure function of the plan spans, and a tile is reused iff every span
//! touching it is unchanged — so the patched file is **byte-identical to
//! the full fused emit of the same plan**. That identity is a test gate
//! (`tests/incremental.rs`), and the driver's `-incremental-verify`
//! re-proves it per link.
//!
//! Trust model, stated honestly: the record trusts that the on-disk output
//! is the one it recorded. The cheap gate ([`check_output`]) hashes the
//! first page and a deterministic 1/64 sample of the hashed pages; the
//! code signature is the *load-time* integrity mechanism for everything
//! else (a tampered clean page breaks the CodeDirectory at exec), and
//! `-incremental-verify` is the audit gate that hashes nothing less than
//! everything.

use crate::EmitError;
use crate::emit::{indirect_bytes, symtab_bytes};
use crate::signature;
use crate::tile::{TileCtx, emit_tile, tile_hashes};
use pgr_core::layout::{Layout, PatchOp};
use pgr_core::object::InputObject;
use pgr_core::slack::{LayoutFallback, SlackPolicy};
use pgr_format::consts::PAGE_SIZE_16K;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Tile width: one 16 KiB output page (the fused emit's tile invariant —
/// chains never cross it, TDD §7.4).
const TILE: u64 = PAGE_SIZE_16K;

/// The signature's 4 KiB hash-page size (`CS_PAGE_SIZE_LOG2 = 12`).
const HASH_PAGE: u64 = 4096;

/// Record framing magic (versioned; see [`FORMAT_VERSION`]).
const MAGIC: &[u8; 8] = b"PGRINC1\0";

/// Record format revision. Bump when the payload layout changes; older
/// records then fail to decode and the relink silently falls back to the
/// full link (the fallback must always be available — §7.3).
pub const FORMAT_VERSION: u32 = 1;

const HEADER_LEN: usize = 8 + 4 + 8 + 32;

/// A byte-producing span with its content digest: `(dst, len, sha256)`.
/// Emit writes `len` bytes at `dst` from these spans and nothing else
/// (the rest of the buffer is zero by contract), so two plans whose spans
/// agree produce identical bytes — the property the tile-reuse decision
/// leans on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSpan {
    /// Absolute output file offset.
    pub dst: u64,
    /// Span length in bytes.
    pub len: u64,
    /// SHA-256 over the span's bytes as emit would write them.
    pub sha: [u8; 32],
}

/// Every byte-producing span of one emit plan, sorted by `dst` inside each
/// list (the fused emit's tile context, flattened into digest form).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpanTable {
    /// Copy runs (input section bytes, coalesced, M4).
    pub runs: Vec<RecordedSpan>,
    /// Synthetic pieces (`__got` slots, `__stubs` entries, veneers).
    pub synths: Vec<RecordedSpan>,
    /// Placed `__LINKEDIT` / `__chain_starts` chunks.
    pub blobs: Vec<RecordedSpan>,
    /// The absolute-position patch stream (≤ 8-byte writes at `dst`).
    pub patches: Vec<RecordedSpan>,
    /// Encoded chained-fixup slot words (8-byte writes at `dst`).
    pub words: Vec<RecordedSpan>,
}

/// One recorded `LC_SEGMENT_64`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSegment {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size.
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
    /// Maximum protection.
    pub maxprot: u32,
    /// Initial protection.
    pub initprot: u32,
}

/// One recorded output section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSection {
    /// Owning segment name.
    pub seg: String,
    /// Section name.
    pub name: String,
    /// Merged `S_*` flags.
    pub flags: u32,
    /// Alignment exponent.
    pub align_log2: u32,
    /// vaddr.
    pub vm_addr: u64,
    /// Content bytes (the pre-slack cursor — the ladder's `new_content`).
    pub content_size: u64,
    /// Reserved (padded) output size — the anchor value.
    pub size: u64,
    /// File offset.
    pub file_off: u64,
    /// Zero-fill (no file bytes).
    pub zerofill: bool,
}

/// The recorded state of one full link — everything the incremental relink
/// needs to decide what changed and to patch only those bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkRecord {
    /// The format revision this record decodes under.
    pub format_version: u32,
    /// Total output file size.
    pub file_size: u64,
    /// The image base (vaddr → file offset subtraction base).
    pub image_base: u64,
    /// Mach-O file type.
    pub filetype: u32,
    /// `__TEXT` vmsize (the signature's execSegLimit).
    pub text_vmsize: u64,
    /// Entry offset within `__TEXT`.
    pub entryoff: u64,
    /// The signature identity string (CodeDirectory length depends on it).
    pub ident: String,
    /// The hashed prefix length (the CodeDirectory codeLimit = `sig_off`
    /// when the image is signed, 0 when `-no_adhoc`).
    pub code_limit: u64,
    /// The `__LINKEDIT` chunk plan (offsets + sizes, contract-coupled).
    pub linkedit: pgr_core::layout::LinkeditPlan,
    /// SHA-256 over the header + load-command bytes.
    pub header_sha: [u8; 32],
    /// Segments in command order.
    pub segments: Vec<RecordedSegment>,
    /// Sections in file order.
    pub sections: Vec<RecordedSection>,
    /// The recorded emit spans.
    pub spans: SpanTable,
    /// The signature's final page-hash table (page 0 hashed with the UUID
    /// in place, pages ≥ 1 over the final content — the fused emit's
    /// table exactly).
    pub page_hashes: Vec<[u8; 32]>,
}

/// Why the incremental planner fell back to the full link. The fallback is
/// always available and always correct (§7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackReason {
    /// No record exists yet (the first link of this output).
    NoRecord,
    /// The record is unreadable (foreign, corrupt, or from another
    /// format/parser revision) — it is deleted and re-recorded.
    RecordUnreadable,
    /// The output file on disk no longer matches the record (missing,
    /// resized, or failed the sampled integrity gate).
    OutputChanged {
        /// What diverged.
        detail: String,
    },
    /// The link's skeleton moved: a section/segment placement, the
    /// `__LINKEDIT` segment extent, the signature boundary or the file size
    /// changed. Classified through the §7.3 ladder when slack is active.
    Skeleton {
        /// What moved.
        detail: String,
        /// The ladder tier the change maps to (`None` when the change is
        /// structural rather than a section-size change).
        tier: Option<LayoutFallback>,
    },
    /// Every content tile is dirty; the full emit is cheaper.
    Economics {
        /// Dirty tiles / total tiles.
        dirty: u32,
        /// Total tiles in the image.
        total: u32,
    },
    /// The caller disabled the in-place tier.
    Disabled,
}

impl std::fmt::Display for FallbackReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRecord => write!(f, "no record for this output yet"),
            Self::RecordUnreadable => write!(f, "record unreadable; re-recording"),
            Self::OutputChanged { detail } => write!(f, "output changed: {detail}"),
            Self::Skeleton { detail, tier } => match tier {
                Some(t) => write!(f, "skeleton moved ({detail}; ladder tier {t:?})"),
                None => write!(f, "skeleton moved ({detail})"),
            },
            Self::Economics { dirty, total } => {
                write!(f, "{dirty}/{total} tiles dirty; the full emit is cheaper")
            }
            Self::Disabled => write!(f, "in-place tier disabled"),
        }
    }
}

/// The planner's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatchDecision {
    /// The skeleton holds and the dirty-tile set is computable: patch in
    /// place.
    InPlace(PatchPlan),
    /// Run the full clean link (always correct).
    Fallback(FallbackReason),
}

/// One planner product: the 16 KiB tiles emit must recompute, plus the new
/// plan's span table (the digests the patch applier reuses when assembling
/// the refreshed record — extracted once per relink, not twice). Tile 0 is
/// in the set whenever anything else is (the `LC_UUID` derives from the
/// page hashes and lives on page 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchPlan {
    /// Dirty tile indices, ascending.
    pub dirty_tiles: Vec<u32>,
    /// Total tiles in the image.
    pub total_tiles: u32,
    /// The new plan's byte-producing spans (see [`LinkRecord::assemble_from`]).
    pub spans: SpanTable,
}

impl PatchPlan {
    /// True when nothing changed and the output can be left alone.
    #[must_use]
    pub fn is_untouched(&self) -> bool {
        self.dirty_tiles.is_empty()
    }
}

/// The patch's measured effect (the bench and the driver's report).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchOutcome {
    /// Bytes `pwrite`d into the clone (dirty tiles + page 0 + signature).
    pub bytes_patched: u64,
    /// Dirty tiles actually emitted.
    pub dirty_tiles: u32,
    /// Total tiles in the image.
    pub total_tiles: u32,
    /// True when nothing changed (the output was left byte-for-byte alone).
    pub untouched: bool,
}

/// A patch-path failure. [`PatchError::Fallback`] is control flow (the
/// driver re-runs the full link); the rest are real errors.
#[derive(Debug, thiserror::Error)]
pub enum PatchError {
    /// The planner or the caller decided on the full link.
    #[error("incremental fallback: {0}")]
    Fallback(FallbackReason),
    /// A plan/emit contract the full path would also have caught.
    #[error("emit contract violated: {message}")]
    Contract {
        /// What failed.
        message: String,
    },
    /// Filesystem failures on the clone/patch path. No partial output is
    /// left behind (the temp file is removed).
    #[error("patching {path}: {source}")]
    Io {
        /// The failing path.
        path: String,
        /// The OS error.
        source: std::io::Error,
    },
}

impl From<EmitError> for PatchError {
    fn from(e: EmitError) -> Self {
        match e {
            EmitError::Contract { message } => Self::Contract { message },
            EmitError::Internal { message } => Self::Contract {
                message: format!("internal: {message}"),
            },
            EmitError::Io { path, source } => Self::Io { path, source },
        }
    }
}

/// The sampled-integrity verdict for the previous output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Integrity {
    /// Size and every sampled page hash match the record.
    Match,
    /// Something diverged; the relink falls back.
    Mismatch {
        /// What diverged.
        detail: String,
    },
}

/// Integrity-gate sampling stride: hash pages 0, every 64th page, and the
/// last hashed page of the previous output. ~1.6% of a full re-hash — the
/// signature is the load-time gate for the rest.
const SAMPLE_STRIDE: u64 = 64;

// ---------------------------------------------------------------------------
// Recording
// ---------------------------------------------------------------------------

/// The span digest of one `(dst, bytes)` pair.
fn span_of(dst: u64, bytes: &[u8]) -> RecordedSpan {
    let mut h = Sha256::new();
    h.update(bytes);
    RecordedSpan {
        dst,
        len: bytes.len() as u64,
        sha: h.finalize().into(),
    }
}

/// Splits one byte-producing range into **tile-piece spans** — SHA-256 per
/// 16 KiB-aligned piece. A one-function edit inside a 256 KiB copy run
/// then dirties one tile instead of the whole run: the diff's granularity
/// is the span, so the span must not be coarser than the patch unit (the
/// same bytes are covered either way; only the dirtiness bookkeeping
/// sharpens).
fn tile_piece_spans(dst: u64, bytes: &[u8]) -> Vec<RecordedSpan> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let dst_at = dst + at as u64;
        let tile_end = (dst_at / TILE + 1) * TILE;
        let take = (((tile_end - dst_at) as usize).min(bytes.len() - at)).max(1);
        out.push(span_of(dst_at, &bytes[at..at + take]));
        at += take;
    }
    out
}

/// Encodes a [`PatchOp`] as a span: an ≤ 8-byte write at the absolute
/// patch position, digest over the operand encoding. Patch writes never
/// exceed 8 bytes (ADR/imm12/branch are 4, subtractors are 8), so 8 is
/// the safe mark width for the tile diff.
fn patch_span(at: u64, op: &PatchOp) -> RecordedSpan {
    let mut h = Sha256::new();
    let (in_offset, a, b): (u32, u64, u64) = match op {
        PatchOp::Adrp { in_offset, page_delta } => (*in_offset, *page_delta as u64, 0),
        PatchOp::PageOff12 { in_offset, imm12 } => (*in_offset, u64::from(*imm12), 0),
        PatchOp::Branch26 { in_offset, pc, delta } => (*in_offset, *pc, *delta as u64),
        PatchOp::Write64 { in_offset, value } => (*in_offset, *value, 0),
    };
    let kind: u8 = match op {
        PatchOp::Adrp { .. } => 1,
        PatchOp::PageOff12 { .. } => 2,
        PatchOp::Branch26 { .. } => 3,
        PatchOp::Write64 { .. } => 4,
    };
    h.update([kind]);
    h.update(in_offset.to_le_bytes());
    h.update(a.to_le_bytes());
    h.update(b.to_le_bytes());
    RecordedSpan {
        dst: at,
        len: 8,
        sha: h.finalize().into(),
    }
}

/// Flattens the fused emit's tile context into the recorded span table
/// (the same spans the full emit would write, in the same sorted order).
fn span_table(layout: &Layout, objects: &[InputObject]) -> Result<SpanTable, PatchError> {
    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
    let to_span = |&(dst, end, bytes): &(u64, u64, &[u8])| {
        debug_assert_eq!(end - dst, bytes.len() as u64);
        span_of(dst, bytes)
    };
    let to_pieces = |&(dst, end, bytes): &(u64, u64, &[u8])| {
        debug_assert_eq!(end - dst, bytes.len() as u64);
        tile_piece_spans(dst, bytes)
    };
    Ok(SpanTable {
        // Copy runs and `__LINKEDIT` chunks are the only spans that can
        // dwarf a tile; their digests are per tile piece so the dirty-tile
        // set tracks the change, not the span. Synthetics, patch writes
        // and chain words never exceed a tile.
        runs: ctx
            .run_spans
            .iter()
            .flat_map(to_pieces)
            .collect(),
        synths: ctx.synth_spans.iter().map(to_span).collect(),
        blobs: ctx.blob_spans.iter().flat_map(to_pieces).collect(),
        patches: ctx.patches.iter().map(|(at, op)| patch_span(*at, op)).collect(),
        words: ctx
            .words
            .iter()
            .map(|&(at, word)| span_of(at, &word.to_le_bytes()))
            .collect(),
    })
}

/// The skeleton (identity + placement + `__LINKEDIT` plan) of a layout.
fn skeleton_of(layout: &Layout) -> (Vec<RecordedSegment>, Vec<RecordedSection>) {
    let segments = layout
        .segments
        .iter()
        .map(|s| RecordedSegment {
            name: s.name.clone(),
            vmaddr: s.vmaddr,
            vmsize: s.vmsize,
            fileoff: s.fileoff,
            filesize: s.filesize,
            maxprot: s.maxprot,
            initprot: s.initprot,
        })
        .collect();
    let sections = layout
        .sections
        .iter()
        .map(|s| RecordedSection {
            seg: s.seg_name.clone(),
            name: s.name.clone(),
            flags: s.flags,
            align_log2: s.align_log2,
            vm_addr: s.vm_addr,
            content_size: s.pieces.iter().map(|p| p.offset + p.size).max().unwrap_or(0),
            size: s.size,
            file_off: s.file_off,
            zerofill: s.zerofill,
        })
        .collect();
    (segments, sections)
}

/// The hashed prefix of a layout (the fused emit's `content_end`).
fn content_limit(layout: &Layout) -> u64 {
    if layout.linkedit.sig_size > 0 {
        layout.linkedit.sig_off
    } else {
        0
    }
}

impl LinkRecord {
    /// Records a completed full link: the plan spans, the skeleton and the
    /// signature's final page-hash table, all derived from the finished
    /// image (so what is recorded is what is on disk).
    ///
    /// # Errors
    /// [`PatchError::Contract`] when the image/plan shapes disagree (the
    /// full emit would have failed the same way).
    pub fn record(
        layout: &Layout,
        objects: &[InputObject],
        image: &[u8],
    ) -> Result<Self, PatchError> {
        if image.len() as u64 != layout.file_size {
            return Err(PatchError::Contract {
                message: format!(
                    "image is {} bytes but the plan says {}",
                    image.len(),
                    layout.file_size
                ),
            });
        }
        // The fused emit's final table: page 0 hashed with the UUID in
        // place, pages ≥ 1 over the final content (the UUID lives only on
        // page 0, so their zeroed and final forms coincide).
        let code_limit = content_limit(layout);
        let mut page_hashes: Vec<[u8; 32]> = Vec::new();
        if code_limit > 0 {
            let first_end = (HASH_PAGE as usize).min(image.len());
            let first: [u8; 32] = Sha256::digest(&image[..first_end]).into();
            page_hashes.push(first);
            let mut at = HASH_PAGE;
            while at < code_limit {
                let end = (at + HASH_PAGE).min(code_limit) as usize;
                let h: [u8; 32] = Sha256::digest(&image[at as usize..end]).into();
                page_hashes.push(h);
                at += HASH_PAGE;
            }
        }
        Self::assemble(layout, objects, page_hashes)
    }

    /// [`LinkRecord::record`] with the hash table supplied by the patch
    /// path (which computes it while writing, without a whole-image read).
    ///
    /// # Errors
    /// [`PatchError::Contract`] when the plan's spans cannot be extracted
    /// (a shape the full emit would also reject).
    pub fn assemble(
        layout: &Layout,
        objects: &[InputObject],
        page_hashes: Vec<[u8; 32]>,
    ) -> Result<Self, PatchError> {
        let spans = span_table(layout, objects)?;
        Self::assemble_from(layout, spans, page_hashes)
    }

    /// [`LinkRecord::assemble`] with a pre-extracted span table — the patch
    /// path reuses the planner's digests (the same plan, extracted once).
    ///
    /// # Errors
    /// [`PatchError::Contract`] when the layout is inconsistent with the
    /// table (a shape the full emit would also reject).
    pub fn assemble_from(
        layout: &Layout,
        spans: SpanTable,
        page_hashes: Vec<[u8; 32]>,
    ) -> Result<Self, PatchError> {
        let (segments, sections) = skeleton_of(layout);
        let header_sha: [u8; 32] = Sha256::digest(&layout.header_bytes).into();
        Ok(Self {
            format_version: FORMAT_VERSION,
            file_size: layout.file_size,
            image_base: layout.image_base,
            filetype: layout.filetype,
            text_vmsize: layout.text_vmsize,
            entryoff: layout.entryoff,
            ident: layout.ident.clone(),
            code_limit: content_limit(layout),
            linkedit: layout.linkedit,
            header_sha,
            segments,
            sections,
            spans,
            page_hashes,
        })
    }

    /// The signature hash table length in pages.
    #[must_use]
    pub fn hashed_pages(&self) -> u64 {
        self.code_limit.div_ceil(HASH_PAGE)
    }

    /// Serializes the record: `magic | version | payload_len | sha256 |
    /// payload` — the M7 cache framing shape, little-endian, pointer-free,
    /// deterministic (no timestamps, no paths).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut p = Vec::with_capacity(4096);
        let e = |p: &mut Vec<u8>, v: u64| p.extend_from_slice(&v.to_le_bytes());
        e(&mut p, self.file_size);
        e(&mut p, self.image_base);
        e(&mut p, u64::from(self.filetype));
        e(&mut p, self.text_vmsize);
        e(&mut p, self.entryoff);
        e(&mut p, self.code_limit);
        e(&mut p, self.ident.len() as u64);
        p.extend_from_slice(self.ident.as_bytes());
        e(&mut p, self.linkedit.fixup_payload_off);
        e(&mut p, self.linkedit.fixup_payload_size as u64);
        e(&mut p, self.linkedit.trie_off);
        e(&mut p, self.linkedit.trie_size as u64);
        e(&mut p, self.linkedit.func_starts_off);
        e(&mut p, self.linkedit.func_starts_size as u64);
        e(&mut p, self.linkedit.sym_off);
        e(&mut p, self.linkedit.sym_size as u64);
        e(&mut p, self.linkedit.str_off);
        e(&mut p, self.linkedit.str_size as u64);
        e(&mut p, self.linkedit.indirect_off);
        e(&mut p, self.linkedit.indirect_size as u64);
        e(&mut p, self.linkedit.uuid_at);
        e(&mut p, self.linkedit.sig_off);
        e(&mut p, self.linkedit.sig_size);
        e(&mut p, self.linkedit.dyld_rebase_off);
        e(&mut p, self.linkedit.dyld_rebase_size as u64);
        e(&mut p, self.linkedit.dyld_bind_off);
        e(&mut p, self.linkedit.dyld_bind_size as u64);
        p.extend_from_slice(&self.header_sha);
        e(&mut p, self.segments.len() as u64);
        for s in &self.segments {
            e(&mut p, s.name.len() as u64);
            p.extend_from_slice(s.name.as_bytes());
            e(&mut p, s.vmaddr);
            e(&mut p, s.vmsize);
            e(&mut p, s.fileoff);
            e(&mut p, s.filesize);
            e(&mut p, u64::from(s.maxprot));
            e(&mut p, u64::from(s.initprot));
        }
        e(&mut p, self.sections.len() as u64);
        for s in &self.sections {
            e(&mut p, s.seg.len() as u64);
            p.extend_from_slice(s.seg.as_bytes());
            e(&mut p, s.name.len() as u64);
            p.extend_from_slice(s.name.as_bytes());
            e(&mut p, u64::from(s.flags));
            e(&mut p, u64::from(s.align_log2));
            e(&mut p, s.vm_addr);
            e(&mut p, s.content_size);
            e(&mut p, s.size);
            e(&mut p, s.file_off);
            e(&mut p, u64::from(s.zerofill));
        }
        let spans = |p: &mut Vec<u8>, list: &[RecordedSpan]| {
            e(p, list.len() as u64);
            for s in list {
                e(p, s.dst);
                e(p, s.len);
                p.extend_from_slice(&s.sha);
            }
        };
        spans(&mut p, &self.spans.runs);
        spans(&mut p, &self.spans.synths);
        spans(&mut p, &self.spans.blobs);
        spans(&mut p, &self.spans.patches);
        spans(&mut p, &self.spans.words);
        e(&mut p, self.page_hashes.len() as u64);
        for h in &self.page_hashes {
            p.extend_from_slice(h);
        }

        let mut out = Vec::with_capacity(HEADER_LEN + p.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        let digest: [u8; 32] = Sha256::digest(&p).into();
        out.extend_from_slice(&digest);
        out.extend_from_slice(&p);
        out
    }

    /// Decodes a record (the inverse of [`LinkRecord::encode`]). Any
    /// corruption — wrong magic, unknown version, truncated or trailing
    /// bytes, checksum mismatch — returns `None`, never panics: the record
    /// is an accelerator only.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < HEADER_LEN || bytes[..8] != *MAGIC {
            return None;
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
        let payload_len = u64::from_le_bytes(bytes[12..20].try_into().ok()?);
        let payload_len = usize::try_from(payload_len).ok()?;
        if bytes.len() != HEADER_LEN + payload_len {
            return None;
        }
        let payload = &bytes[HEADER_LEN..];
        let want: [u8; 32] = bytes[20..52].try_into().ok()?;
        let got: [u8; 32] = Sha256::digest(payload).into();
        if got != want {
            return None;
        }
        let mut d = Decoder { b: payload, at: 0 };
        if version != FORMAT_VERSION {
            return None;
        }
        let file_size = d.u64()?;
        let image_base = d.u64()?;
        let filetype = u32::try_from(d.u64()?).ok()?;
        let text_vmsize = d.u64()?;
        let entryoff = d.u64()?;
        let code_limit = d.u64()?;
        let ident = d.str()?;
        let le = pgr_core::layout::LinkeditPlan {
            fixup_payload_off: d.u64()?,
            fixup_payload_size: usize::try_from(d.u64()?).ok()?,
            trie_off: d.u64()?,
            trie_size: usize::try_from(d.u64()?).ok()?,
            func_starts_off: d.u64()?,
            func_starts_size: usize::try_from(d.u64()?).ok()?,
            sym_off: d.u64()?,
            sym_size: usize::try_from(d.u64()?).ok()?,
            str_off: d.u64()?,
            str_size: usize::try_from(d.u64()?).ok()?,
            indirect_off: d.u64()?,
            indirect_size: usize::try_from(d.u64()?).ok()?,
            uuid_at: d.u64()?,
            sig_off: d.u64()?,
            sig_size: d.u64()?,
            dyld_rebase_off: d.u64()?,
            dyld_rebase_size: usize::try_from(d.u64()?).ok()?,
            dyld_bind_off: d.u64()?,
            dyld_bind_size: usize::try_from(d.u64()?).ok()?,
        };
        let mut header_sha = [0u8; 32];
        d.bytes(&mut header_sha)?;
        let mut segment = |d: &mut Decoder<'_>| {
            let name = d.str()?;
            Some(RecordedSegment {
                name,
                vmaddr: d.u64()?,
                vmsize: d.u64()?,
                fileoff: d.u64()?,
                filesize: d.u64()?,
                maxprot: u32::try_from(d.u64()?).ok()?,
                initprot: u32::try_from(d.u64()?).ok()?,
            })
        };
        let segments = d.list(&mut segment)?;
        let mut section = |d: &mut Decoder<'_>| {
            let seg = d.str()?;
            let name = d.str()?;
            Some(RecordedSection {
                seg,
                name,
                flags: u32::try_from(d.u64()?).ok()?,
                align_log2: u32::try_from(d.u64()?).ok()?,
                vm_addr: d.u64()?,
                content_size: d.u64()?,
                size: d.u64()?,
                file_off: d.u64()?,
                zerofill: d.u64()? == 1,
            })
        };
        let sections = d.list(&mut section)?;
        let mut span = |d: &mut Decoder<'_>| {
            let dst = d.u64()?;
            let len = d.u64()?;
            let mut sha = [0u8; 32];
            d.bytes(&mut sha)?;
            Some(RecordedSpan { dst, len, sha })
        };
        let spans = SpanTable {
            runs: d.list(&mut span)?,
            synths: d.list(&mut span)?,
            blobs: d.list(&mut span)?,
            patches: d.list(&mut span)?,
            words: d.list(&mut span)?,
        };
        let n_hashes = usize::try_from(d.u64()?).ok()?;
        if n_hashes > d.b.len() / 32 {
            return None;
        }
        let mut page_hashes = Vec::with_capacity(n_hashes);
        for _ in 0..n_hashes {
            let mut h = [0u8; 32];
            d.bytes(&mut h)?;
            page_hashes.push(h);
        }
        if d.at != d.b.len() {
            return None;
        }
        Some(Self {
            format_version: version,
            file_size,
            image_base,
            filetype,
            text_vmsize,
            entryoff,
            ident,
            code_limit,
            linkedit: le,
            header_sha,
            segments,
            sections,
            spans,
            page_hashes,
        })
    }
}

/// A checked little-endian decoder: every read is bounds-checked and
/// returns `Option` — the decode path is panic-free by construction.
struct Decoder<'a> {
    b: &'a [u8],
    at: usize,
}

impl Decoder<'_> {
    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.b.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn bytes(&mut self, dst: &mut [u8]) -> Option<()> {
        let src = self.take(dst.len())?;
        dst.copy_from_slice(src);
        Some(())
    }

    fn str(&mut self) -> Option<String> {
        let len = usize::try_from(self.u64()?).ok()?;
        // A record's strings are short (segment/section/identity names);
        // absurd lengths are corruption, not allocations waiting to happen.
        if len > 4096 {
            return None;
        }
        String::from_utf8(self.take(len)?.to_vec()).ok()
    }

    fn list<T>(
        &mut self,
        item: &mut impl FnMut(&mut Decoder<'_>) -> Option<T>,
    ) -> Option<Vec<T>> {
        let n = usize::try_from(self.u64()?).ok()?;
        if n > self.b.len() {
            return None;
        }
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(item(self)?);
        }
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// The first structural difference between the recorded skeleton and the
/// new plan, or `None` when the frozen structure holds. Anything listed
/// here moves bytes the patch path cannot rewrite in place.
fn skeleton_mismatch(record: &LinkRecord, layout: &Layout) -> Option<String> {
    let le = &layout.linkedit;
    let check = |r: u64, n: u64, what: &str| {
        if r == n {
            None
        } else {
            Some(format!("{what}: recorded {r:#x}, new {n:#x}"))
        }
    };
    let (segments, sections) = skeleton_of(layout);
    // The frozen skeleton: identity, placement, and the signature boundary.
    // `__LINKEDIT` *internals* (chunk offsets/sizes) are deliberately NOT
    // frozen: a grown function-starts stream or one more symtab entry
    // rearranges chunks inside the segment, and the blob-span diff handles
    // exactly that — the affected tiles are dirty, the bytes rewritten, the
    // boundary (sig_off/sig_size/uuid_at/file_size) untouched. Only the
    // segment's own plan (fileoff/filesize) pins the region's extent.
    let numeric: [(&str, u64, u64); 9] = [
        ("file_size", record.file_size, layout.file_size),
        ("image_base", record.image_base, layout.image_base),
        ("filetype", u64::from(record.filetype), u64::from(layout.filetype)),
        ("text_vmsize", record.text_vmsize, layout.text_vmsize),
        ("entryoff", record.entryoff, layout.entryoff),
        ("code_limit", record.code_limit, content_limit(layout)),
        ("sig_off", record.linkedit.sig_off, le.sig_off),
        ("sig_size", record.linkedit.sig_size, le.sig_size),
        ("uuid_at", record.linkedit.uuid_at, le.uuid_at),
    ];
    for (what, r, n) in numeric {
        if let Some(d) = check(r, n, what) {
            return Some(d);
        }
    }
    if le.uuid_at.checked_add(16).is_none_or(|end| end > HASH_PAGE) {
        return Some(format!(
            "uuid_at {:#x} leaves the first hash page — not supported by the in-place tier",
            le.uuid_at
        ));
    }
    if record.ident != layout.ident {
        return Some(format!("ident {:?} -> {:?}", record.ident, layout.ident));
    }
    if record.segments.len() != segments.len() {
        return Some(format!(
            "segment count {} -> {}",
            record.segments.len(),
            segments.len()
        ));
    }
    for (r, n) in record.segments.iter().zip(&segments) {
        if r != n {
            return Some(format!("segment {} moved", n.name));
        }
    }
    if record.sections.len() != sections.len() {
        return Some(format!(
            "section count {} -> {}",
            record.sections.len(),
            sections.len()
        ));
    }
    for (r, n) in record.sections.iter().zip(&sections) {
        // Content may grow *within* the reservation (that is the point of
        // slack); the reserved size and everything around it may not.
        if r.seg != n.seg
            || r.name != n.name
            || r.flags != n.flags
            || r.align_log2 != n.align_log2
            || r.vm_addr != n.vm_addr
            || r.size != n.size
            || r.file_off != n.file_off
            || r.zerofill != n.zerofill
        {
            return Some(format!("section {}:{} moved or resized", n.seg, n.name));
        }
    }
    None
}

/// Classifies a skeleton fallback through the §7.3 ladder: the first
/// section whose *reserved size* changed is run through
/// [`SlackPolicy::fits`] (tier 2 = segment re-layout, tier 3 = clean
/// link); anything else is structural and lands on the clean link
/// directly.
fn ladder_tier(
    record: &LinkRecord,
    layout: &Layout,
    policy: Option<&SlackPolicy>,
) -> Option<LayoutFallback> {
    let policy = policy?;
    let (_, sections) = skeleton_of(layout);
    for (r, n) in record.sections.iter().zip(&sections) {
        let same_slot = r.seg == n.seg && r.name == n.name;
        if same_slot && r.size != n.size {
            return Some(policy.fits(r.content_size, n.content_size, r.size));
        }
    }
    None
}

/// Marks the divergent ranges of one span list pair. Both lists are sorted
/// by `dst`; the two-pointer walk aligns matching spans and marks
/// everything else on *both* sides (a removed or moved span changes bytes
/// at its old position too — the zeros the new plan leaves behind differ
/// from the old bytes).
fn diff_spans(old: &[RecordedSpan], new: &[RecordedSpan], out: &mut Vec<Range<u64>>) {
    let (mut i, mut j) = (0usize, 0usize);
    while i < old.len() && j < new.len() {
        let (o, n) = (&old[i], &new[j]);
        if o.dst == n.dst && o.len == n.len {
            if o.sha != n.sha {
                out.push(o.dst..o.dst + o.len);
            }
            i += 1;
            j += 1;
        } else if o.dst < n.dst {
            out.push(o.dst..o.dst + o.len);
            i += 1;
        } else {
            out.push(n.dst..n.dst + n.len);
            j += 1;
        }
    }
    for o in &old[i..] {
        out.push(o.dst..o.dst + o.len);
    }
    for n in &new[j..] {
        out.push(n.dst..n.dst + n.len);
    }
}

/// Plans the incremental relink: skeleton gate, span diff, dirty tiles.
///
/// `slack` is the link's active policy (used only to classify a skeleton
/// fallback through the §7.3 ladder).
///
/// # Errors
/// [`PatchError::Contract`] on plan shapes the full emit would also
/// reject.
pub fn plan_patch(
    record: &LinkRecord,
    layout: &Layout,
    objects: &[InputObject],
    slack: Option<&SlackPolicy>,
) -> Result<PatchDecision, PatchError> {
    if let Some(detail) = skeleton_mismatch(record, layout) {
        let tier = ladder_tier(record, layout, slack);
        return Ok(PatchDecision::Fallback(FallbackReason::Skeleton { detail, tier }));
    }
    let new_spans = span_table(layout, objects)?;
    let mut ranges: Vec<Range<u64>> = Vec::new();
    diff_spans(&record.spans.runs, &new_spans.runs, &mut ranges);
    diff_spans(&record.spans.synths, &new_spans.synths, &mut ranges);
    diff_spans(&record.spans.blobs, &new_spans.blobs, &mut ranges);
    diff_spans(&record.spans.patches, &new_spans.patches, &mut ranges);
    diff_spans(&record.spans.words, &new_spans.words, &mut ranges);
    // The header bytes are written outside the span lists; a header change
    // (entryoff, load commands) dirties tile 0.
    let header_digest: [u8; 32] = Sha256::digest(&layout.header_bytes).into();
    if record.header_sha != header_digest {
        ranges.push(0..layout.header_bytes.len() as u64);
    }

    let total = layout.file_size.div_ceil(TILE) as u32;
    let mut dirty: Vec<u32> = Vec::new();
    for r in ranges {
        let first = (r.start / TILE) as u32;
        let last = ((r.end.saturating_sub(1)).max(r.start) / TILE) as u32;
        for t in first..=last.min(total - 1) {
            if !dirty.contains(&t) {
                dirty.push(t);
            }
        }
    }
    dirty.sort_unstable();
    // Anything dirty changes the page hashes, hence the UUID, hence page 0
    // — but only when the image is signed (an unsigned image keeps the
    // zero UUID and has no hash table; the full emit never derives one).
    if !dirty.is_empty() && dirty[0] != 0 && record.code_limit > 0 {
        dirty.insert(0, 0);
    }
    // Economics: when *every* content tile needs rewriting, the full emit
    // (no clone, no per-tile scratch) is strictly cheaper. Tile 0 always
    // rides along (the UUID) and is not counted against the patch.
    let content_dirty = dirty.len() - usize::from(!dirty.is_empty());
    if u64::from(content_dirty as u32) >= u64::from(total.saturating_sub(1).max(1)) {
        return Ok(PatchDecision::Fallback(FallbackReason::Economics {
            dirty: dirty.len() as u32,
            total,
        }));
    }
    Ok(PatchDecision::InPlace(PatchPlan {
        dirty_tiles: dirty,
        total_tiles: total,
        spans: new_spans,
    }))
}

// ---------------------------------------------------------------------------
// The output integrity gate
// ---------------------------------------------------------------------------

/// Cheaply verifies the previous output still matches the record: the file
/// length and the SHA-256 of page 0, every [`SAMPLE_STRIDE`]th hashed page
/// and the last hashed page. [`Integrity::Mismatch`] falls back — never
/// overwrites.
///
/// # Errors
/// [`PatchError::Io`] when the file cannot be read (missing output → the
/// caller falls back).
pub fn check_output(prev_path: &Path, record: &LinkRecord) -> Result<Integrity, PatchError> {
    let file = std::fs::File::open(prev_path).map_err(|source| PatchError::Io {
        path: prev_path.display().to_string(),
        source,
    })?;
    let len = file.metadata().map_err(|source| PatchError::Io {
        path: prev_path.display().to_string(),
        source,
    })?.len();
    if len != record.file_size {
        return Ok(Integrity::Mismatch {
            detail: format!("file is {len} bytes, record says {}", record.file_size),
        });
    }
    let pages = record.hashed_pages();
    if pages == 0 {
        return Ok(Integrity::Match);
    }
    let last = pages - 1;
    let mut sample: Vec<u64> = (0..pages).step_by(SAMPLE_STRIDE as usize).collect();
    sample.push(last);
    sample.sort_unstable();
    sample.dedup();
    for p in sample {
        let at = p * HASH_PAGE;
        let take = HASH_PAGE.min(record.code_limit - at);
        let mut buf = vec![0u8; take as usize];
        file.read_exact_at(&mut buf, at).map_err(|source| PatchError::Io {
            path: prev_path.display().to_string(),
            source,
        })?;
        let got: [u8; 32] = Sha256::digest(&buf).into();
        let want = record
            .page_hashes
            .get(p as usize)
            .ok_or_else(|| PatchError::Contract {
                message: format!("record has no hash for sampled page {p}"),
            })?;
        if got != *want {
            return Ok(Integrity::Mismatch {
                detail: format!("page {p} hash diverges from the record"),
            });
        }
    }
    Ok(Integrity::Match)
}

// ---------------------------------------------------------------------------
// The patch path
// ---------------------------------------------------------------------------

/// Applies an in-place [`PatchDecision`]: clones the previous output,
/// `pwrite`s the dirty tiles, rebuilds page 0 (new `LC_UUID`) and the
/// CodeDirectory (merged hash table), renames over the destination, and
/// returns the outcome *plus the record of the new state* (the next
/// relink's baseline).
///
/// The result is byte-identical to the full fused emit of the same plan —
/// the identity is the engine's correctness contract (see the module docs
/// and `tests/incremental.rs`).
///
/// # Errors
/// [`PatchError::Fallback`] when the plan is empty (untouched) or the
/// caller handed over a fallback decision; [`PatchError::Io`] on
/// filesystem failures; [`PatchError::Contract`] on plan shape bugs.
pub fn apply_patch(
    prev_path: &Path,
    record: &LinkRecord,
    plan: &PatchPlan,
    layout: &Layout,
    objects: &[InputObject],
    out_path: &Path,
) -> Result<(PatchOutcome, LinkRecord), PatchError> {
    if plan.is_untouched() {
        return Err(PatchError::Fallback(FallbackReason::OutputChanged {
            detail: "plan says nothing changed".into(),
        }));
    }
    let code_limit = content_limit(layout);
    if code_limit != record.code_limit {
        return Err(PatchError::Contract {
            message: "plan passed the skeleton gate but the code limit moved".into(),
        });
    }
    if plan.total_tiles != layout.file_size.div_ceil(TILE) as u32 {
        return Err(PatchError::Contract {
            message: "plan tile count disagrees with the layout".into(),
        });
    }

    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
    // The planner guarantees tile 0 rides in the dirty set (the UUID page);
    // a caller-built plan without it would silently sign against a stale
    // page-0 hash.
    if code_limit > 0 && plan.dirty_tiles.first() != Some(&0) {
        return Err(PatchError::Contract {
            message: "plan must include tile 0 (the UUID page) when anything is dirty".into(),
        });
    }

    // The §7.3 output path: clone (APFS COW on macOS) → pwrite dirty pages
    // → re-sign → rename. A fresh temp name; no partial output is ever
    // visible under the destination.
    let tmp_path = tmp_name(out_path);
    let cloned = std::fs::copy(prev_path, &tmp_path).map_err(|source| PatchError::Io {
        path: tmp_path.display().to_string(),
        source,
    })?;
    if cloned != record.file_size {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PatchError::Fallback(FallbackReason::OutputChanged {
            detail: format!("previous output resized to {cloned} bytes mid-link"),
        }));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&tmp_path)
        .map_err(|source| PatchError::Io {
            path: tmp_path.display().to_string(),
            source,
        })?;

    let (outcome, page_hashes) = match patch_file(&mut file, record, plan, layout, &ctx, code_limit)
    {
        Ok(ok) => ok,
        Err(e) => {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    };
    if let Err(source) = file.sync_all() {
        drop(file);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(PatchError::Io {
            path: tmp_path.display().to_string(),
            source,
        });
    }
    drop(file);
    std::fs::rename(&tmp_path, out_path).map_err(|source| {
        let _ = std::fs::remove_file(&tmp_path);
        PatchError::Io {
            path: out_path.display().to_string(),
            source,
        }
    })?;
    let new_record = LinkRecord::assemble_from(layout, plan.spans.clone(), page_hashes)?;
    Ok((outcome, new_record))
}

/// The clone's temp name (sibling, `pgr`-shaped, removed on failure).
fn tmp_name(out_path: &Path) -> std::path::PathBuf {
    let mut name = out_path.as_os_str().to_owned();
    name.push(".pgr.inc.tmp");
    std::path::PathBuf::from(name)
}

/// The patch body over an open temp file: emit dirty tiles, derive the
/// UUID, re-sign. Returns the outcome and the final (record-form) hash
/// table.
fn patch_file(
    file: &mut std::fs::File,
    record: &LinkRecord,
    plan: &PatchPlan,
    layout: &Layout,
    ctx: &TileCtx<'_>,
    code_limit: u64,
) -> Result<(PatchOutcome, Vec<[u8; 32]>), PatchError> {
    let write_at = |file: &mut std::fs::File, at: u64, bytes: &[u8]| -> Result<u64, PatchError> {
        file.write_all_at(bytes, at).map_err(|source| PatchError::Io {
            path: "patch target".into(),
            source,
        })?;
        Ok(bytes.len() as u64)
    };

    // Phase A: emit every dirty tile into the scratch, keep its bytes and
    // its (UUID-zeroed) page hashes. Tile 0 always rides in the dirty set,
    // so its page-0 hash (zeroed form) is part of the table from the start.
    let mut scratches: Vec<(u32, Vec<u8>)> = Vec::with_capacity(plan.dirty_tiles.len());
    let mut dirty_hashes: HashMap<u32, Vec<[u8; 32]>> = HashMap::new();
    for &t in &plan.dirty_tiles {
        let lo = u64::from(t) * TILE;
        let len = (TILE.min(layout.file_size - lo)) as usize;
        let mut tile = vec![0u8; len];
        emit_tile(&mut tile, lo, ctx)?;
        if t == 0 {
            // The header is written by the fused emit before the tile loop;
            // the tile body itself only covers spans beyond it.
            tile[..layout.header_bytes.len()].copy_from_slice(&layout.header_bytes);
        }
        if code_limit > lo {
            let hashes = tile_hashes(&tile, lo, code_limit);
            if !hashes.is_empty() {
                dirty_hashes.insert(t, hashes);
            }
        }
        scratches.push((t, tile));
    }

    // The merged UUID-zeroed hash table: dirty tiles contribute their
    // recomputed page hashes, clean tiles the record's (pages ≥ 1 are
    // content-form — the UUID lives only on page 0, gated by the skeleton).
    let pages = code_limit.div_ceil(HASH_PAGE);
    let mut merged: Vec<[u8; 32]> = Vec::with_capacity(pages as usize);
    for t in 0..plan.total_tiles {
        if page_count_of(t, code_limit) == 0 {
            break;
        }
        let lo = u64::from(t) * TILE;
        if let Some(hashes) = dirty_hashes.get(&t) {
            merged.extend_from_slice(hashes);
        } else {
            let first_page = (lo / HASH_PAGE) as usize;
            let page_count = ((lo + TILE).min(code_limit) - lo).div_ceil(HASH_PAGE) as usize;
            let want = record
                .page_hashes
                .get(first_page..first_page + page_count)
                .ok_or_else(|| PatchError::Contract {
                    message: format!("record has no hashes for clean tile {t}"),
                })?;
            merged.extend_from_slice(want);
        }
    }
    debug_assert_eq!(merged.len(), pages as usize);

    // Phase B: the UUID derives from the zeroed table (§9), lands on page
    // 0 (gated by the skeleton), and page 0's entry becomes the final form.
    // Unsigned images (`code_limit == 0`) have neither table nor UUID —
    // the header stays exactly as the full emit writes it.
    if code_limit > 0 {
        let uuid = signature::derive_uuid(&merged.concat());
        for (t, tile) in scratches.iter_mut() {
            if *t == 0 {
                let uuid_at = layout.linkedit.uuid_at as usize;
                let dst = tile
                    .get_mut(uuid_at..uuid_at + 16)
                    .ok_or_else(|| PatchError::Contract {
                        message: "UUID field leaves tile 0".into(),
                    })?;
                dst.copy_from_slice(&uuid);
                if page_count_of(*t, code_limit) > 0 {
                    let first_page = HASH_PAGE as usize;
                    let end = first_page.min(tile.len());
                    merged[0] = Sha256::digest(&tile[..end]).into();
                }
            }
        }
    }

    // Phase C: pwrite the dirty tiles + the rebuilt CodeDirectory.
    let mut bytes_patched = 0u64;
    for (t, tile) in &scratches {
        bytes_patched += write_at(file, u64::from(*t) * TILE, tile)?;
    }
    if code_limit > 0 {
        let mut final_flat: Vec<u8> = Vec::with_capacity(merged.len() * 32);
        for h in &merged {
            final_flat.extend_from_slice(h);
        }
        let is_exec = layout.filetype == pgr_format::consts::MH_EXECUTE;
        let blob =
            signature::build_superblob(&layout.ident, code_limit, &final_flat, layout.text_vmsize, is_exec)?;
        if blob.len() as u64 != layout.linkedit.sig_size {
            return Err(PatchError::Contract {
                message: format!(
                    "rebuilt signature is {} bytes but the layout reserved {}",
                    blob.len(),
                    layout.linkedit.sig_size
                ),
            });
        }
        bytes_patched += write_at(file, layout.linkedit.sig_off, &blob)?;
    }

    Ok((
        PatchOutcome {
            bytes_patched,
            dirty_tiles: plan.dirty_tiles.len() as u32,
            total_tiles: plan.total_tiles,
            untouched: false,
        },
        merged,
    ))
}

/// The number of 4 KiB hash pages tile `t` carries (clipped to the hashed
/// prefix).
fn page_count_of(tile: u32, code_limit: u64) -> usize {
    let lo = u64::from(tile) * TILE;
    if lo >= code_limit {
        return 0;
    }
    ((lo + TILE).min(code_limit) - lo).div_ceil(HASH_PAGE) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_spans_marks_both_sides_of_a_move() {
        let mk = |dst: u64, seed: u8| RecordedSpan {
            dst,
            len: 8,
            sha: Sha256::digest([seed]).into(),
        };
        let old = vec![mk(0, 1), mk(100, 2), mk(200, 3)];
        // The middle span moved (its old slot is zero-filled by the new
        // plan, which differs from the old bytes there too).
        let new = vec![mk(0, 1), mk(120, 2), mk(200, 3)];
        let mut ranges = Vec::new();
        diff_spans(&old, &new, &mut ranges);
        assert_eq!(ranges.len(), 2, "{ranges:?}");
        assert!(ranges.iter().any(|r| r.start == 100 && r.end == 108));
        assert!(ranges.iter().any(|r| r.start == 120 && r.end == 128));
    }

    #[test]
    fn diff_spans_is_quiet_when_lists_match() {
        let mk = |dst: u64, seed: u8| RecordedSpan {
            dst,
            len: 8,
            sha: Sha256::digest([seed]).into(),
        };
        let old = vec![mk(0, 1), mk(100, 2)];
        let mut ranges = Vec::new();
        diff_spans(&old, &old.clone(), &mut ranges);
        assert!(ranges.is_empty());
        // Same digests at the same offsets, different objects: quiet.
        let new = vec![mk(0, 1), mk(100, 2)];
        diff_spans(&old, &new, &mut ranges);
        assert!(ranges.is_empty());
    }

    #[test]
    fn record_roundtrip_and_corruption_tolerance() {
        let r = LinkRecord {
            format_version: FORMAT_VERSION,
            file_size: 0x8000,
            image_base: 0,
            filetype: 2,
            text_vmsize: 0x8000,
            entryoff: 0x10,
            ident: "x".into(),
            code_limit: 0x3000,
            linkedit: pgr_core::layout::LinkeditPlan {
                sig_off: 0x3000,
                sig_size: 0x100,
                ..Default::default()
            },
            header_sha: [7; 32],
            segments: vec![RecordedSegment {
                name: "__TEXT".into(),
                vmaddr: 0,
                vmsize: 0x8000,
                fileoff: 0,
                filesize: 0x3000,
                maxprot: 5,
                initprot: 5,
            }],
            sections: vec![RecordedSection {
                seg: "__TEXT".into(),
                name: "__text".into(),
                flags: 0x80000400,
                align_log2: 2,
                vm_addr: 0x4000,
                content_size: 40,
                size: 4096,
                file_off: 0x4000,
                zerofill: false,
            }],
            spans: SpanTable {
                runs: vec![RecordedSpan {
                    dst: 0x4000,
                    len: 40,
                    sha: [1; 32],
                }],
                ..Default::default()
            },
            page_hashes: vec![[2; 32]],
        };
        let bytes = r.encode();
        let back = LinkRecord::decode(&bytes).expect("roundtrip");
        assert_eq!(back, r, "the codec must be lossless");

        // Corruption tolerance: flip a payload byte, truncate, append, and
        // swap the magic — every case must be a clean `None`.
        let mut corrupt = bytes.clone();
        corrupt[HEADER_LEN + 3] ^= 0xff;
        assert!(LinkRecord::decode(&corrupt).is_none(), "payload flip");
        assert!(
            LinkRecord::decode(&bytes[..bytes.len() - 1]).is_none(),
            "truncated"
        );
        let mut extended = bytes.clone();
        extended.push(0);
        assert!(LinkRecord::decode(&extended).is_none(), "trailing byte");
        let mut magic = bytes.clone();
        magic[0] = b'X';
        assert!(LinkRecord::decode(&magic).is_none(), "foreign magic");
        // Arbitrary garbage never panics.
        for n in 0..64u32 {
            let junk: Vec<u8> = (0..n * 7).map(|i| (i ^ n) as u8).collect();
            let _ = LinkRecord::decode(&junk);
        }
    }
}
