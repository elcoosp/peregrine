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
//!    * the **relayout tier** (tier 2, §7.3 "layout stability") re-admits
//!      a *shifted* skeleton as a patch plan ([`RelayoutDelta`]): a
//!      section that overflowed its anchor within the ladder's
//!      segment-relayout bound holds its base while everything behind it
//!      shifts, and an outgrown `__LINKEDIT` reservation moves the
//!      signature boundary with it. The patch rewrites the moved suffix,
//!      the record's output-section digests exempt byte-identical moved
//!      sections from the propagation gate, and the clone is resized
//!      before the dirty tiles land;
//!    * the **span diff** marks every 16 KiB tile whose byte-producing
//!      spans changed; the dirty-tile set *is* the patch plan. When every
//!      content tile is dirty the full emit is cheaper and the planner
//!      falls back (the patch path exists to avoid work, not to hoist it);
//!    * the **propagation gate** (tier 2b, §7.3 step 3) requires the span
//!      diff to be *explainable*: every changed content span must sit
//!      inside the change-propagation scope (`pgr_core::propagate::predict`)
//!      — the changed input sections' own placements plus the reverse-index
//!      closure of their dependents. A content change the recorded parse
//!      cannot vouch for (the stale-record shape, or literal-pool dedup
//!      churn the scope does not model yet — GA scope) falls back instead
//!      of patching bytes nobody predicted.
//! 3. **patch** ([`apply_patch`]) — clone the previous output (on macOS
//!    `std::fs::copy` resolves to `fclonefileat`: an instant APFS
//!    copy-on-write clone; on Linux to `copy_file_range`), `pwrite` only
//!    the dirty tiles into the clone, rebuild page 0 with the freshly
//!    derived `LC_UUID`, and rebuild the `CodeDirectory` from the *merged*
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
//! else (a tampered clean page breaks the `CodeDirectory` at exec), and
//! `-incremental-verify` is the audit gate that hashes nothing less than
//! everything.

pub mod audit;

use crate::EmitError;
use crate::emit::{indirect_bytes, symtab_bytes};
use crate::signature;
use crate::tile::{TileCtx, emit_tile, tile_hashes};
use pgr_core::layout::{Layout, PatchOp};
use pgr_core::object::InputObject;
use pgr_core::slack::{LayoutFallback, SlackPolicy};
use pgr_format::consts::PAGE_SIZE_16K;
use rayon::prelude::*;
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
/// full link (the fallback must always be available — §7.3). **v2** added
/// the link's import table ([`LinkRecord::imports`], M9 tier 2a): the
/// anchored relink keeps recorded bind ordinals instead of renumbering
/// them (§7.3 step 5). **v3** adds the parse's section-digest table
/// ([`LinkRecord::section_digests`], M9 tier 2b): the propagation gate
/// diffs it against the relink's parse to scope the change (§7.3 step 3);
/// v1/v2 records decode to `None` and re-record. **v4** adds the
/// output-section content-digest table ([`LinkRecord::content_digests`],
/// M9 tier 2):
/// the relayout tier's shift-exemption compares a moved section's final
/// bytes against the recorded ones, so a pure move rides the ladder while
/// content churn inside the moved suffix stays gated; v1–v3 records
/// decode to `None` and re-record. **v5** adds the resolution snapshot
/// ([`LinkRecord::resolution`], M9 GA rung — the resolve's record-side
/// wiring): the relink's Pass 2 plans through the recorded decisions
/// (`pgr_core::resolve_reuse`) instead of re-deciding every external, and
/// falls back to the full resolve whenever the shape guard refuses;
/// v1–v4 records decode to `None` and re-record.
pub const FORMAT_VERSION: u32 = 5;

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

/// One output section's content digest (v4, M9 tier 2): SHA-256 over the
/// section's **copy-run bytes** — the placed input content, pre-relocation,
/// in placement order (tile-piece splitting included; the concatenation is
/// placement-invariant). The relayout tier's shift-exemption compares a
/// moved section's recorded digest against the new plan's: equality means
/// the section's *content* is a pure move — its derived bytes (applied
/// relocations, chain words) are re-emitted from the plan and re-proven by
/// the byte-identity contract — while a content change must still answer
/// to the propagation scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputSectionDigest {
    /// Owning output segment (`__TEXT`).
    pub seg: String,
    /// Output section name (`__text`).
    pub name: String,
    /// SHA-256 over the section's copy-run bytes in placement order
    /// (zero-fill and synthetic sections carry no runs and hash the empty
    /// slice).
    pub sha: [u8; 32],
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
    /// The signature identity string (`CodeDirectory` length depends on it).
    pub ident: String,
    /// The hashed prefix length (the `CodeDirectory` codeLimit = `sig_off`
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
    /// The link's import table as identities, in ordinal order (v2, M9
    /// tier 2a): the anchor the next relink binds its own import ordinals
    /// to — recorded entries keep their ordinals, new binds append, and no
    /// edit renumbers the table (§7.3 step 5; `LinkConfig::stable_imports`).
    pub imports: Vec<pgr_core::stable_imports::StableImport>,
    /// The linked parse's section-digest table (v3, M9 tier 2b): the
    /// change-propagation seeds the next relink diffs against its own
    /// parse (§7.3 steps 1–3; `pgr_core::propagate::section_digests`).
    pub section_digests: Vec<pgr_core::propagate::SectionDigest>,
    /// Every output section's content digest (v4, M9 tier 2), in section
    /// order — the same order the layout places them and the skeleton
    /// records them. The relayout tier's shift-exemption compares these
    /// against the new plan's table.
    pub content_digests: Vec<OutputSectionDigest>,
    /// The linked parse's Pass-2 snapshot (v5, M9 GA rung — the resolve's
    /// record-side wiring): the candidate stream and the winning decisions
    /// the next relink's resolve plans from
    /// (`pgr_core::resolve_reuse::plan_reuse` / `install_reused`), refusing
    /// to the full resolve whenever the reuse shape moved. `None` on links
    /// that did not capture (every clean link); those relinks resolve in
    /// full.
    pub resolution: Option<pgr_core::resolve::ResolutionSnapshot>,
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
    /// The span diff moved content the change-propagation scope cannot
    /// explain (M9 tier 2b, §7.3 step 3): the changed parse does not vouch
    /// for the recorded output's bytes — the stale-record shape. The full
    /// link re-records from scratch.
    PropagationMismatch {
        /// What escaped the scope.
        detail: String,
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
            Self::PropagationMismatch { detail } => {
                write!(f, "propagation mismatch: {detail}")
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

/// The §7.3 ladder tier-2 admission (architecture doc §7.3 "layout
/// stability"): the skeleton moved, and the move is a pure suffix
/// relayout. Every section before the first resize holds its placement,
/// the resized section holds its base and grows within the ladder's
/// segment-relayout bound ([`SlackPolicy::fits`]), an outgrown
/// `__LINKEDIT` reservation moves the signature boundary without touching
/// a content section, and everything behind the change only shifts.
/// The planner vouches for the moved suffix: the patch rewrites it from
/// the new plan, and the shift table translates old-side diff ranges into
/// the new plan's coordinates for the propagation gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayoutDelta {
    /// Per-section file-offset shift (new minus recorded), index-aligned
    /// with the record's and the layout's section lists (equal lengths by
    /// admission). Zero for held sections; zero-fill sections carry no
    /// file placement and shift as zero.
    pub shifts: Vec<i64>,
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
    /// The tier-2 admission ([`RelayoutDelta`]) when the skeleton shifted
    /// and the planner vouches for the moved suffix; `None` is the tier-1
    /// in-place plan over a frozen skeleton.
    pub relayout: Option<RelayoutDelta>,
    /// The new plan's output-section content digests (the refreshed
    /// record's v4 field — extracted once per relink, not twice).
    pub content_digests: Vec<OutputSectionDigest>,
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
            // A relocatable-object refusal cannot arise on the incremental
            // path (the engine patches images, never `-r` objects); the
            // arm keeps the match exhaustive and honest about it.
            EmitError::RelocRefusal { refusal } => Self::Contract {
                message: refusal.to_string(),
            },
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
        PatchOp::Adrp {
            in_offset,
            page_delta,
        } => (*in_offset, *page_delta as u64, 0),
        PatchOp::PageOff12 { in_offset, imm12 } => (*in_offset, u64::from(*imm12), 0),
        PatchOp::Branch26 {
            in_offset,
            pc,
            delta,
        } => (*in_offset, *pc, *delta as u64),
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
#[must_use]
fn span_table_with(ctx: &TileCtx<'_>) -> SpanTable {
    let to_span = |&(dst, end, bytes): &(u64, u64, &[u8])| {
        debug_assert_eq!(end - dst, bytes.len() as u64);
        span_of(dst, bytes)
    };
    let to_pieces = |&(dst, end, bytes): &(u64, u64, &[u8])| {
        debug_assert_eq!(end - dst, bytes.len() as u64);
        tile_piece_spans(dst, bytes)
    };
    SpanTable {
        // Copy runs and `__LINKEDIT` chunks are the only spans that can
        // dwarf a tile; their digests are per tile piece so the dirty-tile
        // set tracks the change, not the span. Synthetics, patch writes
        // and chain words never exceed a tile.
        runs: ctx.run_spans.iter().flat_map(to_pieces).collect(),
        synths: ctx.synth_spans.iter().map(to_span).collect(),
        blobs: ctx.blob_spans.iter().flat_map(to_pieces).collect(),
        patches: ctx
            .patches
            .iter()
            .map(|(at, op)| patch_span(*at, op))
            .collect(),
        words: ctx
            .words
            .iter()
            .map(|&(at, word)| span_of(at, &word.to_le_bytes()))
            .collect(),
    }
}

/// One output section's content digest from the plan: the section's
/// copy-run bytes hashed in placement order. Runs are coalesced inside
/// sections (a run never straddles one) and both lists are sorted by
/// destination, so the section's runs are a contiguous slice of the run
/// list — no emitting, no scanning past it.
fn section_content_sha(
    sect: &pgr_core::layout::PlacedSection,
    runs: &[crate::tile::Span<'_>],
) -> [u8; 32] {
    if sect.zerofill {
        return Sha256::digest([]).into();
    }
    let end = sect.file_off + sect.size;
    let first = runs.partition_point(|&(dst, _, _)| dst < sect.file_off);
    let last = first
        + runs[first..]
            .iter()
            .take_while(|&&(dst, _, _)| dst < end)
            .count();
    let mut h = Sha256::new();
    for &(_, _, bytes) in &runs[first..last] {
        h.update(bytes);
    }
    h.finalize().into()
}

/// The record path's content-digest table: every section hashed (no prior
/// record to copy from), in parallel — the run bytes are borrowed input
/// slices, so the hashes are schedule-independent (§4.3).
fn content_digests_for(layout: &Layout, ctx: &TileCtx<'_>) -> Vec<OutputSectionDigest> {
    layout
        .sections
        .par_iter()
        .map(|s| OutputSectionDigest {
            seg: s.seg_name.clone(),
            name: s.name.clone(),
            sha: section_content_sha(s, &ctx.run_spans),
        })
        .collect()
}

/// The planner paths' content-digest table: a section whose run content is
/// provably unchanged copies the recorded digest (identical run spans mean
/// identical run bytes — the placement-invariant concatenation), and only
/// the sections a run diff touches re-hash. `run_changes` is the run-class
/// diff (both sides); a tier-1 plan has no moved sections, so the
/// old-extent test is exact, and a tier-2 plan over-approximates by
/// touching sections whose old extent a moved-away range grazes.
fn next_content_digests(
    record: &LinkRecord,
    layout: &Layout,
    ctx: &TileCtx<'_>,
    run_changes: &[Range<u64>],
) -> Vec<OutputSectionDigest> {
    let copyable = record.content_digests.len() == layout.sections.len();
    layout
        .sections
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let old = record.sections.get(i);
            let new_extent = s.file_off..s.file_off + s.size;
            let old_extent = old.map(|r| r.file_off..r.file_off + r.size);
            let touched = run_changes.iter().any(|c| {
                (c.start < new_extent.end && new_extent.start < c.end)
                    || old_extent
                        .as_ref()
                        .is_some_and(|o| c.start < o.end && o.start < c.end)
            });
            let sha = if !touched && copyable && old.is_some_and(|r| r.zerofill == s.zerofill) {
                record.content_digests[i].sha
            } else {
                section_content_sha(s, &ctx.run_spans)
            };
            OutputSectionDigest {
                seg: s.seg_name.clone(),
                name: s.name.clone(),
                sha,
            }
        })
        .collect()
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
            content_size: s
                .pieces
                .iter()
                .map(|p| p.offset + p.size)
                .max()
                .unwrap_or(0),
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
    /// image (so what is recorded is what is on disk). The resolution
    /// snapshot rides along when the link captured its Pass-2 state (the
    /// M9 resolve wiring) — `None` keeps the record lean.
    ///
    /// # Errors
    /// [`PatchError::Contract`] when the image/plan shapes disagree (the
    /// full emit would have failed the same way).
    pub fn record(
        layout: &Layout,
        objects: &[InputObject],
        image: &[u8],
        resolution: Option<&pgr_core::resolve::ResolutionSnapshot>,
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
        let symtab = symtab_bytes(layout);
        let indirect = indirect_bytes(layout);
        let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
        let content_digests = content_digests_for(layout, &ctx);
        let spans = span_table_with(&ctx);
        let digests = pgr_core::propagate::section_digests(objects);
        Self::assemble_from(
            layout,
            spans,
            page_hashes,
            digests,
            content_digests,
            resolution.cloned(),
        )
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
        resolution: Option<pgr_core::resolve::ResolutionSnapshot>,
    ) -> Result<Self, PatchError> {
        let symtab = symtab_bytes(layout);
        let indirect = indirect_bytes(layout);
        let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
        let content_digests = content_digests_for(layout, &ctx);
        let spans = span_table_with(&ctx);
        let digests = pgr_core::propagate::section_digests(objects);
        Self::assemble_from(
            layout,
            spans,
            page_hashes,
            digests,
            content_digests,
            resolution,
        )
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
        section_digests: Vec<pgr_core::propagate::SectionDigest>,
        content_digests: Vec<OutputSectionDigest>,
        resolution: Option<pgr_core::resolve::ResolutionSnapshot>,
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
            // The import identities the next relink anchors its ordinals
            // to (M9 tier 2a; the planner's assigned order).
            imports: layout.fixups.stable_keys.clone(),
            // The parse's change-detection table (M9 tier 2b): the
            // propagation seeds the next relink diffs against.
            section_digests,
            // The output sections' content digests (M9 tier 2): the
            // relayout shift-exemption's recorded side.
            content_digests,
            // The Pass-2 snapshot the next relink's resolve plans from
            // (M9 GA rung): `None` resolves in full.
            resolution,
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
        e(&mut p, self.imports.len() as u64);
        for k in &self.imports {
            e(&mut p, u64::from(k.lib_ordinal));
            e(&mut p, u64::from(k.weak));
            e(&mut p, k.outlined_addend as u64);
            e(&mut p, k.name.len() as u64);
            p.extend_from_slice(&k.name);
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
        // v3: the parse's section-digest table (M9 tier 2b) — the
        // propagation seeds the next relink diffs against.
        e(&mut p, self.section_digests.len() as u64);
        for d in &self.section_digests {
            e(&mut p, u64::from(d.file));
            e(&mut p, d.in_sect as u64);
            p.extend_from_slice(&d.sha);
        }
        // v4: the output-section content-digest table (M9 tier 2) — the
        // relayout shift-exemption's recorded side.
        e(&mut p, self.content_digests.len() as u64);
        for d in &self.content_digests {
            e(&mut p, d.seg.len() as u64);
            p.extend_from_slice(d.seg.as_bytes());
            e(&mut p, d.name.len() as u64);
            p.extend_from_slice(d.name.as_bytes());
            p.extend_from_slice(&d.sha);
        }
        // v5: the resolution snapshot (M9 GA rung) — the recorded Pass-2
        // state the next relink's resolve plans from. Absent on links that
        // did not capture (every clean link); those relinks resolve in full.
        match &self.resolution {
            None => e(&mut p, 0),
            Some(snap) => {
                e(&mut p, 1);
                encode_snapshot(&mut p, snap);
            }
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
        let mut import = |d: &mut Decoder<'_>| {
            let lib_ordinal = d.u64()?;
            let weak_byte = d.u64()?;
            let outlined_addend = d.u64()? as i64;
            let name_len = usize::try_from(d.u64()?).ok()?;
            if name_len > 4096 {
                return None;
            }
            let name = d.take(name_len)?.to_vec();
            Some(pgr_core::stable_imports::StableImport {
                lib_ordinal: u8::try_from(lib_ordinal).ok()?,
                name,
                outlined_addend,
                weak: weak_byte == 1,
            })
        };
        let imports = d.list(&mut import)?;
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
        let mut digest = |d: &mut Decoder<'_>| {
            let file = d.u64()?;
            let in_sect = usize::try_from(d.u64()?).ok()?;
            if file > u64::from(u32::MAX) || in_sect > 1 << 20 {
                return None;
            }
            let mut sha = [0u8; 32];
            d.bytes(&mut sha)?;
            Some(pgr_core::propagate::SectionDigest {
                file: u32::try_from(file).ok()?,
                in_sect,
                sha,
            })
        };
        let section_digests = d.list(&mut digest)?;
        let mut out_digest = |d: &mut Decoder<'_>| {
            let seg = d.str()?;
            let name = d.str()?;
            let mut sha = [0u8; 32];
            d.bytes(&mut sha)?;
            Some(OutputSectionDigest { seg, name, sha })
        };
        let content_digests = d.list(&mut out_digest)?;
        // v5: the resolution snapshot (M9 GA rung). 0 = absent, 1 = present;
        // anything else is corruption.
        let resolution = match d.u64()? {
            0 => None,
            1 => Some(decode_snapshot(&mut d)?),
            _ => return None,
        };
        if d.at != d.b.len() || content_digests.len() != sections.len() {
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
            imports,
            sections,
            spans,
            page_hashes,
            section_digests,
            content_digests,
            resolution,
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

    fn list<T>(&mut self, item: &mut impl FnMut(&mut Decoder<'_>) -> Option<T>) -> Option<Vec<T>> {
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
// Resolution-snapshot codec (v5, M9 GA rung)
// ---------------------------------------------------------------------------

/// The wire discriminant of a [`pgr_core::resolve::Rank`] (explicit — no
/// transmute; an unknown discriminant fails the decode).
fn rank_to_u64(rank: pgr_core::resolve::Rank) -> u64 {
    match rank {
        pgr_core::resolve::Rank::Strong => 1,
        pgr_core::resolve::Rank::WeakDef => 2,
        pgr_core::resolve::Rank::ArchiveStrong => 3,
        pgr_core::resolve::Rank::ArchiveWeak => 4,
        pgr_core::resolve::Rank::Common => 5,
        pgr_core::resolve::Rank::DylibExport => 6,
    }
}

/// The inverse of [`rank_to_u64`].
fn rank_from_u64(v: u64) -> Option<pgr_core::resolve::Rank> {
    match v {
        1 => Some(pgr_core::resolve::Rank::Strong),
        2 => Some(pgr_core::resolve::Rank::WeakDef),
        3 => Some(pgr_core::resolve::Rank::ArchiveStrong),
        4 => Some(pgr_core::resolve::Rank::ArchiveWeak),
        5 => Some(pgr_core::resolve::Rank::Common),
        6 => Some(pgr_core::resolve::Rank::DylibExport),
        _ => None,
    }
}

/// A length-capped raw byte string (the file/candidate names; the same
/// 4 KiB cap the string decoder applies — an honest overflow decodes to
/// `None` and the relink falls back, it never guesses).
fn byte_string(d: &mut Decoder<'_>) -> Option<Vec<u8>> {
    let len = usize::try_from(d.u64()?).ok()?;
    if len > 4096 {
        return None;
    }
    Some(d.take(len)?.to_vec())
}

/// Encodes one [`pgr_core::resolve::DefLite`]: the defining position, the
/// precedence the replay applies, and the definition's own fields.
fn encode_def(p: &mut Vec<u8>, def: &pgr_core::resolve::DefLite) {
    let e = |p: &mut Vec<u8>, v: u64| p.extend_from_slice(&v.to_le_bytes());
    e(p, u64::from(def.file));
    e(p, def.sym as u64);
    e(p, rank_to_u64(def.rank));
    e(p, u64::from(def.weak));
    e(p, def.value);
    // `0` = no input section, `n + 1` = section `n` (the `Option` tag).
    e(p, def.section.map_or(0, |s| s as u64 + 1));
    e(p, u64::from(def.common_align));
    e(p, def.common_size);
}

/// Decodes one [`pgr_core::resolve::DefLite`]. Every field is
/// range-checked to the shapes `ResolutionSnapshot::capture` can produce —
/// a hostile or truncated tail decodes to `None`, never a panic.
fn decode_def(d: &mut Decoder<'_>) -> Option<pgr_core::resolve::DefLite> {
    let file = d.u64()?;
    let sym = d.u64()?;
    let rank = rank_from_u64(d.u64()?)?;
    let weak_byte = d.u64()?;
    let value = d.u64()?;
    let section = d.u64()?;
    let common_align = d.u64()?;
    let common_size = d.u64()?;
    if file > u64::from(u32::MAX)
        || sym > 1 << 32
        || weak_byte > 1
        || section > (1 << 20) + 1
        || common_align > 15
    {
        return None;
    }
    Some(pgr_core::resolve::DefLite {
        file: u32::try_from(file).ok()?,
        sym: usize::try_from(sym).ok()?,
        rank,
        weak: weak_byte == 1,
        value,
        section: if section == 0 {
            None
        } else {
            Some(usize::try_from(section - 1).ok()?)
        },
        common_align: u32::try_from(common_align).ok()?,
        common_size,
    })
}

/// Encodes the snapshot: the shape guard's file identities, the complete
/// candidate stream (name-sorted; the replay's index), the dense winner
/// matrix (a `None` slot is one flag byte's worth of "no recorded
/// winner"), and the flattened dylib export surface.
fn encode_snapshot(p: &mut Vec<u8>, snap: &pgr_core::resolve::ResolutionSnapshot) {
    let e = |p: &mut Vec<u8>, v: u64| p.extend_from_slice(&v.to_le_bytes());
    e(p, snap.file_names.len() as u64);
    for name in &snap.file_names {
        e(p, name.len() as u64);
        p.extend_from_slice(name);
    }
    e(p, snap.candidates.len() as u64);
    for (name, def) in &snap.candidates {
        e(p, name.len() as u64);
        p.extend_from_slice(name);
        encode_def(p, def);
    }
    e(p, snap.winner_slots.len() as u64);
    for slots in &snap.winner_slots {
        e(p, slots.len() as u64);
        for slot in slots {
            match slot {
                None => e(p, 0),
                Some(def) => {
                    e(p, 1);
                    encode_def(p, def);
                }
            }
        }
    }
    e(p, snap.dylib_export_names.len() as u64);
    for name in &snap.dylib_export_names {
        e(p, name.len() as u64);
        p.extend_from_slice(name);
    }
}

/// Decodes the snapshot (the inverse of [`encode_snapshot`]). The winner
/// matrix's file count must line up with the shape guard's file list (the
/// reuse path's first invariant); every other mismatch decodes to `None`
/// and the relink resolves in full.
fn decode_snapshot(d: &mut Decoder<'_>) -> Option<pgr_core::resolve::ResolutionSnapshot> {
    let file_names = d.list(&mut byte_string)?;
    let mut candidate = |d: &mut Decoder<'_>| {
        let name = byte_string(d)?;
        let def = decode_def(d)?;
        Some((name, def))
    };
    let candidates = d.list(&mut candidate)?;
    // Each slot costs at least its flag byte on the wire, so the per-file
    // slot count is bounded by the remaining payload — a hostile count
    // cannot inflate the allocation.
    let mut slot_file = |d: &mut Decoder<'_>| {
        let count = usize::try_from(d.u64()?).ok()?;
        if count > d.b.len() / 8 {
            return None;
        }
        let mut slots: Vec<Option<pgr_core::resolve::DefLite>> = vec![None; count];
        for slot in &mut slots {
            if d.u64()? == 1 {
                *slot = Some(decode_def(d)?);
            }
        }
        Some(slots)
    };
    let winner_slots = d.list(&mut slot_file)?;
    if winner_slots.len() != file_names.len() {
        return None;
    }
    let dylib_export_names = d.list(&mut byte_string)?;
    Some(pgr_core::resolve::ResolutionSnapshot {
        file_names,
        candidates,
        winner_slots,
        dylib_export_names,
    })
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
        (
            "filetype",
            u64::from(record.filetype),
            u64::from(layout.filetype),
        ),
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
    for (r, _) in diff_spans_sided(old, new) {
        out.push(r);
    }
}

/// Which side of the diff a divergent range came from: a removed or moved
/// span leaves its old position (`Old`); a changed or added span sits at
/// the new plan's coordinates (`New`). Aligned positions report as `New`
/// (the two sides coincide spatially; the new plan's coordinates are what
/// the scope lookup reads).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffSide {
    Old,
    New,
}

/// [`diff_spans`] with side attribution — the relayout gate translates
/// old-side ranges by their section's shift before consulting the scope.
fn diff_spans_sided(old: &[RecordedSpan], new: &[RecordedSpan]) -> Vec<(Range<u64>, DiffSide)> {
    let mut out = Vec::new();
    let (mut i, mut j) = (0usize, 0usize);
    while i < old.len() && j < new.len() {
        let (o, n) = (&old[i], &new[j]);
        if o.dst == n.dst && o.len == n.len {
            if o.sha != n.sha {
                out.push((o.dst..o.dst + o.len, DiffSide::New));
            }
            i += 1;
            j += 1;
        } else if o.dst < n.dst {
            out.push((o.dst..o.dst + o.len, DiffSide::Old));
            i += 1;
        } else {
            out.push((n.dst..n.dst + n.len, DiffSide::New));
            j += 1;
        }
    }
    for o in &old[i..] {
        out.push((o.dst..o.dst + o.len, DiffSide::Old));
    }
    for n in &new[j..] {
        out.push((n.dst..n.dst + n.len, DiffSide::New));
    }
    out
}

/// The output section containing file offset `at` in a skeleton list
/// (recorded or fresh — both carry `(file_off, size, zerofill)`), skipping
/// zero-fill sections (no file placement; their degenerate `[0, size)`
/// extent must never claim a lookup).
fn section_index_at(sections: &[RecordedSection], at: u64) -> Option<usize> {
    sections
        .iter()
        .enumerate()
        .find(|(_, s)| !s.zerofill && s.file_off <= at && at < s.file_off + s.size)
        .map(|(i, _)| i)
}

/// Plans the incremental relink: skeleton gate, span diff, dirty tiles.
///
/// `slack` is the link's active policy (used to admit a skeleton shift
/// through the §7.3 relayout tier and to classify a refusal through the
/// ladder).
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
        if let Some(delta) = relayout_delta(record, layout, slack) {
            return plan_relayout(record, layout, objects, delta);
        }
        let tier = ladder_tier(record, layout, slack);
        return Ok(PatchDecision::Fallback(FallbackReason::Skeleton {
            detail,
            tier,
        }));
    }
    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
    let new_spans = span_table_with(&ctx);
    // The content (copy-run) diff is kept apart: it is the span class the
    // propagation gate adjudicates (derived classes are re-emitted from
    // the plan and re-proven by the byte-identity contract).
    let run_diffs = diff_spans_sided(&record.spans.runs, &new_spans.runs);
    let mut span_changes: Vec<Range<u64>> = Vec::new();
    for (r, _) in &run_diffs {
        span_changes.push(r.clone());
    }
    // Every span class feeds the section-digest copy decision: a chain
    // word or patch changes the section's final bytes exactly like a run.
    let mut class_changes: Vec<Range<u64>> = span_changes.clone();
    diff_spans(&record.spans.synths, &new_spans.synths, &mut class_changes);
    diff_spans(&record.spans.blobs, &new_spans.blobs, &mut class_changes);
    diff_spans(
        &record.spans.patches,
        &new_spans.patches,
        &mut class_changes,
    );
    diff_spans(&record.spans.words, &new_spans.words, &mut class_changes);
    let mut ranges: Vec<Range<u64>> = class_changes.clone();
    // The header bytes are written outside the span lists; a header change
    // (entryoff, load commands) dirties tile 0.
    let header_digest: [u8; 32] = Sha256::digest(&layout.header_bytes).into();
    if record.header_sha != header_digest {
        ranges.push(0..layout.header_bytes.len() as u64);
    }

    // The propagation gate (M9 tier 2b, §7.3 step 3): every changed
    // content span must sit inside the change-propagation scope — the
    // changed input sections' own placements plus the reverse-index
    // closure of their dependents. A content change the recorded parse
    // does not vouch for (the stale-record shape; literal-pool dedup
    // churn is GA scope) means the diff cannot be trusted to be the
    // whole change: the planner declines to the full link instead of
    // patching bytes nobody predicted. Skipped when nothing content-side
    // changed (the untouched relink pays no reverse-index build).
    if !span_changes.is_empty() {
        let scope = pgr_core::propagate::predict(&record.section_digests, objects, layout);
        let unexplained: Vec<&Range<u64>> = span_changes
            .iter()
            .filter(|r| {
                !scope
                    .ranges
                    .iter()
                    .any(|p| p.start < r.end && r.start < p.end)
            })
            .collect();
        if !unexplained.is_empty() {
            return Ok(PatchDecision::Fallback(
                FallbackReason::PropagationMismatch {
                    detail: format!(
                        "{} content change(s) outside the propagation scope: {}",
                        unexplained.len(),
                        list_ranges(unexplained.iter().map(|r| (*r).clone()))
                    ),
                },
            ));
        }
    }

    // The gate passed — the content changes join the derived ones in the
    // dirty-tile computation. Only run-touched sections re-hash; the rest
    // copy the recorded digest.
    let content_digests = next_content_digests(record, layout, &ctx, &span_changes);
    let plan = finish_plan(record, layout, ranges, new_spans, None, content_digests);
    Ok(match plan {
        Ok(plan) => PatchDecision::InPlace(plan),
        Err(reason) => PatchDecision::Fallback(reason),
    })
}

/// The dirty-tile arithmetic shared by the two planner paths: tiles from
/// the diff ranges, tile 0 riding along for the UUID, and the §7.3
/// economics gate. `Err` is the fallback the tier could not absorb.
fn finish_plan(
    record: &LinkRecord,
    layout: &Layout,
    mut ranges: Vec<Range<u64>>,
    spans: SpanTable,
    relayout: Option<RelayoutDelta>,
    content_digests: Vec<OutputSectionDigest>,
) -> Result<PatchPlan, FallbackReason> {
    let total = layout.file_size.div_ceil(TILE) as u32;
    let mut dirty: Vec<u32> = Vec::new();
    for r in ranges.drain(..) {
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
        return Err(FallbackReason::Economics {
            dirty: dirty.len() as u32,
            total,
        });
    }
    Ok(PatchPlan {
        dirty_tiles: dirty,
        total_tiles: total,
        spans,
        relayout,
        content_digests,
    })
}

/// Formats diff ranges as their tile spread (the fallback diagnostics).
fn list_ranges(ranges: impl Iterator<Item = Range<u64>>) -> String {
    ranges
        .map(|r| {
            let first = (r.start / TILE) as u32;
            let last = ((r.end - 1) / TILE) as u32;
            format!("{}..{} (tiles {first}..={last})", r.start, r.end)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The §7.3 ladder tier-2 admission (architecture doc §7.3 "layout
/// stability"): the skeleton moved, and the move is a pure suffix
/// relayout. Three triggers map onto the tier:
///
/// * a section overflowed its anchor and re-padded naturally — it holds
///   its base while everything behind it shifts, and the growth stays
///   within the ladder's segment-relayout bound ([`SlackPolicy::fits`]
///   says `SegmentRelayout` for *every* resized section);
/// * the `__LINKEDIT` chunk stream outgrew its signature-boundary
///   reservation — the boundary moves with it while every content
///   section stays put;
/// * the chunk stream *shrank* below its boundary with no signature
///   reservation to absorb it (an unsigned image records `sig_off = 0`,
///   so there is nothing to anchor the tail) — the boundary comes down
///   and the image shrinks with it, while every content section and
///   segment stays put. The clone is truncated to the new size; the
///   moved chunk tail is re-emitted by the span diff.
///
/// Anything else (a segment base moving, a section swapping slots, a
/// held section shifting, identity or image-base changes, a new
/// `LC_UUID` slot off page 0, an image *shrink* that moves any content
/// byte) is structural and refuses the tier — the full link remains the
/// always-correct fallback.
fn relayout_delta(
    record: &LinkRecord,
    layout: &Layout,
    policy: Option<&SlackPolicy>,
) -> Option<RelayoutDelta> {
    let policy = policy?;
    // The shrink rung is admitted only for a frozen content skeleton —
    // verified below by refusing every resized section while shrinking.
    let shrinking = layout.file_size < record.file_size;
    if record.ident != layout.ident
        || record.filetype != layout.filetype
        || record.image_base != layout.image_base
    {
        return None;
    }
    // The UUID field must stay inside the first hash page — the patch
    // path rewrites it in tile 0 only.
    if layout
        .linkedit
        .uuid_at
        .checked_add(16)
        .is_none_or(|end| end > HASH_PAGE)
    {
        return None;
    }
    let (_, sections) = skeleton_of(layout);
    if record.segments.is_empty()
        || record.sections.len() != sections.len()
        || record.segments.len() != layout.segments.len()
    {
        return None;
    }
    // Slots hold everywhere: same names, order, flags, alignment,
    // zero-fill class. Placement and size may only change behind the
    // first resize.
    for (r, n) in record.sections.iter().zip(&sections) {
        if r.seg != n.seg
            || r.name != n.name
            || r.flags != n.flags
            || r.align_log2 != n.align_log2
            || r.zerofill != n.zerofill
        {
            return None;
        }
    }
    // The first placement/size change; everything before it holds.
    let mut first_change = None;
    for (i, (r, n)) in record.sections.iter().zip(&sections).enumerate() {
        if r.vm_addr != n.vm_addr || r.file_off != n.file_off || r.size != n.size {
            first_change = Some(i);
            break;
        }
    }
    if let Some(k) = first_change {
        // A shrinking image may not resize any section: under the M9
        // anchors a content section only ever outgrows its reservation, so
        // a resize beside a shrinking tail means something downstream
        // moved backwards — structural (the full link re-derives it).
        if shrinking {
            return None;
        }
        let r = &record.sections[k];
        let n = &sections[k];
        // The overflowing section holds its base and grows.
        if r.vm_addr != n.vm_addr || r.file_off != n.file_off || n.size <= r.size {
            return None;
        }
        // Every resized section stays within the ladder's segment-relayout
        // bound (growth beyond the max pad escalates to the clean link).
        if policy.fits(r.content_size, n.content_size, r.size) != LayoutFallback::SegmentRelayout {
            return None;
        }
        for (r, n) in record.sections.iter().zip(&sections).skip(k + 1) {
            if r.size != n.size
                && policy.fits(r.content_size, n.content_size, r.size)
                    != LayoutFallback::SegmentRelayout
            {
                return None;
            }
        }
    }
    // Segments: sections before the overflowing one may not move a byte,
    // the overflowing segment holds its base and may only grow, and the
    // segments behind it shift with the suffix (the tier's whole point).
    // `__LINKEDIT` is the tail the image grows into either way. The
    // LINKEDIT-overflow trigger (no resized section) freezes every content
    // segment and lets only the tail move.
    let overflow_seg = first_change.map(|k| sections[k].seg.clone());
    let overflow_idx = layout
        .segments
        .iter()
        .position(|s| Some(&s.name) == overflow_seg.as_ref());
    for (i, (r, n)) in record.segments.iter().zip(&layout.segments).enumerate() {
        if r.name != n.name {
            return None;
        }
        if n.name == "__LINKEDIT" {
            continue;
        }
        match overflow_idx {
            Some(k) if i > k => {}
            Some(k) if i == k => {
                if r.vmaddr != n.vmaddr
                    || r.fileoff != n.fileoff
                    || n.vmsize < r.vmsize
                    || n.filesize < r.filesize
                {
                    return None;
                }
            }
            _ => {
                if r.vmaddr != n.vmaddr
                    || r.vmsize != n.vmsize
                    || r.fileoff != n.fileoff
                    || r.filesize != n.filesize
                    || r.maxprot != n.maxprot
                    || r.initprot != n.initprot
                {
                    return None;
                }
            }
        }
    }
    let shifts = record
        .sections
        .iter()
        .zip(&sections)
        .map(|(r, n)| {
            let r = if r.zerofill { 0 } else { r.file_off };
            let n = if n.zerofill { 0 } else { n.file_off };
            n as i64 - r as i64
        })
        .collect();
    Some(RelayoutDelta { shifts })
}

/// Plans the relayout tier: the skeleton shifted and [`relayout_delta`]
/// vouched for the shape. The span diff runs as in the in-place tier, but
/// the propagation gate learns two relayout-specific explanations — a
/// moved section whose final bytes are unchanged (the recorded v4 digest
/// equals the new plan's) rides the shift, and a genuinely changed
/// section's *old-side* ranges are translated into the new coordinates by
/// its shift before the scope is consulted. The moved-away
/// `CodeDirectory` location joins the diff so its bytes do not survive
/// the patch.
///
/// # Errors
/// [`PatchError::Contract`] on plan shapes the full emit would also
/// reject.
fn plan_relayout(
    record: &LinkRecord,
    layout: &Layout,
    objects: &[InputObject],
    delta: RelayoutDelta,
) -> Result<PatchDecision, PatchError> {
    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
    let new_spans = span_table_with(&ctx);
    let (_, new_sections) = skeleton_of(layout);
    let run_diffs = diff_spans_sided(&record.spans.runs, &new_spans.runs);
    let mut span_changes: Vec<Range<u64>> = Vec::new();
    for (r, _) in &run_diffs {
        span_changes.push(r.clone());
    }
    let mut class_changes: Vec<Range<u64>> = span_changes.clone();
    diff_spans(&record.spans.synths, &new_spans.synths, &mut class_changes);
    diff_spans(&record.spans.blobs, &new_spans.blobs, &mut class_changes);
    diff_spans(
        &record.spans.patches,
        &new_spans.patches,
        &mut class_changes,
    );
    diff_spans(&record.spans.words, &new_spans.words, &mut class_changes);
    let mut ranges: Vec<Range<u64>> = class_changes.clone();
    let header_digest: [u8; 32] = Sha256::digest(&layout.header_bytes).into();
    if record.header_sha != header_digest {
        ranges.push(0..layout.header_bytes.len() as u64);
    }
    // The boundary moved (the tier's second trigger): everything between
    // the previous CodeDirectory's start and the new one — the old
    // signature's bytes, the grown chunk tail, the zero padding — joins
    // the diff. These tiles hold no recorded page hashes (they were past
    // the old hashed prefix), so they must be re-emitted, not reused; the
    // new blob itself is rebuilt by the patch path.
    if record.code_limit > 0 && record.code_limit < layout.linkedit.sig_off {
        ranges.push(record.code_limit..layout.linkedit.sig_off);
    }

    let content_digests = next_content_digests(record, layout, &ctx, &span_changes);

    // The propagation gate, relayout-aware: a byte-identical move is
    // explained by the skeleton shift; genuine content churn must still
    // sit inside the propagation scope (old-side ranges translated by
    // their section's shift).
    if !span_changes.is_empty() {
        let scope = pgr_core::propagate::predict(&record.section_digests, objects, layout);
        let mut unexplained: Vec<Range<u64>> = Vec::new();
        for (range, side) in &run_diffs {
            // Each side's coordinates read its own skeleton — the two
            // lists are index-aligned (the admission checked the slots),
            // so the digest comparison pairs the same section either way.
            let index = match side {
                DiffSide::New => section_index_at(&new_sections, range.start),
                DiffSide::Old => section_index_at(&record.sections, range.start),
            };
            let Some(i) = index else {
                unexplained.push(range.clone());
                continue;
            };
            if record.content_digests[i].sha == content_digests[i].sha {
                continue;
            }
            let probe = match side {
                DiffSide::New => range.clone(),
                DiffSide::Old => {
                    let shift = delta.shifts[i];
                    let start = (range.start as i64 + shift).max(0) as u64;
                    let end = (range.end as i64 + shift).max(0) as u64;
                    start..end.max(start)
                }
            };
            if !scope
                .ranges
                .iter()
                .any(|p| p.start < probe.end && probe.start < p.end)
            {
                unexplained.push(probe);
            }
        }
        if !unexplained.is_empty() {
            return Ok(PatchDecision::Fallback(
                FallbackReason::PropagationMismatch {
                    detail: format!(
                        "{} content change(s) outside the propagation scope: {}",
                        unexplained.len(),
                        list_ranges(unexplained.into_iter())
                    ),
                },
            ));
        }
    }

    let plan = finish_plan(
        record,
        layout,
        ranges,
        new_spans,
        Some(delta),
        content_digests,
    );
    Ok(match plan {
        Ok(plan) => PatchDecision::InPlace(plan),
        Err(reason) => PatchDecision::Fallback(reason),
    })
}

// ---------------------------------------------------------------------------
// The output integrity gate
// ---------------------------------------------------------------------------

/// The sampled page set both integrity gates check: page 0, every
/// `SAMPLE_STRIDE`-th hashed page, the last hashed page — sorted, deduped.
fn sample_pages(pages: u64) -> Vec<u64> {
    let last = pages - 1;
    let mut sample: Vec<u64> = (0..pages).step_by(SAMPLE_STRIDE as usize).collect();
    sample.push(last);
    sample.sort_unstable();
    sample.dedup();
    sample
}

/// Cheaply verifies the previous output still matches the record: the file
/// length and the SHA-256 of page 0, every 64th hashed page and the last
/// hashed page. [`Integrity::Mismatch`] falls back — never overwrites.
///
/// # Errors
/// [`PatchError::Io`] when the file cannot be read (missing output → the
/// caller falls back).
pub fn check_output(prev_path: &Path, record: &LinkRecord) -> Result<Integrity, PatchError> {
    let file = std::fs::File::open(prev_path).map_err(|source| PatchError::Io {
        path: prev_path.display().to_string(),
        source,
    })?;
    let len = file
        .metadata()
        .map_err(|source| PatchError::Io {
            path: prev_path.display().to_string(),
            source,
        })?
        .len();
    if len != record.file_size {
        return Ok(Integrity::Mismatch {
            detail: format!("file is {len} bytes, record says {}", record.file_size),
        });
    }
    let pages = record.hashed_pages();
    if pages == 0 {
        return Ok(Integrity::Match);
    }
    for p in sample_pages(pages) {
        let at = p * HASH_PAGE;
        let take = HASH_PAGE.min(record.code_limit - at);
        let mut buf = vec![0u8; take as usize];
        file.read_exact_at(&mut buf, at)
            .map_err(|source| PatchError::Io {
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

/// The bytes-level twin of [`check_output`]: the same length and
/// sampled-page-hash gate over an in-memory image — the resident session's
/// ladder runs it on the previous output the client transferred as a blob.
/// The two gates check the same sampled page set (page 0, every
/// `SAMPLE_STRIDE`-th hashed page, the last) and answer identically on
/// identical state.
///
/// # Errors
/// [`PatchError::Contract`] when the record carries no hash for a sampled
/// page (a decode-level bug, not a state mismatch).
pub fn output_integrity(prev: &[u8], record: &LinkRecord) -> Result<Integrity, PatchError> {
    if prev.len() as u64 != record.file_size {
        return Ok(Integrity::Mismatch {
            detail: format!(
                "image is {} bytes, record says {}",
                prev.len(),
                record.file_size
            ),
        });
    }
    let pages = record.hashed_pages();
    if pages == 0 {
        return Ok(Integrity::Match);
    }
    for p in sample_pages(pages) {
        let at = p * HASH_PAGE;
        let end = at + HASH_PAGE.min(record.code_limit - at);
        let buf = prev
            .get(at as usize..end as usize)
            .ok_or_else(|| PatchError::Contract {
                message: format!("image shorter than the hashed page {p}"),
            })?;
        let got: [u8; 32] = Sha256::digest(buf).into();
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
/// resizes the clone when the plan grew the image (the relayout tier),
/// `pwrite`s the dirty tiles, rebuilds page 0 (new `LC_UUID`) and the
/// `CodeDirectory` (merged hash table), renames over the destination, and
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
    resolution: Option<pgr_core::resolve::ResolutionSnapshot>,
) -> Result<(PatchOutcome, LinkRecord), PatchError> {
    if plan.is_untouched() {
        return Err(PatchError::Fallback(FallbackReason::OutputChanged {
            detail: "plan says nothing changed".into(),
        }));
    }
    let code_limit = content_limit(layout);
    // The signature boundary moves only under the relayout tier's second
    // trigger (the `__LINKEDIT` tail outgrew its reservation); a tier-1
    // plan with a moved boundary is a planner bug.
    if plan.relayout.is_none() && code_limit != record.code_limit {
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
    // The relayout tier grew the image: the clone extends to the new file
    // size before the dirty tiles land (the extension is zeros; the moved
    // suffix's tiles rewrite everything the new plan places there).
    if layout.file_size != record.file_size {
        if let Err(source) = file.set_len(layout.file_size) {
            drop(file);
            let _ = std::fs::remove_file(&tmp_path);
            return Err(PatchError::Io {
                path: tmp_path.display().to_string(),
                source,
            });
        }
    }

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
    let new_record = LinkRecord::assemble_from(
        layout,
        plan.spans.clone(),
        page_hashes,
        pgr_core::propagate::section_digests(objects),
        plan.content_digests.clone(),
        resolution,
    )?;
    Ok((outcome, new_record))
}

/// The bytes-level twin of [`apply_patch`]: the same plan contract and the
/// same patch body (the shared, sink-generic `patch_file`), spliced into
/// an in-memory copy of the previous
/// output instead of a cloned file. The resident session's ladder runs it
/// (§7.2 "the daemon holds no output state" survives: the patched bytes
/// cross the wire like any image and the client's Pass 5 write owns the
/// vnode). The result is byte-identical to the file path's output — the
/// engine's contract, gated for both forms in `tests/incremental.rs`.
///
/// # Errors
/// [`PatchError::Fallback`] when the plan is empty (untouched) or the
/// previous bytes are not the recorded size; [`PatchError::Contract`] on
/// plan shape bugs.
pub fn apply_patch_bytes(
    prev: &[u8],
    record: &LinkRecord,
    plan: &PatchPlan,
    layout: &Layout,
    objects: &[InputObject],
    resolution: Option<pgr_core::resolve::ResolutionSnapshot>,
) -> Result<(PatchOutcome, LinkRecord, Vec<u8>), PatchError> {
    if plan.is_untouched() {
        return Err(PatchError::Fallback(FallbackReason::OutputChanged {
            detail: "plan says nothing changed".into(),
        }));
    }
    let code_limit = content_limit(layout);
    if plan.relayout.is_none() && code_limit != record.code_limit {
        return Err(PatchError::Contract {
            message: "plan passed the skeleton gate but the code limit moved".into(),
        });
    }
    if plan.total_tiles != layout.file_size.div_ceil(TILE) as u32 {
        return Err(PatchError::Contract {
            message: "plan tile count disagrees with the layout".into(),
        });
    }
    if prev.len() as u64 != record.file_size {
        return Err(PatchError::Fallback(FallbackReason::OutputChanged {
            detail: format!(
                "previous output is {} bytes, record says {}",
                prev.len(),
                record.file_size
            ),
        }));
    }
    let symtab = symtab_bytes(layout);
    let indirect = indirect_bytes(layout);
    let ctx = TileCtx::build(layout, objects, &symtab, &indirect)?;
    if code_limit > 0 && plan.dirty_tiles.first() != Some(&0) {
        return Err(PatchError::Contract {
            message: "plan must include tile 0 (the UUID page) when anything is dirty".into(),
        });
    }
    // The relayout tier grew the image: the copy extends to the new size
    // (zeros — the moved suffix's tiles rewrite everything placed there),
    // exactly the clone path's `set_len` extension.
    let mut out = prev.to_vec();
    out.resize(layout.file_size as usize, 0);
    let (outcome, page_hashes) = patch_file(&mut out, record, plan, layout, &ctx, code_limit)?;
    let new_record = LinkRecord::assemble_from(
        layout,
        plan.spans.clone(),
        page_hashes,
        pgr_core::propagate::section_digests(objects),
        plan.content_digests.clone(),
        resolution,
    )?;
    Ok((outcome, new_record, out))
}

/// The clone's temp name (sibling, `pgr`-shaped, removed on failure).
fn tmp_name(out_path: &Path) -> std::path::PathBuf {
    let mut name = out_path.as_os_str().to_owned();
    name.push(".pgr.inc.tmp");
    std::path::PathBuf::from(name)
}

/// The patch body's write target: positioned writes of tile/superblob
/// bytes. `std::fs::File` implements it with `pwrite` (`write_all_at` —
/// the clone-and-patch path's no-seek-races discipline); `Vec<u8>`
/// implements it with a splice — the resident session patches in memory
/// with the identical body ([`patch_file`] is generic over the sink).
trait PatchSink {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<(), PatchError>;
}

impl PatchSink for std::fs::File {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<(), PatchError> {
        self.write_all_at(bytes, at)
            .map_err(|source| PatchError::Io {
                path: "patch target".into(),
                source,
            })
    }
}

impl PatchSink for Vec<u8> {
    fn write_at(&mut self, at: u64, bytes: &[u8]) -> Result<(), PatchError> {
        let end = at
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| PatchError::Contract {
                message: "patch write overflows the image".into(),
            })? as usize;
        if end > self.len() {
            self.resize(end, 0);
        }
        self[at as usize..end].copy_from_slice(bytes);
        Ok(())
    }
}

/// The patch body over an open output sink: emit dirty tiles, derive the
/// UUID, re-sign. Returns the outcome and the final (record-form) hash
/// table. Generic over the sink: the file path (`pwrite` into the clone)
/// and the bytes path (splice into the in-memory image) run the identical
/// body, so the byte-identity contract covers both.
fn patch_file<S: PatchSink>(
    sink: &mut S,
    record: &LinkRecord,
    plan: &PatchPlan,
    layout: &Layout,
    ctx: &TileCtx<'_>,
    code_limit: u64,
) -> Result<(PatchOutcome, Vec<[u8; 32]>), PatchError> {
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
        for (t, tile) in &mut scratches {
            if *t == 0 {
                let uuid_at = layout.linkedit.uuid_at as usize;
                let dst =
                    tile.get_mut(uuid_at..uuid_at + 16)
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
        sink.write_at(u64::from(*t) * TILE, tile)?;
        bytes_patched += tile.len() as u64;
    }
    if code_limit > 0 {
        let mut final_flat: Vec<u8> = Vec::with_capacity(merged.len() * 32);
        for h in &merged {
            final_flat.extend_from_slice(h);
        }
        let is_exec = layout.filetype == pgr_format::consts::MH_EXECUTE;
        let blob = signature::build_superblob(
            &layout.ident,
            code_limit,
            &final_flat,
            layout.text_vmsize,
            is_exec,
        )?;
        if blob.len() as u64 != layout.linkedit.sig_size {
            return Err(PatchError::Contract {
                message: format!(
                    "rebuilt signature is {} bytes but the layout reserved {}",
                    blob.len(),
                    layout.linkedit.sig_size
                ),
            });
        }
        sink.write_at(layout.linkedit.sig_off, &blob)?;
        bytes_patched += blob.len() as u64;
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

// ---- the wire's tile stream (M9 output-residency rung, wire v5) -------------

/// The changed-tile stream the resident wire serves (protocol v5, the §7.2
/// output-residency rung). When the session holds the previous output, a
/// patched relink ships only the 16 KiB tiles whose bytes moved instead of
/// the whole image. Tile granularity is lossless by construction — the
/// fused emit's own tile invariant (chains never cross a tile, TDD §7.4)
/// means every byte of the patched image lives in exactly one tile — so
/// [`apply_tiles`] over the previous bytes reproduces the patched image
/// byte for byte, and the stream carries that image's SHA-256 as the
/// client's replay gate (a diverged replay is refused, never written).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TilePatch {
    /// The patched image's size in bytes (the relayout tiers resize the
    /// clone; the replay resizes to this before splicing).
    pub final_size: u64,
    /// Every changed tile as `(offset, bytes)`, offsets ascending; each
    /// offset is 16 KiB-aligned and `bytes` reaches the next tile boundary
    /// or the image end.
    pub tiles: Vec<(u64, Vec<u8>)>,
    /// SHA-256 of the patched image the stream reproduces (the client's
    /// replay gate — a divergence never ships, §7.3).
    pub image_hash: [u8; 32],
}

impl TilePatch {
    /// The wire's honest price: the bytes the tile stream carries (what
    /// the full image would have cost, minus what residency saved).
    #[must_use]
    pub fn wire_bytes(&self) -> u64 {
        self.tiles.iter().map(|(_, b)| b.len() as u64).sum()
    }
}

/// A refused-to-ship tile replay (v5, the §7.2 rung): the resident client
/// rebuilt the patched image from the wire's tile stream and the result
/// missed the stream's own content-hash gate. Nothing is written — the
/// transparency contract stands the link down to the in-process path,
/// which re-patches from the local record. Refusals render with miette
/// help-text (the fix, not just the verdict), the same discipline as
/// [`crate::incremental::audit::AuditRefusal`].
#[derive(Debug, Clone, thiserror::Error, miette::Diagnostic)]
#[error(
    "the resident tile replay did not reproduce the audited image (got {}, wanted {})",
    .got,
    .want
)]
#[diagnostic(help(
    "a divergence never ships: the relink falls back to the in-process \
     path, which re-patches from the local record; re-run with \
     PGR_RESIDENT_DEBUG=1 to log the tile replay, or drop -resident once \
     to rebuild the session's resident output state"
))]
pub struct TileReplayRefusal {
    /// The replay gate's hash (what the stream vouched for).
    pub want: String,
    /// The hash of what the replay actually produced.
    pub got: String,
}

impl TileReplayRefusal {
    /// Renders the refusal with its help text (multi-line, no backtrace
    /// noise) — the string the driver logs on the stand-down.
    #[must_use]
    pub fn render(&self) -> String {
        let report = miette::Report::new(self.clone());
        format!("{report:?}")
    }
}

/// The changed-tile stream between the previous output and the patched
/// image, at 16 KiB granularity, deterministic. An unchanged image yields
/// an empty stream (the untouched relink ships nothing); a resized image
/// yields `final_size` plus the changed tail tiles.
#[must_use]
pub fn diff_tiles(prev: &[u8], patched: &[u8]) -> TilePatch {
    let span = tracing::info_span!(
        "diff_tiles",
        prev_len = prev.len(),
        patched_len = patched.len()
    );
    let _entered = span.enter();
    let mut tiles: Vec<(u64, Vec<u8>)> = Vec::new();
    let n = prev.len().max(patched.len());
    let mut at = 0usize;
    while at < n {
        let end = (at + TILE as usize).min(n);
        // A tile is dirty when either image's view of it differs (a tile
        // past one image's end compares against nothing — the resize edge).
        let old = prev.get(at..end).unwrap_or(&[]);
        let new = patched.get(at..end).unwrap_or(&[]);
        if old != new && !new.is_empty() {
            // An empty `new` is pure truncation past the patched end —
            // `final_size` carries it; a zero-byte tile would only pin a
            // splice past the replay's own resize.
            tiles.push((at as u64, new.to_vec()));
        }
        at = end;
    }
    tracing::debug!(tiles = tiles.len(), "the tile stream was diffed");
    TilePatch {
        final_size: patched.len() as u64,
        tiles,
        image_hash: Sha256::digest(patched).into(),
    }
}

/// Applies a tile stream to the previous bytes — the client-side replay
/// twin of [`diff_tiles`]: resize to `final_size` (the relayout tiers move
/// the image end), then splice every tile. The caller verifies the replay
/// against `TilePatch::image_hash` before anything is written (a
/// divergence never ships).
#[must_use]
pub fn apply_tiles(prev: &[u8], patch: &TilePatch) -> Vec<u8> {
    let span = tracing::info_span!(
        "apply_tiles",
        tiles = patch.tiles.len(),
        final_size = patch.final_size
    );
    let _entered = span.enter();
    let mut out = prev.to_vec();
    out.resize(patch.final_size as usize, 0);
    for (at, bytes) in &patch.tiles {
        let start = *at as usize;
        if start >= out.len() {
            continue; // A stream that only shrinks past the replay's end.
        }
        let end = (start + bytes.len()).min(out.len());
        out[start..end].copy_from_slice(&bytes[..end - start]);
    }
    out
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
        assert_eq!(ranges, [] as [std::ops::Range<u64>; 0]);
        // Same digests at the same offsets, different objects: quiet.
        let new = vec![mk(0, 1), mk(100, 2)];
        diff_spans(&old, &new, &mut ranges);
        assert_eq!(ranges, [] as [std::ops::Range<u64>; 0]);
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
                flags: 0x8000_0400,
                align_log2: 2,
                vm_addr: 0x4000,
                content_size: 40,
                size: 4096,
                file_off: 0x4000,
                zerofill: false,
            }],
            imports: vec![pgr_core::stable_imports::StableImport {
                lib_ordinal: 1,
                name: b"_log".to_vec(),
                outlined_addend: 0,
                weak: false,
            }],
            section_digests: vec![pgr_core::propagate::SectionDigest {
                file: 0,
                in_sect: 0,
                sha: [3; 32],
            }],
            content_digests: vec![OutputSectionDigest {
                seg: "__TEXT".into(),
                name: "__text".into(),
                sha: [4; 32],
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
            resolution: Some(pgr_core::resolve::ResolutionSnapshot {
                file_names: vec![b"a.o".to_vec()],
                candidates: vec![(
                    b"_main".to_vec(),
                    pgr_core::resolve::DefLite {
                        file: 0,
                        sym: 3,
                        rank: pgr_core::resolve::Rank::Strong,
                        weak: false,
                        value: 0,
                        section: Some(0),
                        common_align: 0,
                        common_size: 0,
                    },
                )],
                winner_slots: vec![vec![
                    None,
                    None,
                    None,
                    Some(pgr_core::resolve::DefLite {
                        file: 0,
                        sym: 3,
                        rank: pgr_core::resolve::Rank::Strong,
                        weak: false,
                        value: 0,
                        section: Some(0),
                        common_align: 0,
                        common_size: 0,
                    }),
                ]],
                dylib_export_names: Vec::new(),
            }),
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
